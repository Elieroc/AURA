"""Tests des helpers de génération de case IRIS (sans base ni IRIS).

Le formatage des notes et le choix de classification/IOC sont déterministes et
doivent l'être : c'est ce qui atterrit dans le dossier d'incident lu par un
analyste.
"""

from soc_agent.iris import (
    CLASSIF_BRUTE,
    CLASSIF_DEFAUT,
    CLASSIF_RANSOMWARE,
    _classification,
    _iocs,
    _note_fp,
    _note_tp,
    _poser_note,
    _taguer,
)


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
    alertes = [
        {"srcip": "45.134.26.87", "entity": "/tmp/x",
         "raw": json.dumps({"data": {"virustotal": {"source": {"sha256": "abc"}}}})},
        {"srcip": "45.134.26.87", "entity": "/tmp/x",   # doublon
         "raw": json.dumps({"data": {}})},
    ]
    iocs = _iocs(alertes)
    valeurs = {v for v, _, _ in iocs}
    types = {t for _, t, _ in iocs}
    assert valeurs == {"45.134.26.87", "/tmp/x", "abc"}   # dédupliqué
    assert "ip-any" in types and "sha256" in types


def test_taguer_ajoute_hostname():
    """Le hostname de la machine touchée devient un tag du case."""
    c = FakeCase(tags="")
    _taguer(c, 5, "debian-vm")
    assert c.updates == [{"case_tags": ["debian-vm"]}]


def test_taguer_union_sans_ecraser_ni_dupliquer():
    """On complète les tags existants ; un hostname déjà présent ne rejoue rien."""
    c = FakeCase(tags="prod, debian-vm")
    _taguer(c, 5, "debian-vm")            # déjà présent
    assert c.updates == []
    c2 = FakeCase(tags="prod")
    _taguer(c2, 5, "debian-vm")
    assert c2.updates == [{"case_tags": ["debian-vm", "prod"]}]


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
    inc = {"id": 1, "agent_name": "debian-vm", "agent_id": "001",
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
