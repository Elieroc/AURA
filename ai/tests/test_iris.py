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
)

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


def test_note_tp_fallback_sans_llm(monkeypatch):
    """Si le LLM est injoignable, le case se crée avec la justification du triage."""
    import soc_agent.iris as iris

    def boom(*a, **k):
        raise RuntimeError("LLM down")

    monkeypatch.setattr(iris, "completion", boom)
    triage = {"verdict": "true_positive", "confidence": "high", "mitre": "T1486",
              "reason": "Ransomware confirmé.",
              "actions": ["propose_isolate_host", "open_case"]}
    inc = {"id": 1, "agent_name": "debian-vm", "agent_id": "001",
           "first_seen": __import__("datetime").datetime(2026, 7, 22),
           "last_seen": __import__("datetime").datetime(2026, 7, 22),
           "alert_count": 3, "max_level": 15, "mitre_tactics": ["Impact"]}
    note = _note_tp(inc, triage, [{"rule_id": "100670", "rule_level": 15,
                                   "rule_desc": "canari", "rule_groups": ["ransomware"],
                                   "srcip": None, "srcuser": None,
                                   "entity": "/root/c.docx", "raw": "{}"}])
    assert "Ransomware confirmé" in note
    assert "Isoler l'hôte" in note
    assert "validation humaine requise" in note   # action à fort impact signalée
