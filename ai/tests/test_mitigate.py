"""Logique pure de la remédiation (sans Shuffle, Wazuh ni IRIS)."""

import json

from soc_agent.mitigate import REMEDIATIONS, _cibles, _desc_tache, _interpreter


def test_interpreter_etat_isolation():
    # Marqueur présent -> isolé.
    e = _interpreter('{"isolated": true, "since": "x"}', 0)
    assert e == {"isolated": True, "reachable": True,
                 "marker": {"isolated": True, "since": "x"}}
    # Fichier absent (stdout vide, rc non nul) -> non isolé.
    assert _interpreter("", 1) == {"isolated": False, "reachable": True,
                                   "marker": None}
    # Échec SSH -> état inconnu.
    assert _interpreter("", 255) == {"isolated": None, "reachable": False,
                                     "marker": None}
    # Marqueur illisible mais présent -> isolé, sans détail.
    e = _interpreter("corrompu", 0)
    assert e["isolated"] is True and e["marker"] is None


def test_cibles_par_action():
    inc = {"agent_id": "001"}
    alertes = [
        {"srcip": "45.134.26.87", "srcuser": "jdupont", "entity": None, "raw": "{}"},
        {"srcip": "192.168.1.50", "srcuser": "root", "entity": None, "raw": "{}"},
    ]
    # Isolation vise l'agent.
    assert _cibles("propose_isolate_host", inc, alertes) == ["001"]
    # Blocage : seulement les IP externes (l'IP privée n'est pas une cible).
    assert _cibles("propose_block_ip", inc, alertes) == ["45.134.26.87"]
    # Désactivation : comptes nommés, pas les génériques (root).
    assert _cibles("propose_disable_user", inc, alertes) == ["jdupont"]


def test_cibles_kill_process_vise_implant_en_dir_suspect():
    """Kill : nom exact des exécutables lancés depuis /tmp, /dev/shm… ; jamais
    un binaire système légitime."""
    inc = {"agent_id": "001"}
    alertes = [
        {"srcip": None, "srcuser": None, "entity": "/dev/shm/.kworker", "raw": "{}"},
        {"srcip": None, "srcuser": None, "entity": "/usr/bin/bash", "raw": "{}"},
        {"srcip": None, "srcuser": None, "entity": None,
         "raw": json.dumps({"data": {"audit": {"exe": "/tmp/malware"}}})},
    ]
    assert _cibles("propose_kill_process", inc, alertes) == [".kworker", "malware"]


def test_open_case_et_escalade_hors_remediation():
    assert "open_case" not in REMEDIATIONS
    assert "close_false_positive" not in REMEDIATIONS
    assert "escalate_human" not in REMEDIATIONS


def test_desc_tache_contient_quoi_pourquoi_annulation():
    triage = {"verdict": "true_positive", "confidence": "high",
              "reason": "Ransomware en cours."}
    desc = _desc_tache(triage, "001", "exécuté", "Shuffle",
                       "Isolation nftables.", "curl ... !host-unisolate.sh")
    assert "Ce qui a été fait" in desc
    assert "Pourquoi" in desc and "Ransomware en cours." in desc
    assert "Comment annuler" in desc and "unisolate" in desc
    assert "**Statut** : exécuté" in desc
