"""Logique pure de la remédiation (sans Shuffle, Wazuh ni IRIS)."""

import json

from soc_agent.mitigate import (REMEDIATIONS, REVERSEURS, _cibles,
                                _comptes_crees, _desc_tache, _interpreter,
                                _taches_annulees)


def _alerte_proctitle(cmd: str) -> dict:
    """Alerte auditd portant `cmd` dans son proctitle hex (args nul-séparés)."""
    hexp = cmd.replace(" ", "\x00").encode().hex()
    return {"srcip": None, "srcuser": None, "entity": None,
            "raw": json.dumps({"full_log": f"type=PROCTITLE proctitle={hexp}"})}


def test_comptes_crees_extrait_backdoor_du_proctitle():
    """Le compte créé par useradd est capté depuis le proctitle auditd (niv. 3),
    sans l'alerte syslog 5902 — c'est ce qui permet de bloquer le backdoor sans
    monter le niveau de l'alerte d'ajout d'utilisateur."""
    al = [_alerte_proctitle("useradd -m -s /bin/bash svcbackup")]
    assert _comptes_crees(al) == ["svcbackup"]
    # …et devient une cible de désactivation.
    cibles = _cibles("propose_disable_user", {"agent_id": "001"}, al)
    assert "svcbackup" in cibles


def test_comptes_crees_exclut_comptes_proteges():
    # root / comptes système ne sont jamais des cibles de désactivation auto.
    assert _comptes_crees([_alerte_proctitle("useradd -m root")]) == []


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
        {"srcip": "192.168.50.50", "srcuser": "root", "entity": None, "raw": "{}"},
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


def test_taches_annulees_ne_garde_que_canceled():
    """Réconciliation : seules les tâches en 'Canceled' déclenchent un reverse."""
    tasks = [
        {"task_id": 1, "status_name": "Done"},
        {"task_id": 2, "status_name": "Canceled"},
        {"task_id": 3, "status_name": "To do"},
        {"task_id": 4, "status_name": "Canceled"},
    ]
    assert _taches_annulees(tasks) == {2, 4}
    assert _taches_annulees([]) == set()
    assert _taches_annulees(None) == set()


def test_reverse_pour_actions_reversibles_pas_pour_kill():
    """Isolation, blocage IP et désactivation ont un reverse ; le kill non
    (un process tué ne se « unkill » pas)."""
    assert set(REVERSEURS) == {"propose_isolate_host", "propose_block_ip",
                               "propose_disable_user"}
    assert "propose_kill_process" not in REVERSEURS


def test_desc_tache_contient_quoi_pourquoi_annulation():
    triage = {"verdict": "true_positive", "confidence": "high",
              "reason": "Ransomware en cours."}
    desc = _desc_tache(triage, "001", "exécuté", "Shuffle",
                       "Isolation nftables.", "curl ... !host-unisolate.sh")
    assert "Ce qui a été fait" in desc
    assert "Pourquoi" in desc and "Ransomware en cours." in desc
    assert "Comment annuler" in desc and "unisolate" in desc
    assert "**Statut** : exécuté" in desc
