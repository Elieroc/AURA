"""Logique pure de la remédiation (sans Shuffle, Wazuh ni IRIS)."""

from soc_agent.mitigate import REMEDIATIONS, _cibles, _note


def test_cibles_par_action():
    inc = {"agent_id": "001"}
    alertes = [
        {"srcip": "45.134.26.87", "srcuser": "jdupont"},   # IP publique, compte
        {"srcip": "192.168.1.50", "srcuser": "root"},      # IP privée, générique
    ]
    # Isolation/collecte visent l'agent.
    assert _cibles("propose_isolate_host", inc, alertes) == ["001"]
    assert _cibles("collect_endpoint_evidence", inc, alertes) == ["001"]
    # Blocage : seulement les IP externes (l'IP privée n'est pas une cible).
    assert _cibles("propose_block_ip", inc, alertes) == ["45.134.26.87"]
    # Désactivation : comptes nommés, pas les génériques (root).
    assert _cibles("propose_disable_user", inc, alertes) == ["jdupont"]


def test_open_case_et_escalade_hors_remediation():
    assert "open_case" not in REMEDIATIONS
    assert "close_false_positive" not in REMEDIATIONS
    assert "escalate_human" not in REMEDIATIONS


def test_note_contient_quoi_pourquoi_annulation():
    triage = {"verdict": "true_positive", "confidence": "high",
              "reason": "Ransomware en cours."}
    note = _note(triage, "propose_isolate_host", "001", "exécuté",
                 "Shuffle", "Isolation nftables.", "curl ... !host-unisolate.sh")
    assert "Ce qui a été fait" in note
    assert "Pourquoi" in note and "Ransomware en cours." in note
    assert "Comment annuler" in note and "unisolate" in note
    assert "[SIMULATION]" not in note        # pas de marqueur si exécuté


def test_note_marque_simulation_en_dry_run():
    triage = {"verdict": "true_positive", "confidence": "high", "reason": "x"}
    note = _note(triage, "propose_isolate_host", "001", "dry_run",
                 "Shuffle", "d", "u")
    assert note.startswith("# [SIMULATION]")
