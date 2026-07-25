"""Tests des actions dérivées et du contrôle de cohérence.

Ces deux modules sont la barrière entre une sortie de modèle et une action sur
la production. Ils doivent être vérifiables sans modèle ni base — c'est
précisément ce qui les rend fiables.
"""

from soc_agent.actions import deduire, actions_fort_impact
from soc_agent.coherence import verifier


# --- actions dérivées -------------------------------------------------------

def test_vrai_positif_ouvre_toujours_un_case():
    """Le modèle omettait open_case deux fois sur quatre — d'où la déduction."""
    assert "open_case" in deduire("true_positive", ["propose_block_ip"])
    assert "open_case" in deduire("true_positive", [])


def test_faux_positif_ecarte_toute_remediation():
    """Si l'activité est légitime, il n'y a rien à couper."""
    actions = deduire("false_positive",
                      ["propose_block_ip", "propose_isolate_host"])
    assert actions == ["close_false_positive"]


def test_doute_demande_de_quoi_lever_le_doute():
    assert deduire("needs_investigation", []) == ["collect_endpoint_evidence"]


def test_doute_ne_cloture_jamais():
    actions = deduire("needs_investigation", ["escalate_human"])
    assert "close_false_positive" not in actions


def test_isolation_passe_en_premier():
    """Ordre d'urgence : isoler arrête l'attaque, le reste vient après."""
    actions = deduire("true_positive",
                      ["collect_endpoint_evidence", "propose_block_ip",
                       "propose_isolate_host"])
    assert actions[0] == "propose_isolate_host"


def test_actions_a_fort_impact_signalees():
    actions = deduire("true_positive",
                      ["propose_isolate_host", "collect_endpoint_evidence"])
    a_valider = actions_fort_impact(actions)
    assert "propose_isolate_host" in a_valider
    # La collecte est en lecture seule et l'ouverture d'un case sans effet sur
    # la production : ni l'une ni l'autre n'a à passer par une validation.
    assert "collect_endpoint_evidence" not in a_valider
    assert "open_case" not in a_valider


# --- cohérence --------------------------------------------------------------

def test_faux_positif_avec_blocage_est_incoherent():
    """Cas réellement observé au premier passage."""
    problemes = verifier("false_positive", ["propose_block_ip"])
    assert problemes and "propose_block_ip" in problemes[0]


def test_faux_positif_sans_action_est_coherent():
    assert verifier("false_positive", []) == []


def test_isolation_sur_doute_sans_collecte_est_incoherente():
    assert verifier("needs_investigation", ["propose_isolate_host"])
    assert verifier("needs_investigation",
                    ["propose_isolate_host", "collect_endpoint_evidence"]) == []


def test_vrai_positif_sans_action_est_signale():
    assert verifier("true_positive", []) != []


def test_sortie_nominale_est_coherente():
    assert verifier("true_positive",
                    ["propose_isolate_host", "propose_block_ip"]) == []
