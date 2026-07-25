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


def test_doute_escalade_a_un_humain():
    """La collecte forensique n'est pas une action de l'IA : le doute escalade."""
    assert deduire("needs_investigation", []) == ["escalate_human"]


def test_doute_ne_cloture_jamais():
    actions = deduire("needs_investigation", ["escalate_human"])
    assert "close_false_positive" not in actions


def test_kill_process_passe_avant_isolation():
    """Ordre d'urgence : tuer le process prime (chirurgical), isoler ensuite."""
    actions = deduire("true_positive",
                      ["propose_block_ip", "propose_isolate_host",
                       "propose_kill_process"])
    assert actions[0] == "propose_kill_process"
    assert actions.index("propose_kill_process") < actions.index("propose_isolate_host")


def test_actions_a_fort_impact_signalees():
    actions = deduire("true_positive",
                      ["propose_isolate_host", "propose_kill_process"])
    fort = actions_fort_impact(actions)
    assert "propose_isolate_host" in fort
    assert "propose_kill_process" in fort          # tuer un process = fort impact
    # open_case est sans effet sur la production : pas une action à fort impact.
    assert "open_case" not in fort


# --- cohérence --------------------------------------------------------------

def test_faux_positif_avec_blocage_est_incoherent():
    """Cas réellement observé au premier passage."""
    problemes = verifier("false_positive", ["propose_block_ip"])
    assert problemes and "propose_block_ip" in problemes[0]


def test_faux_positif_sans_action_est_coherent():
    assert verifier("false_positive", []) == []


def test_couper_sur_doute_est_incoherent():
    """Sur un simple doute, aucune action irréversible ne se justifie."""
    assert verifier("needs_investigation", ["propose_isolate_host"])
    assert verifier("needs_investigation", ["propose_kill_process"])
    # Escalader (pas une coupure) reste cohérent sur un doute.
    assert verifier("needs_investigation", ["escalate_human"]) == []


def test_vrai_positif_sans_action_est_signale():
    assert verifier("true_positive", []) != []


def test_sortie_nominale_est_coherente():
    assert verifier("true_positive",
                    ["propose_isolate_host", "propose_block_ip"]) == []
