"""Tests des actions dérivées et du contrôle de cohérence.

Ces deux modules sont la barrière entre une sortie de modèle et une action sur
la production. Ils doivent être vérifiables sans modèle ni base — c'est
précisément ce qui les rend fiables.
"""

from soc_agent.actions import (apply_guardrails, infer,
                               high_impact_actions)
from soc_agent.coherence import check


# --- actions dérivées -------------------------------------------------------

def test_vrai_positif_ouvre_toujours_un_case():
    """Le modèle omettait open_case deux fois sur quatre — d'où la déduction."""
    assert "open_case" in infer("true_positive", ["propose_block_ip"])
    assert "open_case" in infer("true_positive", [])


def test_faux_positif_ecarte_toute_remediation():
    """Si l'activité est légitime, il n'y a rien à couper."""
    actions = infer("false_positive",
                      ["propose_block_ip", "propose_isolate_host"])
    assert actions == ["close_false_positive"]


def test_doute_escalade_a_un_humain():
    """La collecte forensique n'est pas une action de l'IA : le doute escalade."""
    assert infer("needs_investigation", []) == ["escalate_human"]


def test_doute_ne_cloture_jamais():
    actions = infer("needs_investigation", ["escalate_human"])
    assert "close_false_positive" not in actions


def test_kill_process_passe_avant_isolation():
    """Ordre d'urgence : tuer le process prime (chirurgical), isoler ensuite."""
    actions = infer("true_positive",
                      ["propose_block_ip", "propose_isolate_host",
                       "propose_kill_process"])
    assert actions[0] == "propose_kill_process"
    assert actions.index("propose_kill_process") < actions.index("propose_isolate_host")


def test_actions_a_fort_impact_signalees():
    actions = infer("true_positive",
                      ["propose_isolate_host", "propose_kill_process"])
    high = high_impact_actions(actions)
    assert "propose_isolate_host" in high
    assert "propose_kill_process" in high          # tuer un process = fort impact
    # open_case est sans effet sur la production : pas une action à fort impact.
    assert "open_case" not in high


# --- garde-fous déterministes -----------------------------------------------

def test_isolation_retiree_si_confinement_moins_invasif_suffit():
    """Cas nominal : un scanner qui tape une URL (pas de compromission active)
    -> bloquer l'IP suffit, l'isolation est retirée et un humain tranche."""
    actions, patterns = apply_guardrails(
        "true_positive", ["propose_isolate_host", "propose_block_ip"],
        max_level=12, suspected_injection=False, active_compromise=False)
    assert "propose_isolate_host" not in actions
    assert "propose_block_ip" in actions
    assert "escalate_human" in actions
    assert any("isolation retirée" in m for m in patterns)


def test_isolation_maintenue_si_compromission_active():
    """Compromission active de l'hôte (webshell/reverse shell/rootkit) :
    l'isolation est MAINTENUE malgré le block_ip — couper l'IP ne déloge pas un
    attaquant déjà installé. Régression mesurée à un exercice purple-team."""
    actions, patterns = apply_guardrails(
        "true_positive", ["propose_isolate_host", "propose_block_ip"],
        max_level=13, suspected_injection=False, active_compromise=True)
    assert "propose_isolate_host" in actions
    assert "propose_block_ip" in actions
    assert any("isolation MAINTENUE" in m for m in patterns)


def test_cloture_refusee_sur_niveau_critique_meme_avec_compromission():
    """La barrière anti-clôture prime : un FP de niveau >= 14 n'est jamais clos,
    quel que soit le drapeau de compromission."""
    actions, patterns = apply_guardrails(
        "false_positive", ["close_false_positive"],
        max_level=15, suspected_injection=False, active_compromise=True)
    assert actions == ["escalate_human", "open_case"]
    assert patterns


# --- cohérence --------------------------------------------------------------

def test_faux_positif_avec_blocage_est_incoherent():
    """Cas réellement observé au premier passage."""
    issues = check("false_positive", ["propose_block_ip"])
    assert issues and "propose_block_ip" in issues[0]


def test_faux_positif_sans_action_est_coherent():
    assert check("false_positive", []) == []


def test_couper_sur_doute_est_incoherent():
    """Sur un simple doute, aucune action irréversible ne se justifie."""
    assert check("needs_investigation", ["propose_isolate_host"])
    assert check("needs_investigation", ["propose_kill_process"])
    # Escalader (pas une coupure) reste cohérent sur un doute.
    assert check("needs_investigation", ["escalate_human"]) == []


def test_vrai_positif_sans_action_est_signale():
    assert check("true_positive", []) != []


def test_sortie_nominale_est_coherente():
    assert check("true_positive",
                    ["propose_isolate_host", "propose_block_ip"]) == []
