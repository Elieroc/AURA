"""Le serveur MCP ne doit pas affaiblir les garde-fous du pipeline.

Ces tests ne revérifient pas la logique de `soc_agent.actions` — elle a ses
propres tests. Ils vérifient que le chemin MCP passe bien par elle, et qu'un
client qui demande poliment autre chose ne l'obtient pas.
"""

from aura_mcp import auth
from aura_mcp.tools import simulation


def _read():
    return auth.SCOPES.set(frozenset({"aura:read"}))


def test_injection_empeche_la_cloture_automatique():
    """La barrière qui compte.

    Le modèle se laisse retourner par une injection dans les journaux 3 fois
    sur 4. Une alerte piégée qui lui fait conclure « faux positif » ne doit
    donc jamais suffire à fermer le dossier.
    """
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="false_positive",
            proposed_actions=[],
            max_level=13,
            suspected_injection=True)
        assert "close_false_positive" not in r["actions_finales"]
        assert r["garde_fous_declenches"]
    finally:
        auth.SCOPES.reset(token)


def test_niveau_critique_empeche_la_cloture_automatique():
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="false_positive", proposed_actions=[], max_level=15)
        assert "close_false_positive" not in r["actions_finales"]
    finally:
        auth.SCOPES.reset(token)


def test_isolation_retrogradee_si_confinement_moins_invasif():
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="true_positive",
            proposed_actions=["propose_isolate_host", "propose_block_ip"],
            max_level=12)
        assert "propose_isolate_host" not in r["actions_finales"]
        assert "propose_block_ip" in r["actions_finales"]
    finally:
        auth.SCOPES.reset(token)


def test_isolation_maintenue_si_compromission_etablie():
    """Rétrograder une isolation sur un hôte compromis serait le pire des cas."""
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="true_positive",
            proposed_actions=["propose_isolate_host", "propose_block_ip"],
            max_level=12,
            active_compromise=True)
        assert "propose_isolate_host" in r["actions_finales"]
    finally:
        auth.SCOPES.reset(token)


def test_rule_preview_refuse_une_fille_avant_sa_parente():
    """Wazuh chargerait la règle et ne l'évaluerait jamais, sans erreur."""
    token = _read()
    try:
        r = simulation.aura_rule_preview(
            rule_id=101000, parent="101500", level=5,
            signature={"rule_id": "101500"})
        assert "error" in r
        assert "SUPÉRIEUR" in r["error"]
    finally:
        auth.SCOPES.reset(token)


def test_rule_preview_refuse_hors_plage_reservee():
    token = _read()
    try:
        r = simulation.aura_rule_preview(
            rule_id=100657, parent="1002", level=5, signature={})
        assert "error" in r
    finally:
        auth.SCOPES.reset(token)
