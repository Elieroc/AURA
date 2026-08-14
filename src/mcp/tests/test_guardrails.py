"""The MCP server must not weaken the pipeline's guardrails.

These tests do not re-verify the logic of `soc_agent.actions` — it has its own
tests. They verify that the MCP path really goes through it, and that a client
who politely asks for something else does not get it.
"""

from aura_mcp import auth
from aura_mcp.tools import simulation


def _read():
    return auth.SCOPES.set(frozenset({"aura:read"}))


def test_injection_prevents_automatic_closure():
    """The barrier that matters.

    The model gets turned by an injection in the logs 3 times out of 4. A
    trapped alert that makes it conclude "false positive" must therefore never
    be enough on its own to close the case.
    """
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="false_positive",
            proposed_actions=[],
            max_level=13,
            suspected_injection=True)
        assert "close_false_positive" not in r["final_actions"]
        assert r["triggered_guardrails"]
    finally:
        auth.SCOPES.reset(token)


def test_critical_level_prevents_automatic_closure():
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="false_positive", proposed_actions=[], max_level=15)
        assert "close_false_positive" not in r["final_actions"]
    finally:
        auth.SCOPES.reset(token)


def test_isolation_downgraded_if_less_invasive_containment():
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="true_positive",
            proposed_actions=["propose_isolate_host", "propose_block_ip"],
            max_level=12)
        assert "propose_isolate_host" not in r["final_actions"]
        assert "propose_block_ip" in r["final_actions"]
    finally:
        auth.SCOPES.reset(token)


def test_isolation_kept_if_active_compromise():
    """Downgrading an isolation on a compromised host would be the worst case."""
    token = _read()
    try:
        r = simulation.aura_simulate_decision(
            verdict="true_positive",
            proposed_actions=["propose_isolate_host", "propose_block_ip"],
            max_level=12,
            active_compromise=True)
        assert "propose_isolate_host" in r["final_actions"]
    finally:
        auth.SCOPES.reset(token)


def test_rule_preview_refuses_a_child_before_its_parent():
    """Wazuh would load the rule and never evaluate it, without error."""
    token = _read()
    try:
        r = simulation.aura_rule_preview(
            rule_id=101000, parent="101500", level=5,
            signature={"rule_id": "101500"})
        assert "error" in r
        assert "GREATER" in r["error"]
    finally:
        auth.SCOPES.reset(token)


def test_rule_preview_refuses_outside_reserved_range():
    token = _read()
    try:
        r = simulation.aura_rule_preview(
            rule_id=100657, parent="1002", level=5, signature={})
        assert "error" in r
    finally:
        auth.SCOPES.reset(token)
