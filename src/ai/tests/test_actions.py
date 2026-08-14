"""Tests for derived actions and consistency checking.

These two modules are the barrier between a model output and an action on
production. They must be verifiable without a model or a database — that is
exactly what makes them reliable.
"""

from soc_agent.actions import (apply_guardrails, infer,
                               high_impact_actions)
from soc_agent.coherence import check


# --- derived actions ---------------------------------------------------------

def test_true_positive_always_opens_a_case():
    """The model omitted open_case two times out of four — hence the deduction."""
    assert "open_case" in infer("true_positive", ["propose_block_ip"])
    assert "open_case" in infer("true_positive", [])


def test_false_positive_discards_any_remediation():
    """If the activity is legitimate, there is nothing to cut."""
    actions = infer("false_positive",
                      ["propose_block_ip", "propose_isolate_host"])
    assert actions == ["close_false_positive"]


def test_doubt_escalates_to_a_human():
    """Forensic collection is not an AI action: doubt escalates."""
    assert infer("needs_investigation", []) == ["escalate_human"]


def test_doubt_never_closes():
    actions = infer("needs_investigation", ["escalate_human"])
    assert "close_false_positive" not in actions


def test_kill_process_comes_before_isolation():
    """Emergency order: killing the process comes first (surgical), isolation next."""
    actions = infer("true_positive",
                      ["propose_block_ip", "propose_isolate_host",
                       "propose_kill_process"])
    assert actions[0] == "propose_kill_process"
    assert actions.index("propose_kill_process") < actions.index("propose_isolate_host")


def test_high_impact_actions_flagged():
    actions = infer("true_positive",
                      ["propose_isolate_host", "propose_kill_process"])
    high = high_impact_actions(actions)
    assert "propose_isolate_host" in high
    assert "propose_kill_process" in high          # killing a process = high impact
    # open_case has no effect on production: not a high-impact action.
    assert "open_case" not in high


# --- deterministic guardrails ------------------------------------------------

def test_isolation_dropped_if_less_invasive_containment_suffices():
    """Nominal case: a scanner hitting a URL (no active compromise)
    -> blocking the IP suffices, isolation is dropped and a human decides."""
    actions, patterns = apply_guardrails(
        "true_positive", ["propose_isolate_host", "propose_block_ip"],
        max_level=12, suspected_injection=False, active_compromise=False)
    assert "propose_isolate_host" not in actions
    assert "propose_block_ip" in actions
    assert "escalate_human" in actions
    assert any("isolation dropped" in m for m in patterns)


def test_isolation_kept_if_active_compromise():
    """Active host compromise (webshell/reverse shell/rootkit):
    isolation is KEPT despite block_ip — cutting the IP does not dislodge an
    attacker already in place. Regression measured on a purple-team exercise."""
    actions, patterns = apply_guardrails(
        "true_positive", ["propose_isolate_host", "propose_block_ip"],
        max_level=13, suspected_injection=False, active_compromise=True)
    assert "propose_isolate_host" in actions
    assert "propose_block_ip" in actions
    assert any("isolation KEPT" in m for m in patterns)


def test_closure_refused_on_critical_level_even_with_compromise():
    """The anti-closure barrier takes precedence: an FP of level >= 14 is never
    closed, whatever the compromise flag."""
    actions, patterns = apply_guardrails(
        "false_positive", ["close_false_positive"],
        max_level=15, suspected_injection=False, active_compromise=True)
    assert actions == ["escalate_human", "open_case"]
    assert patterns


# --- consistency --------------------------------------------------------------

def test_false_positive_with_blocking_is_inconsistent():
    """Case actually observed on the first pass."""
    issues = check("false_positive", ["propose_block_ip"])
    assert issues and "propose_block_ip" in issues[0]


def test_false_positive_without_action_is_consistent():
    assert check("false_positive", []) == []


def test_cutting_on_doubt_is_inconsistent():
    """On simple doubt, no irreversible action is justified."""
    assert check("needs_investigation", ["propose_isolate_host"])
    assert check("needs_investigation", ["propose_kill_process"])
    # Escalating (not a cut) stays consistent on a doubt.
    assert check("needs_investigation", ["escalate_human"]) == []


def test_true_positive_without_action_is_flagged():
    assert check("true_positive", []) != []


def test_nominal_output_is_consistent():
    assert check("true_positive",
                    ["propose_isolate_host", "propose_block_ip"]) == []
