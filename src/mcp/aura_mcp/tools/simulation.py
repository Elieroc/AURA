"""Simulation tools: answering "what would happen if…" without doing it.

All at `aura:read`, all side-effect free. They exist because the question
that precedes an action is always the same: what would actually go out, and
what would the guardrails hold back? Answering it by firing the action to
see isn't an option on a production fleet.

They call the pipeline's pure functions — same guardrails, same code. A
simulation that diverged from execution would be worthless.
"""

from soc_agent import actions as soc_actions
from soc_agent import config as soc_config
from soc_agent import mitigate, rule_tuning, ueba, whitelist

from .. import auth, output
from ..db import read as base
from ..server import register


@auth.require("aura:read")
def aura_simulate_decision(
    verdict: str,
    proposed_actions: list[str],
    max_level: int,
    suspected_injection: bool = False,
    active_compromise: bool = False,
    priority: int | None = None,
) -> dict:
    """What would this verdict become after the deterministic guardrails?

    The model only proposes remediations; AURA derives the case's opening
    or closure from them, then applies three invariants that nothing
    bypasses:

    1. no automatic closure if the level reaches 14 — lowered threshold on
       a priority asset (12 on a P1);
    2. no closure if an injection pattern was spotted in the logs — the
       model gets turned around by an injection 3 times out of 4;
    3. host isolation is downgraded if a less invasive containment exists,
       UNLESS the host's compromise is established.

    Args:
        verdict: `true_positive`, `false_positive`, or `needs_investigation`.
        proposed_actions: the model's actions (`propose_block_ip`,
            `propose_isolate_host`, `propose_kill_process`,
            `propose_disable_user`, `propose_quarantine_file`,
            `propose_remove_privileged_group`, `escalate_human`).
        max_level: highest Wazuh level of the incident.
        suspected_injection: an injection pattern was spotted in the logs.
        active_compromise: a post-exploitation rule matched (a webshell
            executing, reverse shell, rootkit, root persistence).
        priority: priority of the affected asset (1 to 4). It decides the
            closure threshold: on a P1, the model can no longer close from
            level 12 on. Absent = historical threshold (14).
    """
    inferred = soc_actions.infer(verdict, proposed_actions)
    final, guardrails = soc_actions.apply_guardrails(
        verdict, inferred, max_level, suspected_injection,
        active_compromise, priority)
    return {
        "proposed_actions": proposed_actions,
        "after_inference": inferred,
        "final_actions": final,
        "triggered_guardrails": guardrails,
        "high_impact_actions": soc_actions.high_impact_actions(final),
        "priority": priority,
        "closure_forbidden_level": soc_actions.closure_threshold(priority),
    }


@auth.require("aura:read")
def aura_validate_whitelist_signature(signature: dict, level: int) -> dict:
    """Could this signature be whitelisted?

    Three possible refusals, all deterministic and non-bypassable: no
    discriminant (account, command, or file — without which the exception
    would blind far more than the targeted noise), level too high, or a
    signature already observed on a true positive. This last point is the
    anti-normalization guardrail: whatever served an intrusion once never
    becomes "normal".

    Args:
        signature: constant fields of the signature, e.g.
            `{"rule_id": "100657", "agent_name": "web01", "command": "uname -a"}`.
        level: Wazuh level of the concerned alerts.
    """
    with base() as conn:
        sig_tp = whitelist.signatures_seen_tp(conn)
    refusal = whitelist.validate_signature(signature, level, sig_tp)
    return {
        "signature": signature,
        "acceptable": refusal is None,
        "refusal_reason": refusal,
        "max_level": soc_config.WHITELIST_MAX_LEVEL,
        "min_fp_required": soc_config.WHITELIST_MIN_FP,
    }


@auth.require("aura:read")
def aura_ueba_score_group(alert_ids: list[str]) -> dict:
    """What UEBA score would this group of alerts get?

    Used for calibration: understanding why a behavior stayed under the
    floor, or conversely what pushed it above. The score adds up the
    rarity of each trait (surprisal in bits), capped per trait and per
    alert, with a kill-chain progression bonus.

    Args:
        alert_ids: native Wazuh identifiers of the group's alerts
            (returned by `aura_alerts_search`).
    """
    if not alert_ids:
        return {"error": "No alert provided."}
    with base() as conn:
        lines = conn.execute(
            "SELECT * FROM alerts WHERE id = ANY(%s) ORDER BY ts",
            (list(alert_ids),)).fetchall()
    if not lines:
        return {"error": "None of these alerts are in the database."}

    score, patterns = ueba.score_group([dict(r) for r in lines])
    return output.jsonifiable({
        "alerts": len(lines),
        "score": score,
        "floor": soc_config.UEBA_SCORE_FLOOR,
        "would_cross_the_floor": score >= soc_config.UEBA_SCORE_FLOOR,
        "patterns": patterns,
    })


@auth.require("aura:read")
def aura_rule_preview(rule_id: int, parent: str, level: int,
                      signature: dict, n_fp: int = 0,
                      incidents: list[int] | None = None) -> dict:
    """The XML of the exception rule that would be deployed, without writing anything.

    Second stage of the whitelist: rather than discarding noise after the
    fact, the rule itself is calmed INSIDE the Wazuh engine. This tool
    returns the XML for review; it doesn't write it and doesn't restart the
    manager — that's `aura:admin` and `aura_rule_tuning_apply`.

    Pitfall to know: a child rule must have an identifier GREATER than its
    parent's, otherwise Wazuh loads it and never evaluates it, without any
    error message.

    Args:
        rule_id: identifier of the rule to create (reserved range
            101000-101999).
        parent: identifier of the parent rule (`if_sid`).
        level: level of the child rule (0 = total suppression, locked by
            configuration).
        signature: discriminant fields to match.
        n_fp: number of false positives motivating the rule (comment).
        incidents: originating incidents (traceability comment).
    """
    if not (soc_config.RULE_TUNING_ID_MIN <= rule_id
            <= soc_config.RULE_TUNING_ID_MAX):
        return {"error": f"rule_id outside the reserved range "
                          f"{soc_config.RULE_TUNING_ID_MIN}-"
                          f"{soc_config.RULE_TUNING_ID_MAX}."}
    if int(parent) >= rule_id:
        return {"error": f"Rule {rule_id} can't be a child of "
                          f"{parent}: a child must have an identifier "
                          f"GREATER than its parent's, otherwise Wazuh "
                          f"never evaluates it (without error)."}

    xml = rule_tuning.build_xml(rule_id, parent, level, signature, {},
                                     n_fp, incidents or [])
    return {
        "rule_id": rule_id, "parent": parent, "level": level,
        "translatable": xml is not None,
        "xml": xml,
        "level_0_allowed": soc_config.RULE_TUNING_ALLOW_LEVEL_0,
    }


@auth.require("aura:read")
def aura_isolation_check(agent_id: str) -> dict:
    """Can this agent be isolated, and is it already?

    Two distinct questions, often conflated: what AURA's policy allows
    (`refusal_reason`), and what the machine says about itself (`state`,
    read over SSH on the host). A machine can be marked isolated in IRIS
    without actually being so — it's the host's state that decides.

    Refusals are deliberately closed: protected agent (the manager, 000),
    membership in an infrastructure group (firewall, proxy, DNS, VPN), or
    unknown role. Isolating a firewall cuts everyone off, SOC included.

    Args:
        agent_id: Wazuh agent identifier (`003`, `001`…).
    """
    refusal = mitigate.not_isolatable_reason(agent_id)
    response = {
        "agent_id": agent_id,
        "isolatable": refusal is None,
        "refusal_reason": refusal,
        "protected_agents": sorted(soc_config.AGENTS_PROTECTED),
        "refuse_if_unknown_role": soc_config.ISOLATION_REFUSE_IF_ROLE_UNKNOWN,
    }
    try:
        response["state"] = mitigate.isolation_state(agent_id)
    except Exception as e:  # noqa: BLE001
        # An unreachable host is information, not a tool failure: it could
        # be powered off, or already cut from the network by an isolation.
        response["state"] = None
        response["state_unavailable"] = str(e)
    return response


register(aura_simulate_decision)
register(aura_validate_whitelist_signature)
register(aura_ueba_score_group)
register(aura_rule_preview)
register(aura_isolation_check)
