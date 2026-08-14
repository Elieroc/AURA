"""Action tools: the ones that change something.

Three principles, upheld by the code and not by the instructions:

1. **Dry-run is the default.** Every tool that touches production has an
   `apply` parameter defaulting to `False`. Without it, you get what would
   be done.
2. **Irreversible actions require explicit confirmation.** The `confirm`
   parameter has no true default and the refusal states exactly what would
   happen — an AI client doesn't pass it by accident.
3. **Guardrails aren't here.** They live in `soc_agent`, upstream, and apply
   regardless of the caller. This layer doesn't replay them and can't
   disable them.

What is **never** exposed, at any scope:

- `correlate.restart` — wipes every incident;
- `ueba.purge` — permanently deletes the baseline history;
- `label.save` — ground truth is used to grade the AI, the AI doesn't write it;
- `iris.clean_iocs(simulation=False)` — irreversible deletion in IRIS;
- `llm.completion` — would bypass pseudonymization;
- the `anonymization_map` table — token ↔ real value correspondences.
"""

from soc_agent import config as soc_config
from soc_agent import cycle, iris, mitigate, rule_tuning, triage, whitelist

from .. import auth, output
from ..server import register


@auth.require("aura:write")
def aura_run_cycle(batch_size: int = 500, triage_limit: int = 20,
                   since: str = "30d") -> dict:
    """Triggers a full AURA cycle, without waiting for the 5-minute loop.

    Chains ingestion, VirusTotal filter, UEBA, correlation, sensor watchdog,
    LLM triage, whitelist, and IRIS case creation. An advisory lock prevents
    two simultaneous cycles: if the periodic loop is already running, this
    call returns `locked` and does nothing — that's not an error.

    Can take several minutes and consumes DeepSeek tokens (one call per
    triaged incident).

    Args:
        batch_size: alerts ingested per page.
        triage_limit: maximum number of incidents triaged in this cycle.
            This is the parameter that caps the call's LLM bill.
        since: initial ingestion window (`30d`, `6h`) — ignored as soon as an
            ingestion cursor exists, which is the case in steady state.
    """
    code = cycle.run(since, batch_size, triage_limit)
    return {
        "exit_code": code,
        # `cycle.run` doesn't distinguish "nothing to do" from "lock already
        # held": both return 0. Better to say so than let the client
        # conclude the cycle necessarily ran.
        "note": "An exit code of 0 means either 'cycle finished' OR 'another "
                "cycle was already running' — both are normal. The result is "
                "read from aura_incidents_list; the per-incident detail is in "
                "the aura-mcp container's logs.",
    }


@auth.require("aura:write")
def aura_triage_incident(incident_id: int, force: bool = False) -> dict:
    """(Re)triages an incident through the LLM.

    By default, an incident already triaged and outside the refresh window
    isn't picked up again — the result is then an empty list, that's not a
    failure. `force` retriages anyway: that's what you do after a prompt
    change to compare, the previous verdict being kept
    (`aura_triage_history`).

    Consumes a DeepSeek call. Data is sent pseudonymized; if an internal
    identifier escapes pseudonymization, the send is refused and the status
    is `leak`.

    Args:
        incident_id: incident to triage.
        force: retriage even if it already has been.
    """
    results = triage.sort(1, incident_id, force, False)
    return {"incident_id": incident_id,
            "results": output.jsonifiable(results),
            "note": None if results else
                    "Incident already triaged and outside the refresh "
                    "window — use force=true to pick it up again."}


@auth.require("aura:write")
def aura_iris_case_sync(incident_id: int | None = None) -> dict:
    """Creates or updates the DFIR-IRIS cases of triaged incidents.

    For a true positive, the analysis report is written by the LLM (so it
    costs tokens); for a false positive, the note is deterministic. An
    incident whose case already exists and that carries `needs_refresh` gets
    its case completed, not duplicated.

    Side effect worth knowing: duplicate detection can MERGE two incidents,
    which removes one from the AURA database (the IRIS case itself is kept).

    Args:
        incident_id: restrict to one incident. Without it, processes all
            those awaiting a case.
    """
    done = iris.create_cases(incident_id)
    return {"cases": [{"incident_id": i, "case_id": c, "verdict": v}
                      for i, c, v in done],
            "total": len(done)}


@auth.require("aura:write")
def aura_ar_reconcile() -> dict:
    """Freezes the real outcome of remediations sent to agents.

    A remediation starts out `issued`: the order has been sent, we don't yet
    know what it produced. This tool reads the active response results
    reported back by the agents and flips the status to `confirmed`,
    `no_effect`, `refused_by_agent`, or `failed`. Without it, a dashboard
    would announce "successful" remediations that may have been refused on
    the machine.

    Idempotent, no destructive effect.
    """
    frozen = mitigate.reconcile_ar_results()
    return {"reconciled": output.jsonifiable(frozen), "total": len(frozen)}


@auth.require("aura:admin")
def aura_mitigate_execute(incident_id: int, confirm: bool = False) -> dict:
    """Executes the remediations decided for an incident. REAL ACTION.

    Can cut a machine off the network, kill a process, block an address,
    disable an account, or quarantine a file, on production. Killing a
    process has **no undo** whatsoever.

    Three upstream barriers, not bypassable from here: remediation is
    entirely suspended if injection patterns were flagged on the incident;
    protected agents, system accounts, and internal addresses are excluded;
    and if `MITIGATE_EXECUTE` is `false` in the stack's configuration,
    everything stays in `dry_run` no matter what is requested here.

    Args:
        incident_id: incident whose remediations to apply.
        confirm: must be `true` to act. At `false` (default), the tool
            returns what would be attempted without sending anything.
    """
    if not confirm:
        dry_state = "already globally in dry-run" if not soc_config.MITIGATE_EXECUTE \
            else "ARMED: actions would really be sent"
        return {
            "execute": False,
            "reason": "confirm=false — no action sent.",
            "stack_state": dry_state,
            "advice": "Read aura_incident_get first, then "
                       "aura_simulate_decision to see what the guardrails "
                       "let through.",
        }
    done = mitigate.run(incident_id)
    return {"execute": True, "mitigate_execute_global": soc_config.MITIGATE_EXECUTE,
            "actions": output.jsonifiable(done), "total": len(done)}


@auth.require("aura:admin")
def aura_isolate(agent_id: str, reason: str, confirm: bool = False,
                 force: bool = False) -> dict:
    """Isolates a host from the network. REAL, disruptive ACTION.

    The host loses all connectivity except the Wazuh agent channel. Check
    first with `aura_isolation_check`: isolating a firewall, a proxy, a DNS
    resolver, or a VPN gateway cuts everyone off, SOC included.

    Args:
        agent_id: Wazuh agent to isolate.
        reason: why — carried into the trace and into IRIS. Mandatory: an
            isolation without a reason is unmanageable when it's time to
            lift it.
        confirm: must be `true` to act.
        force: overrides a policy refusal. Only use on an established
            compromise of an infrastructure machine, knowing what you're
            cutting off.
    """
    refusal = mitigate.not_isolatable_reason(agent_id)
    if not confirm:
        return {"execute": False,
                "reason": "confirm=false — no action sent.",
                "would_be_refused_by_policy": refusal,
                "force_needed": bool(refusal)}
    if refusal and not force:
        return {"execute": False, "reason": refusal,
                "advice": "force=true overrides it — assess what the host "
                           "carries first."}
    mitigate.isolate(agent_id, reason, force)
    return {"execute": True, "agent_id": agent_id, "reason": reason,
            "policy_forced": bool(refusal and force),
            "state": output.jsonifiable(mitigate.isolation_state(agent_id))}


@auth.require("aura:admin")
def aura_unisolate(agent_id: str, reason: str, confirm: bool = False) -> dict:
    """Lifts a host's isolation. REAL ACTION.

    Restores connectivity to a machine that had been contained. Only do
    this after verifying the cause is gone: autonomous remediation does NOT
    remove persistence planted by an attacker (cron, web shell, UID 0
    account). A machine unisolated too soon calls its C2 back.

    Args:
        agent_id: Wazuh agent to unisolate.
        reason: why — traced.
        confirm: must be `true` to act.
    """
    if not confirm:
        return {"execute": False,
                "reason": "confirm=false — no action sent.",
                "reminder": "Check for the absence of persistence (cron, web "
                          "shell, UID 0 account) before restoring the "
                          "network."}
    mitigate.unisolate(agent_id, reason)
    return {"execute": True, "agent_id": agent_id, "reason": reason,
            "state": output.jsonifiable(mitigate.isolation_state(agent_id))}


@auth.require("aura:admin")
def aura_whitelist_apply(min_fp: int | None = None,
                         apply: bool = False) -> dict:
    """Creates whitelist exceptions for recurring false positives.

    Every exception created is a deliberate blind spot: those alerts will no
    longer be reported. Guardrails refuse a signature without a
    discriminant, above the ceiling level, or already seen on a true
    positive.

    Args:
        min_fp: number of false positives required before exempting a
            signature.
        apply: at `false` (default), returns the decisions without creating
            anything.
    """
    decisions = whitelist.analyze(
        min_fp if min_fp is not None else soc_config.WHITELIST_MIN_FP,
        simulation=not apply)
    return {"applied": apply,
            "decisions": output.jsonifiable(decisions),
            "total": len(decisions)}


@auth.require("aura:admin")
def aura_rule_tuning_apply(min_fp: int | None = None,
                           apply: bool = False) -> dict:
    """Generates and deploys Wazuh exception rules. RESTARTS THE MANAGER.

    Second stage of the whitelist: noise is calmed in the rule engine
    instead of being discarded after the fact. Every generated rule is
    PROVEN by `/logtest` replay — the false-positive event must match it,
    and a real counter-example must stay matched to the parent rule. An
    unproven rule is removed from disk.

    Applying restarts the Wazuh manager: detection is interrupted for the
    duration of the restart, twice if a rule fails its proof.

    Args:
        min_fp: false positives required before generating a rule.
        apply: at `false` (default), returns the XML without writing or
            restarting anything.
    """
    decisions = rule_tuning.analyze(
        min_fp if min_fp is not None else soc_config.WHITELIST_MIN_FP,
        simulation=not apply)
    return {"applied": apply,
            "manager_restarted": apply and bool(decisions),
            "decisions": output.jsonifiable(decisions),
            "total": len(decisions)}


register(aura_run_cycle)
register(aura_triage_incident)
register(aura_iris_case_sync)
register(aura_ar_reconcile)
register(aura_mitigate_execute)
register(aura_isolate)
register(aura_unisolate)
register(aura_whitelist_apply)
register(aura_rule_tuning_apply)
