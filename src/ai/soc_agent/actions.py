"""Actions inferred from the verdict, and ranking by impact.

Opening a case and closing as a false positive are not decisions: they follow
mechanically from the verdict. Asking the model for them amounted to making it
keep books — and it forgot two times out of four. We derive them here, where the
rule is explicit and cannot drift.

The model therefore only judges what needs judgement: the verdict, the
confidence, and the remediations that apply.
"""

# Actions that touch production. They are executed AUTONOMOUSLY (autonomous XDR,
# see mitigate.py); the list is not there to demand a human sign-off, but to
# FLAG them as such in the report and to order them by urgency. Their safety
# rests on deterministic guardrails, not on a click.
HIGH_IMPACT_ACTIONS = {
    "propose_kill_process",              # kills a running process
    "propose_isolate_host",              # cuts the host off the network
    "propose_disable_user",              # locks an account (local or AD)
    "propose_block_ip",                  # cuts a network flow
    "propose_quarantine_file",           # quarantines a file
    "propose_remove_privileged_group",   # removes from a privileged AD group
}

# Urgency order for presentation to the analyst. Killing the malicious process
# comes first (the most surgical: stops execution without cutting the machine
# off); isolation comes right after (stops everything but also stops the
# investigation). Forensic collection is NOT an AI action (too heavy, pulled
# over SSH by the manager, outside the scope of automatic triage).
ORDER = [
    "propose_kill_process",
    "propose_quarantine_file",
    "propose_isolate_host",
    "propose_disable_user",
    "propose_remove_privileged_group",
    "propose_block_ip",
    "escalate_human",
    "open_case",
    "close_false_positive",
]


def _order(actions) -> list[str]:
    """Actions sorted by presentation urgency (ORDER)."""
    return sorted(actions, key=lambda a: ORDER.index(a) if a in ORDER else 99)


def infer(verdict: str, model_actions: list[str]) -> list[str]:
    """The model's actions plus those the verdict imposes, ordered."""
    actions = set(model_actions)

    if verdict == "true_positive":
        actions.add("open_case")
    elif verdict == "false_positive":
        # A false positive is legitimate activity: nothing to remediate. We drop
        # any remediation the model proposed anyway — the inconsistency is
        # recorded by coherence.py; here we just produce a usable output.
        actions = {"close_false_positive"}
    elif verdict == "needs_investigation":
        # Doubt calls for a human: forensic collection is not an AI action, and
        # we cut nothing on mere doubt.
        if not actions:
            actions.add("escalate_human")

    return _order(actions)


def high_impact_actions(actions: list[str]) -> list[str]:
    """High-impact actions present, so the report can FLAG them.

    They run automatically (no human validation); this filter only exists to
    highlight them for the analyst reading the case.
    """
    return [a for a in actions if a in HIGH_IMPACT_ACTIONS]


# Wazuh level from which automatic closure is forbidden. 14 and 15 are the
# "confirmed attack" levels: ransomware, mass destruction, confirmed compromise.
# A rule firing at 14+ required several correlations on the Wazuh side —
# classifying it as a false positive takes a human.
#
# Historical default, kept for assets with no known priority and for callers
# that pass no priority (tests, replay of incidents predating the CMDB). On a
# prioritised asset `config.CLOSURE_FORBIDDEN_BY_PRIORITY` applies instead: the
# threshold GOES DOWN when the asset matters (12 on a domain controller). The
# cost of a false negative there is nothing like the cost of one more case to
# read.
LEVEL_CLOSURE_FORBIDDEN = 14

# Containments less invasive than isolation. As long as one of them applies, it
# handles the threat without cutting the machine off the network.
LEAST_INVASIVE_CONFINEMENT = (
    "propose_block_ip",
    "propose_kill_process",
    "propose_disable_user",
    "propose_quarantine_file",
    "propose_remove_privileged_group",
)


def closure_threshold(priority: int | None) -> int:
    """Level above which automatic closure is refused, per asset.

    Local import: `actions` is a pure module (no I/O, no database) and must stay
    that way to be testable on its own; `config` only reads the environment.
    """
    from . import config
    if priority is None:
        return LEVEL_CLOSURE_FORBIDDEN
    return config.CLOSURE_FORBIDDEN_BY_PRIORITY.get(
        int(priority), LEVEL_CLOSURE_FORBIDDEN)


def apply_guardrails(verdict: str, actions: list[str], max_level: int,
                         suspected_injection: bool,
                         active_compromise: bool = False,
                         priority: int | None = None,
                         ) -> tuple[list[str], list[str]]:
    """Deterministic barrier between the model's output and a real action.

    Measured: three injection payloads out of four flip the model's verdict to
    `false_positive` on a confirmed ransomware. The system prompt does not hold,
    and it cannot hold — a language model is not a security boundary. This is:
    it depends on no probability and cannot be argued with by text in a log.

    Three invariants:

    1. An incident of level >= 14 can NOT be closed automatically, whatever the
       model says. That is exactly the scenario an injection aims for: silently
       closing an intrusion. The threshold GOES DOWN on a priority asset
       (`priority`, see `closure_threshold`): 12 on a domain controller or a
       firewall.
    2. An incident where injection patterns were spotted cannot be closed
       either — a verdict rendered on a manipulated context is worthless.
    3. Isolating a host is a LAST RESORT: it only fires when no less invasive
       containment applies (see below) — UNLESS the host is under active
       compromise (confirmed post-exploitation), in which case isolation is KEPT
       despite a less invasive containment being available (blocking an IP does
       not dislodge an attacker who is already in).

    `active_compromise`: the incident carries a post-exploitation rule (see
    config.RULES_COMPROMISE_HOST) — the attacker already runs code on the
    machine (webshell, reverse shell, rootkit, root persistence). The flag is
    computed by the caller (triage) from the incident's rule_ids; the barrier
    here only takes it into account.

    Returns (effective actions, reasons for the intervention).
    """
    patterns: list[str] = []

    if verdict == "false_positive":
        threshold = closure_threshold(priority)
        if max_level >= threshold:
            patterns.append(
                f"closure refused: level {max_level} >= {threshold}"
                + (f" (asset P{priority})" if priority else ""))
        if suspected_injection:
            patterns.append(
                "closure refused: injection patterns in the data")

    if patterns:
        # We do not invent a verdict in the model's place: we only refuse the
        # dangerous consequence, and hand back to a human.
        return ["escalate_human", "open_case"], patterns

    # --- Isolation as a last resort -----------------------------------------
    #
    # Cutting a host off the network is the most expensive action in the
    # catalogue: it stops the attack, but also the service. Measured: an
    # internet scanner probing //adminer.php (404, nothing served) got a reverse
    # proxy fronting a whole fleet isolated. Blocking the IP was enough, and it
    # was proposed in the same verdict.
    #
    # So: as long as a less invasive containment applies — block the IP, kill
    # the process, disable the account — that is what fires, and isolation is
    # dropped. It is NOT silently abandoned: `escalate_human` takes its place,
    # the analyst sees in the case that isolation was judged relevant and
    # decides.
    #
    # Deliberately deterministic and not negotiable by the prompt: the model is
    # nudged to prefer blocking (prompts/system.md), but a nudge does not hold
    # against a hostile log. This barrier does.
    if "propose_isolate_host" in actions:
        less_invasive = [a for a in LEAST_INVASIVE_CONFINEMENT if a in actions]
        if less_invasive and active_compromise:
            # Active compromise of the host: the attacker already runs code on
            # it (webshell, reverse shell, rootkit, root persistence). A less
            # invasive containment is not enough — cutting an IP leaves the
            # foothold in place. Isolation IS kept, on top of the rest.
            patterns.append(
                "isolation KEPT: active compromise of the host "
                "(confirmed post-exploitation) — the less invasive containment "
                f"({', '.join(less_invasive)}) does not dislodge an attacker "
                "already in place")
        elif less_invasive:
            actions = [a for a in actions if a != "propose_isolate_host"]
            if "escalate_human" not in actions:
                actions.append("escalate_human")
            actions = _order(actions)
            patterns.append(
                "isolation dropped (last resort): "
                f"{', '.join(less_invasive)} is enough — escalated to a human")

    return actions, patterns
