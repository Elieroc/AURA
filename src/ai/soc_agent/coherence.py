"""Consistency check between the model's verdict and the actions it proposes.

Output validation (`triage._validate`) guarantees the *shape* — fields present,
values within the enum. It cannot guarantee anything *across* fields: nothing
stops the model from returning `false_positive` while proposing to block an IP.
That happened on two incidents out of four on the very first real pass.

This check is deterministic and runs after every triage. It fixes nothing —
rewriting the model's verdict would hide the problem instead of measuring it —
but it records it. A rising inconsistency rate flags a prompt we have just
degraded, and it is measurable **without any labelled set**.

It only covers the MODEL's actions. Those inferred from the verdict
(`open_case`, `close_false_positive`, see actions.py) are consistent by
construction.
"""

from .actions import HIGH_IMPACT_ACTIONS


def check(verdict: str, model_actions: list[str]) -> list[str]:
    """Inconsistencies found. Empty means the output is consistent."""
    issues: list[str] = []
    proposed = set(model_actions)

    if verdict == "false_positive":
        # If the activity is legitimate there is nothing to cut off. Proposing a
        # remediation contradicts the verdict.
        high = proposed & HIGH_IMPACT_ACTIONS
        if high:
            issues.append(
                "false_positive proposes " + ", ".join(sorted(high)))

    if verdict == "needs_investigation":
        # On mere doubt we cut nothing irreversibly: cutting (isolation, kill,
        # account disable, IP block) without certainty is inconsistent.
        high = proposed & HIGH_IMPACT_ACTIONS
        if high:
            issues.append(
                "needs_investigation cuts without certainty: "
                + ", ".join(sorted(high)))

    if verdict == "true_positive" and not proposed:
        # Legitimate for a true positive with no possible follow-up, but rare
        # enough to be worth counting.
        issues.append("true_positive with no action at all")

    return issues
