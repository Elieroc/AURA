"""Automatic whitelist built from recurring false positives.

The closed loop of the autonomous POC: when LLM triage repeatedly judges
false_positive on the same event signature, we create an exception. Alerts
matching that signature are dropped before correlation and triage even happen —
the AI stops endlessly re-judging the same false positive.

    python -m soc_agent.whitelist                # creates the due exceptions
    python -m soc_agent.whitelist --simulation   # shows without creating
    python -m soc_agent.whitelist --list         # active exceptions
    python -m soc_agent.whitelist --min-fp 1     # lowered threshold (POC/demo)

Three guardrails, inherited from the same logic as triage:

- A PRECISE signature is required: rule_id alone is not enough (it would
  neutralise a whole rule). At least an account, a command or a file is needed.
- Never an automatic whitelist above WHITELIST_MAX_LEVEL: a rule firing at
  critical deserves a human. It is also the wall against an attacker who would
  cause repeated FPs to get themselves whitelisted.
- A signature seen AT LEAST once as true_positive is never whitelisted, even if
  it appears elsewhere as an FP: contradictory signal.
"""

import argparse
import json
from collections.abc import Iterable

import psycopg
from psycopg.rows import dict_row, tuple_row

from . import config
from .noise import _value_field

# Candidate fields of a whitelist signature. Deliberately restricted:
# - rule_id locates the detection;
# - src_user / command / file discriminate the precise activity.
# dst_user and agent_name are excluded: too broad (dst root, or a whole host).
DISCRIMINANT_FIELDS = ("src_user", "command", "file")
FIELDS_SIGNATURE = ("rule_id",) + DISCRIMINANT_FIELDS


def _signature(raw_alerts: Iterable[dict],
               discriminant: tuple[str, ...] = DISCRIMINANT_FIELDS) -> dict | None:
    """Signature of an incident: fields constant across all its alerts.

    A field only enters the signature when it has a single non-null value,
    identical across every alert of the incident. Returns None when the
    signature is not precise enough for a safe whitelist.

    `discriminant` is parameterised for `rule_tuning.py`, which accepts one more
    (`url`): an exception written into the rule engine can discriminate on the
    URL, which the post-retrieval filter cannot do.

    Takes an ITERABLE and walks it only once: the caller can therefore hand it a
    server-side cursor instead of a list. Each field only keeps TWO distinct
    values, because that is all the decision needs — "a single value" or
    "several". Without that cap, materialising the alerts of a flood incident
    (126,508 `raw`) cost 1 GB and got the cycle OOM-killed on 2026-08-14,
    stopping ingestion.

    Do NOT replace this walk by a bounded sample: a field judged constant over
    the first 2,000 alerts while it varies on the 2,001st would produce a
    whitelist exception broader than the incident observed. The bound is on the
    memory retained, never on what is examined.
    """
    fields = ("rule_id",) + tuple(discriminant)
    values: dict[str, set] = {c: set() for c in fields}
    seen = False
    for a in raw_alerts:
        seen = True
        for field in fields:
            if len(values[field]) > 1:
                continue  # already multi-valued: the rest cannot change anything
            if (v := _value_field(a, field)) is not None:
                values[field].add(v)
    if not seen:
        return None

    signature = {c: str(next(iter(s))) for c, s in values.items() if len(s) == 1}

    # Precision: at least one discriminant, otherwise we would neutralise far
    # too broadly (rule_id alone = the whole rule).
    if not any(c in signature for c in discriminant):
        return None
    return signature


def _canonical(signature: dict) -> str:
    return "|".join(f"{k}={signature[k]}" for k in sorted(signature))


def _incidents_by_verdict(
        conn,
        discriminant: tuple[str, ...] = DISCRIMINANT_FIELDS) -> tuple[dict, set]:
    """(FPs per signature, set of signatures seen as TP).

    Only the LAST triage of each incident counts: earlier passes reflect prompts
    we have abandoned.
    """
    lines = conn.execute("""
        SELECT DISTINCT ON (t.incident_id)
               t.incident_id, t.verdict, i.max_level, i.status
          FROM triages t
          JOIN incidents i ON i.id = t.incident_id
         ORDER BY t.incident_id, t.created_at DESC
    """).fetchall()

    fp_by_sig: dict[str, dict] = {}
    sig_tp: set[str] = set()

    for l in lines:
        # SERVER-side cursor (`name=`): rows arrive in packets and are never
        # all in memory. A flood incident holds 126,508 of them, each with its
        # full `raw` — 1 GB materialised at once, past the container limit (see
        # _signature).
        # Explicit `row_factory`: the connection is in `dict_row`, which the
        # cursor would inherit — we only want one column, so read it by position
        # without building a dict per row.
        with conn.cursor(name=f"sig_{l['incident_id']}",
                         row_factory=tuple_row) as cur:
            cur.itersize = 2000
            cur.execute("SELECT raw FROM alerts WHERE incident_id = %s",
                        (l["incident_id"],))
            signature = _signature((r[0] for r in cur), discriminant)
        if signature is None:
            continue
        canon = _canonical(signature)

        if l["verdict"] == "true_positive":
            sig_tp.add(canon)
        elif l["verdict"] == "false_positive":
            e = fp_by_sig.setdefault(canon, {
                "signature": signature, "incidents": [], "max_level": 0})
            e["incidents"].append(l["incident_id"])
            e["max_level"] = max(e["max_level"], l["max_level"])

    return fp_by_sig, sig_tp


def analyze(min_fp: int, simulation: bool) -> list[dict]:
    """Creates (or simulates) the due exceptions. Returns the decisions."""
    decisions: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        fp_by_sig, sig_tp = _incidents_by_verdict(conn)
        existing = {r["signature"] for r in conn.execute(
            "SELECT signature FROM whitelist_rules WHERE active").fetchall()}

        for canon, e in sorted(fp_by_sig.items()):
            n = len(e["incidents"])
            if canon in existing:
                continue
            if canon in sig_tp:
                decisions.append({"signature": canon, "action": "refused",
                                  "reason": "also seen as true_positive"})
                continue
            if e["max_level"] >= config.WHITELIST_MAX_LEVEL:
                decisions.append({"signature": canon, "action": "refused",
                                  "reason": f"level {e['max_level']} >= "
                                            f"{config.WHITELIST_MAX_LEVEL}"})
                continue
            if n < min_fp:
                decisions.append({"signature": canon, "action": "pending",
                                  "reason": f"{n}/{min_fp} FP"})
                continue

            reason = (f"recurring FP ({n} incidents) judged by the AI — "
                      f"{canon}")
            if not simulation:
                conn.execute("""
                    INSERT INTO whitelist_rules
                        (signature, match_all, reason, source, origin_incidents,
                         fp_count)
                    VALUES (%s, %s, %s, 'auto', %s, %s)
                    ON CONFLICT (signature) DO NOTHING
                """, (canon, json.dumps(e["signature"]), reason,
                      e["incidents"], n))
                # The originating incidents move to 'whitelisted': they will
                # not be counted again, and the status records why.
                conn.execute(
                    "UPDATE incidents SET status = 'whitelisted' "
                    "WHERE id = ANY(%s)", (e["incidents"],))
                conn.commit()
            decisions.append({"signature": canon, "action": "created",
                              "match_all": e["signature"], "fp": n})

    return decisions


def signatures_seen_tp(conn) -> set[str]:
    """Signatures (canonical form) seen at least once as true_positive.

    Reused by whitelist_task.py: a whitelist requested by hand by the analyst
    obeys the same guardrail as an automatic one — never on a signature
    contradicted by a true positive.
    """
    return _incidents_by_verdict(conn)[1]


def validate_signature(signature: dict, level: int, sig_tp: set[str]) -> str | None:
    """Deterministic guardrails before any whitelist_rules creation.

    Returns the reason for refusal, or None when the signature is acceptable. The
    LLM (automatic or manual task) PROPOSES; this guardrail DECIDES — the same
    three rules as `analyze()`: precise signature, bounded level, never seen as
    true_positive.
    """
    if not any(c in signature for c in DISCRIMINANT_FIELDS):
        return "signature too broad: rule_id alone is not enough"
    if level >= config.WHITELIST_MAX_LEVEL:
        return (f"level {level} >= {config.WHITELIST_MAX_LEVEL} "
                "(automatic whitelist forbidden)")
    if _canonical(signature) in sig_tp:
        return "signature already seen as true_positive"
    return None


def exceptions() -> list[dict]:
    """The whitelist exceptions, active or revoked, most recent first."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lines = conn.execute("""
            SELECT id, signature, match_all, reason, source, fp_count, active,
                   origin_incidents, iris_task_id, created_at
              FROM whitelist_rules ORDER BY created_at DESC
        """).fetchall()
    return [dict(r, created_at=r["created_at"].isoformat()) for r in lines]


def list_exceptions() -> None:
    lines = exceptions()
    if not lines:
        print("No whitelist exception.")
        return
    for r in lines:
        state = "active  " if r["active"] else "inactive"
        print(f"  #{r['id']:<3} [{state}] {r['source']:<6} "
              f"{r['fp_count']} FP  {json.dumps(r['match_all'], ensure_ascii=False)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-fp", type=int, default=config.WHITELIST_MIN_FP)
    ap.add_argument("--simulation", action="store_true",
                    help="shows the decisions without creating anything")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        list_exceptions()
        return

    decisions = analyze(args.min_fp, args.simulation)
    if not decisions:
        print("No false positive to examine.")
        return

    prefix = "[simulation] " if args.simulation else ""
    for d in decisions:
        if d["action"] == "created":
            print(f"{prefix}CREATED {d['signature']}  ({d['fp']} FP)")
        elif d["action"] == "pending":
            print(f"        pending {d['signature']}  ({d['reason']})")
        else:
            print(f"        refused {d['signature']}  ({d['reason']})")


if __name__ == "__main__":
    main()
