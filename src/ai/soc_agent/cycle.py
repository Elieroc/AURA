"""One full pipeline cycle: ingest -> correlate -> triage.

Entry point of the periodic trigger (soc-agent-cycle container, see
ai/docker-compose.yml — shell loop every 5 min). Chains the three steps already
written, in a single run, with a lock so a slow cycle does not overlap the next.

    python -m soc_agent.cycle

Designed to be run in a loop: each step resumes where it left off (ingest
cursor, uncorrelated alerts, untriaged incidents), so replaying the cycle
duplicates nothing.
"""

import argparse
import logging
import sys

import psycopg

from . import (assets, config, correlate, ingest, iris, training, triage, ueba,
               vt, watchdog, whitelist)

# Logged to stderr -> picked up by the container's `docker compose logs`.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("cycle")

# Arbitrary key of the Postgres advisory lock. One cycle at a time: ingestion
# and triage write the same tables, and triage already saturates the CPU. Two
# cycles in parallel would step on each other for no gain.
LOCK = 0x50CA1


def run(since: str, batch_size: int, triage_limit: int) -> int:
    """Chains the three steps. Returns an exit code."""
    # Connection dedicated to the lock, kept open for the whole cycle: a session
    # advisory lock is released when it closes.
    with psycopg.connect(config.PG_DSN) as guard:
        taken = guard.execute(
            "SELECT pg_try_advisory_lock(%s)", (LOCK,)).fetchone()[0]
        if not taken:
            # Normal case when the previous cycle overruns the timer interval.
            # We exit cleanly; the next trigger will pick up.
            log.info("cycle already running, skipping this round")
            return 0

        try:
            # CMDB first: correlation freezes the asset priority into the
            # incident it opens. A machine enrolled between two cycles must
            # therefore be known BEFORE, otherwise its first incident — often
            # the most interesting one — is born at the default P4 and stays
            # there. Best-effort: an unreachable Wazuh API does not cost a
            # cycle.
            try:
                r = assets.sync()
                log.info("cmdb: %d assets (%d created)", r["seen"], r["created"])
            except Exception as e:  # noqa: BLE001
                log.warning("CMDB sync skipped: %s", e)

            n = ingest.ingest(since, batch_size)
            log.info("ingest: %d alerts processed", n)

            # Training window open: we INGEST and nothing more. No correlation,
            # no triage, no case, hence no remediation (it starts from
            # iris.create_case). The estate has not been learned yet; judging
            # and acting now would isolate healthy servers on business noise.
            # The soc-training container learns from those alerts; on closing it
            # reapplies the noise filter to everything already stored, and
            # correlation resumes on what is left.
            if training.in_progress(guard):
                log.info("training in progress: correlation, triage, cases and "
                         "remediation suspended (see soc_agent.training --state)")
                return 0

            # VT filter BEFORE correlation: an executable judged legitimate is
            # suppressed, so it neither seeds nor joins a case (correlate reads
            # NOT suppressed). Best-effort: a VT outage does not break the cycle.
            try:
                n_vt = vt.filter()
                if n_vt:
                    log.info("vt: %d alert(s) dropped (legitimate exe)", n_vt)
            except Exception as e:  # noqa: BLE001
                log.warning("VT filter skipped: %s", e)

            # UEBA between the VT filter and correlation: it observes the fresh
            # alerts, updates the behavioural baseline, and PROMOTES the
            # best-scoring LOW/MEDIUM concentrations to seeds — within a daily
            # budget. Zero tokens: the engine does not judge, it ranks. What it
            # promotes then follows everyone else's path (correlation -> LLM
            # triage -> IRIS case).
            #
            # Best-effort, like VT: a broken behavioural engine must not stop
            # the level >= 12 pipeline from running.
            try:
                seen, scored, promoted = ueba.run()
                if seen:
                    log.info("ueba: %d alerts observed, %d scored, "
                             "%d signal(s) promoted", seen, scored,
                             len(promoted))
                for s in promoted:
                    log.info("ueba: signal #%s %s score %.1f -> %d seed "
                             "alerts", s["id"], s["agent_name"], s["score"],
                             len(s["alert_ids"]))
            except Exception as e:  # noqa: BLE001
                log.warning("ueba skipped: %s", e)

            n_inc, n_alerts = correlate.correlate(config.MIN_LEVEL)
            log.info("correlate: %d alerts -> %d incidents", n_alerts, n_inc)

            # Silent sensor: an established feed that goes quiet (Suricata
            # smothered, journald reader stuck, audit cut off) makes whole
            # swathes of the ruleset inert without a single alert. Detected on
            # the database side, so it does not depend on the agent's backlog.
            # Log-only for now (IRIS escalation = separate review).
            try:
                watchdog.check()  # logs every silent sensor at WARNING
            except Exception as e:  # noqa: BLE001 — a watchdog never breaks the cycle
                log.warning("silent-sensor watchdog skipped: %s", e)

            # Triage depends on the LLM server. If it is unavailable we do not
            # fail the whole cycle: ingestion and correlation already have
            # value, and untriaged incidents will be picked up next round.
            try:
                triage.sort(triage_limit, None, False, False)
            except Exception as e:  # noqa: BLE001 — we want to catch everything here
                # A triage failure MUST NOT stop case creation: incidents
                # already triaged in earlier cycles are waiting for their case
                # (iris_case_id IS NULL) and no longer need the triage LLM. The
                # old `return 0` here froze case creation for hours as soon as
                # the LLM returned empty content. We log and carry on to
                # whitelist + IRIS cases.
                log.warning("triage skipped (LLM server unreachable?): %s", e)

            # Closed loop: recurring FPs become exceptions. Runs only after
            # triage, since it needs fresh verdicts.
            created = [d for d in whitelist.analyze(config.WHITELIST_MIN_FP, False)
                     if d["action"] == "created"]
            if created:
                log.info("whitelist: %d exception(s) created: %s",
                         len(created), ", ".join(d["signature"] for d in created))

            # One IRIS case per triaged incident. After the whitelist: an
            # incident that just moved to 'whitelisted' has no verdict to push
            # (already dropped), the others do.
            try:
                cases = iris.create_cases()
                if cases:
                    log.info("IRIS: %d case(s) created", len(cases))
            except Exception as e:  # noqa: BLE001 — IRIS down never breaks the cycle
                log.warning("IRIS case creation skipped: %s", e)

            # Reconciling cancelled remediations (an IRIS task moved to
            # 'Canceled') is DECOUPLED from this cycle: it has its own, shorter
            # timer (soc-agent-reconcile, 1 min) because it is light
            # (list_tasks + reverse) and must not wait for the CPU-bound triage.
            return 0
        finally:
            guard.execute("SELECT pg_advisory_unlock(%s)", (LOCK,))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--since", default="30d",
                    help="ingestion window on the very first pass "
                         "(ignored as soon as a cursor exists)")
    ap.add_argument("--batch-size", type=int, default=500)
    ap.add_argument("--triage-limit", type=int, default=50,
                    help="cap on incidents triaged per cycle, a guardrail "
                         "against an influx that would saturate the CPU")
    args = ap.parse_args()
    sys.exit(run(args.since, args.batch_size, args.triage_limit))


if __name__ == "__main__":
    main()
