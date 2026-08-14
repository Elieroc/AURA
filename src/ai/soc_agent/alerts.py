"""Loading an incident's alerts without ever burning the cycle's memory.

A flood incident lines up tens of thousands of alerts (126,508 on one pfSense
incident on 2026-08-14), and each carries its `raw` — the full JSON of the Wazuh
alert. `SELECT ... FROM alerts WHERE incident_id = X` is therefore a 186 MB
query of JSON in database, far more once materialised into Python objects: past
the container memory cap (1 GB), the process is OOM-killed.

That failure happened FOUR times, at the same logical spot and each time in a
different module — `iris._alerts`, `whitelist._signature`,
`rule_tuning._fp_example`, then `mitigate.run`. Each was fixed separately, which
never prevented the next one. Hence this module: bounding is a pipeline
invariant, not a local precaution to reinvent.

And the failure is especially insidious: the jobs run inside a shell loop
(`while true; do python -m soc_agent.X; sleep N; done`), which SURVIVES the
process being killed. The container stays `Up`, `docker ps` is green, and the
cycle dies on every pass at the same place without ever finishing anything —
no triage, no case, no remediation. That is what happened between 2026-08-14
11:24 and 14:20.

Two strategies, depending on what the caller does with the rows:

- `load_bounded()` when it needs a LIST in memory (targeting a remediation,
  building a prompt, rendering a report);
- `iterate()` when it only scans (computing a signature, updating row by row):
  server-side cursor, nothing is materialised.
"""

from __future__ import annotations

import logging

from psycopg.rows import tuple_row

from . import config

log = logging.getLogger(__name__)

# Column sets used across the pipeline. Named rather than passed inline: a
# column string built by the caller would sooner or later be concatenated from
# a variable.
COLUMNS_REPORT = ("id, ts, rule_id, rule_level, rule_desc, rule_groups, "
                    "mitre_ids, mitre_tactics, srcip, srcuser, entity, raw")
COLUMNS_TRIAGE = ("id, ts, rule_id, rule_level, rule_desc, srcip, srcuser, "
                   "entity, raw")
COLUMNS_TARGETING = "agent_id, agent_name, srcip, srcuser, entity, raw"
COLUMNS_UEBA = ("id, ts, agent_id, agent_name, rule_id, srcip, srcuser, "
                 "entity, raw")


def _carries_ts(columns: str) -> bool:
    """Is the `ts` column already projected? Compared on split names, not by
    substring search: "rule_groups, mitre_tactics" contains "ts" without
    carrying the column."""
    return "ts" in {c.strip() for c in columns.split(",")}


def load_bounded(conn, incident_id: int, columns: str,
                    label: str = "") -> list[dict]:
    """An incident's alerts, bounded to `config.INCIDENT_MAX_ALERTS`.

    We keep the OLDEST and the most RECENT in equal shares. The beginning
    carries the seed of the incident (what triggered correlation, the targets of
    the initial attack) and the end carries the current state; it is the middle
    of a repetitive burst that teaches nothing. Taking "the last N" would lose
    the start of the attack, which is precisely what an analyst looks for.

    Truncation is logged at WARNING, never silently: on a flood incident, what
    sits in the middle of the burst is not examined, and that must stay
    readable. The real count is never lost — it lives in
    `incidents.alert_count`.
    """
    n = conn.execute("SELECT count(*) c FROM alerts WHERE incident_id = %s",
                     (incident_id,)).fetchone()["c"]
    cap = config.INCIDENT_MAX_ALERTS
    if n <= cap:
        return conn.execute(
            f"SELECT {columns} FROM alerts WHERE incident_id = %s ORDER BY ts",
            (incident_id,)).fetchall()
    half = cap // 2
    log.warning("incident #%s%s: %d alerts, loading bounded to %d "
                "(%d oldest + %d newest) — %d not examined",
                incident_id, f" ({label})" if label else "",
                n, cap, half, cap - half, n - cap)
    # `ts` must appear in the SELECT of both branches, since the final ORDER BY
    # is on it — but ONLY if it is not there already: adding it blindly projects
    # it twice and Postgres rejects the whole query ("ORDER BY \"ts\" is
    # ambiguous"). Three of the pipeline's four column sets already contain
    # `ts`, so that is the nominal case.
    projection = columns if _carries_ts(columns) else f"{columns}, ts"
    return conn.execute(
        f"(SELECT {projection} FROM alerts WHERE incident_id = %(i)s "
        f" ORDER BY ts ASC LIMIT %(head)s)"
        # UNION ALL, not UNION: the two halves are disjoint by construction (we
        # only get here if n > cap), and deduplicating would force a sort on the
        # whole jsonb `raw` of every row.
        " UNION ALL "
        f"(SELECT {projection} FROM alerts WHERE incident_id = %(i)s "
        f" ORDER BY ts DESC LIMIT %(tail)s)"
        " ORDER BY ts",
        {"i": incident_id, "head": half, "tail": cap - half}).fetchall()


def iterate(conn, incident_id: int, columns: str, itersize: int = 2000):
    """Generator over ALL the alerts of an incident, without materialising them.

    Named server-side cursor: Postgres keeps the result set, the client only
    holds `itersize` rows at a time. Prefer it over `load_bounded` as soon as
    the caller merely scans — it then sees the WHOLE incident with no memory
    cap, which is strictly better than a sample.
    """
    with conn.cursor(name=f"alerts_{incident_id}", row_factory=tuple_row) as cur:
        cur.itersize = itersize
        cur.execute(f"SELECT {columns} FROM alerts WHERE incident_id = %s "
                    "ORDER BY ts", (incident_id,))
        yield from cur
