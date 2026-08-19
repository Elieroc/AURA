"""Ingesting Wazuh alerts from the indexer into Postgres.

Pulls in batches from a persisted cursor, changing nothing on the manager side.
Idempotent: replaying a window creates no duplicates (ON CONFLICT on the native
Wazuh identifier).

    python -m soc_agent.ingest [--since 30d] [--batch-size 500]
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone

import psycopg
import requests
import urllib3

from . import config, noise, routing

# --- LXC container attribution (auditd of the Proxmox host) ------------------
# The pve agent (009) captures the execve of EVERY LXC container (shared kernel);
# `data.lxc_ct` (extracted by the indexer pipeline) — or the tag in full_log as a
# fallback — says which one. We then reattribute the alert to the container's OWN
# Wazuh agent when it has one (jellyfin -> 005): correlation happens per container
# (agent_id is the key) and remediation targets the right host. Otherwise we keep
# pve and record the container in the `container` column for readability.
_HOST_AUDITD = {"pve", "009"}
_CT_IGNORE = {"", "host", "unknown"}
_LXC_CT = re.compile(r"lxc_ct=([A-Za-z0-9_.-]+)")
_AGENTS: dict[str, str] = {}   # container name -> its own Wazuh agent_id


def _load_agents(conn) -> None:
    """Agent name -> id map, to reattribute a container to its own agent.
    Reloaded on every ingestion run (agents are stable, the query is trivial)."""
    _AGENTS.clear()
    for name, aid in conn.execute(
            "SELECT DISTINCT agent_name, agent_id FROM alerts "
            "WHERE agent_name IS NOT NULL"):
        if name and name not in _HOST_AUDITD:
            _AGENTS.setdefault(name, aid)

# The indexer uses the Wazuh stack's self-signed certificates, over loopback.
# The urllib3 warning would drown the output on every batch; TLS verification
# stays driven by INDEXER_VERIFY_TLS.
if not config.INDEXER_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _list(value) -> list[str]:
    """Wazuh returns sometimes a string, sometimes a list, sometimes nothing."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _first(src: dict, paths: list[tuple]) -> str | None:
    """First non-empty value among several possible locations.

    Wazuh and its integrations store the same information in different places
    depending on which decoder handled the event.
    """
    for path in paths:
        node = src
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, str) and node:
            return node
    return None


def _entity(src: dict) -> str | None:
    """Object the alert is about, used to bring different rules together.

    One intrusion triggers distinct rules that point at the same file or the same
    process; that common ground is what allows gluing them back into a single
    incident.
    """
    return _first(src, [
        ("syscheck", "path"),
        ("data", "virustotal", "source", "file"),
        ("data", "audit", "exe"),
        ("data", "audit", "file", "name"),
        ("data", "win", "eventdata", "image"),
    ])


def _flatten(src: dict, noise_filter: noise.NoiseFilter) -> dict:
    """Indexer document -> row of the alerts table."""
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})
    mitre = rule.get("mitre", {})
    reason = noise_filter.deletion_reason(src)

    # Container attribution: if the emitter is the auditd host (pve) and the
    # originating container is resolved, we reattribute to its own agent when
    # there is one, and record the container in every case.
    agent_id = agent.get("id", "?")
    agent_name = agent.get("name")
    container = None
    lxc = data.get("lxc_ct") or ""
    if not lxc:
        m = _LXC_CT.search(src.get("full_log") or "")
        lxc = m.group(1) if m else ""
    if lxc not in _CT_IGNORE and (agent_name in _HOST_AUDITD
                                  or agent_id in _HOST_AUDITD):
        container = lxc
        own = _AGENTS.get(lxc)
        if own:
            agent_id, agent_name = own, lxc

    # CTI/MISP reattribution: custom-misp.py re-injects its match as a new
    # event, which the pipeline re-decodes with the MANAGER's own agent
    # context (the integration script's log is read locally) — not the agent
    # whose alert actually matched the IOC. That real agent is the one
    # custom-misp.py captured into data.misp.agent/agent_id before the
    # re-injection. Without this, CTI incidents get analyzed and remediated
    # against the manager instead of the real host (e.g. Suricata/pfsense
    # read via its own collector agent).
    misp = data.get("misp") or {}
    misp_agent_id = misp.get("agent_id") or ""
    if misp_agent_id and misp_agent_id != agent_id:
        agent_id, agent_name = misp_agent_id, misp.get("agent") or agent_name

    return {
        "id": src["id"],
        "ts": src["@timestamp"],
        "agent_id": agent_id,
        "agent_name": agent_name,
        "container": container,
        "rule_id": str(rule.get("id", "?")),
        "rule_level": int(rule.get("level", 0)),
        "rule_desc": rule.get("description"),
        "rule_groups": _list(rule.get("groups")),
        "mitre_ids": _list(mitre.get("id")),
        "mitre_tactics": _list(mitre.get("tactic")),
        "srcip": _first(src, [
            ("data", "srcip"),
            # Integrations store the IP under their own key. Without this
            # entry, the AbuseIPDB alerts — precisely the ones carrying the
            # reputation — arrived with no source IP, hence uncorrelatable.
            ("data", "abuseipdb", "srcip"),
            ("data", "virustotal", "source", "srcip"),
            ("GeoLocation", "ip"),
        ]),
        "srcuser": _first(src, [
            ("data", "srcuser"),
            ("data", "dstuser"),
            ("data", "win", "eventdata", "targetUserName"),
        ]),
        "entity": _entity(src),
        # auditd UID of the event. Used by correlation: the attacker's actions
        # (and those of its SUID privesc descendants, which keep the real uid)
        # share this uid, which tells its activity apart from the legitimate
        # background noise of the same machine (daemons, login sessions).
        "audit_uid": (data.get("audit", {}) or {}).get("uid"),
        # Post-retrieval suppression by the noise filter: the alert is ingested
        # but marked, so it stays readable while leaving correlation.
        "suppress_reason": reason,
        # Derived boolean computed in Python: passing it in SQL through
        # `%(...)s IS NOT NULL` made the parameter type undeterminable for
        # Postgres when the reason is NULL (AmbiguousParameter).
        "suppressed": reason is not None,
        "raw": json.dumps(src),
    }


INSERT = """
INSERT INTO alerts (id, ts, agent_id, agent_name, container, rule_id, rule_level,
                    rule_desc, rule_groups, mitre_ids, mitre_tactics,
                    srcip, srcuser, entity, audit_uid, suppressed,
                    suppress_reason, raw)
VALUES (%(id)s, %(ts)s, %(agent_id)s, %(agent_name)s, %(container)s, %(rule_id)s,
        %(rule_level)s, %(rule_desc)s, %(rule_groups)s, %(mitre_ids)s,
        %(mitre_tactics)s, %(srcip)s, %(srcuser)s, %(entity)s, %(audit_uid)s,
        %(suppressed)s, %(suppress_reason)s, %(raw)s)
ON CONFLICT (id) DO NOTHING
"""


def _batch(since: str | None, after: tuple | None, size: int,
         noise_filter: noise.NoiseFilter) -> list[dict]:
    """One batch of alerts, sorted by (timestamp, id) for a reliable resume."""
    query: dict = {"bool": {"filter": [], "must_not": []}}
    if config.INGEST_MIN_LEVEL > 0:
        query["bool"]["filter"].append(
            {"range": {"rule.level": {"gte": config.INGEST_MIN_LEVEL}}})
    if since:
        query["bool"]["filter"].append(
            {"range": {"@timestamp": {"gte": f"now-{since}"}}})
    # Ingestion shield: certain noise (query_level: true) is dropped on the
    # indexer side, it never enters the database.
    query["bool"]["must_not"] = noise_filter.clauses_must_not()
    if not query["bool"]["filter"] and not query["bool"]["must_not"]:
        query = {"match_all": {}}

    body = {
        "size": size,
        "query": query,
        # search_after requires a total order; sorting on @timestamp alone is
        # not one, since several alerts share the same millisecond.
        "sort": [{"@timestamp": "asc"}, {"id": "asc"}],
    }
    if after:
        body["search_after"] = list(after)

    rep = requests.post(
        # Static list UNION the index sets created since by routing.py: an
        # index created without being added here is a sensor the AI silently
        # does not see (see routing.read_indices).
        f"{config.INDEXER_URL}/{routing.read_indices()}/_search",
        json=body,
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=60,
    )
    rep.raise_for_status()
    return rep.json()["hits"]["hits"]


UPDATE_CURSOR = """
INSERT INTO ingest_cursor (id, last_ts, last_alert_id, updated_at)
VALUES (true, %s, %s, now())
ON CONFLICT (id) DO UPDATE
  SET last_ts = EXCLUDED.last_ts,
      last_alert_id = EXCLUDED.last_alert_id,
      updated_at = now()
"""

UPDATE_SWEEP = """
INSERT INTO ingest_cursor (id, last_sweep_at) VALUES (true, now())
ON CONFLICT (id) DO UPDATE SET last_sweep_at = now()
"""


def _iterate(conn, noise_filter: noise.NoiseFilter, since: str | None,
               after: tuple | None, batch_size: int, *,
               advance_cursor: bool, label: str) -> tuple[int, int]:
    """Pages through a window and inserts. Returns (seen, new).

    `advance_cursor=False` for the catch-up sweep: it scans backwards and must
    absolutely not reposition the cursor of the normal stream.
    """
    seen = new = 0
    while True:
        hits = _batch(since, after, batch_size, noise_filter)
        if not hits:
            break

        lines = [_flatten(h["_source"], noise_filter) for h in hits]
        with conn.cursor() as cur:
            cur.executemany(INSERT, lines)
            # ON CONFLICT DO NOTHING: rowcount only counts real insertions,
            # which gives the number of alerts actually recovered (useful for the
            # sweep, where almost the whole batch is already known).
            new += max(cur.rowcount, 0)
            last = hits[-1]
            if advance_cursor:
                cur.execute(UPDATE_CURSOR, (last["_source"]["@timestamp"],
                                          last["_source"]["id"]))
        conn.commit()

        seen += len(hits)
        after = tuple(last["sort"])
        print(f"  {label}: {seen} alerts seen, {new} new...",
              file=sys.stderr)

        if len(hits) < batch_size:
            break
    return seen, new


def _sweep_since(conn, batch_size: int, noise_filter: noise.NoiseFilter) -> int:
    """Rescans a long window to recover alerts that were indexed late.

    The cursor advances on `@timestamp`, the date of the EVENT, not of its
    indexing. A Wazuh agent cut off from the manager buffers its logs and replays
    them on reconnection with their original timestamps: if the cursor has
    already gone past, `search_after` will NEVER return them and those alerts are
    lost for good — never ingested, hence never correlated nor triaged. The
    lookback in `ingest()` only covers a few minutes of skew; an agent outage is
    counted in hours or days.

    Hence this full, periodic sweep of `INGEST_SWEEP_HOURS`, independent of the
    cursor. Ingestion being idempotent, it only costs the read — and at the
    observed volume (a few hundred alerts a day) that is negligible next to one
    LLM triage.
    """
    _, new = _iterate(
        conn, noise_filter, f"{config.INGEST_SWEEP_HOURS}h", None, batch_size,
        advance_cursor=False, label="catch-up")
    conn.execute(UPDATE_SWEEP)
    conn.commit()
    return new


def ingest(since: str | None, batch_size: int,
           force_sweep: bool = False) -> int:
    total = 0
    with psycopg.connect(config.PG_DSN) as conn:
        # Filter built once per run, automatic whitelist (DB) included.
        noise_filter = noise.load_with_db(conn)
        # Container -> own agent map, for reattributing the pve alerts.
        _load_agents(conn)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT last_ts, last_alert_id, last_sweep_at FROM ingest_cursor")
            line = cur.fetchone()

        # The cursor wins over --since: a resume must not rescan a window
        # already processed.
        after = None
        if line and line[0]:
            # Safety rewind: we restart slightly BEFORE the recorded position.
            # Between the moment an alert is dated and the moment it becomes
            # visible to search, there is the agent -> manager -> indexer transit
            # time plus the index refresh. Resuming exactly at the cursor skips
            # whatever landed behind it. The overlap costs nothing: the insert is
            # idempotent.
            #
            # This only covers normal skew. A disconnected agent replaying hours
            # of logs is caught by the sweep, see `_sweep_since`.
            start = line[0] - timedelta(minutes=config.INGEST_LOOKBACK_MINUTES)
            # The id ("" below) is the second sort key: the empty string comes
            # before all others, so no alert of the starting millisecond is
            # excluded.
            after = (int(start.timestamp() * 1000), "")
            since = None

        seen, _ = _iterate(conn, noise_filter, since, after, batch_size,
                             advance_cursor=True, label="ingest")
        total += seen

        # Catch-up sweep, paced independently of the cycle (which runs every
        # 5 min: sweeping on every round would be waste).
        first_pass = not (line and line[0])
        last_sweep = line[2] if line else None
        due = force_sweep or (
            not first_pass
            and (last_sweep is None
                 or (datetime.now(timezone.utc) - last_sweep
                     >= timedelta(minutes=config.INGEST_SWEEP_INTERVAL_MINUTES))))
        if first_pass and not force_sweep:
            # The very first run has just scanned --since (30 d by default):
            # nothing to catch up, we only set the marker.
            conn.execute(UPDATE_SWEEP)
            conn.commit()
        elif due:
            n = _sweep_since(conn, batch_size, noise_filter)
            if n:
                print(f"  catch-up: {n} late-indexed alert(s) recovered",
                      file=sys.stderr)
            total += n
    return total


def reapply_filter() -> tuple[int, int]:
    """Re-evaluates the noise filter suppression on alerts already stored.

    Ingestion being idempotent, a modified filter does not apply to existing rows
    on its own — yet that is the normal use case, the filter grows in operation.
    So we replay the decision from the raw document kept. Does not touch the
    linkage: a newly suppressed alert will leave correlation on the next
    `correlate --restart`.
    """
    seen = deleted = 0
    with psycopg.connect(config.PG_DSN, row_factory=psycopg.rows.dict_row) as conn:
        noise_filter = noise.load_with_db(conn)
        # In BATCHES, never the whole table: `raw` is the full JSON of every
        # alert, and this query carries no filter — on the production database
        # (several hundred thousand alerts, see alerts.py) it held the entire
        # base in memory before the first row was processed. The ids alone are
        # light; the `raw` only comes for the current batch.
        ids = [r["id"] for r in conn.execute("SELECT id FROM alerts").fetchall()]
        for offset in range(0, len(ids), 2000):
            batch = ids[offset:offset + 2000]
            lines = conn.execute(
                "SELECT id, raw FROM alerts WHERE id = ANY(%s)", (batch,)).fetchall()
            for line in lines:
                seen += 1
                reason = noise_filter.deletion_reason(line["raw"])
                if reason:
                    deleted += 1
                conn.execute(
                    "UPDATE alerts SET suppressed = %s, suppress_reason = %s "
                    "WHERE id = %s",
                    (reason is not None, reason, line["id"]))
            conn.commit()
    return deleted, seen


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--since", default="30d",
                    help="window on the first pass (ignored if a cursor exists)")
    ap.add_argument("--batch-size", type=int, default=500)
    ap.add_argument("--reset-cursor", action="store_true",
                    help="starts over from the beginning; ingestion being "
                         "idempotent, this duplicates nothing")
    ap.add_argument("--reapply-filter", action="store_true",
                    help="re-evaluates the noise filter on the alerts already "
                         "stored, without re-ingesting")
    ap.add_argument("--catchup", action="store_true",
                    help=f"forces the sweep of the last "
                         f"{config.INGEST_SWEEP_HOURS} hours without waiting for "
                         "its cadence: recovers late-indexed alerts (agent "
                         "reconnected)")
    args = ap.parse_args()

    if args.reapply_filter:
        supp, seen = reapply_filter()
        print(f"Noise filter reapplied: {supp}/{seen} alerts suppressed.")
        print("Run `correlate --restart` to re-correlate.")
        return

    if args.reset_cursor:
        with psycopg.connect(config.PG_DSN) as conn:
            conn.execute("DELETE FROM ingest_cursor")
            conn.commit()
        print("Cursor reset.")

    start = datetime.now(timezone.utc)
    n = ingest(args.since, args.batch_size, args.catchup)
    duration = (datetime.now(timezone.utc) - start).total_seconds()
    print(f"{n} alerts processed in {duration:.1f} s")


if __name__ == "__main__":
    main()
