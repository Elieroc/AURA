"""Exporting the archive catalog to the Wazuh indexer, for the Archive dashboard.

`archives_s3` (Postgres, see `archive.py`) is the only authority on what is
archived — this module never reads it. It reads Postgres and writes what it
finds into a FIXED-NAME index (`ARCHIVE_METRICS_INDEX`, no `-YYYY.MM.DD`
suffix): unlike alerts, an archive doesn't happen every day and there is
nothing here to purge by date. Same convention as `wazuh-voc-vulns` — a state
index, not a time series of events.

One document per (index set, month), `_id` deterministic
(`archive-<index_base>-<period>`): re-exporting overwrites the row in place,
never duplicates it. `@timestamp` is `archived_at`, which never changes once
written — so a date histogram on this index genuinely shows when storage was
added, even though every pass rewrites every document identically.

Called from two places, both after `archives_s3` may have changed:

- `archive.run()`, at the end of every pass (periodic or on-demand via
  `aura_archive_create`) — best-effort, a metrics failure must never fail
  the archiving pass itself;
- `python -m soc_agent.archive_metrics`, standalone, for a manual refresh or
  to backfill the index after it's been dropped.

    python -m soc_agent.archive_metrics               # export everything
    python -m soc_agent.archive_metrics --simulation  # shows, writes nothing
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)

EVENT_TYPE = "archive_catalog"


def _iso(ts) -> str | None:
    return ts.astimezone(timezone.utc).isoformat() if ts else None


def _doc(row: dict) -> dict:
    """One archive row -> one document.

    `cost_usd_month` prices the ENCRYPTED object actually stored — it is what
    B2 bills, not the plaintext volume `plain_bytes` describes. `ratio` is
    read the other way round (plain / encrypted): it is what explains why the
    object is so much smaller than the index it came from.
    """
    object_bytes = row["object_bytes"] or 0
    plain_bytes = row["plain_bytes"] or 0
    return {
        "@timestamp": _iso(row["archived_at"]),
        "timestamp": _iso(row["archived_at"]),
        "event_type": EVENT_TYPE,
        "archive": {
            "index_set": row["index_base"],
            "period": row["period"],
            "documents": row["documents"],
            "plain_bytes": plain_bytes,
            "object_bytes": object_bytes,
            "ratio": round(plain_bytes / object_bytes, 2) if object_bytes else 0,
            "cost_usd_month": round(
                object_bytes / 1_000_000_000
                * config.ARCHIVE_S3_COST_USD_PER_GB_MONTH, 6),
            "archived_at": _iso(row["archived_at"]),
            "verified_at": _iso(row["verified_at"]),
            "verify_state": row["verify_state"],
            "verify_full": row["verify_full"],
            "object_lock_until": _iso(row["object_lock_until"]),
        },
    }


def _bulk(lines: list[str]) -> tuple[int, list[str]]:
    """Bulk send to the indexer. Returns (number written, errors)."""
    if not lines:
        return 0, []
    r = requests.post(
        f"{config.INDEXER_URL}/_bulk",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data="".join(lines).encode("utf-8"),
        verify=config.INDEXER_CA or config.INDEXER_VERIFY_TLS,
        timeout=60)
    r.raise_for_status()
    body = r.json()
    errors = []
    if body.get("errors"):
        for item in body.get("items", []):
            info = next(iter(item.values()))
            if info.get("error"):
                errors.append(json.dumps(info["error"])[:300])
    return len(body.get("items", [])) - len(errors), errors


def _line(doc_id: str, doc: dict) -> list[str]:
    return [json.dumps(
                {"index": {"_index": config.ARCHIVE_METRICS_INDEX,
                            "_id": doc_id}}) + "\n",
            json.dumps(doc, default=str) + "\n"]


def export(conn=None, simulation: bool = False) -> dict:
    """Exports the whole catalog. The table is small (one row per index set
    per month): there is no window to re-export, unlike `metrics.py`."""
    own_conn = conn is None
    if own_conn:
        conn = psycopg.connect(config.PG_DSN, row_factory=dict_row)
    try:
        rows = conn.execute(
            "SELECT * FROM archives_s3 WHERE format_version = %s",
            (config.ARCHIVE_FORMAT_VERSION,)).fetchall()
    finally:
        if own_conn:
            conn.close()

    lines = []
    for row in rows:
        lines += _line(f"archive-{row['index_base']}-{row['period']}",
                       _doc(row))

    if simulation:
        for line in lines:
            print(line, end="")
        return {"archives": len(rows)}

    written, errors = _bulk(lines)
    if errors:
        log.warning("archive_metrics: %d error(s) writing to %s: %s",
                    len(errors), config.ARCHIVE_METRICS_INDEX, errors[:3])
    return {"archives": len(rows), "written": written, "errors": errors}


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--simulation", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    r = export(simulation=args.simulation)
    if args.simulation:
        return
    print(f"  {r['written']} document(s) indexed ({r['archives']} archives)")
    for e in r["errors"]:
        print(f"  ERROR {e}")


if __name__ == "__main__":
    main()
