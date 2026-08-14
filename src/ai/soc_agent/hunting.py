"""Threat hunting space: putting an archive back online to hunt inside it.

Retention drops the indices at 90 days, archiving keeps an encrypted copy for
twelve months ([ARCHIVAGE.md](../../../docs/ARCHIVAGE.md)). What is left is the
gesture that makes that copy useful: putting it back into the indexer so it can
be queried in Discover, aggregated, pivoted on — hunted.

What `wazuh-hunting-*` is NOT
----------------------------
It is **not a routing index set**. No log source writes to it, no branch of the
ingest pipeline points at it. It deliberately lacks two of the five pieces of an
index set (see docs/ROUTAGE.md), and that absence *is* the feature:

- **not read by ingestion.** That is the hard point. Re-ingesting ten-month-old
  alerts would bring them into correlation, then triage, then the IRIS cases —
  and AURA remediates on its own on a true-positive verdict. A poorly partitioned
  restore does not produce a false positive, it produces a host isolation or an
  IP block in response to last year's attack.
- **not observed by routing.** Restored alerts keep their `decoder.name`. Seen by
  `routing.observed_sources()`, they would look like a source no longer landing
  in its expected index, hence like a routing drift, with the matching IRIS
  alert.

Both exclusions are set by a NEGATION in `routing.read_indices()`
(`-wazuh-hunting-*`), not by a list someone would have to remember to maintain.
It wins even if someone puts `wazuh-*` in `INDEXER_ALERT_INDICES`: the protection
does not depend on configuration discipline.

What it keeps: the template (the same mapping as the live alerts — without it
every field would be `text` and no aggregation would work), an index pattern for
Discover, and a retention of its own (`aura-hunting`, 30 days), because this is
workspace and not preservation.

The index name
--------------
`wazuh-hunting-<source>-<YYYY-MM>` — `wazuh-hunting-firewall-2026-03`.

Deliberately **not** dated to the day: it is the shape of the name
(`-YYYY.MM.DD`) that determines what archiving takes, so this naming alone
guarantees we never archive a restored archive. `ARCHIVE_INDEX_EXCLUDED` says it
again explicitly, as a second barrier.

Guardrails
----------
This space is reachable from the MCP server, hence by an AI agent. "Restore
everything so I can look" must be refused by the CODE, not discouraged by an
instruction: caps on documents, on indices, on bytes, and a flat refusal if the
disk is already above the watchdog alert threshold. A full disk stops the whole
SOC (see docs/RETENTION.md).

    python -m soc_agent.hunting --prepare
    python -m soc_agent.hunting --state
    python -m soc_agent.hunting --restore wazuh-firewall/2026-03
    python -m soc_agent.hunting --purge wazuh-hunting-firewall-2026-03
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)


def _indexer(method: str, path: str, body: dict | None = None,
             timeout: int = 120, raw: bytes | None = None,
             content_type: str | None = None) -> requests.Response:
    headers = {"Content-Type": content_type} if content_type else None
    return requests.request(
        method, f"{config.INDEXER_URL}{path}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=body if raw is None else None, data=raw, headers=headers,
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=timeout)


def index_name(index_base: str, period: str) -> str:
    """`wazuh-firewall` + `2026-03` -> `wazuh-hunting-firewall-2026-03`.

    The source's `wazuh-` prefix is stripped: `wazuh-hunting-wazuh-firewall`
    would say nothing more and would read badly in Discover.
    """
    source = index_base.removeprefix("wazuh-")
    return f"{config.HUNTING_INDEX_BASE}-{source}-{period}"


# --------------------------------------------------------------------------
# Preparing the space
# --------------------------------------------------------------------------

def prepare() -> dict:
    """Sets what the space needs: template, ISM, index pattern.

    Idempotent, and called automatically before every restore: a hunting space
    that prepares itself avoids the silliest failure mode — restoring 200,000
    documents into an index with no mapping, where no aggregation works any more
    and no retention will ever purge it.
    """
    from . import retention, routing
    summary: dict = {"index_base": config.HUNTING_INDEX_BASE}

    # Template: the SAME as the live alerts. `_set_template` reads the template
    # in place and only adds a pattern to it — that is what guarantees restored
    # fields behave exactly as they did, including after a Wazuh upgrade that
    # changed the mappings.
    try:
        routing._set_template(config.HUNTING_INDEX_BASE)
        summary["template"] = routing.TEMPLATE
    except Exception as e:                                    # noqa: BLE001
        # Without a mapping the data still goes in but becomes unusable
        # (everything `text`, no aggregation). Better say so loudly and refuse.
        raise RuntimeError(
            f"template {routing.TEMPLATE} not set for "
            f"{config.HUNTING_INDEX_BASE} ({e}): a restore without a mapping "
            "would produce an index unusable for hunting.") from e

    try:
        retention.apply_ism()
        summary["ism"] = retention.ISM_HUNTING_ID
    except Exception as e:                                    # noqa: BLE001
        log.warning("hunting ISM policy not set (%s): the restored indices "
                    "will not be purged automatically", e)
        summary["ism"] = f"failed: {e}"

    routing._set_index_pattern(config.HUNTING_INDEX_BASE)
    summary["index_pattern"] = f"{config.HUNTING_INDEX_BASE}-*"
    return summary


# --------------------------------------------------------------------------
# State of the space
# --------------------------------------------------------------------------

def state() -> dict:
    """What occupies the hunting space, and what is left before the caps.

    Returning `caps` with the state rather than on failure: a client (human or
    AI) must be able to decide whether there is room BEFORE launching a
    three-minute restore that gets refused at the end.
    """
    r = _indexer("GET", f"/_cat/indices/{config.HUNTING_INDEX_BASE}-*"
                        "?format=json&h=index,docs.count,pri.store.size,"
                        "creation.date.string&bytes=b&expand_wildcards=open")
    indices = []
    if r.status_code != 404:
        if not r.ok:
            raise RuntimeError(f"_cat/indices refused ({r.status_code}): {r.text}")
        for line in r.json():
            indices.append({
                "index": line["index"],
                "documents": int(line.get("docs.count") or 0),
                "bytes": int(line.get("pri.store.size") or 0),
                "created_at": line.get("creation.date.string"),
            })
    indices.sort(key=lambda i: i["index"])
    byte_count = sum(i["bytes"] for i in indices)
    free = shutil.disk_usage(config.ARCHIVE_TMP_DIR)
    return {
        "index_base": config.HUNTING_INDEX_BASE,
        "indices": indices,
        "total_indices": len(indices),
        "total_documents": sum(i["documents"] for i in indices),
        "total_bytes": byte_count,
        "caps": {
            "max_indices": config.HUNTING_MAX_INDICES,
            "max_bytes": config.HUNTING_MAX_BYTES,
            "max_documents_per_restore": config.HUNTING_MAX_DOCS,
            "bytes_left": max(0, config.HUNTING_MAX_BYTES - byte_count),
            "indices_left": max(0, config.HUNTING_MAX_INDICES - len(indices)),
        },
        "disk_pct": round(100 * free.used / free.total),
        "retention_days": config.HUNTING_RETENTION_DAYS,
    }


# --------------------------------------------------------------------------
# Guardrails
# --------------------------------------------------------------------------

def check_space(archive: dict, current: dict | None = None) -> None:
    """Raises if this restore must not happen. No side effect.

    Separated from `restore` so it can be called in simulation: that is what lets
    the dry-run say "it would go through" or "it would be refused, and why"
    without downloading anything.
    """
    e = current or state()

    # The disk first. Restoring is comfort; a full disk flips the indexer to
    # read-only and stops ingestion for the WHOLE fleet.
    if e["disk_pct"] >= config.DISK_THRESHOLD_ALERT:
        raise RuntimeError(
            f"disk at {e['disk_pct']} % (alert threshold "
            f"{config.DISK_THRESHOLD_ALERT} %): restore refused. Hunting is "
            "comfort, a full disk stops ingestion for the whole fleet. Free "
            "some space or purge hunting indices (soc_agent.hunting --state).")

    if archive["documents"] > config.HUNTING_MAX_DOCS:
        raise RuntimeError(
            f"{archive['documents']} documents to restore, cap "
            f"{config.HUNTING_MAX_DOCS} (HUNTING_MAX_DOCS). This archive is too "
            "large for the hunting space: restoring the NDJSON file locally and "
            "filtering it with jq (soc_agent.archive --restore) is the right "
            "move here.")

    if e["total_indices"] >= config.HUNTING_MAX_INDICES:
        raise RuntimeError(
            f"{e['total_indices']} hunting indices already in place, cap "
            f"{config.HUNTING_MAX_INDICES} (HUNTING_MAX_INDICES). Purge what is "
            "no longer useful: those indices are copies, the S3 archive stays.")

    # The archive is encrypted and compressed; what weighs in the indexer is the
    # PLAINTEXT. We estimate from `plain_bytes`, which is in the manifest, with a
    # factor close to 1: the indexer compresses its segments but adds its own
    # structures. An assumed approximation, announced as such.
    projected = e["total_bytes"] + archive["plain_bytes"]
    if projected > config.HUNTING_MAX_BYTES:
        raise RuntimeError(
            f"{projected / 1073741824:.1f} GB projected into the hunting space, "
            f"cap {config.HUNTING_MAX_BYTES / 1073741824:.1f} GB "
            "(HUNTING_MAX_GB). Purge a hunting index first.")


def archive_available(conn, index_base: str, period: str) -> dict:
    """The archive row, or an error that says what to do.

    We query Postgres and not S3: that is the authoritative marker (see
    archive.py). An S3 that does not answer must not translate into "this archive
    does not exist".
    """
    r = conn.execute(
        "SELECT * FROM archives_s3 WHERE format_version=%s AND index_base=%s "
        "  AND period=%s", (config.ARCHIVE_FORMAT_VERSION, index_base,
                            period)).fetchone()
    if r is None:
        available = conn.execute(
            "SELECT index_base, min(period) d, max(period) f, count(*) n "
            "  FROM archives_s3 WHERE format_version=%s GROUP BY index_base "
            "  ORDER BY index_base", (config.ARCHIVE_FORMAT_VERSION,)).fetchall()
        raise RuntimeError(
            f"no archive for {index_base}/{period}. Available: "
            + (", ".join(f"{d['index_base']} {d['d']}..{d['f']} ({d['n']} months)"
                         for d in available) or "nothing (archiving wrote nothing)"))
    if r["verify_state"] and r["verify_state"] != "ok":
        # Do not refuse: a doubtful archive is precisely what we want to
        # inspect. But say so, so nobody concludes on a partial copy believing
        # they hold the truth.
        log.warning("archive %s/%s in state \"%s\": the restore may be "
                    "incomplete", index_base, period, r["verify_state"])
    return dict(r)


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------

def _create_index(target: str, archive: dict) -> None:
    """Creates the index with its provenance in `_meta`.

    The provenance goes into the INDEX metadata, never into `_source`: a restored
    alert must stay byte for byte what was archived. A field added to the
    document would make the manifest SHA-256 useless as proof, and would skew the
    aggregations on the fields being hunted.
    """
    body = {"mappings": {"_meta": {"aura_hunting": {
        "archive_key": archive["key"],
        "source_index": archive["index_base"],
        "period": archive["period"],
        "source_indices": archive["indices"],
        "expected_documents": archive["documents"],
        "sha256_plain": archive["sha256_plain"],
        "restored_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }}}}
    r = _indexer("PUT", f"/{target}", body)
    if r.status_code == 400 and "resource_already_exists" in r.text:
        log.info("index %s already present: re-injecting on top (the _id are "
                 "kept, so the documents are overwritten identically)",
                 target)
        return
    if not r.ok:
        raise RuntimeError(f"creation of {target} refused ({r.status_code}): "
                           f"{r.text[:300]}")


def _inject(target: str, ndjson: Path) -> dict:
    """Re-injects the NDJSON into the target index, in `_bulk` batches.

    The original `_id` is KEPT: a replayed restore overwrites the same documents
    instead of creating duplicates. That is what makes the operation idempotent
    with no marker to maintain.
    """
    injected = errors = 0
    examples: list[str] = []
    batch: list[bytes] = []

    def clear() -> None:
        nonlocal injected, errors
        if not batch:
            return
        r = _indexer("POST", "/_bulk", raw=b"".join(batch),
                     content_type="application/x-ndjson", timeout=300)
        batch.clear()
        if not r.ok:
            raise RuntimeError(f"_bulk refused ({r.status_code}): {r.text[:300]}")
        response = r.json()
        for item in response.get("items", []):
            detail = item.get("index") or {}
            if detail.get("error"):
                errors += 1
                if len(examples) < 3:
                    examples.append(str(detail["error"])[:200])
            else:
                injected += 1

    with ndjson.open("rb") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue
            header = {"index": {"_index": target}}
            if doc.get("_id"):
                header["index"]["_id"] = doc["_id"]
            batch.append(json.dumps(header, separators=(",", ":")).encode() + b"\n")
            batch.append(json.dumps(doc.get("_source") or {}, ensure_ascii=False,
                                  separators=(",", ":")).encode() + b"\n")
            if len(batch) >= config.HUNTING_BULK_SIZE * 2:
                clear()
    clear()
    return {"injected": injected, "errors": errors,
            "error_examples": examples}


def restore(index_base: str, period: str, apply: bool = False,
              identity: str | None = None) -> dict:
    """Puts an archive back into the hunting space.

    In dry-run (the default) it returns what would be done, guardrail verdict
    included: that is the only honest way to answer "will it go through?" without
    downloading 40 MB to find out.
    """
    from . import archive as arch

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        line = archive_available(conn, index_base, period)

    target = index_name(index_base, period)
    current = state()
    preview = {
        "target_index": target,
        "archive": {"key": line["key"], "documents": line["documents"],
                    "plain_bytes": line["plain_bytes"],
                    "source_indices": line["indices"],
                    "verification": line["verify_state"] or "never verified"},
        "space_before": {k: current[k] for k in
                         ("total_indices", "total_documents", "total_bytes")},
        "caps": current["caps"],
        "retention_days": config.HUNTING_RETENTION_DAYS,
    }

    try:
        check_space(line, current)
        preview["guardrails"] = "ok"
    except RuntimeError as e:
        preview["guardrails"] = f"REFUSED: {e}"
        if not apply:
            return {"applied": False, **preview}
        raise

    if not apply:
        return {
            "applied": False, **preview,
            "note": "Dry-run: nothing was downloaded nor indexed. Re-run with "
                    "apply=true. The restore does NOT enter the pipeline: those "
                    "alerts will be neither correlated, nor triaged, nor "
                    "remediated — this is a read-only space.",
        }

    prepare()
    tmp = Path(tempfile.mkdtemp(prefix="aura-hunting-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        ndjson = tmp / f"{target}.ndjson"
        rest = arch.restore(arch._s3(), index_base, period, ndjson, identity)
        if rest["lines"] != line["documents"]:
            log.warning("archive %s/%s: %d lines decrypted, %d in the manifest "
                        "— restore continued, but the copy is incomplete",
                        index_base, period, rest["lines"], line["documents"])
        _create_index(target, line)
        summary = _inject(target, ndjson)
        _indexer("POST", f"/{target}/_refresh")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    log.info("hunting: %d document(s) restored into %s from %s/%s",
             summary["injected"], target, index_base, period)
    return {
        "applied": True, **preview,
        "decrypted_lines": rest["lines"], **summary,
        "complete": summary["injected"] == line["documents"],
        "where_to_look": f"Discover, index pattern "
                         f"{config.HUNTING_INDEX_BASE}-*, index {target}",
        "note": "Those alerts are NOT in the pipeline: no correlation, no "
                "triage, no remediation. They will be deleted automatically "
                f"after {config.HUNTING_RETENTION_DAYS} days — the S3 archive "
                "itself stays.",
    }


def purge(index: str, confirm: bool = False) -> dict:
    """Deletes a hunting index to free room.

    Bounded to the hunting prefix, and not out of rhetorical caution: the same
    request on `wazuh-firewall-2026.08.14` would destroy production data that
    only the S3 archive could give back — if it already exists.
    """
    if not index.startswith(f"{config.HUNTING_INDEX_BASE}-"):
        raise RuntimeError(
            f"\"{index}\" is not a hunting index (expected prefix: "
            f"{config.HUNTING_INDEX_BASE}-). Refused: this tool only deletes "
            "restored copies, never production data.")
    if "*" in index or "," in index:
        raise RuntimeError(
            "one index at a time, fully named — no wildcard. A pattern deletion "
            "is exactly the gesture whose reach nobody measures.")
    if not confirm:
        return {"deleted": False,
                "note": f"{index} would be deleted. It is a COPY: the S3 archive "
                        "stays and the restore is replayable. Pass confirm=true."}
    r = _indexer("DELETE", f"/{index}")
    if not r.ok:
        raise RuntimeError(f"deletion of {index} refused ({r.status_code}): "
                           f"{r.text[:200]}")
    log.info("hunting index %s deleted", index)
    return {"deleted": True, "index": index}


# --------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prepare", action="store_true",
                   help="set template, ISM and index pattern, then exit")
    p.add_argument("--state", action="store_true",
                   help="what occupies the hunting space")
    p.add_argument("--restore", metavar="INDEX_SET/YYYY-MM",
                   help="put an archive back into the hunting space")
    p.add_argument("--apply", action="store_true",
                   help="run for real (default: dry-run)")
    p.add_argument("--identity", help="backup age key, if the SOC one is lost")
    p.add_argument("--purge", metavar="INDEX",
                   help="delete a hunting index")
    p.add_argument("--confirm", action="store_true",
                   help="confirm the deletion")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.prepare:
        output = prepare()
    elif args.state:
        output = state()
    elif args.purge:
        output = purge(args.purge, args.confirm)
    elif args.restore:
        base, _, period = args.restore.rpartition("/")
        output = restore(base, period, args.apply, args.identity)
    else:
        p.print_help()
        return
    print(json.dumps(output, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
