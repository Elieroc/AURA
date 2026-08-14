"""Cold archiving of the indexer's indices to S3 (Backblaze B2).

Retention (`retention.py`) deletes the dated indices at 90 days. A SOC must be
able to answer later than that: judicial request, audit, an intrusion discovered
six months after it began. This module produces the copy that survives the purge.

What it is, and what it is not
------------------------------
One object per (index set x month), in NDJSON compressed then ENCRYPTED, plus a
plaintext manifest next to it. It is NOT an OpenSearch snapshot, and the choice
is deliberate:

- a snapshot only reads back with a cluster of a compatible version. A
  twelve-month archive must stand alone, in 2029, with `zstdcat` and `age`;
- the tree of a snapshot repository is imposed and opaque
  (`indices/<uuid>/__xyz`): impossible to file by index set and by year;
- a client-encrypted repository is no longer a repository — OpenSearch must be
  able to read its own metadata. The key would have had to go to the provider.

The price paid, deliberately: no incremental (every archive is self-contained)
and restoring is not one click (see docs/ARCHIVAGE.md).

Three properties that hold the rest together
--------------------------------------------
1. **The SOC holds the whole key** (`ARCHIVE_AGE_KEYFILE`): it encrypts and
   decrypts its own archives. What follows, for better and worse:

   - the restore drill goes all the way on its own — it decrypts, counts the
     documents and compares with the manifest. It proves READABILITY, not only
     the integrity of the storage;
   - restoring a month requires no key mounting by hand;
   - but that file is the only thing between an attacker with root on this host
     and reading the entire history. The provider only ever sees opaque bytes —
     that is the point of client-side encryption, and it is achieved. The threat
     model covered is "B2 reads my archives", not "the SOC is compromised".
2. **The marker lives in Postgres**, never in the remote system. Querying S3 to
   know what is archived reproduces the IRIS Evidence bug: the call fails, the
   failure is swallowed, the list of "already done" falls back to empty and
   everything is redone — 8.3 GB and 54 copies of the same file.
3. **The month is read from the index NAME**, never from an `@timestamp`.
   `wazuh-firewall-2026.08.14` belongs to 2026-08, full stop. No straddling query
   window, no time zone, and the archive covers exactly what the ISM purge will
   delete.

The plaintext never touches the disk: it goes through `zstd | age` over pipes,
and only the ciphertext is written to a working file.

The IRIS anomalies produced here stay in French: analysts read them.

    python -m soc_agent.archive --check     # key + bucket preflight, before all
    python -m soc_agent.archive --plan      # what would be archived
    python -m soc_agent.archive             # one pass
    python -m soc_agent.archive --drill     # read back and decrypt archives
    python -m soc_agent.archive --restore wazuh-firewall/2026-03 --to f.ndjson
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)

# Same advisory-lock family as the other periodic jobs (0x50CA*).
_LOCK_ARCHIVE = 0x50CA6

# Index DATED TO THE DAY, the only form archived. This pattern is the module's
# real filter: with no list at all it excludes `wazuh-voc-vulns` (a state index,
# it carries the MTTR) as well as `wazuh-monitoring-*` / `wazuh-statistics-*`,
# dated to the week by Wazuh (`2026.33w`) and which are not alerts.
_DATE_INDEX = re.compile(r"^(?P<base>.+)-(?P<a>\d{4})\.(?P<m>\d{2})\.(?P<j>\d{2})$")

SUFFIX_OBJECT = "ndjson.zst.age"
SUFFIX_MANIFEST = "manifest.json"

# Pseudo-sensors set in `sensor_outages` by the watchdog. Same table, same IRIS
# channel, same automatic closure as the saturated disk: a missing archive is a
# future loss of visibility, of exactly the same nature.
PREFIX_SENSOR = "archiving:"


# --------------------------------------------------------------------------
# Indexer
# --------------------------------------------------------------------------

def _indexer(method: str, path: str, body: dict | None = None,
             timeout: int = 120) -> requests.Response:
    return requests.request(
        method, f"{config.INDEXER_URL}{path}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=body,
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=timeout)


def _excluded(name: str) -> bool:
    return any(fnmatch.fnmatch(name, m) for m in config.ARCHIVE_INDEX_EXCLUDED)


def dated_indices() -> list[dict]:
    """Day-dated indices, with their base, their month and their size.

    The list of candidate patterns is deliberately broad (`wazuh-*`): the house
    trap is the list to keep up to date that gets forgotten — three times for
    `INDEXER_ALERT_INDICES` (see docs/ROUTAGE.md), and every omission was an
    invisible sensor. An index set created tomorrow by `routing.py` must be
    archived without anyone thinking about it.
    """
    r = _indexer("GET", f"/_cat/indices/{config.ARCHIVE_INDEX_PATTERNS}"
                        "?format=json&h=index,docs.count,pri.store.size"
                        "&bytes=b&expand_wildcards=open")
    if r.status_code == 404:
        return []
    if not r.ok:
        raise RuntimeError(f"_cat/indices refused ({r.status_code}): {r.text}")
    output = []
    for line in r.json():
        name = line["index"]
        m = _DATE_INDEX.match(name)
        if not m or _excluded(name):
            continue
        output.append({
            "index": name,
            "base": m.group("base"),
            "day": date(int(m.group("a")), int(m.group("m")), int(m.group("j"))),
            "month": f"{m.group('a')}-{m.group('m')}",
            "documents": int(line.get("docs.count") or 0),
            "bytes": int(line.get("pri.store.size") or 0),
        })
    return output


def _first_of_next_month(month: str) -> date:
    a, m = (int(x) for x in month.split("-"))
    return date(a + 1, 1, 1) if m == 12 else date(a, m + 1, 1)


def _closed_months(month: str, today: date | None = None) -> bool:
    """Is the month over AND settled enough to be frozen?

    The grace delay is not decorative: the catch-up of late-indexed alerts still
    writes into yesterday's indices, and an index created across midnight can
    receive afterwards. Archiving too early freezes an incomplete copy — and an
    incomplete archive does not repair itself, it believes it is complete.
    """
    ref = today or datetime.now(timezone.utc).date()
    return ref >= _first_of_next_month(month) + timedelta(
        days=config.ARCHIVE_DELAY_DAYS)


def batches_to_archive(conn, today: date | None = None) -> list[dict]:
    """Closed (index_base, month) pairs not archived yet.

    An EMPTY month still produces an archive (a few hundred bytes). That is
    deliberate: the invariant "every month of every index set has exactly one
    object" is what makes a gap detectable. A month simply absent would be
    indistinguishable from a month lost.
    """
    already = {(r["index_base"], r["period"]) for r in conn.execute(
        "SELECT index_base, period FROM archives_s3 WHERE format_version=%s",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()}
    batches: dict[tuple[str, str], dict] = {}
    for i in dated_indices():
        key = (i["base"], i["month"])
        if key in already or not _closed_months(i["month"], today):
            continue
        batch = batches.setdefault(key, {"index_base": i["base"], "period": i["month"],
                                    "indices": [], "documents": 0, "bytes": 0})
        batch["indices"].append(i["index"])
        batch["documents"] += i["documents"]
        batch["bytes"] += i["bytes"]
    for batch in batches.values():
        batch["indices"].sort()
    return sorted(batches.values(), key=lambda l: (l["period"], l["index_base"]))


# --------------------------------------------------------------------------
# Export: scroll pagination (see `pages` for the why)
# --------------------------------------------------------------------------

def _body_search(size: int) -> dict:
    body: dict = {"size": size, "query": {"match_all": {}}}
    if config.ARCHIVE_FIELDS_EXCLUDED:
        body["_source"] = {"excludes": config.ARCHIVE_FIELDS_EXCLUDED}
    # EXACT and uncapped count. Without this setting OpenSearch stops counting
    # at 10,000 and returns `{"value": 10000, "relation": "gte"}`: a cap one
    # would take for a total, hence a completeness check that would validate any
    # export of more than 10,000 documents.
    body["track_total_hits"] = True
    return body


def _check_shards(doc: dict, indices: list[str]) -> None:
    """Refuses a PARTIAL result. That is the check that was missing.

    OpenSearch answers `HTTP 200` with partial results when a shard goes down or
    times out: the failure is in `_shards.failed`, not in the HTTP code. Without
    this control, a shard unavailable during the export produces a truncated
    archive that records ITS OWN truncated count as the reference — the manifest,
    the SHA-256, the drill and the adoption then all agree with each other, and
    alerts are missing that nothing will ever claim.

    That is the worst possible failure mode for archiving: silent and
    self-confirmed. Hence a hard failure of the batch, even if it has to be
    redone tomorrow.
    """
    shards = doc.get("_shards") or {}
    rates = shards.get("failed") or 0
    if rates or doc.get("timed_out"):
        patterns = "; ".join(
            f"{e.get('index', '?')}: {e.get('reason', {}).get('reason', e)}"
            for e in (shards.get("failures") or [])[:3]) or "no detail given"
        raise RuntimeError(
            f"partial export refused on {','.join(indices[:3])}"
            f"{'...' if len(indices) > 3 else ''}: {rates} shard(s) failed out of "
            f"{shards.get('total', '?')}"
            f"{', search timed out' if doc.get('timed_out') else ''} — {patterns}. "
            "A partial export would produce a truncated archive believing itself "
            "complete. Batch abandoned, it will be picked up on the next pass.")


def pages(indices: list[str], size: int | None = None,
          control: dict | None = None):
    """Paginating the export through the scroll API.

    Why scroll and not `point_in_time` + `search_after`, the method recommended
    everywhere: **`_shard_doc` does not exist in OpenSearch.** That sort field was
    added in Elasticsearch 7.12, after the OpenSearch fork, and was never ported.
    A PIT therefore creates fine, but the search relying on it is rejected:

        query_shard_exception: No mapping found for [_shard_doc] in order to
        sort on

    That is exactly what the production indexer (OpenSearch 2.x) answered on the
    first real pass, on all ten batches. And without a **total** sort criterion,
    `search_after` is unusable: sorting on `@timestamp` alone skips or duplicates
    the documents sharing the same millisecond, and `_id` is not sortable. Only
    scroll is left.

    Scroll is deprecated on the Elasticsearch side, not on the OpenSearch side,
    and its drawback (it holds a search context) has no bearing here: the export
    is a single shot on indices that no longer receive anything.

    `control` receives `expected`, the EXACT total of the same search snapshot as
    the pages. Comparing it with the number of documents actually written is what
    proves completeness, and taking it HERE rather than from `_cat/indices`
    removes any race: it is the same scroll context, hence the same set of
    documents.
    """
    size = size or config.ARCHIVE_SIZE_BATCH
    csv = ",".join(indices)
    r = _indexer("POST", f"/{csv}/_search?scroll=10m", _body_search(size))
    if not r.ok:
        raise RuntimeError(f"scroll refused ({r.status_code}): {r.text}")
    doc = r.json()
    _check_shards(doc, indices)
    if control is not None:
        total = (doc.get("hits") or {}).get("total") or {}
        control["expected"] = total.get("value")
        control["relation"] = total.get("relation")
    sid = doc.get("_scroll_id")
    try:
        while True:
            hits = doc["hits"]["hits"]
            if not hits:
                return
            yield hits
            r = _indexer("POST", "/_search/scroll",
                         {"scroll": "10m", "scroll_id": sid})
            if not r.ok:
                raise RuntimeError(f"scroll refused ({r.status_code}): {r.text}")
            doc = r.json()
            # On EVERY page: a shard can go down in the middle of a scroll
            # lasting several minutes, and the page concerned simply comes back
            # shorter, with no HTTP error.
            _check_shards(doc, indices)
            # The scroll id CAN change from one call to the next: reusing the
            # first one forever works until the day it does not.
            sid = doc.get("_scroll_id") or sid
    finally:
        # A scroll context not released holds segments on disk, and a full disk
        # is the outage that stops the whole SOC. Best-effort, but never
        # forgotten.
        if sid:
            try:
                _indexer("DELETE", "/_search/scroll", {"scroll_id": [sid]})
            except Exception as e:                                # noqa: BLE001
                log.warning("scroll not released: %s", e)


# --------------------------------------------------------------------------
# Compression plus encryption chain
# --------------------------------------------------------------------------

def public_key() -> str:
    """Public key matching `ARCHIVE_AGE_KEYFILE`.

    `age-keygen` writes the public key as a comment of the identity; we read it
    there rather than spawning a subprocess for every archive. Falls back on
    `age-keygen -y` if the comment was removed — settling for a failure here
    would block archiving over a comment line.
    """
    for line in Path(config.ARCHIVE_AGE_KEYFILE).read_text(
            encoding="utf-8", errors="replace").splitlines():
        if line.lower().startswith("# public key:"):
            return line.split(":", 1)[1].strip()
    r = subprocess.run(["age-keygen", "-y", config.ARCHIVE_AGE_KEYFILE],
                       capture_output=True)
    if r.returncode:
        raise RuntimeError(
            f"public key undeterminable from {config.ARCHIVE_AGE_KEYFILE}: "
            + r.stderr.decode(errors="replace")[:300])
    return r.stdout.decode().strip()


def recipients() -> list[str]:
    """The SOC key, plus any backup keys.

    The SOC key is DERIVED from the key file, never copied into the `.env`. That
    is what removes a whole class of failures: a badly copied recipient would
    produce archives the SOC cannot read back, and nobody would notice before the
    first drill.
    """
    return [public_key(), *config.ARCHIVE_AGE_RECIPIENTS_EXTRA]


def processing_chain() -> str:
    """Exact description of the chain, as written into the manifest.

    This is not cosmetic: it is what allows reading an archive back in three
    years without reading the code of that version.
    """
    return (f"zstd -{config.ARCHIVE_ZSTD_LEVEL} --long=27 | age -r "
            + " -r ".join(recipients()))


def _check_tools() -> None:
    for tool in ("zstd", "age"):
        if not shutil.which(tool):
            raise RuntimeError(
                f"\"{tool}\" missing from the image. Archiving compresses and "
                "encrypts over pipes, never in memory: both binaries are "
                "required (Debian packages `zstd` and `age`).")


def _free_space(index_bytes: int) -> None:
    """Refuse to export for lack of room, rather than fill the disk.

    The encrypted archive is always MUCH smaller than the index store; requiring
    the equivalent of the store is therefore generous, and that is the point. A
    full disk stops ingestion without any alert saying so (see
    docs/RETENTION.md): this housekeeping job must not be its cause.
    """
    need = max(index_bytes, 256 * 1024 * 1024)
    free = shutil.disk_usage(config.ARCHIVE_TMP_DIR).free
    if free < need:
        raise RuntimeError(
            f"not enough room in {config.ARCHIVE_TMP_DIR}: "
            f"{free / 1073741824:.1f} GB free, {need / 1073741824:.1f} GB "
            "required. Export refused — filling the SOC disk would stop "
            "ingestion.")


def export(batch: dict, destination: Path) -> dict:
    """Writes the ENCRYPTED archive into `destination`. Returns the metrics.

    The plaintext NDJSON never touches the disk: it is written to the input of
    `zstd`, whose output feeds `age`, whose output alone is a file. The SHA-256 of
    the plaintext is computed on the fly, while we have it at hand.
    """
    _check_tools()
    _free_space(batch["bytes"])

    recipient_args: list[str] = []
    for r in recipients():
        recipient_args += ["-r", r]

    sha_plain = hashlib.sha256()
    plain_bytes = documents = 0
    control: dict = {}

    with destination.open("wb") as output:
        zstd = subprocess.Popen(
            ["zstd", f"-{config.ARCHIVE_ZSTD_LEVEL}", "--long=27", "-T0",
             "-q", "-c"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        age = subprocess.Popen(["age", *recipient_args], stdin=zstd.stdout,
                               stdout=output, stderr=subprocess.PIPE)
        # Indispensable: without it `zstd` never sees the EOF of its reader and
        # the chain hangs on close.
        zstd.stdout.close()
        try:
            for page in pages(batch["indices"], control=control):
                for hit in page:
                    line = (json.dumps(
                        {"_index": hit["_index"], "_id": hit["_id"],
                         "_source": hit.get("_source") or {}},
                        ensure_ascii=False, separators=(",", ":"),
                        sort_keys=True) + "\n").encode()
                    sha_plain.update(line)
                    plain_bytes += len(line)
                    documents += 1
                    zstd.stdin.write(line)
        except BrokenPipeError as e:
            err = (zstd.stderr.read() or b"").decode(errors="replace")
            raise RuntimeError(f"zstd broke the pipe: {err or e}") from e
        finally:
            try:
                zstd.stdin.close()
            except BrokenPipeError:
                pass
            code_zstd = zstd.wait()
            code_age = age.wait()

    if code_zstd or code_age:
        # NEVER keep a file produced by a failed chain: it would be truncated,
        # and a truncated file uploaded to S3 passes for a valid archive until the
        # day it is needed.
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"processing chain failed (zstd={code_zstd}, age={code_age}): "
            + (zstd.stderr.read() or b"").decode(errors="replace")
            + (age.stderr.read() or b"").decode(errors="replace"))

    # COMPLETENESS CONTROL. The count comes from the same scroll snapshot as the
    # pages, so a gap cannot come from a concurrent write: it can only come from
    # an export that stopped before the end.
    #
    # FEWER written = truncated archive: refusal, and deletion of the file. That
    # case is the one that made the gap undetectable, since the manifest would
    # have recorded the truncated count as the reference and everything else
    # (SHA-256, drill, adoption) compares against the manifest.
    #
    # MORE written is not an error: the scroll returns what it has, and a surplus
    # would at worst mean a duplicate, not a loss. We log it.
    expected = control.get("expected")
    if expected is not None and documents < expected:
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"INCOMPLETE export refused: {documents} documents written for "
            f"{expected} announced by the indexer "
            f"({batch['index_base']}/{batch['period']}). The file was deleted — "
            "archiving it would have produced a truncated copy believing itself "
            "complete. Batch picked up on the next pass.")
    if expected is not None and documents > expected:
        log.warning("export %s/%s: %d documents written for %d announced — "
                    "surplus kept (no loss), to watch if it repeats",
                    batch["index_base"], batch["period"], documents, expected)

    return {"documents": documents, "plain_bytes": plain_bytes,
            "sha256_plain": sha_plain.hexdigest(),
            "object_bytes": destination.stat().st_size,
            "sha256_encrypted": _sha256_file(destination)}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for bloc in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloc)
    return h.hexdigest()


# --------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------

def _s3():
    import boto3
    from botocore.config import Config as BotoConfig
    return boto3.client(
        "s3",
        endpoint_url=config.ARCHIVE_S3_ENDPOINT,
        region_name=config.ARCHIVE_S3_REGION,
        aws_access_key_id=config.ARCHIVE_S3_KEY_ID,
        aws_secret_access_key=config.ARCHIVE_S3_APP_KEY,
        config=BotoConfig(signature_version="s3v4",
                          retries={"max_attempts": 5, "mode": "standard"}))


def object_key(index_base: str, period: str, suffix: str) -> str:
    """`[prefix/]<version>/<index-set>/<year>/<index-set>.<YYYY-MM>.<suffix>`

    Index set BEFORE the year, counter-intuitively. The question asked of an
    archive is almost always "what did the firewall say between March and June?",
    not "what happened in 2026, across all sources?": a single prefix to restore,
    and a window straddling New Year is not looked for in two places. It is also
    the only layout that allows expressing a lifecycle rule per index set.
    """
    parts = [p for p in (config.ARCHIVE_S3_PREFIX,
                         config.ARCHIVE_FORMAT_VERSION,
                         index_base, period[:4]) if p]
    return "/".join(parts) + f"/{index_base}.{period}.{suffix}"


def manifest(batch: dict, metrics: dict, key: str) -> dict:
    """Manifest, written IN PLAINTEXT next to the object.

    It contains no alert data — only enough to know what the object holds, how to
    read it back, and what to compare what comes out against. `sha256_plain` is
    what makes the difference between a backup and a proof.
    """
    return {
        "format_version": config.ARCHIVE_FORMAT_VERSION,
        "index_set": batch["index_base"],
        "period": batch["period"],
        "indices": batch["indices"],
        "documents": metrics["documents"],
        "plain_bytes": metrics["plain_bytes"],
        "object_bytes": metrics["object_bytes"],
        "sha256_plain": metrics["sha256_plain"],
        "sha256_encrypted": metrics["sha256_encrypted"],
        "key": key,
        "chain": processing_chain(),
        "age_recipients": recipients(),
        "excluded_fields": config.ARCHIVE_FIELDS_EXCLUDED,
        "line_schema": "{_index, _id, _source}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "soc_agent.archive",
        "read_back": ("age -d -i <age-key> <object> | zstd -d | "
                      "jq -c 'select(._source.rule.level >= 10)'"),
    }


def _args_lock() -> dict:
    if not config.ARCHIVE_OBJECT_LOCK:
        return {}
    until = datetime.now(timezone.utc) + timedelta(
        days=config.ARCHIVE_OBJECT_LOCK_DAYS)
    return {"ObjectLockMode": config.ARCHIVE_OBJECT_LOCK_MODE,
            "ObjectLockRetainUntilDate": until}


def upload(s3, path: Path, key: str, meta: dict) -> None:
    extra = {"Metadata": {k: str(v) for k, v in meta.items()},
             "ContentType": "application/octet-stream", **_args_lock()}
    try:
        s3.upload_file(str(path), config.ARCHIVE_S3_BUCKET, key,
                       ExtraArgs=extra)
    except Exception as e:                                        # noqa: BLE001
        if config.ARCHIVE_OBJECT_LOCK and "ObjectLock" in str(e):
            raise RuntimeError(
                "Object Lock refused by the bucket. The property does NOT "
                "apply retroactively to an existing bucket: a bucket created "
                "with Object Lock is required, or ARCHIVE_OBJECT_LOCK=false."
                ) from e
        raise


def _reread(s3, key: str, expected_bytes: int) -> None:
    """HEAD after upload. Nothing is declared archived without this read-back.

    An `upload_file` returning without an exception is not proof the object is
    there and complete — it is a client library's promise.
    """
    head = s3.head_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=key)
    if head["ContentLength"] != expected_bytes:
        raise RuntimeError(
            f"object {key} read back at {head['ContentLength']} bytes, "
            f"{expected_bytes} expected: incomplete upload.")


# --------------------------------------------------------------------------
# Archiving one batch
# --------------------------------------------------------------------------

def _record(conn, batch: dict, metrics: dict, key: str,
                 man_key: str) -> None:
    lock = _args_lock()
    conn.execute(
        """INSERT INTO archives_s3
               (format_version, index_base, period, key, manifest_key,
                indices, documents, plain_bytes, object_bytes, sha256_plain,
                sha256_encrypted, chain, recipients, excluded_fields,
                object_lock_until)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (format_version, index_base, period) DO NOTHING""",
        (config.ARCHIVE_FORMAT_VERSION, batch["index_base"], batch["period"],
         key, man_key, batch["indices"], metrics["documents"],
         metrics["plain_bytes"], metrics["object_bytes"],
         metrics["sha256_plain"], metrics["sha256_encrypted"],
         processing_chain(), recipients(),
         config.ARCHIVE_FIELDS_EXCLUDED, lock.get("ObjectLockRetainUntilDate")))
    conn.commit()


def _adopt(conn, s3, batch: dict, key: str, man_key: str) -> bool:
    """Object already present with no database row: adopt it instead of redoing.

    That case happens when the process dies between the upload and the INSERT.
    The key being deterministic, we find the object again; its manifest
    (plaintext, tiny) says how many documents it holds. If that count matches the
    live count of the indices, the object is the right one and we simply write the
    missing row.

    Why not simply rewrite: under Object Lock a second upload does not replace the
    object, it creates an additional VERSION, also locked — we would pay twice
    twelve months for the same data.

    The manifest keys are read through `_man_get`, which also accepts the French
    names used before this refactor: archives written by an earlier version must
    stay adoptable.
    """
    try:
        s3.head_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=key)
    except Exception:                                             # noqa: BLE001
        return False
    try:
        body = s3.get_object(Bucket=config.ARCHIVE_S3_BUCKET,
                              Key=man_key)["Body"].read()
        man = json.loads(body)
    except Exception as e:                                        # noqa: BLE001
        log.warning("orphan object %s with no readable manifest (%s): "
                    "re-archiving", key, e)
        return False
    if man.get("documents") != batch["documents"]:
        log.warning("orphan object %s: %s documents in the manifest, %s live — "
                    "re-archiving", key, man.get("documents"),
                    batch["documents"])
        return False
    _record(conn, batch, {
        "documents": man["documents"],
        "plain_bytes": _man_get(man, "plain_bytes", "octets_clair"),
        "object_bytes": _man_get(man, "object_bytes", "octets_objet"),
        "sha256_plain": _man_get(man, "sha256_plain", "sha256_clair"),
        "sha256_encrypted": _man_get(man, "sha256_encrypted",
                                     "sha256_chiffre")}, key, man_key)
    log.warning("archive %s/%s ADOPTED: the object existed with no marker in "
                "database (interrupted between the upload and the record).",
                batch["index_base"], batch["period"])
    return True


def archive(conn, s3, batch: dict) -> dict:
    key = object_key(batch["index_base"], batch["period"], SUFFIX_OBJECT)
    man_key = object_key(batch["index_base"], batch["period"], SUFFIX_MANIFEST)

    if _adopt(conn, s3, batch, key, man_key):
        return {"index_base": batch["index_base"], "period": batch["period"],
                "state": "adopted", "key": key}

    tmp = Path(tempfile.mkdtemp(prefix="aura-archive-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        object_path = tmp / f"{batch['index_base']}.{batch['period']}.{SUFFIX_OBJECT}"
        metrics = export(batch, object_path)
        man = manifest(batch, metrics, key)

        upload(s3, object_path, key, {
            "index-set": batch["index_base"], "period": batch["period"],
            "documents": metrics["documents"],
            "sha256-plain": metrics["sha256_plain"],
            "sha256-encrypted": metrics["sha256_encrypted"],
            "format-version": config.ARCHIVE_FORMAT_VERSION})
        _reread(s3, key, metrics["object_bytes"])

        man_path = tmp / f"{batch['index_base']}.{batch['period']}.{SUFFIX_MANIFEST}"
        man_path.write_text(json.dumps(man, indent=2, ensure_ascii=False),
                              encoding="utf-8")
        upload(s3, man_path, man_key, {"index-set": batch["index_base"]})

        # The marker is only written here: after the object AND its manifest
        # have been read back on the S3 side.
        _record(conn, batch, metrics, key, man_key)
        ratio = (metrics["plain_bytes"] / metrics["object_bytes"]
                 if metrics["object_bytes"] else 0)
        log.info("archived %s/%s: %d documents, %.1f MB -> %.1f MB (x%.1f), %s",
                 batch["index_base"], batch["period"], metrics["documents"],
                 metrics["plain_bytes"] / 1048576,
                 metrics["object_bytes"] / 1048576, ratio, key)
        return {"index_base": batch["index_base"], "period": batch["period"],
                "state": "archived", "key": key, **metrics}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Cleaning up after a killed pass
# --------------------------------------------------------------------------
#
# All the module's cleanup lives in `finally` blocks, and a `finally` does NOT
# run on SIGKILL (OOM killer, `docker kill`, power cut). Every violent death
# therefore leaves two traces, neither of them visible:
#
#  - a working directory in ARCHIVE_TMP_DIR. On this SOC, silent accumulation on
#    disk is precisely what filled 92 GB without anyone seeing it (see
#    docs/RETENTION.md);
#  - an unfinished multipart upload on the S3 side: its parts are BILLED and
#    appear in no `list_objects`.
#
# Both are swept at the start of every pass, with an age threshold: the advisory
# lock forbids two simultaneous archiving passes, but not a `--drill` launched by
# hand while a pass runs.

PREFIXES_TMP = ("aura-archive-", "aura-drill-", "aura-clecheck-")


def sweep_temporary(age_hours: int = 2) -> dict:
    """Deletes the working directories abandoned by a killed pass."""
    base = Path(config.ARCHIVE_TMP_DIR)
    limit = time.time() - age_hours * 3600
    n = byte_count = 0
    for path in base.glob("*"):
        if not path.is_dir() or not path.name.startswith(PREFIXES_TMP):
            continue
        try:
            if path.stat().st_mtime >= limit:
                continue          # may belong to a drill under way
            byte_count += sum(f.stat().st_size for f in path.rglob("*")
                          if f.is_file())
            shutil.rmtree(path, ignore_errors=True)
            n += 1
        except OSError as e:
            log.debug("residue %s not deleted: %s", path, e)
    if n:
        log.warning("%d abandoned archiving working director(ies) deleted "
                    "(%.1f MB) — a sign a pass was killed without being able to "
                    "clean up", n, byte_count / 1048576)
    return {"directories": n, "bytes": byte_count}


def abort_multiparts(s3, age_hours: int = 24) -> dict:
    """Aborts the bucket's unfinished multipart uploads.

    Best-effort: if the application key is not allowed to list or abort them, we
    say so and carry on. Not archiving at all would be a far worse answer to a
    billing defect.
    """
    limit = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    aborted, ignored = [], 0
    try:
        response = s3.list_multipart_uploads(Bucket=config.ARCHIVE_S3_BUCKET)
    except Exception as e:                                        # noqa: BLE001
        log.info("unfinished multiparts not listable (%s): control skipped. "
                 "Setting a lifecycle rule on the B2 side is the right answer "
                 "anyway.", e)
        return {"state": f"undetermined: {e}"[:200]}
    for u in response.get("Uploads") or []:
        if u.get("Initiated") and u["Initiated"] > limit:
            ignored += 1          # may be under way
            continue
        try:
            s3.abort_multipart_upload(Bucket=config.ARCHIVE_S3_BUCKET,
                                      Key=u["Key"], UploadId=u["UploadId"])
            aborted.append(u["Key"])
        except Exception as e:                                    # noqa: BLE001
            log.warning("multipart %s not aborted: %s", u["Key"], e)
    if aborted:
        log.warning("%d unfinished multipart upload(s) aborted: %s — their "
                    "parts were billed and invisible to a list_objects",
                    len(aborted), ", ".join(aborted[:5]))
    return {"aborted": aborted, "in_progress_ignored": ignored}


# --------------------------------------------------------------------------
# Protection against the purge
# --------------------------------------------------------------------------

def indices_at_risk(conn, today: date | None = None) -> list[dict]:
    """Indices the ISM purge will delete while no archive exists.

    That is the question that matters: not "did archiving succeed?" but "is there
    still data about to disappear without a copy?". Archiving broken for three
    days is not serious; the same broken for eighty days destroys data at the
    next rotation.
    """
    if not config.ARCHIVING_ENABLED:
        return []
    ref = today or datetime.now(timezone.utc).date()
    threshold = config.RETENTION_INDEX_DAYS - config.ARCHIVE_MARGIN_DAYS
    already = {(r["index_base"], r["period"]) for r in conn.execute(
        "SELECT index_base, period FROM archives_s3 WHERE format_version=%s",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()}
    risk = []
    for i in dated_indices():
        age = (ref - i["day"]).days
        if age < threshold or (i["base"], i["month"]) in already:
            continue
        risk.append({**i, "age_days": age,
                      "deleted_in": config.RETENTION_INDEX_DAYS - age})
    return sorted(risk, key=lambda i: i["deleted_in"])


def protect(indices: list[str]) -> int:
    """Removes these indices from the ISM policy to prevent their deletion.

    Suspending the SETTING of the policy would protect nothing: it is already
    attached to the existing indices and would keep deleting them on schedule.
    The only effective gesture is `_ism/remove`, which detaches the policy from
    the named indices.

    That detachment is TEMPORARY and repairs itself: on the next pass,
    `retention.apply_ism()` reattaches the policy by pattern, so an index archived
    in the meantime becomes purgeable again with no manual step. That is also why
    the protection must be set AFTER `apply_ism`, never before — otherwise the
    `_ism/add` by pattern undoes it a second later.
    """
    if not indices:
        return 0
    r = _indexer("POST", "/_plugins/_ism/remove/" + ",".join(indices))
    if not r.ok:
        raise RuntimeError(f"_ism/remove refused ({r.status_code}): {r.text}")
    n = r.json().get("updated_indices", 0)
    log.error("PURGE SUSPENDED on %d indices (%d detached from the "
              "\"aura-retention\" policy): their S3 archive does not exist and "
              "they were entering the deletion margin. They will NOT be deleted "
              "as long as the copy does not exist — so the disk will grow until "
              "archiving starts again.", len(indices), n)
    return n


# --------------------------------------------------------------------------
# Restore drill
# --------------------------------------------------------------------------

def _drill_one(s3, line: dict, full: bool = True) -> dict:
    """Downloads an archive again, decrypts it and compares what it holds.

    Three checks that do not say the same thing, in this order:

    1. the object is **present** — otherwise someone or something deleted it;
    2. its SHA-256 matches — the storage neither altered nor truncated it;
    3. it **decrypts** and returns the manifest's document count. That is the
       only one of the three proving an archive is good for anything, and it is
       only possible because the SOC holds its key.

    `full=False` stops after (2): useful when the key is momentarily unavailable,
    so as not to declare failed what we simply could not read.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aura-drill-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        local = tmp / "objet"
        try:
            s3.download_file(config.ARCHIVE_S3_BUCKET, line["key"], str(local))
        except Exception as e:                                    # noqa: BLE001
            return {"state": "missing", "detail": str(e)}
        if _sha256_file(local) != line["sha256_encrypted"]:
            return {"state": "sha256-mismatch",
                    "detail": "the stored object differs from what was written"}
        if not full:
            return {"state": "ok", "full": False}

        decrypted = subprocess.run(
            f"age -d -i {config.ARCHIVE_AGE_KEYFILE!r} {str(local)!r} "
            "| zstd -d -c", shell=True, capture_output=True)
        if decrypted.returncode:
            return {"state": "error: decryption",
                    "detail": decrypted.stderr.decode(errors="replace")[:500]}
        plain = decrypted.stdout
        if hashlib.sha256(plain).hexdigest() != line["sha256_plain"]:
            return {"state": "sha256-mismatch",
                    "detail": "the decrypted plaintext differs from the archived"}
        lines = plain.count(b"\n")
        if lines != line["documents"]:
            return {"state": "documents-mismatch",
                    "detail": f"{lines} lines, {line['documents']} expected"}
        return {"state": "ok", "full": True}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def drill(conn, s3, batch: int | None = None,
          full: bool | None = None) -> list[dict]:
    """Checks the archives verified least recently.

    Selection by `verified_at NULLS FIRST`: deterministic, and every archive gets
    its turn eventually. A random draw would leave lasting gaps.
    """
    n = config.ARCHIVE_DRILL_BATCH if batch is None else batch
    drill_full = config.ARCHIVE_DRILL_FULL if full is None else full
    lines = conn.execute(
        "SELECT * FROM archives_s3 WHERE format_version=%s "
        " ORDER BY verified_at NULLS FIRST, archived_at LIMIT %s",
        (config.ARCHIVE_FORMAT_VERSION, n)).fetchall()
    summary = []
    for line in lines:
        try:
            r = _drill_one(s3, line, drill_full)
        except Exception as e:                                    # noqa: BLE001
            r = {"state": f"error: {e}"[:200]}
        conn.execute(
            "UPDATE archives_s3 SET verified_at=now(), verify_state=%s, "
            " verify_full=%s WHERE id=%s",
            (r["state"], bool(r.get("full")), line["id"]))
        conn.commit()
        if r["state"] == "ok":
            log.info("drill %s/%s: OK%s", line["index_base"],
                     line["period"], " (full)" if r.get("full") else "")
        else:
            log.error("DRILL FAILED %s/%s: %s — %s. This month's archive is not "
                      "reliable; the original data is probably already purged "
                      "from the indexer.", line["index_base"],
                      line["period"], r["state"], r.get("detail", ""))
        summary.append({"index_base": line["index_base"],
                      "period": line["period"], **r})
    return summary


# --------------------------------------------------------------------------
# Anomalies reported to the watchdog
# --------------------------------------------------------------------------

def _months_between(start: str, end: str) -> list[str]:
    a, m = (int(x) for x in start.split("-"))
    af, mf = (int(x) for x in end.split("-"))
    output = []
    while (a, m) <= (af, mf):
        output.append(f"{a:04d}-{m:02d}")
        a, m = (a + 1, 1) if m == 12 else (a, m + 1)
    return output


def anomalies(conn) -> list[dict]:
    """State of archiving, read-only, in the silent-sensor shape.

    Four signals, each matching a way an archiving that "runs" can archive
    nothing:

    - data entering the deletion margin with no copy (High);
    - a month missing in the middle of a series (Medium): the indices are already
      purged, the data is lost and nothing said so;
    - an archive not read back for too long (Medium);
    - a drill failed (High).
    """
    if not config.ARCHIVING_ENABLED:
        return []
    output = []

    try:
        risk = indices_at_risk(conn)
    except Exception as e:                                        # noqa: BLE001
        log.warning("archiving risk incomputable: %s", e)
        risk = []
    if risk:
        detail = "\n".join(
            f"  {i['index']:<40} {i['documents']:>9} docs  "
            f"supprimé dans {i['deleted_in']} j"
            for i in risk[:15])
        output.append(_anomaly(
            "risk",
            f"[ARCHIVAGE] {len(risk)} index vont être purgés sans copie",
            "\n".join([
                "DONNÉE SUR LE POINT D'ÊTRE PERDUE",
                "",
                f"{len(risk)} index datés entrent dans les "
                f"{config.ARCHIVE_MARGIN_DAYS} jours qui précèdent leur "
                f"suppression par la politique ISM "
                f"(RETENTION_INDEX_JOURS={config.RETENTION_INDEX_DAYS}) et "
                "aucune archive S3 ne les couvre.",
                "", detail,
                "" if len(risk) <= 15 else f"  … et {len(risk) - 15} autres.",
                "",
                "Ce qui a été fait automatiquement : ces index ont été DÉTACHÉS "
                "de la politique « aura-retention ». Ils ne seront pas "
                "supprimés — mais ils ne seront pas non plus purgés, donc le "
                "disque va grossir jusqu'à ce que l'archivage reparte.",
                "",
                "Où regarder :",
                "",
                "1. `docker logs soc-agent-archive --tail 100` — l'échec y est.",
                "2. `python -m soc_agent.archive --verifier` — bucket, clé, "
                "droits, Object Lock.",
                "3. Cause la plus fréquente : clé applicative B2 expirée ou "
                "révoquée, ou bucket plein côté quota.",
                "",
                "Une fois l'archivage reparti, le rattachement à la politique "
                "ISM se refait tout seul au passage suivant de la rétention.",
            ]),
            "High", len(risk)))

    lines = conn.execute(
        "SELECT index_base, period, verified_at, verify_state FROM archives_s3 "
        " WHERE format_version=%s ORDER BY index_base, period",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()

    # Trous dans une série : un mois absent ENTRE deux mois présents. Borné aux
    # séries déjà commencées — un index set créé le mois dernier n'a pas de
    # trou, il a juste un passé qui n'existe pas.
    by_base: dict[str, list[str]] = {}
    for l in lines:
        by_base.setdefault(l["index_base"], []).append(l["period"])
    gaps = {b: [m for m in _months_between(min(p), max(p)) if m not in set(p)]
             for b, p in by_base.items()}
    gaps = {b: m for b, m in gaps.items() if m}
    if gaps:
        output.append(_anomaly(
            "gap",
            f"[ARCHIVAGE] {sum(len(m) for m in gaps.values())} mois manquant(s) "
            "dans les séries d'archives",
            "\n".join([
                "TROU DANS LA COUVERTURE D'ARCHIVAGE",
                "",
                "Un mois manque entre deux mois archivés. Les index d'origine "
                "sont donc purgés depuis longtemps : cette donnée n'existe plus "
                "nulle part, et rien ne l'avait signalé au moment où elle "
                "partait.",
                "",
                *(f"  {b} : {', '.join(m)}" for b, m in sorted(gaps.items())),
                "",
                "Il n'y a rien à réparer ici — c'est un constat, à consigner. "
                "L'action utile est de comprendre POURQUOI l'archivage était "
                "muet sur cette période et de vérifier que le garde-fou de "
                "péril fonctionne aujourd'hui.",
            ]),
            "Medium", sum(len(m) for m in gaps.values())))

    failures = [l for l in lines if l["verify_state"] and l["verify_state"] != "ok"]
    if failures:
        output.append(_anomaly(
            "drill",
            f"[ARCHIVAGE] {len(failures)} archive(s) en échec de vérification",
            "\n".join([
                "ARCHIVE NON FIABLE",
                "",
                "Le drill de restauration a relu ces archives et n'a pas "
                "retrouvé ce qui avait été écrit :",
                "",
                *(f"  {l['index_base']}/{l['period']} : {l['verify_state']}"
                  for l in failures[:20]),
                "",
                "Une archive qui ne se relit pas n'est pas une archive. La "
                "donnée d'origine est très probablement déjà purgée de "
                "l'indexer : il n'y a pas de seconde chance de la réécrire.",
                "",
                "`absent` : l'objet a disparu du bucket — vérifier que la clé "
                "applicative ne porte pas `deleteFiles` et regarder les "
                "versions masquées du bucket.",
                "`sha256-divergent` : l'objet stocké diffère de ce qui a été "
                "écrit. Corruption ou réécriture par un tiers.",
            ]),
            "High", len(failures)))

    limit = datetime.now(timezone.utc) - timedelta(
        days=config.ARCHIVE_DRILL_DAYS)
    old = [l for l in lines
                if l["verified_at"] is None or l["verified_at"] < limit]
    # Une archive du mois en cours n'a pas encore eu son tour : on ne compte
    # comme « en retard » que ce qui a dépassé la fenêtre de drill.
    if len(old) > config.ARCHIVE_DRILL_BATCH:
        output.append(_anomaly(
            "drill-late",
            f"[ARCHIVAGE] {len(old)} archive(s) non vérifiées depuis plus "
            f"de {config.ARCHIVE_DRILL_DAYS} jours",
            "\n".join([
                "VÉRIFICATION D'ARCHIVES EN RETARD",
                "",
                f"{len(old)} archives n'ont pas été relues depuis "
                f"{config.ARCHIVE_DRILL_DAYS} jours (ou jamais). Une archive "
                "non testée est une croyance, pas une copie.",
                "",
                f"Le service `soc-agent-archive` en vérifie "
                f"{config.ARCHIVE_DRILL_BATCH} par passage. Ce retard signifie "
                "soit que le service ne tourne pas, soit que le lot est trop "
                "petit pour le nombre d'archives (augmenter "
                "ARCHIVE_DRILL_LOT).",
            ]),
            "Medium", len(old)))
    return output


def _anomaly(suffix: str, title: str, note: str, severity: str,
              volume: int) -> dict:
    """Shape of a silent sensor, to go through the watchdog loop with no special
    case — same convention as `routing._anomaly`."""
    now = datetime.now(timezone.utc)
    return {"agent_id": "000", "agent_name": "wazuh.manager",
            "sensor": f"{PREFIX_SENSOR}{suffix}", "title": title,
            "note": note, "severity": severity, "volume": volume, "threshold": 0,
            "last": now, "horizon": now}


def _man_get(man: dict, key: str, legacy: str):
    """Manifest value, accepting the French key names written before the
    English refactor. An archive produced by an earlier version must stay
    adoptable and readable."""
    return man[key] if key in man else man[legacy]


# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------

def check_key() -> dict:
    """A REAL encryption round trip on a witness, before relying on the key.

    Encrypting then decrypting three bytes costs a few milliseconds and answers
    the only question that matters before archiving a whole month: does this key
    allow READING BACK? A public key pasted by mistake into the file, an identity
    truncated on copy, a missing `age` — all of that passes the `config` checks
    and shows up here.
    """
    _check_tools()
    summary = {"keyfile": config.ARCHIVE_AGE_KEYFILE,
             "recipients": recipients()}
    tmp = Path(tempfile.mkdtemp(prefix="aura-clecheck-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        witness, encrypted = b"aura\n", tmp / "t.age"
        recipient_args: list[str] = []
        for r in summary["recipients"]:
            recipient_args += ["-r", r]
        c = subprocess.run(["age", *recipient_args, "-o", str(encrypted)],
                           input=witness, capture_output=True)
        if c.returncode:
            raise RuntimeError("witness encryption failed: "
                               + c.stderr.decode(errors="replace")[:300])
        d = subprocess.run(
            ["age", "-d", "-i", config.ARCHIVE_AGE_KEYFILE, str(encrypted)],
            capture_output=True)
        if d.returncode or d.stdout != witness:
            raise RuntimeError(
                "the key does NOT decrypt back what it encrypted: "
                + d.stderr.decode(errors="replace")[:300]
                + " — archiving in this state would produce unreadable objects.")
        summary["round_trip"] = "ok"
        summary["backup_keys"] = (config.ARCHIVE_AGE_RECIPIENTS_EXTRA
                                  or "NONE — losing the keyfile would lose all")
        return summary
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_bucket() -> dict:
    """Preflight to run BEFORE relying on archiving.

    It also checks what should be ABSENT: the delete permission. A production key
    that can delete is a ransomware that can erase the twelve months after
    encrypting the rest.
    """
    s3 = _s3()
    summary: dict = {"bucket": config.ARCHIVE_S3_BUCKET,
                   "endpoint": config.ARCHIVE_S3_ENDPOINT}
    s3.head_bucket(Bucket=config.ARCHIVE_S3_BUCKET)
    summary["reachable"] = True

    for name, call in (
            ("versioning", lambda: s3.get_bucket_versioning(
                Bucket=config.ARCHIVE_S3_BUCKET).get("Status", "Disabled")),
            ("object_lock", lambda: s3.get_object_lock_configuration(
                Bucket=config.ARCHIVE_S3_BUCKET)
                .get("ObjectLockConfiguration", {})
                .get("ObjectLockEnabled", "Disabled")),
            ("lifecycle", lambda: [
                r.get("ID") or r.get("Prefix", "")
                for r in s3.get_bucket_lifecycle_configuration(
                    Bucket=config.ARCHIVE_S3_BUCKET).get("Rules", [])])):
        try:
            summary[name] = call()
        except Exception as e:                                    # noqa: BLE001
            summary[name] = f"undetermined ({type(e).__name__})"

    witness = "/".join(p for p in (config.ARCHIVE_S3_PREFIX,
                                 config.ARCHIVE_FORMAT_VERSION,
                                 "_preflight.txt") if p)
    s3.put_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=witness,
                  Body=b"aura preflight\n")
    summary["write"] = "ok"
    try:
        s3.delete_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=witness)
        summary["delete"] = ("POSSIBLE — the key carries deleteFiles, which is "
                             "not desirable for a production key")
    except Exception:                                             # noqa: BLE001
        summary["delete"] = "refused (expected)"

    if config.ARCHIVE_OBJECT_LOCK and summary.get("object_lock") != "Enabled":
        summary["warning"] = ("ARCHIVE_OBJECT_LOCK=true but the bucket has no "
                              "Object Lock. The property does not apply "
                              "retroactively to an existing bucket: recreate the "
                              "bucket with Object Lock, or set the option back "
                              "to false.")
    if config.ARCHIVE_OBJECT_LOCK_DAYS < config.ARCHIVE_RETENTION_MONTH * 30:
        summary.setdefault("warning", "")
        summary["warning"] += (" Object Lock shorter than the intended "
                               "retention: an object will become deletable again "
                               f"before the end of the "
                               f"{config.ARCHIVE_RETENTION_MONTH} months.")
    return summary


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------

def restore(s3, index_base: str, period: str, destination: Path,
              identity: str | None = None) -> dict:
    """Downloads and decrypts an archive to disk, with the SOC key.

    Deliberately separated from any re-injection into the indexer: deciding where
    to put back ten-month-old data is an analyst's gesture, not an automaton's.
    Re-ingesting into `wazuh-firewall-*` would bring those alerts into the triage
    pipeline and manufacture incidents on year-old facts. The NDJSON obtained is
    injected with `_bulk` (see docs/ARCHIVAGE.md).

    `identity` allows passing a BACKUP key, for the case that justifies its
    existence: the SOC key is lost or the host was rebuilt.
    """
    age_key = identity or config.ARCHIVE_AGE_KEYFILE
    key = object_key(index_base, period, SUFFIX_OBJECT)
    encrypted = destination.with_suffix(destination.suffix + ".age")
    s3.download_file(config.ARCHIVE_S3_BUCKET, key, str(encrypted))
    r = subprocess.run(
        f"age -d -i {age_key!r} {str(encrypted)!r} | zstd -d -o "
        f"{str(destination)!r} -f",
        shell=True, capture_output=True)
    encrypted.unlink(missing_ok=True)
    if r.returncode:
        raise RuntimeError("restore failed: "
                           + r.stderr.decode(errors="replace")[:800])
    # Comparing with the manifest belongs to the caller, but counting the lines
    # here avoids the most common misreading: believing a file obtained without
    # an error is a complete file.
    return {"key": key, "file": str(destination),
            "lines": sum(1 for _ in destination.open("rb")),
            "bytes": destination.stat().st_size}


# --------------------------------------------------------------------------

def run(dry_run: bool = False) -> dict:
    """One pass: archive what is closed, then verify a few archives.

    The drill runs even when archiving had nothing to do — that is the normal
    case most days, and it is precisely then that we want to know whether the
    archives of past months still hold.
    """
    if not config.ARCHIVING_ENABLED:
        return {"state": "disabled"}
    summary: dict = {"dry_run": dry_run, "archived": [], "failures": []}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_LOCK_ARCHIVE,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("archiving: pass already running, skipping this round")
            return {"state": "locked"}
        try:
            # Cleanup BEFORE anything: what a killed pass left behind must not
            # pile up from one day to the next. Not in `--plan`, which must be
            # runnable without modifying anything anywhere.
            if not dry_run:
                summary["local_cleanup"] = sweep_temporary()
            batches = batches_to_archive(conn)
            summary["todo"] = [f"{l['index_base']}/{l['period']}" for l in batches]
            if dry_run:
                summary["batches"] = batches
                summary["at_risk"] = [i["index"] for i in indices_at_risk(conn)]
                return summary

            s3 = _s3()
            summary["s3_cleanup"] = abort_multiparts(s3)
            for batch in batches:
                try:
                    summary["archived"].append(archive(conn, s3, batch))
                except Exception as e:                            # noqa: BLE001
                    # A failing batch must not take the others down: the next
                    # month may belong to another index set, and refusing to
                    # archive it repairs nothing.
                    log.error("archiving %s/%s failed: %s",
                              batch["index_base"], batch["period"], e)
                    summary["failures"].append(
                        {"index_base": batch["index_base"],
                         "period": batch["period"], "error": str(e)[:300]})

            summary["drill"] = drill(conn, s3)
            risk = indices_at_risk(conn)
            summary["at_risk"] = [i["index"] for i in risk]
            if risk:
                try:
                    summary["protected"] = protect([i["index"] for i in risk])
                except Exception as e:                            # noqa: BLE001
                    log.error("PROTECTION IMPOSSIBLE (%s): %d indices remain "
                              "candidates for deletion WITHOUT a copy.", e,
                              len(risk))
        finally:
            _unlock(conn)
    return summary


def _unlock(conn) -> None:
    """Releases the advisory lock WITHOUT hiding the error that brought us here.

    Seen in production on the first pass: the `archives_s3` table did not exist
    yet, `batches_to_archive` raised `UndefinedTable`, and the `finally` tried to
    run the `UNLOCK` inside an already aborted transaction. Postgres answered
    `InFailedSqlTransaction`, that second exception REPLACED the first, and the
    traceback no longer said at all what was wrong — the useful diagnosis ("a
    table is missing") had become invisible.

    Hence the rollback first, and all of it best-effort: a session advisory lock
    is released when the connection closes anyway, so failing here has no
    consequence, whereas hiding the cause does.
    """
    for step in (conn.rollback,
                  lambda: conn.execute("SELECT pg_advisory_unlock(%s)",
                                       (_LOCK_ARCHIVE,))):
        try:
            step()
        except Exception as e:                                    # noqa: BLE001
            log.debug("releasing the archiving lock: %s", e)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", action="store_true",
                   help="what would be archived, writing nothing")
    p.add_argument("--check", action="store_true",
                   help="preflight: key round trip, then bucket (reachable, "
                        "permissions, Object Lock)")
    p.add_argument("--drill", action="store_true",
                   help="read back, decrypt and recount archives, then exit")
    p.add_argument("--without-decrypting", action="store_true",
                   help="drill limited to the SHA-256 of the object")
    p.add_argument("--identity", help="BACKUP age key, if the SOC one is lost "
                                      "(drill and restore)")
    p.add_argument("--batch", type=int, help="number of archives to verify")
    p.add_argument("--restore", metavar="INDEX_SET/YYYY-MM",
                   help="download and decrypt an archive")
    p.add_argument("--to", default="archive.ndjson",
                   help="output file of --restore")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if not config.ARCHIVING_ENABLED:
        print("ARCHIVING_ENABLED=false: nothing to do. See docs/ARCHIVAGE.md.")
        return

    if args.check:
        # The key first: a perfect bucket is useless if what we write into it
        # is unreadable.
        print(json.dumps({"key": check_key(), "s3": check_bucket()},
                         indent=2, ensure_ascii=False, default=str))
        return

    if args.restore:
        base, _, period = args.restore.rpartition("/")
        print(json.dumps(restore(_s3(), base, period, Path(args.to),
                                   args.identity),
                         indent=2, ensure_ascii=False))
        return

    if args.drill:
        if args.identity:
            previous = config.ARCHIVE_AGE_KEYFILE
            config.ARCHIVE_AGE_KEYFILE = args.identity
            log.warning("drill with the backup key %s (instead of %s)",
                        args.identity, previous)
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            r = drill(conn, _s3(), args.batch, not args.without_decrypting)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    print(json.dumps(run(args.plan), indent=2, ensure_ascii=False,
                     default=str))


if __name__ == "__main__":
    main()
