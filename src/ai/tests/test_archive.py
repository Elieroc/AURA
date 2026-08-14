"""Guardrails of cold archiving (soc_agent.archive).

What is tested here is what fails SILENTLY in production: an archive that
believes it is complete, a month frozen too early, a state index swallowed by
too broad a pattern, a compression chain that yields a truncated file. The rest
(S3, indexer) belongs to the `--verify` preflight, not to a unit suite.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import date, datetime, timezone

import pytest

os.environ.setdefault("ARCHIVING_ENABLED", "false")

from soc_agent import archive, config  # noqa: E402


# --------------------------------------------------------------------------
# Scope: what is archivable, and above all what is not
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name, base, month", [
    ("wazuh-firewall-2026.08.14", "wazuh-firewall", "2026-08"),
    ("wazuh-alerts-4.x-2026.01.01", "wazuh-alerts-4.x", "2026-01"),
    ("wazuh-voc-2026.12.31", "wazuh-voc", "2026-12"),
])
def test_index_date_recognised(name, base, month):
    m = archive._DATE_INDEX.match(name)
    assert m and m.group("base") == base
    assert f"{m.group('a')}-{m.group('m')}" == month


@pytest.mark.parametrize("name", [
    # STATE index, undated: it carries the vulnerability lifecycle, hence the
    # MTTR. Archiving by date would erase the very notion of debt history.
    # Excluded by the SHAPE of the name, with no list to maintain.
    "wazuh-voc-vulns",
    # Dated at the WEEK by Wazuh, and this is not alerting.
    "wazuh-monitoring-2026.33w",
    "wazuh-statistics-2026.33w",
    # Neither date nor day.
    "wazuh-firewall",
    "wazuh-firewall-2026.08",
    ".opendistro-ism-config",
])
def test_index_not_archivable(name):
    assert archive._DATE_INDEX.match(name) is None


# --------------------------------------------------------------------------
# Month closure: the grace delay is not decorative
# --------------------------------------------------------------------------

def test_current_month_never_archived(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    assert not archive._closed_months("2026-08", date(2026, 8, 31))


def test_closed_month_waits_for_the_grace_delay(monkeypatch):
    """The catch-up of late-indexed alerts still writes into yesterday's
    indices: archiving on the 1st in the morning freezes an incomplete copy,
    and an incomplete archive does not repair itself — it believes it is
    complete."""
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    assert not archive._closed_months("2026-08", date(2026, 9, 1))
    assert not archive._closed_months("2026-08", date(2026, 9, 2))
    assert archive._closed_months("2026-08", date(2026, 9, 3))


def test_december_rollover():
    assert archive._first_of_next_month("2026-12") == date(2027, 1, 1)


def test_months_between_crosses_the_year():
    assert archive._months_between("2026-11", "2027-02") == [
        "2026-11", "2026-12", "2027-01", "2027-02"]


# --------------------------------------------------------------------------
# S3 key layout
# --------------------------------------------------------------------------

def test_key_index_set_before_year(monkeypatch):
    """Index set first: restoring a source over a window straddling New Year
    must fit in a single prefix, and a lifecycle rule must be able to target
    an index set."""
    monkeypatch.setattr(config, "ARCHIVE_S3_PREFIX", "")
    monkeypatch.setattr(config, "ARCHIVE_FORMAT_VERSION", "v1")
    assert archive.object_key("wazuh-firewall", "2026-03", "ndjson.zst.age") == (
        "v1/wazuh-firewall/2026/wazuh-firewall.2026-03.ndjson.zst.age")


def test_key_prefixed_and_versioned(monkeypatch):
    """`v2` must be able to coexist with `v1` for the same month: changing
    format must neither overwrite the old object nor require deleting it."""
    monkeypatch.setattr(config, "ARCHIVE_S3_PREFIX", "soc")
    monkeypatch.setattr(config, "ARCHIVE_FORMAT_VERSION", "v2")
    assert archive.object_key("wazuh-web", "2027-01", "manifest.json") == (
        "soc/v2/wazuh-web/2027/wazuh-web.2027-01.manifest.json")


# --------------------------------------------------------------------------
# Compression + encryption chain, for real
# --------------------------------------------------------------------------

_TOOLS = shutil.which("zstd") and shutil.which("age") and shutil.which("age-keygen")


def _keyfile(tmp_path, monkeypatch):
    """Generates the SOC's key and declares it, as in production."""
    key = tmp_path / "aura-archive-age.key"
    subprocess.run(["age-keygen", "-o", str(key)], check=True,
                   capture_output=True)
    monkeypatch.setattr(config, "ARCHIVE_AGE_KEYFILE", str(key))
    monkeypatch.setattr(config, "ARCHIVE_AGE_RECIPIENTS_EXTRA", [])
    return key


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_public_key_derived_from_the_keyfile(tmp_path, monkeypatch):
    """The public key is DERIVED from the keyfile, never copied into the .env.
    That removes a whole class of failures: a mis-copied recipient would
    produce archives the SOC cannot read back, and nobody would notice before
    the first drill."""
    key = _keyfile(tmp_path, monkeypatch)
    expected = next(l.split(": ")[1].strip() for l in key.read_text().splitlines()
                   if l.startswith("# public key:"))
    assert archive.public_key() == expected
    assert archive.recipients() == [expected]
    # Without the comment, we fall back to `age-keygen -y` rather than failing.
    key.write_text(next(l for l in key.read_text().splitlines()
                        if l.startswith("AGE-SECRET-KEY-1")) + "\n")
    assert archive.public_key() == expected


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_backup_key_added_to_the_recipients(tmp_path, monkeypatch):
    """A backup key must be ADDED, never replace: the SOC must stay able to
    read back its own archives."""
    _keyfile(tmp_path, monkeypatch)
    backup = tmp_path / "backup.key"
    subprocess.run(["age-keygen", "-o", str(backup)], check=True,
                   capture_output=True)
    backup_pub = next(l.split(": ")[1].strip()
                       for l in backup.read_text().splitlines()
                       if l.startswith("# public key:"))
    monkeypatch.setattr(config, "ARCHIVE_AGE_RECIPIENTS_EXTRA", [backup_pub])
    d = archive.recipients()
    assert len(d) == 2 and d[0] == archive.public_key() and d[1] == backup_pub


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_key_check_does_a_real_round_trip(tmp_path, monkeypatch):
    """The preflight must REFUSE a key that does not decrypt back what it
    encrypts — otherwise it is only learned at the first restoration."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    assert archive.check_key()["round_trip"] == "ok"
    # Key of an OTHER holder as the exclusive recipient: the SOC can no longer read.
    other = tmp_path / "other.key"
    subprocess.run(["age-keygen", "-o", str(other)], check=True,
                   capture_output=True)
    monkeypatch.setattr(archive, "recipients", lambda: [
        next(l.split(": ")[1].strip() for l in other.read_text().splitlines()
             if l.startswith("# public key:"))])
    with pytest.raises(RuntimeError, match="does NOT decrypt back"):
        archive.check_key()


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_export_encrypted_then_read_back(tmp_path, monkeypatch):
    """The test that proves the central property: what comes out of the chain
    decrypts back identically WITH THE SOC'S KEY, and the announced SHA-256 is
    that of the plaintext.

    Without this, it would only be known at the first real restoration — too late.
    """
    key = _keyfile(tmp_path, monkeypatch)

    docs = [{"_index": "wazuh-firewall-2026.08.14", "_id": f"i{n}",
             "_source": {"rule": {"level": 12}, "agent": {"id": "001"},
                         "full_log": "access denied " * 20}}
            for n in range(500)]
    expected = b"".join(
        (json.dumps(d, ensure_ascii=False, separators=(",", ":"),
                    sort_keys=True) + "\n").encode() for d in docs)

    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    # `control` accepted and FILLED IN: that is what the real `pages` does, and
    # export now checks the announced count against the count written.
    monkeypatch.setattr(archive, "pages",
                        lambda idx, size=None, control=None: (
                            control.update(expected=len(docs))
                            if control is not None else None,
                            iter([docs]))[1])

    object_path = tmp_path / "archive.ndjson.zst.age"
    m = archive.export({"indices": ["wazuh-firewall-2026.08.14"],
                          "bytes": 1024}, object_path)

    assert m["documents"] == 500
    assert m["sha256_plain"] == hashlib.sha256(expected).hexdigest()
    assert m["object_bytes"] == object_path.stat().st_size
    assert m["sha256_encrypted"] == archive._sha256_file(object_path)
    # The archive must be markedly smaller than the plaintext: if compression
    # were not biting, the chain would not be doing what we think it does.
    assert m["object_bytes"] < m["plain_bytes"] / 5

    reread = subprocess.run(f"age -d -i {str(key)!r} {str(object_path)!r} | zstd -d -c",
                          shell=True, capture_output=True, check=True)
    assert reread.stdout == expected


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_invalid_recipient_leaves_no_file_behind(tmp_path, monkeypatch):
    """A failed chain must NEVER leave its file behind: a truncated file
    uploaded to S3 passes for a valid archive until the day it is needed."""
    monkeypatch.setattr(archive, "recipients", lambda: ["age1notakey"])
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    monkeypatch.setattr(archive, "pages",
                        lambda idx, size=None, control=None: iter(
                            [[{"_index": "i", "_id": "1", "_source": {}}]]))
    object_path = tmp_path / "archive.ndjson.zst.age"
    with pytest.raises(RuntimeError):
        archive.export({"indices": ["i"], "bytes": 1}, object_path)
    assert not object_path.exists()


def test_export_refused_without_room(tmp_path, monkeypatch):
    """A full disk stops ingestion without any alert saying so. This
    housekeeping job must not be the cause of it."""
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    free = shutil.disk_usage(tmp_path).free
    with pytest.raises(RuntimeError, match="not enough room"):
        archive._free_space(free * 4)


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------

def test_manifest_carries_enough_to_read_back_without_the_code(monkeypatch):
    """The manifest must be enough for a human in three years: the exact
    chain, the recipients, and the plaintext fingerprint that makes the
    difference between a backup and a proof."""
    monkeypatch.setattr(archive, "recipients", lambda: ["age1abc"])
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 19)
    man = archive.manifest(
        {"index_base": "wazuh-web", "period": "2026-05",
         "indices": ["wazuh-web-2026.05.01"]},
        {"documents": 3, "plain_bytes": 30, "object_bytes": 10,
         "sha256_plain": "a" * 64, "sha256_encrypted": "b" * 64},
        "v1/wazuh-web/2026/wazuh-web.2026-05.ndjson.zst.age")
    assert man["sha256_plain"] == "a" * 64
    assert man["age_recipients"] == ["age1abc"]
    assert "zstd -19" in man["chain"] and "age -r age1abc" in man["chain"]
    assert man["indices"] == ["wazuh-web-2026.05.01"]
    # Serialisable: it goes into S3 as is.
    json.dumps(man)


# --------------------------------------------------------------------------
# Object Lock
# --------------------------------------------------------------------------

def test_object_lock_absent_by_default(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK", False)
    assert archive._args_lock() == {}


def test_object_lock_sets_a_deadline(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK", True)
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK_MODE", "COMPLIANCE")
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK_DAYS", 365)
    a = archive._args_lock()
    assert a["ObjectLockMode"] == "COMPLIANCE"
    assert (a["ObjectLockRetainUntilDate"].date()
            - date.today()).days in (364, 365, 366)


# --------------------------------------------------------------------------
# Disabled = inert
# --------------------------------------------------------------------------

def test_disabled_touches_nothing(monkeypatch):
    """ARCHIVING_ENABLED=false must be inert WITHOUT touching Postgres: the
    module is imported by the watchdog, which runs every two minutes for
    everyone, including those who do not archive."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", False)
    assert archive.run() == {"state": "disabled"}
    assert archive.indices_at_risk(None) == []
    assert archive.anomalies(None) == []


# --------------------------------------------------------------------------
# Anomalies surfaced to the watchdog
# --------------------------------------------------------------------------

class _Conn:
    """Minimal stub: `execute(...).fetchall()`."""

    def __init__(self, lines):
        self._lines = lines

    def execute(self, sql, params=None):
        self._sql = sql
        return self

    def fetchall(self):
        return self._lines


def test_coverage_gap_detected(monkeypatch):
    """A month absent BETWEEN two archived months: the source indices are long
    since purged, the data no longer exists anywhere, and nothing said so at
    the moment it left."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [])
    conn = _Conn([
        {"index_base": "wazuh-web", "period": "2026-01",
         "verified_at": None, "verify_state": "ok"},
        {"index_base": "wazuh-web", "period": "2026-03",
         "verified_at": None, "verify_state": "ok"},
    ])
    gaps = [a for a in archive.anomalies(conn)
             if a["sensor"].endswith("gap")]
    assert len(gaps) == 1
    assert "2026-02" in gaps[0]["note"]
    assert gaps[0]["severity"] == "Medium"


def test_recent_series_without_a_past_is_not_a_gap(monkeypatch):
    """An index set created last month has no gap: it has a past that does not
    exist. Confusing the two would open a case at every index-set creation —
    and routing.py creates up to two a day."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [])
    conn = _Conn([{"index_base": "wazuh-jellyfin", "period": "2026-07",
                   "verified_at": None, "verify_state": "ok"}])
    assert not [a for a in archive.anomalies(conn)
                if a["sensor"].endswith("gap")]


def test_failed_drill_raised_to_high(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [])
    conn = _Conn([{"index_base": "wazuh-web", "period": "2026-01",
                   "verified_at": None, "verify_state": "sha256-divergent"}])
    failures = [a for a in archive.anomalies(conn)
              if a["sensor"].endswith("drill")]
    assert len(failures) == 1 and failures[0]["severity"] == "High"


def test_risk_raised_to_high_with_remaining_delay(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [
        {"index": "wazuh-web-2026.05.02", "documents": 12,
         "age_days": 85, "deleted_in": 5}])
    conn = _Conn([])
    risk = [a for a in archive.anomalies(conn)
             if a["sensor"].endswith("risk")]
    assert len(risk) == 1
    assert risk[0]["severity"] == "High"
    assert "wazuh-web-2026.05.02" in risk[0]["note"]
    assert "5 j" in risk[0]["note"]


def test_sensors_prefixed_for_the_watchdog(monkeypatch):
    """The watchdog recognises these pseudo-sensors by their PREFIX to measure
    them against the clock rather than against the ingestion horizon."""
    from soc_agent import watchdog
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [
        {"index": "i-2026.05.02", "documents": 1, "age_days": 85,
         "deleted_in": 5}])
    for a in archive.anomalies(_Conn([])):
        assert a["sensor"].startswith(archive.PREFIX_SENSOR)
        assert watchdog._is_archiving(a["sensor"])
        assert watchdog._outside_pipeline(a["sensor"])
        # `title`, `note` and `severity` are what the watchdog consumes with no
        # special case (cf. watchdog._rendered / _title / _outage_severity).
        assert a["title"] and a["note"] and a["severity"]
        assert watchdog._title(a) == a["title"]
        assert watchdog._rendered(a, 0, markdown=False) == a["note"]
        assert watchdog._outage_severity(a["sensor"], a) == a["severity"]


# --------------------------------------------------------------------------
# Batch selection and purge risk
# --------------------------------------------------------------------------

def _fake_indices(*specs):
    """(index_base, 'YYYY-MM', nb_days, docs_per_day) -> list of dated indices."""
    out = []
    for base, month, n, docs in specs:
        a, m = month.split("-")
        for j in range(1, n + 1):
            out.append({"index": f"{base}-{a}.{m}.{j:02d}", "base": base,
                        "day": date(int(a), int(m), j), "month": month,
                        "documents": docs, "bytes": docs * 1000})
    return out


def test_batches_ignore_the_current_month(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-firewall", "2026-05", 3, 100),
        ("wazuh-firewall", "2026-08", 2, 50),   # current month
        ("wazuh-web", "2026-05", 1, 7)))
    batches = archive.batches_to_archive(_Conn([]), date(2026, 8, 14))
    assert [(l["index_base"], l["period"]) for l in batches] == [
        ("wazuh-firewall", "2026-05"), ("wazuh-web", "2026-05")]
    # The days of the month are grouped into ONE batch, documents cumulated.
    assert batches[0]["documents"] == 300 and len(batches[0]["indices"]) == 3


def test_already_archived_batch_does_not_come_back(monkeypatch):
    """Without this, every pass would re-export and re-pay for the whole
    history — the IRIS Evidence bug, transposed to S3."""
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-firewall", "2026-05", 3, 100),
        ("wazuh-web", "2026-05", 1, 7)))
    conn = _Conn([{"index_base": "wazuh-firewall", "period": "2026-05"}])
    batches = archive.batches_to_archive(conn, date(2026, 8, 14))
    assert [(l["index_base"], l["period"]) for l in batches] == [
        ("wazuh-web", "2026-05")]


def test_risk_bounded_to_the_margin_before_deletion(monkeypatch):
    """A young index with no archive is not at risk — it has time. Confusing
    the two would open a High case every day, for nothing."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(config, "RETENTION_INDEX_DAYS", 90)
    monkeypatch.setattr(config, "ARCHIVE_MARGIN_DAYS", 7)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-web", "2026-05", 1, 7),      # 105 d -> at risk
        ("wazuh-web", "2026-08", 1, 7)))     # 13 d  -> fine
    risk = archive.indices_at_risk(_Conn([]), date(2026, 8, 14))
    assert [i["index"] for i in risk] == ["wazuh-web-2026.05.01"]
    assert risk[0]["age_days"] == 105


def test_risk_drops_when_the_archive_exists(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(config, "RETENTION_INDEX_DAYS", 90)
    monkeypatch.setattr(config, "ARCHIVE_MARGIN_DAYS", 7)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-web", "2026-05", 1, 7)))
    conn = _Conn([{"index_base": "wazuh-web", "period": "2026-05"}])
    assert archive.indices_at_risk(conn, date(2026, 8, 14)) == []


# --------------------------------------------------------------------------
# The lock must not mask the error that interrupted the pass
# --------------------------------------------------------------------------

class _AbortedConn:
    """Connection whose transaction is aborted: every `execute` fails.

    Reproduces the real state of Postgres after a query error — what prod
    encountered on the first pass, table `archives_s3` missing.
    """

    def __init__(self):
        self.rollback_called = False

    def execute(self, sql, params=None):
        if not self.rollback_called:
            raise RuntimeError("current transaction is aborted")

        class R:
            @staticmethod
            def fetchone():
                return {"pg_advisory_unlock": True}
        return R()

    def rollback(self):
        self.rollback_called = True


def test_unlock_does_not_mask_the_cause():
    """Without a prior rollback, the UNLOCK raises `InFailedSqlTransaction` and
    this second exception REPLACES the first: the trace no longer says what
    went wrong. Hit in prod, where the useful diagnosis ("a table is missing")
    had become invisible under a transaction error."""
    conn = _AbortedConn()
    archive._unlock(conn)          # must raise NOTHING
    assert conn.rollback_called, "rollback not attempted before the unlock"


def test_unlock_survives_a_dead_connection():
    """A session lock is released when the connection closes: failing here has
    no consequence, whereas propagating the failure would mask the cause."""
    class _Dead:
        def rollback(self):
            raise OSError("connection closed")

        def execute(self, *a):
            raise OSError("connection closed")

    archive._unlock(_Dead())      # must raise NOTHING


def test_missing_table_error_surfaces_unchanged(monkeypatch):
    """The end-to-end prod scenario: what must come out of `run` is the real
    cause, not the cleanup's transaction error."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)

    class _Conn(_AbortedConn):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=None):
            if "pg_try_advisory_lock" in sql:
                class R:
                    @staticmethod
                    def fetchone():
                        return {"pg_try_advisory_lock": True}
                return R()
            return super().execute(sql, params)

    monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(archive, "batches_to_archive", lambda conn: (_ for _ in ()).throw(
        RuntimeError('relation "archives_s3" does not exist')))
    with pytest.raises(RuntimeError, match="archives_s3"):
        archive.run()


# --------------------------------------------------------------------------
# Integrity: a partial export must NEVER become an archive
# --------------------------------------------------------------------------

class _Response:
    def __init__(self, body, ok=True, status=200):
        self._body, self.ok, self.status_code = body, ok, status
        self.text = json.dumps(body)

    def json(self):
        return self._body


def _page(hits, failed=0, total_shards=3, timed_out=False, total=None,
          scroll="s1"):
    return {
        "_scroll_id": scroll,
        "timed_out": timed_out,
        "_shards": {"total": total_shards, "successful": total_shards - failed,
                    "skipped": 0, "failed": failed,
                    "failures": [{"index": "wazuh-web-2026.03.01",
                                  "reason": {"reason": "shard unavailable"}}]
                    if failed else []},
        "hits": {"total": {"value": total if total is not None else len(hits),
                           "relation": "eq"},
                 "hits": hits},
    }


def _hit(n):
    return {"_index": "wazuh-web-2026.03.01", "_id": f"i{n}", "_source": {"n": n}}


def test_failed_shard_refused_from_the_first_page(monkeypatch):
    """OpenSearch answers HTTP 200 with PARTIAL results when a shard goes down:
    the failure is in `_shards.failed`, not in the HTTP code. Without this
    check, the archive records its own truncated count as the reference and
    everything else (manifest, SHA-256, drill, adoption) agrees with it."""
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: _Response(_page([_hit(0)], failed=1)))
    with pytest.raises(RuntimeError, match="partial export refused"):
        list(archive.pages(["wazuh-web-2026.03.01"]))


def test_failed_shard_refused_mid_scroll(monkeypatch):
    """A scroll lasts several minutes: a shard can go down AFTER the first
    page, and the affected page simply comes back shorter."""
    responses = [_Response(_page([_hit(0)], total=2)),
                _Response(_page([_hit(1)], failed=1, total=2))]
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: responses.pop(0) if responses
                        else _Response(_page([])))
    with pytest.raises(RuntimeError, match="partial export refused"):
        list(archive.pages(["wazuh-web-2026.03.01"]))


def test_expired_search_refused(monkeypatch):
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: _Response(_page([_hit(0)], timed_out=True)))
    with pytest.raises(RuntimeError, match="partial export refused"):
        list(archive.pages(["wazuh-web-2026.03.01"]))


def test_exact_total_requested_from_the_indexer(monkeypatch):
    """Without `track_total_hits`, OpenSearch caps the total at 10,000 and
    returns `relation: gte`: a cap would be taken for a total, and the
    completeness check would validate any export of more than 10,000
    documents."""
    assert archive._body_search(500)["track_total_hits"] is True
    control = {}
    responses = [_Response(_page([_hit(0)], total=4200)), _Response(_page([]))]
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: responses.pop(0) if responses
                        else _Response(_page([])))
    list(archive.pages(["wazuh-web-2026.03.01"], control=control))
    assert control == {"expected": 4200, "relation": "eq"}


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_truncated_export_refused_and_file_deleted(tmp_path, monkeypatch):
    """The scroll stops before the end: fewer documents written than
    announced. The archive must be REFUSED and the file deleted — exactly the
    case that produced a truncated copy believing itself complete."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))

    def _pages(indices, size=None, control=None):
        if control is not None:
            control["expected"] = 1000     # the indexer announces 1000...
        yield [_hit(n) for n in range(10)]  # ...only 10 are received
    monkeypatch.setattr(archive, "pages", _pages)

    object_path = tmp_path / "a.ndjson.zst.age"
    with pytest.raises(RuntimeError, match="INCOMPLETE export refused"):
        archive.export({"indices": ["i"], "bytes": 1,
                          "index_base": "wazuh-web", "period": "2026-03"}, object_path)
    assert not object_path.exists(), "the truncated file was kept"


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_complete_export_accepted(tmp_path, monkeypatch):
    """The nominal case must keep passing: as many documents as announced."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))

    def _pages(indices, size=None, control=None):
        if control is not None:
            control["expected"] = 10
        yield [_hit(n) for n in range(10)]
    monkeypatch.setattr(archive, "pages", _pages)

    m = archive.export({"indices": ["i"], "bytes": 1,
                          "index_base": "wazuh-web", "period": "2026-03"},
                         tmp_path / "a.age")
    assert m["documents"] == 10


@pytest.mark.skipif(not _TOOLS, reason="zstd/age missing from this environment")
def test_surplus_accepted_since_no_loss(tmp_path, monkeypatch):
    """Writing MORE than announced is not a loss: at worst a duplicate. We
    keep it and log it, rather than discarding a valid archive."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))

    def _pages(indices, size=None, control=None):
        if control is not None:
            control["expected"] = 5
        yield [_hit(n) for n in range(10)]
    monkeypatch.setattr(archive, "pages", _pages)

    m = archive.export({"indices": ["i"], "bytes": 1,
                          "index_base": "wazuh-web", "period": "2026-03"},
                         tmp_path / "a.age")
    assert m["documents"] == 10


# --------------------------------------------------------------------------
# Cleanup of residues from a killed pass (SIGKILL: no `finally` runs)
# --------------------------------------------------------------------------

def test_sweep_deletes_old_residues_not_recent_ones(tmp_path, monkeypatch):
    import os as _os
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    old = tmp_path / "aura-archive-abandoned"
    old.mkdir()
    (old / "object").write_bytes(b"x" * 4096)
    _os.utime(old, (0, 0))                       # left there a long time ago
    recent = tmp_path / "aura-drill-in-progress"   # may belong to a drill
    recent.mkdir()
    foreign = tmp_path / "something-else"         # not ours
    foreign.mkdir()

    r = archive.sweep_temporary(age_hours=2)
    assert r["directories"] == 1 and r["bytes"] >= 4096
    assert not old.exists()
    assert recent.exists() and foreign.exists()


def test_unfinished_multiparts_aborted_except_recent_ones():
    """The parts of an interrupted multipart are BILLED and appear in no
    list_objects. But a recent upload may still be in progress."""
    from datetime import timedelta as _td
    now = datetime.now(timezone.utc)
    aborted = []

    class _S3:
        @staticmethod
        def list_multipart_uploads(Bucket):
            return {"Uploads": [
                {"Key": "v1/a.age", "UploadId": "u1",
                 "Initiated": now - _td(days=3)},
                {"Key": "v1/b.age", "UploadId": "u2",
                 "Initiated": now - _td(minutes=5)},
            ]}

        @staticmethod
        def abort_multipart_upload(Bucket, Key, UploadId):
            aborted.append(Key)

    r = archive.abort_multiparts(_S3(), age_hours=24)
    assert r["aborted"] == ["v1/a.age"] and r["in_progress_ignored"] == 1
    assert aborted == ["v1/a.age"]


def test_unlistable_multiparts_do_not_block_archiving():
    """An application key without the right to list must not prevent
    archiving: not archiving at all is a far worse response."""
    class _S3:
        @staticmethod
        def list_multipart_uploads(Bucket):
            raise Exception("AccessDenied")

    assert "undetermined" in archive.abort_multiparts(_S3())["state"]
