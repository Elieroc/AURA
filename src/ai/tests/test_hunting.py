"""Guardrails of the threat-hunting space (soc_agent.hunting).

Two families of tests, and the first matters more than the second:

1. **Isolation.** `wazuh-hunting-*` must NEVER be read by ingestion nor
   observed by routing. If this exclusion breaks, restoring an old month makes
   AURA replay a past attack — correlation, triage, then autonomous
   remediation on year-old facts. This is the only test in this file whose
   failure is a production incident.
2. **The caps.** This space is reachable by an AI agent via MCP:
   "restore everything for me" must be refused by the code.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("ARCHIVING_ENABLED", "false")

from soc_agent import config, hunting  # noqa: E402


# --------------------------------------------------------------------------
# Isolation — the test that matters
# --------------------------------------------------------------------------

def test_hunting_excluded_from_what_ingestion_reads(monkeypatch):
    """The `-wazuh-hunting-*` negation must be present in the indices read.

    Without it, `ingest.py` picks up the restored alerts, `correlate` turns
    them into incidents, `triage` judges them and `mitigate` acts — on facts
    ten months old, ending in host isolation.
    """
    from soc_agent import routing
    monkeypatch.setattr(routing, "_INDICES_CACHE",
                        {"value": "", "expire": None})
    monkeypatch.setattr(routing, "applied_patterns", lambda conn: [])
    monkeypatch.setattr("psycopg.connect",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no database")))
    read = routing.read_indices()
    assert f"-{config.HUNTING_INDEX_BASE}-*" in read.split(",")
    # And the negation must be LAST: OpenSearch's multi-index syntax applies
    # exclusions in order, a negation followed by a `wazuh-*` would be undone.
    assert read.split(",")[-1] == f"-{config.HUNTING_INDEX_BASE}-*"


def test_negation_holds_even_with_wazuh_star(monkeypatch):
    """Worst-case configuration: someone puts `wazuh-*` in the list.

    The protection must not depend on configuration discipline.
    """
    from soc_agent import routing
    monkeypatch.setattr(config, "INDEXER_ALERT_INDICES", "wazuh-*")
    monkeypatch.setattr(routing, "_INDICES_CACHE",
                        {"value": "", "expire": None})
    monkeypatch.setattr(routing, "applied_patterns", lambda conn: [])
    monkeypatch.setattr("psycopg.connect",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no database")))
    read = routing.read_indices().split(",")
    assert "wazuh-*" in read
    assert read[-1] == f"-{config.HUNTING_INDEX_BASE}-*"


def test_hunting_excluded_from_archiving():
    """Re-archiving a restored archive would mean paying twice for the same
    data for twelve months, under an Object Lock that forbids undoing it."""
    from soc_agent import archive
    assert f"{config.HUNTING_INDEX_BASE}-*" in config.ARCHIVE_INDEX_EXCLUDED
    assert archive._excluded("wazuh-hunting-firewall-2026-03")
    # Second barrier: the name is not dated to the day, so the shape already
    # excludes it, independently of the list.
    assert archive._DATE_INDEX.match("wazuh-hunting-firewall-2026-03") is None


def test_ism_policies_dont_overlap():
    """An index carries only ONE ISM policy. Two `ism_template` matching the
    same index at the same priority would give an arbitrary attachment."""
    from soc_agent import retention
    alert_patterns = retention.ism_patterns()
    hunting_pattern = f"{config.HUNTING_INDEX_BASE}-*"
    assert hunting_pattern not in alert_patterns
    import fnmatch
    example = "wazuh-hunting-firewall-2026-03"
    assert not any(fnmatch.fnmatch(example, m) for m in alert_patterns)
    assert fnmatch.fnmatch(example, hunting_pattern)
    assert retention.ISM_HUNTING_ID != retention.ISM_POLICY_ID


def test_hunting_retention_shorter_than_alerts():
    """It is a copy: keeping it as long as the original would double disk
    occupation for nothing."""
    from soc_agent import retention
    p = retention.ism_policy_hunting()["policy"]
    assert p["states"][0]["transitions"][0]["conditions"]["min_index_age"] == \
        f"{config.HUNTING_RETENTION_DAYS}d"
    assert config.HUNTING_RETENTION_DAYS < config.RETENTION_INDEX_DAYS


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

@pytest.mark.parametrize("base, period, expected", [
    ("wazuh-firewall", "2026-03", "wazuh-hunting-firewall-2026-03"),
    ("wazuh-alerts-4.x", "2026-01", "wazuh-hunting-alerts-4.x-2026-01"),
    ("wazuh-web", "2027-12", "wazuh-hunting-web-2027-12"),
])
def test_index_name(base, period, expected):
    assert hunting.index_name(base, period) == expected


# --------------------------------------------------------------------------
# Caps
# --------------------------------------------------------------------------

def _state(indices=0, byte_count=0, disk=40):
    return {"total_indices": indices, "total_documents": 0,
            "total_bytes": byte_count, "disk_pct": disk,
            "caps": {}}


def test_disk_saturated_refuses_before_all(monkeypatch):
    """The first guardrail, and the most important one: hunting is comfort, a
    full disk flips the indexer to read-only and stops ingestion for the whole
    fleet."""
    monkeypatch.setattr(config, "DISK_THRESHOLD_ALERT", 80)
    with pytest.raises(RuntimeError, match="disk at 85"):
        hunting.check_space({"documents": 1, "plain_bytes": 1},
                               _state(disk=85))


def test_archive_too_large_refused(monkeypatch):
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 1000)
    with pytest.raises(RuntimeError, match="HUNTING_MAX_DOCS"):
        hunting.check_space({"documents": 5000, "plain_bytes": 1}, _state())


def test_index_cap_refuses(monkeypatch):
    monkeypatch.setattr(config, "HUNTING_MAX_INDICES", 3)
    with pytest.raises(RuntimeError, match="HUNTING_MAX_INDICES"):
        hunting.check_space({"documents": 1, "plain_bytes": 1},
                               _state(indices=3))


def test_byte_cap_refuses_on_the_PROJECTED_total(monkeypatch):
    """The cap applies to occupation AFTER restore, not before: refusing only
    when it is already full would always let an overshoot through."""
    monkeypatch.setattr(config, "HUNTING_MAX_BYTES", 1000)
    monkeypatch.setattr(config, "HUNTING_MAX_INDICES", 10)
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 10**9)
    hunting.check_space({"documents": 1, "plain_bytes": 400}, _state(byte_count=500))
    with pytest.raises(RuntimeError, match="HUNTING_MAX_GB"):
        hunting.check_space({"documents": 1, "plain_bytes": 600},
                               _state(byte_count=500))


# --------------------------------------------------------------------------
# Purge: bounded to the hunting prefix
# --------------------------------------------------------------------------

@pytest.mark.parametrize("index", [
    "wazuh-firewall-2026.08.14",   # from PRODUCTION
    "wazuh-alerts-4.x-2026.08.14",
    "wazuh-voc-vulns",
    ".opendistro-ism-config",
    "wazuh-huntingXfirewall",      # near-miss prefix, not the right one
])
def test_purge_refuses_outside_hunting(index):
    """This tool is exposed by MCP, hence callable by an AI agent. It must not
    be able to delete a production alert index."""
    with pytest.raises(RuntimeError, match="is not a hunting index"):
        hunting.purge(index, confirm=True)


@pytest.mark.parametrize("index", [
    "wazuh-hunting-*",
    "wazuh-hunting-a,wazuh-hunting-b",
])
def test_purge_refuses_wildcards(index):
    """A pattern deletion is exactly the gesture whose reach nobody
    measures."""
    with pytest.raises(RuntimeError, match="one index at a time"):
        hunting.purge(index, confirm=True)


def test_purge_without_confirmation_deletes_nothing():
    r = hunting.purge("wazuh-hunting-firewall-2026-03")
    assert r["deleted"] is False and "confirm=true" in r["note"]


# --------------------------------------------------------------------------
# The MCP tools are declared with their scope
# --------------------------------------------------------------------------

def test_mcp_tools_declared_with_their_scope():
    """A tool with no `@auth.require` is reachable by any valid token, even
    read-only ones. The server refuses to register it, but it is still worth
    checking here that the scopes are the expected ones."""
    import importlib.util
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("mcp SDK absent from this environment")
    from aura_mcp.tools import archiving, hunting
    expected = {
        (archiving, "aura_archives_list"): "aura:read",
        (archiving, "aura_archive_create"): "aura:write",
        (hunting, "aura_hunting_state"): "aura:read",
        (hunting, "aura_hunting_restore"): "aura:write",
        (hunting, "aura_hunting_purge"): "aura:write",
    }
    for (module, name), scope in expected.items():
        fn = getattr(module, name)
        assert getattr(fn, "required_scope", None) == scope, name


# --------------------------------------------------------------------------
# _bulk re-injection
# --------------------------------------------------------------------------

class _IndexerStub:
    """Captures calls to the indexer, without having one."""

    def __init__(self, failures: int = 0):
        self.calls: list[tuple] = []
        self.body: list[bytes] = []
        self.failures = failures

    def __call__(self, method, path, body=None, timeout=120, raw=None,
                 content_type=None):
        self.calls.append((method, path, content_type))
        if raw:
            self.body.append(raw)

        class R:
            ok = True
            status_code = 200

            @staticmethod
            def json():
                lines = (raw or b"").count(b"\n") // 2
                items = []
                for i in range(lines):
                    if i < self.failures:
                        items.append({"index": {"error": {"type": "mapper_parsing"}}})
                    else:
                        items.append({"index": {"result": "created"}})
                return {"items": items}
        return R()


def test_injection_keeps_ids_and_content_type(tmp_path, monkeypatch):
    """Two requirements in the same test because they fail together:

    - `_id` kept => replaying a restore OVERWRITES the same documents instead
      of creating duplicates. That is what makes the operation idempotent
      with no marker to maintain;
    - `application/x-ndjson` => without it the indexer refuses the `_bulk`,
      and the diagnostic ("Content-Type header ... is not supported") has
      nothing to do with the apparent cause.
    """
    import json as js
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_text("".join(
        js.dumps({"_index": "wazuh-web-2026.03.01", "_id": f"id{n}",
                  "_source": {"rule": {"level": 7}}}) + "\n" for n in range(5)))
    stub = _IndexerStub()
    monkeypatch.setattr(hunting, "_indexer", stub)
    monkeypatch.setattr(config, "HUNTING_BULK_SIZE", 1000)

    r = hunting._inject("wazuh-hunting-web-2026-03", ndjson)
    assert r == {"injected": 5, "errors": 0, "error_examples": []}
    assert stub.calls[0] == ("POST", "/_bulk", "application/x-ndjson")

    lines = stub.body[0].decode().strip().split("\n")
    headers = [js.loads(l) for l in lines[0::2]]
    assert all(e["index"]["_index"] == "wazuh-hunting-web-2026-03" for e in headers)
    assert [e["index"]["_id"] for e in headers] == [f"id{n}" for n in range(5)]
    # `_source` re-injected ALONE: neither `_index` nor `_id` must pollute the
    # document, or the piece of evidence would be altered.
    docs = [js.loads(l) for l in lines[1::2]]
    assert docs[0] == {"rule": {"level": 7}}


def test_injection_in_batches(tmp_path, monkeypatch):
    """A single `_bulk` over 200,000 documents would make a request several
    hundred MB in size, refused by the indexer."""
    import json as js
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_text("".join(
        js.dumps({"_id": f"id{n}", "_source": {"n": n}}) + "\n"
        for n in range(10)))
    stub = _IndexerStub()
    monkeypatch.setattr(hunting, "_indexer", stub)
    monkeypatch.setattr(config, "HUNTING_BULK_SIZE", 3)
    r = hunting._inject("wazuh-hunting-x-2026-03", ndjson)
    assert r["injected"] == 10
    # 10 documents in batches of 3 -> 4 requests.
    assert len([c for c in stub.body]) == 4


def test_injection_counts_errors_without_hiding_them(tmp_path, monkeypatch):
    """A `_bulk` returns 200 even when some documents are rejected. Counting
    successes without reading `items[].error` would conclude a complete
    restore on a partial copy."""
    import json as js
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_text("".join(
        js.dumps({"_id": f"id{n}", "_source": {"n": n}}) + "\n"
        for n in range(4)))
    monkeypatch.setattr(hunting, "_indexer", _IndexerStub(failures=2))
    monkeypatch.setattr(config, "HUNTING_BULK_SIZE", 1000)
    r = hunting._inject("wazuh-hunting-x-2026-03", ndjson)
    assert r["injected"] == 2 and r["errors"] == 2
    assert r["error_examples"] and "mapper_parsing" in r["error_examples"][0]


def test_injection_ignores_unreadable_lines(tmp_path, monkeypatch):
    """A truncated archive must not fail the whole restore: what is readable
    is put back online, and the rest is counted."""
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_bytes(b'{"_id":"a","_source":{}}\n\n{truncated\n')
    monkeypatch.setattr(hunting, "_indexer", _IndexerStub())
    monkeypatch.setattr(config, "HUNTING_BULK_SIZE", 1000)
    r = hunting._inject("wazuh-hunting-x-2026-03", ndjson)
    assert r["injected"] == 1 and r["errors"] == 1


# --------------------------------------------------------------------------
# Dry-run
# --------------------------------------------------------------------------

def test_dry_run_downloads_nothing_and_returns_the_verdict(monkeypatch):
    """The dry-run must answer "this would go through" or "this would be
    refused, and why" without downloading 40 MB to find out."""
    line = {"key": "v1/wazuh-web/2026/x.age", "documents": 10,
             "plain_bytes": 1000, "indices": ["wazuh-web-2026.03.01"],
             "verify_state": None, "index_base": "wazuh-web", "period": "2026-03",
             "sha256_plain": "a" * 64}
    monkeypatch.setattr(hunting, "archive_available", lambda c, b, p: line)
    monkeypatch.setattr(hunting, "state", lambda: _state())
    monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Ctx())
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 10**9)
    monkeypatch.setattr(config, "HUNTING_MAX_INDICES", 10)
    monkeypatch.setattr(config, "HUNTING_MAX_BYTES", 10**12)
    monkeypatch.setattr(config, "DISK_THRESHOLD_ALERT", 80)

    def _forbidden(*a, **k):
        raise AssertionError("the dry-run touched the indexer or S3")
    monkeypatch.setattr(hunting, "_indexer", _forbidden)
    monkeypatch.setattr(hunting, "prepare", _forbidden)

    r = hunting.restore("wazuh-web", "2026-03")
    assert r["applied"] is False
    assert r["guardrails"] == "ok"
    assert r["target_index"] == "wazuh-hunting-web-2026-03"
    # The isolation reminder must be in the response: it is an AI client that
    # reads it, and it is what stops it from believing it just re-injected
    # alerts into the pipeline.
    assert "correlated" in r["note"] or "correlat" in r["note"]


def test_dry_run_announces_the_refusal_without_raising(monkeypatch):
    """In dry-run, a guardrail that would refuse must be RETURNED, not raised:
    the client asks for a plan, it gets the plan and the verdict."""
    line = {"key": "k", "documents": 10**9, "plain_bytes": 1,
             "indices": [], "verify_state": None, "index_base": "wazuh-web",
             "period": "2026-03", "sha256_plain": "a" * 64}
    monkeypatch.setattr(hunting, "archive_available", lambda c, b, p: line)
    monkeypatch.setattr(hunting, "state", lambda: _state())
    monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Ctx())
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 1000)
    r = hunting.restore("wazuh-web", "2026-03")
    assert r["applied"] is False
    assert r["guardrails"].startswith("REFUSED")
    assert "HUNTING_MAX_DOCS" in r["guardrails"]


class _Ctx:
    """Stubbed Postgres connection context."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
