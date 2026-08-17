"""Archive dashboard export: pure document shaping, no indexer involved.

The only thing worth testing here is `_doc`: the cost estimate and the
compression ratio are computed from the same two byte counts, in opposite
directions, and a swap between them would be silent (both are plausible
numbers) until someone compares the dashboard to a B2 invoice.
"""

from datetime import datetime, timezone

from soc_agent import archive_metrics, config

ROW = {
    "index_base": "wazuh-firewall",
    "period": "2026-03",
    "documents": 184203,
    "plain_bytes": 1_073_741_824,      # 1 GiB clear
    "object_bytes": 41_943_040,        # 40 MiB encrypted
    "archived_at": datetime(2026, 4, 3, 2, 0, tzinfo=timezone.utc),
    "verified_at": datetime(2026, 4, 5, 2, 0, tzinfo=timezone.utc),
    "verify_state": "ok",
    "verify_full": True,
    "object_lock_until": None,
}


def test_doc_carries_the_identifying_fields(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_S3_COST_USD_PER_GB_MONTH", 0.00695)
    doc = archive_metrics._doc(ROW)
    assert doc["event_type"] == "archive_catalog"
    assert doc["archive"]["index_set"] == "wazuh-firewall"
    assert doc["archive"]["period"] == "2026-03"
    assert doc["archive"]["documents"] == 184203
    assert doc["@timestamp"] == "2026-04-03T02:00:00+00:00"


def test_ratio_is_plain_over_encrypted_not_the_reverse():
    """A swapped ratio would still look plausible (both < 1 or > 1 is context
    dependent) — pin the direction explicitly."""
    doc = archive_metrics._doc(ROW)
    assert doc["archive"]["ratio"] == round(1_073_741_824 / 41_943_040, 2)


def test_cost_prices_the_encrypted_object_not_the_plaintext(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_S3_COST_USD_PER_GB_MONTH", 0.01)
    doc = archive_metrics._doc(ROW)
    # 41,943,040 bytes -> ~0.0419 GB -> * 0.01 $/GB
    assert doc["archive"]["cost_usd_month"] == round(
        41_943_040 / 1_000_000_000 * 0.01, 6)


def test_empty_archive_reports_zero_ratio_not_a_crash():
    """A month with no documents still produces a (tiny) object — see
    `archive.py`'s "every month has exactly one object" invariant. Dividing
    by an object_bytes of 0 must never happen, but dividing plain_bytes=0 by
    a real object_bytes must give 0, not a negative or NaN ratio."""
    row = {**ROW, "documents": 0, "plain_bytes": 0, "object_bytes": 213}
    doc = archive_metrics._doc(row)
    assert doc["archive"]["ratio"] == 0


def test_id_is_deterministic_per_index_set_and_period():
    """Re-exporting must overwrite the same document, never accumulate one
    per pass — the whole point of a state index."""
    a = archive_metrics._line("archive-wazuh-firewall-2026-03",
                              archive_metrics._doc(ROW))
    b = archive_metrics._line("archive-wazuh-firewall-2026-03",
                              archive_metrics._doc(ROW))
    assert a == b


def test_simulation_writes_nothing(monkeypatch, capsys):
    class _Conn:
        def execute(self, *a, **k):
            class R:
                @staticmethod
                def fetchall():
                    return [ROW]
            return R()

        def close(self):
            pass

    monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Conn())
    result = archive_metrics.export(simulation=True)
    assert result == {"archives": 1}
    out = capsys.readouterr().out
    assert '"index_set": "wazuh-firewall"' in out
