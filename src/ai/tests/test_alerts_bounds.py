"""Bounding of alert loading for an incident (`soc_agent.alerts`).

What is tested: that the bound applies, that it takes BOTH ends of the
incident, and that it stays quiet when the incident fits under the cap. The
failure this module prevents is not an error but a silent OOM-kill — so no
test "fails" naturally if the bounding disappears, hence these checks on the
query itself.
"""

import pytest

from soc_agent import alerts, config


class FakeCursor:
    """Minimal connection: remembers the queries, returns a fixed count."""

    def __init__(self, total):
        self.total = total
        self.queries = []

    def execute(self, sql, params=None):
        self.queries.append((" ".join(sql.split()), params))
        self._last = sql
        return self

    def fetchone(self):
        return {"c": self.total}

    def fetchall(self):
        return [{"id": "a"}]


def test_under_the_cap_a_single_query_without_limit():
    """The normal case must pay nothing: no UNION, no LIMIT."""
    conn = FakeCursor(total=10)
    alerts.load_bounded(conn, 1, alerts.COLUMNS_TRIAGE)
    sql = conn.queries[-1][0]
    assert "UNION ALL" not in sql and "LIMIT" not in sql


def test_beyond_the_cap_both_ends_are_taken():
    """Taking "the last N" would lose the start of the attack — exactly what an
    analyst looks for, and where remediation targets come from."""
    conn = FakeCursor(total=102869)
    alerts.load_bounded(conn, 2555, alerts.COLUMNS_TARGETING)
    sql, params = conn.queries[-1]
    assert "UNION ALL" in sql
    assert "ORDER BY ts ASC LIMIT" in sql and "ORDER BY ts DESC LIMIT" in sql
    assert params["head"] + params["tail"] == config.INCIDENT_MAX_ALERTS
    assert params["i"] == 2555


def test_ts_not_duplicated_when_columns_already_carry_it():
    """Regression of 2026-08-14: `ts` added blindly to the columns projected it
    twice, and Postgres refused the whole query ("ORDER BY \"ts\" is
    ambiguous"). Three of the four column sets already contain `ts` — so it was
    the NOMINAL case that was broken, and it stayed broken until prod because
    the tests ran on a fake connection, which validates no SQL at all."""
    conn = FakeCursor(total=99999)
    alerts.load_bounded(conn, 7, alerts.COLUMNS_TRIAGE)
    sql = conn.queries[-1][0]
    assert ", ts, ts" not in sql and "raw, ts" not in sql
    assert sql.count("ORDER BY ts") == 3      # ASC, DESC, and the final sort


def test_carries_ts_does_not_mistake_a_substring():
    """"rule_groups, mitre_tactics" contains "ts" without carrying the column."""
    assert alerts._carries_ts("id, ts, raw")
    assert not alerts._carries_ts("rule_groups, mitre_tactics, raw")
    assert not alerts._carries_ts(alerts.COLUMNS_TARGETING)


def test_ts_is_projected_in_both_branches():
    """The final ORDER BY is on `ts`: absent from the SELECT of either branch of
    the UNION, the query is a SQL error — and the bounding would only serve to
    make the cycle fail differently."""
    conn = FakeCursor(total=99999)
    alerts.load_bounded(conn, 7, "agent_id, raw")
    sql = conn.queries[-1][0]
    assert sql.count("agent_id, raw, ts FROM alerts") == 2


def test_truncation_logged(caplog):
    """Never silent: what sits in the middle of the burst is not examined,
    and an analyst must be able to read it in the logs."""
    conn = FakeCursor(total=50000)
    with caplog.at_level("WARNING"):
        alerts.load_bounded(conn, 42, alerts.COLUMNS_UEBA, "remediation")
    msg = caplog.text
    assert "#42" in msg and "remediation" in msg
    assert "50000" in msg and "not examined" in msg


def test_no_noise_under_the_cap(caplog):
    conn = FakeCursor(total=5)
    with caplog.at_level("WARNING"):
        alerts.load_bounded(conn, 42, alerts.COLUMNS_UEBA)
    assert caplog.text == ""


@pytest.mark.parametrize("columns", [
    alerts.COLUMNS_REPORT, alerts.COLUMNS_TRIAGE,
    alerts.COLUMNS_TARGETING, alerts.COLUMNS_UEBA,
])
def test_all_column_sets_carry_raw(columns):
    """`raw` is the heavyweight (186 MB for a flood incident): it is precisely
    because every caller needs it that the bounding must be shared, not redone
    case by case — it was forgotten four times."""
    assert "raw" in columns


def test_callers_go_through_the_shared_module():
    """Non-regression guardrail: the failure reappeared four times, fixed
    locally each time. If a module reloads a whole incident by hand, this test
    must catch it."""
    import inspect
    import re

    from soc_agent import iris, mitigate, triage, ueba

    # What we track is the projection of `raw` over a whole incident. Two
    # precautions learned while writing this test:
    #   - quotes are STRIPPED before analysis: the offending query was written
    #     as two concatenated literals ("SELECT ... raw " "FROM alerts"),
    #     and a pattern that stops at the quote would never have seen it;
    #   - an aggregation (`count(*)`, `array_agg`) over the same rows is
    #     computed by Postgres and returns only one row: legitimate.
    forbidden = re.compile(
        r"SELECT(?!.{0,80}count\().{0,200}?\braw\b.{0,200}?FROM alerts"
        r".{0,80}?WHERE incident_id", re.DOTALL)
    for module in (iris, mitigate, triage, ueba):
        raw = inspect.getsource(module)
        src = re.sub(r"[\"']", "", raw)
        # A query "all the incident's alerts, raw included" must no longer
        # exist hardcoded; it must go through load_bounded or iterate.
        m = forbidden.search(src)
        if m:
            raise AssertionError(
                f"{module.__name__} reloads a whole incident — use "
                f"soc_agent.alerts.load_bounded/iterate. Seen: "
                f"{' '.join(m.group(0).split())[:120]}")


# ---------------------------------------------------------------------------
# Real SQL validation
# ---------------------------------------------------------------------------
#
# The tests above run on a fake connection: they verify the FORM of the
# query, never its validity. That is exactly what let an `ORDER BY "ts" is
# ambiguous` through to prod — the query was well-formed, and rejected by
# Postgres. This one executes it for real when a database is reachable, and
# cleanly skips itself otherwise.
@pytest.mark.parametrize("name", ["COLUMNS_REPORT", "COLUMNS_TRIAGE",
                                 "COLUMNS_TARGETING", "COLUMNS_UEBA"])
def test_sql_accepted_by_postgres(name):
    psycopg = pytest.importorskip("psycopg")
    try:
        conn = psycopg.connect(config.PG_DSN, row_factory=psycopg.rows.dict_row,
                               connect_timeout=3)
    except Exception:                                          # noqa: BLE001
        pytest.skip("no reachable Postgres")
    with conn:
        # NOT bounded branch: nonexistent incident, count is 0.
        alerts.load_bounded(conn, -1, getattr(alerts, name))
        # BOUNDED branch: needs a real incident whose count exceeds the cap,
        # otherwise it is still the first branch being exercised — and it is
        # precisely the UNION that was invalid.
        true = conn.execute(
            "SELECT incident_id FROM alerts WHERE incident_id IS NOT NULL "
            "GROUP BY incident_id HAVING count(*) >= 2 LIMIT 1").fetchone()
        if not true:
            pytest.skip("no incident with 2 or more alerts in the database")
        cap = config.INCIDENT_MAX_ALERTS
        try:
            config.INCIDENT_MAX_ALERTS = 1
            alerts.load_bounded(conn, true["incident_id"],
                                    getattr(alerts, name))
        finally:
            config.INCIDENT_MAX_ALERTS = cap
