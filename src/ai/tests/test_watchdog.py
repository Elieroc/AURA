"""Tests for the "silent sensor" watchdog (no database, no IRIS).

What is tested here is the deciding part: the threshold retained per sensor,
the duration formatting and the content of the record. The SQL query itself is
covered by its real usage — it has no branch.
"""

from datetime import datetime, timedelta, timezone

from soc_agent import config
from soc_agent import watchdog
from soc_agent.watchdog import _duration, _minutes, _outage_note


def _silent(sensor="suricata", minutes=42, agent="008", name="home-r-pf01"):
    return {
        "agent_id": agent, "agent_name": name, "sensor": sensor,
        "volume": 2134,
        "last": datetime.now(timezone.utc) - timedelta(minutes=minutes),
        "threshold": config.WATCHDOG_SILENCE_PER_SENSOR.get(
            sensor, config.WATCHDOG_SILENCE_MINUTES),
    }


def test_default_threshold_is_ten_minutes():
    """Operator setting of 2026-08-11: an outage is 10 minutes of silence.
    Applies to CONTINUOUS sensors, whose measured p95 gap is 5.4 min (audit)
    and 0 min (suricata)."""
    assert config.WATCHDOG_SILENCE_MINUTES == 10


def test_event_driven_sensors_have_their_own_threshold():
    """sshd and syscheck only emit on events: their silence is normal. At the
    10-min threshold, any idle machine would be declared down."""
    by = config.WATCHDOG_SILENCE_PER_SENSOR
    assert by["sshd"] > config.WATCHDOG_SILENCE_MINUTES * 100
    assert by["syscheck"] > config.WATCHDOG_SILENCE_MINUTES * 300
    # Continuous sensors, on the other hand, must NOT have a dispensation.
    assert "suricata" not in by and "audit" not in by


def test_readable_duration():
    assert _duration(12) == "12 min"
    assert _duration(89) == "89 min"
    assert _duration(150) == "2 h 30"
    assert _duration(60 * 50) == "2 j 2 h"


def test_minutes_since_a_timestamp():
    assert _minutes(datetime.now(timezone.utc) - timedelta(minutes=30)) == 30


def test_note_carries_the_diagnosis_and_the_scope():
    """The record must say WHAT IS NO LONGER DETECTED: an analyst reading
    "suricata silent" does not know the backing ruleset by heart."""
    note = _outage_note(_silent(), 42)
    assert "42 min" in note
    assert "home-r-pf01" in note
    assert "détection réseau" in note
    assert "plusieurs" in note          # the stacked-logcollector trap
    assert "isolé" in note              # the false outage of an isolated host


def test_note_covers_every_monitored_sensor():
    """Every monitored sensor must have a written scope, otherwise the record
    comes out with a useless generic text."""
    from soc_agent.watchdog import _SCOPE
    for sensor in config.WATCHDOG_SENSORS:
        assert sensor in _SCOPE, sensor


def test_silence_measured_against_the_horizon_not_the_clock():
    """The database is fed in 5-min cycles: measuring against the clock
    manufactures an outage on every interval. Measured on 2026-08-11 —
    `audit` and `suricata` declared down for "15 min" four minutes after a
    container restart, while both were emitting."""
    horizon = datetime.now(timezone.utc) - timedelta(minutes=14)
    last = horizon - timedelta(minutes=2)
    # Against the clock: 16 min -> above the threshold, false outage.
    assert _minutes(last) > config.WATCHDOG_SILENCE_MINUTES
    # Against the horizon: 2 min -> nothing to report.
    assert _minutes(last, horizon) < config.WATCHDOG_SILENCE_MINUTES


def test_ingest_lag_threshold_covers_several_cycles():
    """The anti-blindness guardrail must not fire on a single lagging cycle:
    at a 300 s cadence, several cycles must be missed."""
    assert config.WATCHDOG_INGEST_LAG_MAX >= 25


# ---------------------------------------------------------------------------
# ALERT channel (IRIS Alerts tab)
# ---------------------------------------------------------------------------


class _Response:
    def __init__(self, data, ok=True, msg=""):
        self._data, self._ok, self._msg = data, ok, msg

    def is_success(self):
        return self._ok

    def get_data(self):
        return self._data

    def get_msg(self):
        return self._msg


class _FakeAlert:
    """The strict minimum of `dfir_iris_client.alert.Alert`: what is tested
    here is the PAYLOAD sent and the decision to close, not the IRIS client."""

    def __init__(self, status="New", description="# Panne de capteur"):
        self.added, self.updates = [], []
        self._status, self._description = status, description

    def add_alert(self, data):
        self.added.append(data)
        return _Response({"alert_id": 77})

    def get_alert(self, alert_id):
        return _Response({"alert_description": self._description,
                         "status": {"status_name": self._status}})

    def update_alert(self, alert_id, data):
        self.updates.append((alert_id, data))
        return _Response({"alert_id": alert_id})


def _outage(sensor="suricata", status="open"):
    return {"id": 3, "agent_id": "008", "agent_name": "home-r-pf01",
            "sensor": sensor, "status": status,
            "detected_at": datetime.now(timezone.utc) - timedelta(hours=2),
            "last_event": datetime.now(timezone.utc) - timedelta(hours=3)}


def test_default_channel_is_alert():
    """A sensor outage is a state to acknowledge, not an investigation: it
    lives in the Alerts tab, where the analyst keeps the choice to escalate."""
    assert config.WATCHDOG_IRIS_CHANNEL == "alert"


def test_alert_statuses_resolved_by_name(monkeypatch):
    """IRIS alert status ids follow no logical order (New=2 but
    Unspecified=1, Closed=6): hard-coding them would be right by accident."""
    from soc_agent import watchdog
    monkeypatch.setattr(watchdog, "_STATUSES_ID", None)

    class _Session:
        def pi_get(self, uri):
            assert uri == "/manage/alert-status/list"
            return _Response([{"status_id": 42, "status_name": "Closed"},
                             {"status_id": 2, "status_name": "New"}])

    class _Alert:
        _s = _Session()

    # The id comes from the SERVER, not from the fallback table (which says 6).
    assert watchdog._status_id(_Alert(), "Closed") == 42


def test_alert_statuses_fall_back_if_iris_is_silent(monkeypatch):
    from soc_agent import watchdog
    monkeypatch.setattr(watchdog, "_STATUSES_ID", None)

    class _Alert:
        class _s:
            @staticmethod
            def pi_get(uri):
                raise RuntimeError("IRIS injoignable")

    assert watchdog._status_id(_Alert(), "New") == 2


def test_alert_carries_source_reference_and_asset(monkeypatch):
    """The source filters the tab, the reference identifies the (agent,
    sensor) pair, the asset groups the alerts of the same machine and follows
    it if the analyst escalates to a case."""
    from soc_agent import watchdog
    fake = _FakeAlert()
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 2)
    monkeypatch.setattr(watchdog, "_alert_severity_id", lambda a, n: 5)

    assert watchdog._open_alert({**_silent(), "os": "pfSense 2.7"}, 42) == 77
    sent = fake.added[0]
    assert sent["alert_source"] == watchdog.SOURCE_ALERT
    assert sent["alert_source_ref"] == "sensor-008-suricata"
    assert sent["alert_classification_id"] == watchdog.CLASSIF_OUTAGE
    assert "détection réseau" in sent["alert_description"]
    assert (sent["alert_assets"][0]["asset_type_id"]
            == watchdog.ASSET_FIREWALL)


def test_severity_distinguishes_continuous_and_event_driven_sensor():
    """A silent continuous sensor is an immediate and certain loss of
    visibility; an event-driven sensor fires on a threshold of several hours
    and is wrong more often."""
    from soc_agent.watchdog import _outage_severity
    assert _outage_severity("suricata") == "High"
    assert _outage_severity("syscheck") == "Medium"


def test_default_asset_type_does_not_block():
    from soc_agent.watchdog import (ASSET_LINUX_SERVER, ASSET_WIN_SERVER,
                                    _type_asset)
    assert _type_asset(None) == ASSET_LINUX_SERVER
    assert _type_asset("Microsoft Windows Server 2022") == ASSET_WIN_SERVER


def test_recovery_closes_the_alert(monkeypatch):
    from soc_agent import watchdog
    fake = _FakeAlert(status="New")
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 6)

    watchdog._close_alert(77, _outage(), 180)
    _, update = fake.updates[0]
    assert update["alert_status_id"] == 6
    assert "CAPTEUR RÉTABLI" in update["alert_description"]
    # The original description is kept: the diagnosis must not disappear on
    # recovery.
    assert "# Panne de capteur" in update["alert_description"]


def test_alert_escalated_by_a_human_is_not_closed(monkeypatch):
    """The analyst judged that the outage deserved a file: the watchdog
    informs of the recovery, it does not close in their place. That is what
    the `case` channel used to get wrong."""
    from soc_agent import watchdog
    fake = _FakeAlert(status="Escalated")
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 6)

    watchdog._close_alert(77, _outage(), 180)
    _, update = fake.updates[0]
    assert "alert_status_id" not in update
    assert "CAPTEUR RÉTABLI" in update["alert_description"]


def test_closure_failure_propagates(monkeypatch):
    """The outage must stay OPEN in database to be retried: marking it
    recovered would leave a ghost alert that nothing closes any more."""
    import pytest

    from soc_agent import watchdog
    fake = _FakeAlert()
    fake.update_alert = lambda i, d: _Response(None, ok=False, msg="boom")
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 6)

    with pytest.raises(RuntimeError):
        watchdog._close_alert(77, _outage(), 180)


def test_alert_description_is_plain_text(monkeypatch):
    """The IRIS Alerts tab does NOT render markdown (verified on 2026-08-13:
    hashes, asterisks, backticks and pipes displayed literally). A markdown
    table becomes six lines of scrap right where the analyst is looking for
    the time of the last event."""
    from soc_agent import watchdog
    fake = _FakeAlert()
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 2)
    monkeypatch.setattr(watchdog, "_alert_severity_id", lambda a, n: 5)

    watchdog._open_alert({**_silent(), "os": "Debian 12"}, 42)
    desc = fake.added[0]["alert_description"]
    for scorie in ("**", "|---|", "`", "# "):
        assert scorie not in desc, scorie
    # The content itself does not change between the two renderings.
    assert "Dernier événement" in desc and "42 min" in desc
    assert "détection réseau" in desc


def test_case_note_stays_in_markdown():
    """Case NOTES, on the other hand, are properly rendered: the investigation
    file is not degraded to align on the Alerts tab limitation."""
    note = _outage_note(_silent(), 42)
    assert note.startswith("# Panne de capteur")
    assert "|---|---|" in note


def test_plain_rendering_aligns_the_facts():
    """Without a table, alignment is the only thing that makes these six lines
    readable at a glance."""
    raw = _outage_note(_silent(), 42, markdown=False)
    columns = {line.index(":") for line in raw.splitlines()
                if line.startswith("  ") and ":" in line}
    assert len(columns) == 1


# --- disk guardrail -------------------------------------------------------------
#
# On 2026-08-14, 6 GB/day left without anything reporting it. The disk is
# treated as a sensor: same state, same alert channel, same closure.

def _usage(total_go, pct):
    """Return value of shutil.disk_usage for a given occupation."""
    total = int(total_go * 1073741824)
    used = int(total * pct / 100)
    return _NamedUsage(total=total, used=used, free=total - used)


class _NamedUsage:
    def __init__(self, total, used, free):
        self.total, self.used, self.free = total, used, free


def test_disk_below_threshold_says_nothing(monkeypatch):
    monkeypatch.setattr(watchdog.shutil, "disk_usage",
                        lambda p: _usage(148, 45))
    assert watchdog.disk_saturated() == []


def test_disk_above_threshold_yields_one_entry(monkeypatch):
    monkeypatch.setattr(watchdog.shutil, "disk_usage",
                        lambda p: _usage(148, 84))
    d = watchdog.disk_saturated()
    assert len(d) == 1
    assert d[0]["sensor"] == watchdog.SENSOR_DISK
    assert d[0]["pct"] == 84
    # Shape of a silent sensor: this is what lets it go through the
    # open/close loop of `monitor` with no special case.
    assert {"agent_id", "agent_name", "sensor", "last", "horizon",
            "volume", "threshold"} <= set(d[0])


def test_disk_severity_follows_the_critical_threshold(monkeypatch):
    """At the alert threshold there is still time to act, at the critical
    threshold there is none."""
    monkeypatch.setattr(config, "DISK_THRESHOLD_CRITICAL", 90)
    assert watchdog._outage_severity(watchdog.SENSOR_DISK, {"pct": 84}) == "Medium"
    assert watchdog._outage_severity(watchdog.SENSOR_DISK, {"pct": 93}) == "High"


def test_disk_note_in_plain_text_without_markdown(monkeypatch):
    """The IRIS Alerts tab does not render markdown: the description must
    carry no title hash, bold, or backtick (cf. `_disk_note`)."""
    monkeypatch.setattr(watchdog.shutil, "disk_usage",
                        lambda p: _usage(148, 93))
    txt = watchdog._disk_note(watchdog.disk_saturated()[0], markdown=False)
    assert "DISQUE DU SOC SATURÉ" in txt
    assert "93 %" in txt
    assert "CRITIQUE" in txt
    for forbidden in ("# ", "**", "`"):
        assert forbidden not in txt


def test_disk_duration_measured_against_the_clock():
    """Disk saturation is measured against the clock, not against the
    ingestion horizon: the latter lags by construction and produced a
    NEGATIVE duration in the recovery alert ("-2 min" in production)."""
    start = datetime.now(timezone.utc) - timedelta(minutes=17)
    assert _minutes(start) == 17
    horizon_lagging = datetime.now(timezone.utc) - timedelta(minutes=19)
    assert _minutes(start, horizon_lagging) < 0
