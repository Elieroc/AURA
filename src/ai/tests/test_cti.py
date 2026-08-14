"""CTI: normalisation, IOC cache, and the Wazuh-side extraction.

Three properties matter more than the rest of this file, because each one
carries a SILENT failure mode — the kind that raises no error and lets you
believe the CTI is working:

- `test_normalisation_identical_on_the_wazuh_side`: the cache is written by
  the soc-agent and read by a manager script that reimplements the
  normalisation (different interpreter, no shared code possible). A drift
  between the two breaks nothing, it just makes nothing ever match again;
- `test_no_loop_on_our_own_alerts`: the integration reinjects events into the
  analyser. Without a guardrail, a CTI alert carries the same IOC as the one
  that produced it and feeds itself in a loop;
- `test_ioc_removed_from_the_feed_disappears_from_the_cache`: revocation. An
  IOC that does not disappear from a rebuilt cache keeps alerting forever on
  a rehabilitated IP.
"""

import importlib.util
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_agent import cti

# The integration script lives outside the package (it runs on the manager,
# with Wazuh's embedded interpreter). Loaded by its path, the way
# wazuh-integratord does.
PATH_INTEGRATION = (Path(__file__).resolve().parents[2]
                      / "wazuh" / "integrations" / "custom-misp.py")


def _load_integration():
    spec = importlib.util.spec_from_file_location("custom_misp", PATH_INTEGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


integration = _load_integration()


# --- Normalisation ----------------------------------------------------------

CASES = [
    ("ip", "185.220.101.1", "185.220.101.1"),
    ("ip", " 185.220.101.1 ", "185.220.101.1"),
    ("ip", "185.220.101.1|443", "185.220.101.1"),
    ("ip", "[2001:0db8::0001]", "2001:db8::1"),
    ("ip", "not-an-ip", None),
    ("domain", "Evil.Example.COM.", "evil.example.com"),
    ("domain", "localhost", None),          # no dot: internal name
    ("domain", "two words", None),
    ("url", "HTTP://Evil.example.com/Payload/", "http://evil.example.com/payload"),
    ("url", "/wp-login.php", None),          # bare path: would match any host
    ("hash", "  D41D8CD98F00B204E9800998ECF8427E  ", "d41d8cd98f00b204e9800998ecf8427e"),
    ("hash", "malware.exe|d41d8cd98f00b204e9800998ecf8427e",
     "d41d8cd98f00b204e9800998ecf8427e"),
    ("hash", "zzzz", None),
    ("hash", "d41d8cd98f00b204e9800998ecf8427", None),   # 31 characters
]


@pytest.mark.parametrize("type_cache,raw,expected", CASES)
def test_normalisation(type_cache, raw, expected):
    assert cti.normalize(type_cache, raw) == expected


@pytest.mark.parametrize("type_cache,raw,expected", CASES)
def test_normalisation_identical_on_the_wazuh_side(type_cache, raw, expected):
    # Two implementations, one expected behaviour. If this test breaks, the
    # cache is written in a form detection never looks for — it will not
    # match anything any more, without the slightest error.
    assert integration.normalize(type_cache, raw) == expected


def test_url_without_scheme_never_indexed():
    # A URL reduced to its path is the classic trap: Apache logs decoded by
    # Wazuh only carry that, and every host in the world shares /index.php.
    assert cti.normalize("url", "evil.example.com/payload") is None


# --- Cache ------------------------------------------------------------------

def _ioc(value, type_="ip", source="ThreatFox", confidence=cti.CONFIDENCE_CURATED,
         threat=2, tags=""):
    return {"value": value, "type": type_, "source": source,
            "category": "Network activity", "event": "Campaign X",
            "event_id": "42", "tags": tags, "threat_level": threat,
            "confidence": confidence}


def test_cache_write_and_read(tmp_path):
    path = str(tmp_path / "ioc.db")
    count = cti.write_cache([_ioc("1.2.3.4"),
                             _ioc("5.6.7.8", confidence=cti.CONFIDENCE_BULK)],
                            path)
    assert count == {cti.CONFIDENCE_CURATED: 1, cti.CONFIDENCE_BULK: 1}
    found = cti.query("1.2.3.4", path)
    assert found and found[0]["source"] == "ThreatFox"
    assert cti.query("9.9.9.9", path) == []


def test_same_ioc_from_two_sources_curated_comes_first(tmp_path):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([
        _ioc("1.2.3.4", source="data-shield", confidence=cti.CONFIDENCE_BULK, threat=4),
        _ioc("1.2.3.4", source="CERT-FR", confidence=cti.CONFIDENCE_CURATED, threat=1),
    ], path)
    results = cti.query("1.2.3.4", path)
    # Both are kept — the analyst wants to know the IP is also on a bulk
    # list — but it is the curated intelligence that decides the alert
    # level, so it must come out first.
    assert [r["source"] for r in results] == ["CERT-FR", "data-shield"]


def test_ioc_removed_from_the_feed_disappears_from_the_cache(tmp_path):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("1.2.3.4"), _ioc("5.6.7.8")], path)
    cti.write_cache([_ioc("1.2.3.4")], path)
    assert cti.query("5.6.7.8", path) == []


def test_failed_sync_leaves_the_previous_cache(tmp_path):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("1.2.3.4")], path)

    def broken_source():
        yield _ioc("5.6.7.8")
        raise RuntimeError("feed interrupted")

    with pytest.raises(RuntimeError):
        cti.write_cache(broken_source(), path)

    # The replacement is atomic: a failed sync must neither empty the cache
    # nor leave it half-written. Yesterday's intelligence beats none at all.
    assert cti.query("1.2.3.4", path)
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".ioc-")]


def test_state_reports_staleness(tmp_path):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("1.2.3.4")], path)
    assert cti.state(path)["stale"] is False

    old = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE meta SET value = ? WHERE key = 'synced_at'", (old,))
    conn.commit()
    conn.close()
    assert cti.state(path)["stale"] is True


# --- MISP extraction ---------------------------------------------------------

def _fake_response(attributes):
    """Two pages: the requested batch, then an empty one (end of pagination)."""
    pages = [{"response": {"Attribute": attributes}}, {"response": {"Attribute": []}}]

    def _misp(method, path, body=None):
        return pages.pop(0) if pages else {"response": {"Attribute": []}}
    return _misp


def test_misp_attributes_ignore_types_without_equivalent(monkeypatch):
    monkeypatch.setattr(cti, "_misp", _fake_response([
        {"type": "ip-dst", "value": "1.2.3.4", "category": "Network activity",
         "event_id": "7", "Event": {"info": "Campaign", "threat_level_id": "1",
                                    "Orgc": {"name": "CERT-FR"}}},
        # No Wazuh alert field carries a registry key: ingesting it would
        # inflate the cache without ever matching.
        {"type": "regkey", "value": "HKLM\\Run\\evil", "Event": {}},
    ]))
    iocs = list(cti.misp_attributes())
    assert [(i["value"], i["type"], i["source"]) for i in iocs] == [
        ("1.2.3.4", "ip", "CERT-FR")]
    assert iocs[0]["confidence"] == cti.CONFIDENCE_CURATED


def _attribute(type_misp, value, event_date):
    return {"type": type_misp, "value": value, "category": "Network activity",
            "event_id": "7", "Event": {"info": "Report", "threat_level_id": "2",
                                       "date": event_date,
                                       "Orgc": {"name": "CIRCL"}}}


def test_ip_from_an_old_report_dropped_but_not_its_hash(monkeypatch):
    # `CTI_WINDOW` is about the MODIFICATION date of the attribute: everything
    # a feed just imported passes, including IPs from 2015 reports. Keeping
    # them means alerting at level 12-14 on the shared host that picked up the
    # address since. A hash, on the other hand, never expires.
    monkeypatch.setattr(cti, "_misp", _fake_response([
        _attribute("ip-dst", "107.6.172.54", "2015-09-01"),
        _attribute("md5", "d41d8cd98f00b204e9800998ecf8427e", "2015-09-01"),
        _attribute("domain", "evil.example.com", "2015-09-01"),
        _attribute("ip-dst", "23.45.67.89", "2026-08-01"),
    ]))
    values = {i["value"] for i in cti.misp_attributes()}
    assert values == {"d41d8cd98f00b204e9800998ecf8427e", "evil.example.com",
                       "23.45.67.89"}


def test_ip_without_event_date_kept(monkeypatch):
    # With no date we do not know: dropping it would lose valid intelligence
    # over a simple metadata gap.
    monkeypatch.setattr(cti, "_misp", _fake_response([
        _attribute("ip-dst", "23.45.67.89", "")]))
    assert [i["value"] for i in cti.misp_attributes()] == ["23.45.67.89"]


def test_ip_expiry_can_be_disabled(monkeypatch):
    monkeypatch.setattr(cti.config, "CTI_IP_MAX_DAYS", 0)
    monkeypatch.setattr(cti, "_misp", _fake_response([
        _attribute("ip-dst", "107.6.172.54", "2015-09-01")]))
    assert [i["value"] for i in cti.misp_attributes()] == ["107.6.172.54"]


def test_misp_extraction_requests_the_detection_indicators(monkeypatch):
    seen = {}

    def _misp(method, path, body=None):
        seen.update(body or {})
        return {"response": {"Attribute": []}}

    monkeypatch.setattr(cti, "_misp", _misp)
    list(cti.misp_attributes())
    # to_ids: MISP holds many CONTEXT attributes (sinkholes, IPs quoted as an
    # example) whose authors explicitly mark them as not meant for detection.
    # Ingesting them manufactures false positives signed "CERT-FR", the most
    # expensive ones to refute.
    assert seen["to_ids"] == 1
    assert seen["published"] == 1
    assert seen["enforceWarninglist"] == 1


# --- Blocklists -------------------------------------------------------------

class _Response:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_blocklist_ignores_comments_and_blank_lines(monkeypatch):
    monkeypatch.setattr(cti.requests, "get", lambda *a, **k: _Response(
        "# provider header\n\n1.2.3.4\n5.6.7.8 # trailing comment\n"
        "; another style\nnot-an-ip\n"))
    catalogue = {"misp_feeds": [], "blocklists": [
        {"name": "test", "type": "ip", "urls": ["https://example/list.txt"],
         "tags": ["cti:test"]}]}
    iocs = list(cti.blocklists(catalogue))
    assert [i["value"] for i in iocs] == ["1.2.3.4", "5.6.7.8"]
    # A bulk list qualifies nothing: it must never make an incident.
    assert all(i["confidence"] == cti.CONFIDENCE_BULK for i in iocs)


def test_unreachable_blocklist_does_not_fail_the_others(monkeypatch):
    def _get(url, **kwargs):
        if "dead" in url:
            raise cti.requests.ConnectionError("unreachable")
        return _Response("1.2.3.4\n")

    monkeypatch.setattr(cti.requests, "get", _get)
    catalogue = {"misp_feeds": [], "blocklists": [
        {"name": "dead", "type": "ip", "urls": ["https://dead/list.txt"]},
        {"name": "alive", "type": "ip", "urls": ["https://alive/list.txt"]}]}
    # The cache is rebuilt in full on every pass: letting one dead source
    # interrupt everything would lose ALL the CTI for a single feed outage.
    assert [i["source"] for i in cti.blocklists(catalogue)] == ["alive"]


def test_bootstrap_recognises_a_feed_preinstalled_by_misp(monkeypatch):
    # MISP ships the CIRCL feed as `.../feed-osint`, the catalog writes it
    # with a trailing slash. Without normalisation the bootstrap creates a
    # DUPLICATE: both copies enabled, MISP pulls the same feed twice and
    # doubles the events. Measured in production on 2026-08-12.
    calls = []

    def _misp(method, path, body=None):
        calls.append((method, path))
        if path == "/feeds/index":
            return [{"Feed": {"id": "1", "url": "https://www.circl.lu/doc/misp/feed-osint",
                              "enabled": True, "caching_enabled": True}}]
        return {}

    monkeypatch.setattr(cti, "_misp", _misp)
    catalogue = {"misp_feeds": [{"name": "CIRCL OSINT Feed", "format": "misp",
                                 "url": "https://www.circl.lu/doc/misp/feed-osint/"}],
                 "blocklists": []}
    summary = cti.bootstrap_feeds(catalogue=catalogue)
    assert summary["created"] == []
    assert not any(path == "/feeds/add" for _, path in calls)


def test_refresh_uses_the_right_endpoint(monkeypatch):
    # /feeds/fetchFromFeed/{id} expects a numeric identifier and answers 404
    # on "all" — measured in production. Only cacheFeeds accepts a named
    # scope.
    calls = []
    monkeypatch.setattr(cti, "_misp",
                        lambda m, c, body=None: calls.append(c))
    cti.refresh_feeds()
    assert calls == ["/feeds/fetchFromAllFeeds", "/feeds/cacheFeeds/all"]


def test_shipped_catalog_is_consistent():
    catalogue = cti.load_catalog()
    assert catalogue["misp_feeds"] and catalogue["blocklists"]
    for feed in catalogue["misp_feeds"]:
        assert feed["url"].startswith("https://")
    for bl in catalogue["blocklists"]:
        assert bl["urls"] and bl.get("type") in ("ip", "url", "domain")
    # The feed requested by name, and the one that justifies half the setup.
    urls = [f["url"] for f in catalogue["misp_feeds"]]
    assert any("cert.ssi.gouv.fr" in u for u in urls)
    assert any("duggytuxy" in u
               for bl in catalogue["blocklists"] for u in bl["urls"])


# --- Wazuh integration -------------------------------------------------------

def _alert(**data):
    base = {"rule": {"id": "5710", "description": "sshd: failed login"},
            "agent": {"id": "003", "name": "web01"}, "data": {}}
    base["data"].update(data.pop("data", {}))
    base.update(data)
    return base


def test_candidate_extraction_by_direction():
    found = integration.candidates(_alert(data={
        "srcip": "185.220.101.1", "dstip": "23.45.67.89"}))
    by_value = {v: (t, field, direction) for t, v, field, direction in found}
    assert by_value["185.220.101.1"][2] == "inbound"
    assert by_value["23.45.67.89"][2] == "outbound"


def test_private_ip_never_looked_up():
    # A private IP cannot be a public IOC. Looking it up risks matching one
    # of our own machines because a feed published some 192.168.x by
    # mistake — it happens.
    found = integration.candidates(_alert(data={
        "srcip": "192.168.1.10", "dstip": "172.20.0.5"}))
    assert found == []


def test_url_reassembled_from_host_and_path():
    found = integration.candidates(_alert(data={
        "http": {"hostname": "evil.example.com", "url": "/payload.bin"}}))
    urls = {v for t, v, _, _ in found if t == "url"}
    assert "http://evil.example.com/payload.bin" in urls
    assert "https://evil.example.com/payload.bin" in urls


def test_sysmon_fingerprints_extracted_from_the_aggregated_field():
    found = integration.candidates({"rule": {"id": "61603"}, "data": {"win": {
        "eventdata": {"hashes": "SHA1=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,"
                                "MD5=D41D8CD98F00B204E9800998ECF8427E"}}}})
    hashes = {v for t, v, _, _ in found if t == "hash"}
    assert hashes == {"da39a3ee5e6b4b0d3255bfef95601890afd80709",
                      "d41d8cd98f00b204e9800998ecf8427e"}


def test_fim_hash_extracted():
    found = integration.candidates({
        "rule": {"id": "550"},
        "syscheck": {"sha256_after": "a" * 64}})
    assert ("hash", "a" * 64, "syscheck.sha256_after", "artifact") in found


def _launch(monkeypatch, tmp_path, alert, iocs=(), age_hours=1.0):
    """Runs the integration on an alert, returns the reinjected events."""
    path = str(tmp_path / "ioc.db")
    cti.write_cache(list(iocs), path)
    if age_hours != 1.0:
        conn = sqlite3.connect(path)
        conn.execute("UPDATE meta SET value = ? WHERE key = 'synced_at'",
                     ((datetime.now(timezone.utc)
                       - timedelta(hours=age_hours)).isoformat(),))
        conn.commit()
        conn.close()
    monkeypatch.setattr(integration, "CACHE", path)
    monkeypatch.setattr(integration, "EXPIRY_WITNESS",
                        str(tmp_path / "witness"))

    sent = []
    monkeypatch.setattr(integration, "send", sent.append)

    file = tmp_path / "alert.json"
    file.write_text(json.dumps(alert))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(file)])
    integration.main()
    return sent


def test_no_loop_on_our_own_alerts(monkeypatch, tmp_path):
    # A 100952 alert carries the same IOC as the one that produced it:
    # reprocessing it would reinject an event, which would match again,
    # forever — and the loop would be fed by the fleet's normal traffic.
    alert = _alert(rule={"id": "100952", "description": "CTI - outbound"},
                     data={"srcip": "185.220.101.1"})
    assert _launch(monkeypatch, tmp_path, alert,
                   [_ioc("185.220.101.1")]) == []


def test_no_reprocessing_of_an_enrichment_alert(monkeypatch, tmp_path):
    alert = _alert(rule={"id": "100622", "description": "AbuseIPDB"},
                     data={"integration": "custom-abuseipdb",
                           "srcip": "185.220.101.1"})
    assert _launch(monkeypatch, tmp_path, alert,
                   [_ioc("185.220.101.1")]) == []


def test_event_enriched_on_a_match(monkeypatch, tmp_path):
    alert = _alert(data={"srcip": "185.220.101.1"})
    sent = _launch(monkeypatch, tmp_path, alert, [_ioc("185.220.101.1")])
    assert len(sent) == 1
    misp = sent[0]["misp"]
    assert sent[0]["integration"] == "custom-misp"
    assert (misp["ioc"], misp["direction"], misp["confidence"]) == (
        "185.220.101.1", "inbound", "curated")
    assert misp["source_alert_rule_id"] == "5710"
    assert misp["agent"] == "web01"
    # srcip at the root: this is what makes the ingest pipeline geolocate the
    # IOC, as for custom-abuseipdb.
    assert sent[0]["srcip"] == "185.220.101.1"


def test_misp_links_set_on_the_event(monkeypatch, tmp_path):
    monkeypatch.setattr(cti.config, "MISP_BASE_URL", "https://misp.example.fr")
    sent = _launch(monkeypatch, tmp_path, _alert(data={"srcip": "185.220.101.1"}),
                      [_ioc("185.220.101.1")])
    misp = sent[0]["misp"]
    # The link comes from the PUBLIC URL, not from the client's call address:
    # a link to loopback is only clickable from the manager.
    assert misp["event_url"] == "https://misp.example.fr/events/view/42"
    assert misp["search_url"] == (
        "https://misp.example.fr/events/index/searchall:185.220.101.1")


def test_bulk_ioc_has_no_event_but_keeps_a_link(monkeypatch, tmp_path):
    monkeypatch.setattr(cti.config, "MISP_BASE_URL", "https://misp.example.fr")
    ioc = _ioc("1.1.1.2", source="data-shield", confidence=cti.CONFIDENCE_BULK)
    ioc["event_id"] = ""     # blocklists live in a Redis cache, with no event
    sent = _launch(monkeypatch, tmp_path,
                      _alert(data={"srcip": "1.1.1.2"}), [ioc])
    misp = sent[0]["misp"]
    assert misp["event_url"] == ""
    # Without this search link, the analyst would have no entry point into
    # MISP for the largest half of the intelligence.
    assert misp["search_url"].endswith("searchall:1.1.1.2")


def test_cache_without_a_public_url_does_not_break_enrichment(monkeypatch, tmp_path):
    # Cache written by an earlier version: no base_url meta. Detection must
    # keep working, with no links — not crash.
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("185.220.101.1")], path)
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM meta WHERE key = 'base_url'")
    conn.commit()
    conn.close()
    monkeypatch.setattr(integration, "CACHE", path)
    monkeypatch.setattr(integration, "EXPIRY_WITNESS", str(tmp_path / "witness"))
    sent = []
    monkeypatch.setattr(integration, "send", sent.append)
    file = tmp_path / "alert.json"
    file.write_text(json.dumps(_alert(data={"srcip": "185.220.101.1"})))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(file)])
    integration.main()
    assert sent[0]["misp"]["ioc"] == "185.220.101.1"
    assert sent[0]["misp"]["event_url"] == ""


def test_all_enriched_fields_are_in_english(monkeypatch, tmp_path):
    # These names go into alerts, dashboards and IRIS cases, alongside
    # Wazuh's native fields. This test pins the contract: rules 100951-100956
    # match on them, renaming them without following through makes the rules
    # silently mute.
    sent = _launch(monkeypatch, tmp_path, _alert(data={"srcip": "185.220.101.1"}),
                      [_ioc("185.220.101.1")])
    assert set(sent[0]["misp"]) == {
        "ioc", "ioc_type", "field", "direction", "source", "confidence",
        "category", "event_info", "event_id", "event_url", "search_url",
        "tags", "threat_level", "match_count", "source_alert_rule_id",
        "source_alert_description", "agent", "agent_id"}


def test_no_match_no_event(monkeypatch, tmp_path):
    alert = _alert(data={"srcip": "185.220.101.1"})
    assert _launch(monkeypatch, tmp_path, alert, [_ioc("9.9.9.9")]) == []


def test_curated_outbound_takes_priority_over_bulk_inbound(monkeypatch, tmp_path):
    # The same alert often carries both: a scanner's source IP (noise) and a
    # C2 destination IP (incident). Only one event is reinjected, and it must
    # carry the second.
    alert = _alert(data={"srcip": "1.1.1.2", "dstip": "23.45.67.89"})
    sent = _launch(monkeypatch, tmp_path, alert, [
        _ioc("1.1.1.2", source="data-shield", confidence=cti.CONFIDENCE_BULK),
        _ioc("23.45.67.89", source="ThreatFox", confidence=cti.CONFIDENCE_CURATED),
    ])
    assert sent[0]["misp"]["ioc"] == "23.45.67.89"
    assert sent[0]["misp"]["direction"] == "outbound"
    assert sent[0]["misp"]["match_count"] == "2"


def test_stale_cache_reported_only_once(monkeypatch, tmp_path):
    alert = _alert(data={"srcip": "185.220.101.1"})
    sent = _launch(monkeypatch, tmp_path, alert, [_ioc("9.9.9.9")],
                      age_hours=72)
    assert len(sent) == 1 and "error" in sent[0]["misp"]

    # Immediate second pass: the witness must muzzle the reminder, otherwise
    # the SOC drowns in its own failure indicator — one alert per alert
    # processed.
    sent = _launch(monkeypatch, tmp_path, alert, [_ioc("9.9.9.9")],
                      age_hours=72)
    assert sent == []


def test_missing_cache_reported_without_crashing(monkeypatch, tmp_path):
    monkeypatch.setattr(integration, "CACHE", str(tmp_path / "absent.db"))
    monkeypatch.setattr(integration, "EXPIRY_WITNESS", str(tmp_path / "witness"))
    sent = []
    monkeypatch.setattr(integration, "send", sent.append)
    file = tmp_path / "alert.json"
    file.write_text(json.dumps(_alert(data={"srcip": "185.220.101.1"})))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(file)])
    integration.main()
    assert len(sent) == 1 and "error" in sent[0]["misp"]


# --- Confidence from tags ----------------------------------------------------

def test_unsupervised_automaton_treated_as_bulk():
    # Measured on 2026-08-12: the CIRCL OSINT feed relays Maltrail's daily
    # publications, that is 255,361 of the 692,543 "curated" IOCs in the
    # cache, all with to_ids=1. As `curated` they matched at levels 12 to 14
    # — an incident and an LLM triage per match, on something that is by
    # construction a blocklist. The MISP taxonomy announces it itself.
    assert cti._confidence([cti.TAG_NON_SUPERVISED, "tlp:clear"]) == cti.CONFIDENCE_BULK


def test_extraction_stays_distinct_from_curated():
    assert cti._confidence([cti.TAG_EXTRACTION]) == cti.CONFIDENCE_EXTRACTED
    assert cti._confidence(["tlp:clear", "type:OSINT"]) == cti.CONFIDENCE_CURATED


def test_the_most_cautious_wins_when_both_tags_are_present():
    assert cti._confidence([cti.TAG_EXTRACTION,
                           cti.TAG_NON_SUPERVISED]) == cti.CONFIDENCE_BULK
