"""VOC: exposure score, SLA, closure, matching against an incident.

Everything tested here is PURE (no indexer, no database) except the closure
part, covered with a fake cursor. Two properties are worth all the rest and
justify this file on their own:

- a machine that stopped answering must NEVER produce a remediation
  (`test_closure_only_touches_seen_agents`) — it is the only lie this module
  could tell, and it would be invisible: a perfect burn-down;
- a CVE is only "linked to the incident" if it is CITED there, never because
  it is severe and the machine is under attack.
"""

from datetime import datetime, timedelta, timezone

import pytest

from soc_agent import config, vulns

T0 = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)


# --- Effective severity -------------------------------------------------------

def test_feed_severity_takes_priority_over_the_score():
    assert vulns.effective_severity("High", 2.0) == "high"


def test_empty_severity_deduced_from_the_cvss_score():
    # 334 CVEs per Debian host arrive with no severity but with a score:
    # discarding them all at "unknown" weight would throw away information we
    # actually have.
    assert vulns.effective_severity("", 9.8) == "critical"
    assert vulns.effective_severity(None, 7.5) == "high"
    assert vulns.effective_severity("untriaged", 5.0) == "medium"
    assert vulns.effective_severity("", 1.0) == "low"


def test_absent_severity_and_absent_score_stays_undetermined():
    assert vulns.effective_severity("", None) == ""
    assert vulns.weight("") == pytest.approx(0.5)


# --- Exposure score -------------------------------------------------------------

def test_score_zero_without_vulnerability():
    assert vulns.risk_score(0) == 0


def test_score_grows_with_the_load():
    scores = [vulns.risk_score(c) for c in (10, 100, 1000, 10000)]
    assert scores == sorted(scores)
    assert all(0 <= s <= 100 for s in scores)


def test_score_saturates_at_the_ceiling():
    # Assumed property, written wherever the score is displayed: two machines
    # at 100 are no longer comparable to each other.
    assert vulns.risk_score(config.VOC_MAX_LOAD) == 100
    assert vulns.risk_score(config.VOC_MAX_LOAD * 10) == 100


def test_weight_scale_very_non_linear():
    # Otherwise the score would be dominated by the background noise of the
    # distributions and rank machines by number of installed packages.
    assert vulns.weight("critical") >= 10 * vulns.weight("medium")
    assert vulns.weight("critical") >= 50 * vulns.weight("low")
    assert vulns.weight("high") > vulns.weight("medium") > vulns.weight("low")


def test_readable_level_bounded():
    assert vulns.risk_level(0) == "nulle"
    assert vulns.risk_level(90) == "critique"
    assert vulns.risk_level(65) == "élevée"


# --- SLA -------------------------------------------------------------------------

def test_sla_shorter_on_a_critical_asset():
    assert vulns.sla_days("critical", 1) < vulns.sla_days("critical", 4)


def test_sla_shorter_for_a_more_severe_severity():
    assert vulns.sla_days("critical", 2) < vulns.sla_days("low", 2)


def test_no_sla_on_unclassified_severity():
    # We do not demand compliance with a deadline we were unable to set.
    assert vulns.sla_days("", 1) is None


def test_out_of_range_priority_clamped():
    # An aberrant priority (0, 9) must not raise an IndexError in the middle of
    # an exposure computation: it is clamped into P1..P4.
    assert vulns.sla_days("high", 0) == vulns.sla_days("high", 1)
    assert vulns.sla_days("high", 9) == vulns.sla_days("high", 4)


# --- Matching against an incident ---------------------------------------------

def _alert(desc="", raw=None, mitre=None):
    return {"rule_desc": desc, "raw": raw or {},
            "mitre_ids": mitre or []}


def test_cve_cited_in_the_description_spotted():
    assert vulns.cited_cves([_alert("Exploit CVE-2021-4034 detected")]) == {
        "CVE-2021-4034"}


def test_cve_cited_in_the_raw_log_spotted_and_normalised():
    a = _alert(raw={"full_log": "curl -O poc-cve-2024-3094.sh"})
    assert vulns.cited_cves([a]) == {"CVE-2024-3094"}


def test_text_without_cve_produces_nothing():
    assert vulns.cited_cves([_alert("ssh brute force"),
                             _alert(raw={"full_log": "CVE- incomplet"})]) == set()


class _FakeCursor:
    """Postgres connection reduced to what `incident_link` does with it: a
    single query, the open vulnerabilities of the agent."""

    def __init__(self, open_by_cve):
        self._open = open_by_cve

    def execute(self, sql, params=None):
        return list(self._open)


def _vuln(cve, severity="critical", score=9.8, age=10.0):
    return {"cve": cve, "package": "openssl", "version": "1.1", "age_days": age,
            "severity": severity, "base_score": score, "published_at": None,
            "first_seen": T0 - timedelta(days=age)}


_EXPO_EMPTY = {"worst": [], "covered": True}


def test_cve_cited_and_open_is_confirmed():
    conn = _FakeCursor([_vuln("CVE-2021-4034")])
    link = vulns.incident_link(conn, "013",
                               [_alert("exploit CVE-2021-4034")], _EXPO_EMPTY)
    assert [v["cve"] for v in link["confirmed"]] == ["CVE-2021-4034"]
    assert link["quoted_not_open"] == []


def test_cve_cited_but_not_open_stays_apart():
    # Attempt against a non-vulnerable version: information about the
    # attacker's METHOD, not about the host's exposure. Must not surface in
    # `confirmed`, on which the report writes "the same access remains
    # reproducible".
    conn = _FakeCursor([_vuln("CVE-2021-4034")])
    link = vulns.incident_link(conn, "013",
                               [_alert("scan CVE-2017-0144")], _EXPO_EMPTY)
    assert link["confirmed"] == []
    assert link["quoted_not_open"] == ["CVE-2017-0144"]


def test_no_vector_proposed_without_an_exploit_technique():
    # The trap this rule avoids: listing the machine's worst CVEs next to an
    # incident that has nothing to do with them. The analyst would make the
    # link on our behalf.
    expo = {"worst": [_vuln("CVE-2024-0001")], "covered": True}
    link = vulns.incident_link(_FakeCursor([]), "013",
                               [_alert("ssh brute force", mitre=["T1110"])],
                               expo)
    assert link["possible_vectors"] == []
    assert link["exploit_techniques"] == []


def test_vectors_proposed_on_an_exploit_technique():
    expo = {"worst": [_vuln("CVE-2024-0001"),
                      _vuln("CVE-2024-0002", "medium", 5.0)],
            "covered": True}
    link = vulns.incident_link(
        _FakeCursor([]), "013",
        [_alert("privilege escalation", mitre=["T1068"])], expo)
    assert link["exploit_techniques"] == ["T1068"]
    # Only the severe ones: proposing a medium as the vector of a privesc
    # would drown the lead.
    assert [v["cve"] for v in link["possible_vectors"]] == ["CVE-2024-0001"]


# --- Closure: the guardrail that matters ---------------------------------------

def test_closure_only_touches_seen_agents():
    """The closure query MUST be bounded to the agents that answered.

    Without this bound, a stopped agent (or one whose syscollector is broken)
    drops out of the state index with all its vulnerabilities, and the diff
    concludes a mass remediation: perfect burn-down, magnificent MTTR,
    invisible estate. Tested on the SQL text for lack of a database: it is the
    clause whose absence would produce no error, only a lie.
    """
    assert "agent_id = ANY(%(agents)s)" in vulns.CLOSURE
    assert "status = 'fixed'" in vulns.CLOSURE


def test_upsert_does_not_rewrite_the_first_seen_date():
    """`first_seen` is what makes the SLA run: rewriting it on every scan would
    reset all the overdue counters to zero on every pass, and the VOC would
    congratulate itself. Only a vulnerability that REAPPEARS after being fixed
    restarts."""
    assert "first_seen        = CASE WHEN vulnerabilities.status = 'fixed'" \
        in vulns.UPSERT


# --- Flattening a Wazuh document -------------------------------------------------

_DOC = {
    "agent": {"id": "013", "name": "debian2"},
    "package": {"name": "linux-image-amd64", "version": "6.1.174-1"},
    "vulnerability": {"id": "CVE-2026-43105", "severity": "Medium",
                      "score": {"base": 5.5},
                      "published_at": "2026-05-06T10:16:24Z"},
    "host": {"os": {"full": "Debian GNU/Linux 12 (bookworm)"}},
}


def test_flatten_full_document():
    v = vulns._flatten(_DOC)
    assert v["agent_id"] == "013"
    assert v["cve"] == "CVE-2026-43105"
    assert v["package"] == "linux-image-amd64"
    assert v["severity"] == "medium"
    assert v["base_score"] == pytest.approx(5.5)


def test_missing_package_replaced_by_a_stable_label():
    # Vulnerability of the OS itself (Windows, fixed by a hotfix): NULL would
    # break the uniqueness key (agent, cve, package).
    doc = {**_DOC, "package": {}}
    assert vulns._flatten(doc)["package"] == "(système)"


def test_document_without_cve_ignored():
    assert vulns._flatten({**_DOC, "vulnerability": {}}) is None
