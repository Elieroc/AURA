"""Tests for grouping alerts into incidents.

`_group` is a pure function: it takes a list of alerts and returns groups,
with no database. That is deliberate — the logic that decides an attack is
one incident and not thirty is the part of the code where a mistake costs the
most, and it must stay verifiable without infrastructure.

    ~/.local/share/soc-ai/venv/bin/python -m pytest ai/tests -q
"""

from datetime import datetime, timedelta, timezone

from soc_agent.correlate import (_is_valid_seed, _group, _signal_decisive,
                                 common_ground)

T0 = datetime(2026, 7, 22, 10, 0, tzinfo=timezone.utc)


def alert(minutes=0, agent="001", rule="100670", level=15,
           groups=("ransomware",), tactics=("Impact",), srcip=None,
           srcuser=None, entity=None):
    return {
        "id": f"a{minutes}-{rule}-{entity or srcip or ''}",
        "ts": T0 + timedelta(minutes=minutes),
        "agent_id": agent, "agent_name": agent,
        "rule_id": rule, "rule_level": level,
        "rule_groups": list(groups), "mitre_tactics": list(tactics),
        "srcip": srcip, "srcuser": srcuser, "entity": entity,
    }


def test_burst_same_tactic_makes_one_incident():
    """The 25 canary ransomware alerts are one incident, not 25."""
    alerts = [alert(minutes=i, entity=f"/data/f{i}.docx") for i in range(25)]
    assert len(_group(alerts)) == 1


def test_different_agents_never_merged():
    alerts = [alert(agent="001"), alert(minutes=1, agent="002")]
    assert len(_group(alerts)) == 2


def test_weak_link_outside_window_separates():
    """Same tactic but 45 min later: two incidents (30 min window)."""
    alerts = [alert(minutes=0), alert(minutes=45)]
    assert len(_group(alerts)) == 2


def test_strong_link_survives_a_wide_window():
    """Same hostile IP 68 min apart: a single campaign.

    This is the real case that motivated the two-speed window — three
    AbuseIPDB alerts from 185.220.101.34 spread over the afternoon.
    """
    alerts = [
        alert(minutes=0, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="185.220.101.34"),
        alert(minutes=68, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="185.220.101.34"),
    ]
    assert len(_group(alerts)) == 1


def test_foreign_alert_in_between_does_not_cut_the_incident():
    """Several incidents stay open in parallel on the same agent.

    With only one incident open per agent, the foreign alert in the middle
    used to close the first one and the two alerts from the same IP ended up
    separated.
    """
    alerts = [
        alert(minutes=0, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="1.2.3.4"),
        alert(minutes=1, rule="87105", tactics=("Execution",),
               groups=("virustotal",), entity="/tmp/eicar.com"),
        alert(minutes=40, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="1.2.3.4"),
    ]
    groups = _group(alerts)
    assert len(groups) == 2
    assert sorted(len(g) for g in groups) == [1, 2]


def test_different_ips_stay_separate():
    alerts = [
        alert(minutes=0, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="1.2.3.4"),
        alert(minutes=5, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="9.9.9.9"),
    ]
    # The "abuseipdb" group is not generic: it links them anyway, and that is
    # intended — two IPs reported back to back belong to the same subject.
    # The test pins this behaviour so a change can only be deliberate.
    assert len(_group(alerts)) == 1


def test_generic_groups_link_nothing():
    """`syscheck` or `pci_dss` sit on half the rules."""
    a = alert(rule="550", groups=("syscheck", "pci_dss"), tactics=())
    b = alert(minutes=5, rule="554", groups=("syscheck", "gdpr"), tactics=())
    assert common_ground(a, b) is None
    assert len(_group([a, b])) == 2


def test_max_duration_cuts_the_chain():
    """One alert every 10 min for 10 h is not a single 10 h incident."""
    alerts = [alert(minutes=10 * i) for i in range(60)]
    groups = _group(alerts)
    assert len(groups) > 1
    for g in groups:
        assert g[-1]["ts"] - g[0]["ts"] <= timedelta(hours=6)


def test_strong_link_takes_priority_over_weak_link():
    a = alert(srcip="1.2.3.4")
    b = alert(minutes=1, srcip="1.2.3.4")
    assert common_ground(a, b) == ("same source IP", True)


# --- Seed filtering: structural noise never opens an incident ---------------

def test_sca_noise_seed_rejected():
    """A CIS/SCA compliance check never founds a case, even at a high level."""
    a = alert(rule="19001", level=12, groups=("sca",), tactics=(),
               entity=None)
    a["rule_desc"] = "CIS Debian benchmark: ensure X"
    assert _is_valid_seed(a) is False


def test_agent_status_noise_seed_rejected():
    a = alert(rule="503", level=12, groups=("ossec",), tactics=())
    a["rule_desc"] = "Wazuh agent stopped."
    assert _is_valid_seed(a) is False


def test_successful_login_noise_seed_rejected():
    a = alert(rule="5715", level=12, groups=("authentication_success",),
               tactics=())
    a["rule_desc"] = "sshd: authentication success."
    assert _is_valid_seed(a) is False


def test_real_intrusion_seed_accepted():
    """A genuine intrusion signal (reverse shell) stays a valid seed."""
    a = alert(rule="100721", level=12, groups=("attack",),
               tactics=("Execution",))
    a["rule_desc"] = "Reverse shell probable : /dev/tcp"
    assert _is_valid_seed(a) is True


# --- fix #2: needs_refresh only fires again on a decisive signal ------------

def test_repeated_noise_signal_does_not_trigger():
    """A burst repeating already-seen rules, with no level increase, is NOT a
    decisive signal: no re-triage + report (token loop)."""
    old = {"100670", "100710"}
    new = [alert(rule="100670", level=12, groups=("attack",))]
    assert _signal_decisive(old, new, max_old=15) is False


def test_structural_noise_signal_even_with_a_new_rule_does_not_trigger():
    """A rule never seen before but STRUCTURAL (rootcheck/SCA/agent status,
    e.g. 100801 auditd missing) does not open a refresh: it is not a seed."""
    a = alert(rule="510", level=12, groups=("rootcheck",), tactics=())
    a["rule_desc"] = "Host-based anomaly detection event (rootcheck)."
    assert _signal_decisive({"100670"}, [a], max_old=15) is False


def test_real_new_rule_signal_triggers():
    """A genuinely new intrusion rule (non structural) is a decisive signal."""
    a = alert(rule="100721", level=12, groups=("attack",),
               tactics=("Execution",))
    a["rule_desc"] = "Reverse shell probable : /dev/tcp"
    assert _signal_decisive({"100670"}, [a], max_old=15) is True


def test_level_increase_signal_triggers():
    """A severity escalation always reopens a refresh, even on a known rule."""
    new = [alert(rule="100670", level=14, groups=("attack",))]
    assert _signal_decisive({"100670"}, new, max_old=12) is True


def test_ueba_signal_stays_a_single_incident():
    """A promoted signal must not get re-fragmented by correlation.

    Measured at rollout: a signal of 239 alerts came out as 8 incidents — 8
    LLM triages instead of one, each stripped of the others' context and
    carrying a score unrelated to the signal's.
    """
    from datetime import datetime, timedelta, timezone
    from soc_agent import correlate

    t0 = datetime(2026, 8, 7, 6, 0, tzinfo=timezone.utc)
    # Nothing in common between them beyond the signal: different rules,
    # objects and accounts throughout, and a gap larger than the weak window
    # (30 min).
    alerts = [{
        "id": str(i), "ts": t0 + timedelta(minutes=45 * i), "agent_id": "014",
        "agent_name": "winsrv", "rule_id": f"9{i}000", "rule_level": 3,
        "rule_desc": "x", "rule_groups": [f"g{i}"], "mitre_tactics": [],
        "srcip": None, "srcuser": None, "entity": f"/tmp/f{i}",
        "audit_uid": None, "ueba_seed": True, "ueba_signal_id": 42,
    } for i in range(6)]

    assert len(correlate._group(alerts)) == 1

    # Without the signal link, the same alerts would have genuinely
    # fragmented: it is that link which holds them, not a coincidence of the
    # fixture.
    for a in alerts:
        a["ueba_signal_id"] = None
    assert len(correlate._group(alerts)) > 1
