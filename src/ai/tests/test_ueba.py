"""UEBA engine: trait extraction, rarity, MITRE chain, grouping.

Everything tested here is PURE (no database): this is precisely the part that
decides what goes to the LLM, hence the part that must stay verifiable without
standing up an infra. The Postgres-backed functions (`observe`, `evaluate`,
`purge`) are covered against the real server, not here.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from soc_agent import config, ueba
from soc_agent.anonymize import Anonymizer, anonymize, check_leak
from soc_agent.render import render

T0 = datetime(2026, 8, 5, 10, 0, tzinfo=timezone.utc)   # mercredi, ouvré


def alert(**kw):
    base = {
        "id": "1.1", "ts": T0, "agent_id": "002", "agent_name": "debian-vm",
        "rule_id": "80792", "rule_level": 3, "rule_desc": "Command executed",
        "rule_groups": ["audit"], "mitre_tactics": [], "srcip": None,
        "srcuser": None, "entity": None, "raw": {},
    }
    base.update(kw)
    return base


# --- Trait extraction ---------------------------------------------------------

def test_traits_exe_and_user_scope():
    a = alert(srcuser="jdupont",
               raw={"data": {"audit": {"exe": "/usr/bin/nc"}}})
    t = ueba.traits(a)
    assert ("host", "002", "exe", "/usr/bin/nc") in t
    # The same trait is observed TWICE: once for the machine, once for the
    # account/machine pair. It is this second scope that sees lateral
    # movement (a legitimate account on a host it never served on).
    assert ("user@host", "jdupont@002", "exe", "/usr/bin/nc") in t


def test_traits_without_account_no_catch_all_scope():
    """An "unknown@host" would create a profile where everything ends up looking normal."""
    a = alert(raw={"data": {"audit": {"exe": "/usr/bin/nc"}}})
    assert all(s == "host" for s, _, _, _ in ueba.traits(a))


def test_traits_generic_shell_ignored():
    """The first `bash` of a machine must not be worth 12 bits."""
    a = alert(raw={"data": {"audit": {"exe": "/bin/bash"}}})
    assert not [t for t in ueba.traits(a) if t[2] == "exe"]


def test_traits_parent_child_windows():
    a = alert(agent_id="010", raw={"data": {"win": {"eventdata": {
        "parentImage": r"C:\Program Files\nginx\nginx.exe",
        "image": r"C:\Windows\System32\cmd.exe"}}}})
    t = ueba.traits(a)
    assert ("host", "010", "parent_child", "nginx.exe>cmd.exe") in t


def test_traits_hour_slot_business_or_not():
    opens = ueba.traits(alert(ts=T0))
    night = ueba.traits(alert(ts=T0.replace(hour=3)))
    assert ("host", "002", "hour", "business") in opens
    assert ("host", "002", "hour", "off_hours") in night


def test_traits_raw_json_serialized():
    """`alerts.raw` comes back sometimes as a dict, sometimes as text depending on the caller."""
    a = alert(raw=json.dumps({"data": {"audit": {"exe": "/opt/x/impl"}}}))
    assert ("host", "002", "exe", "/opt/x/impl") in ueba.traits(a)


# --- Rarity --------------------------------------------------------------------

def test_surprisal_decreases_with_frequency():
    rare = ueba.surprisal(1, 10_000, 50)
    current = ueba.surprisal(5_000, 10_000, 50)
    assert rare > current
    assert current < 2.0


def test_surprisal_never_infinite():
    """Laplace smoothing bounds the score of a still-thin profile."""
    assert ueba.surprisal(0, 0, 0) < 2.0
    assert ueba.surprisal(0, 100, 3) < 10.0


def test_immature_profile_does_not_score():
    """On day one, everything is unseen: scoring would send the whole fleet to the LLM."""
    bits, _ = ueba._trait_bits(None, None, 0, mature=False)
    assert bits == 0.0


def test_first_seen_moderated_by_the_fleet():
    """Unseen here but mundane elsewhere = admin rollout, not intrusion."""
    alone, note_alone = ueba._trait_bits(None, None, 0, mature=True)
    everywhere, _ = ueba._trait_bits(None, None, 12, mature=True)
    assert alone == config.UEBA_FIRSTSEEN_BITS
    assert "flotte" in note_alone
    assert everywhere < alone / 4


def test_habit_no_longer_scores():
    """Seen on enough DISTINCT days: it is a routine."""
    profile = {"total": 40, "days_seen": config.UEBA_DAYS_USUAL + 1,
              "seen_in_tp": False}
    bits, _ = ueba._trait_bits(profile, {"total": 100, "distinct_values": 5}, 0, True)
    assert bits == 0.0


def test_seen_in_true_positive_never_becomes_a_habit():
    """Otherwise an attacker normalises their tooling by running it every day."""
    profile = {"total": 5_000, "days_seen": 300, "seen_in_tp": True}
    bits, note = ueba._trait_bits(profile, {"total": 5_000, "distinct_values": 2},
                                  40, True)
    assert bits == config.UEBA_FIRSTSEEN_BITS
    assert "vrai positif" in note


# --- MITRE chain ---------------------------------------------------------------

def test_chain_below_minimum_does_not_bonus():
    assert ueba.chain_bonus(["Discovery", "Discovery"]) == (0.0, None)


def test_three_discovery_worth_less_than_a_real_chain():
    """The raw "3 tactics" mostly surfaces the admin inventorying their machine."""
    weak, _ = ueba.chain_bonus(["Discovery", "Execution", "Reconnaissance"])
    high, phrase = ueba.chain_bonus(
        ["Initial Access", "Persistence", "Credential Access", "Exfiltration"])
    assert high > weak * 2
    assert "progression kill-chain" in phrase


def test_order_bonus_rewards_progression():
    ordered, _ = ueba.chain_bonus(
        ["Initial Access", "Execution", "Persistence", "Exfiltration"])
    disorder, _ = ueba.chain_bonus(
        ["Exfiltration", "Persistence", "Execution", "Initial Access"])
    assert ordered > disorder


# --- Grouping and scoring of a signal ------------------------------------------

def test_grouping_cuts_on_agent_and_on_window():
    far = T0 + timedelta(minutes=config.UEBA_WINDOW_MINUTES + 10)
    alerts = [
        alert(id="a", ts=T0),
        alert(id="b", ts=T0 + timedelta(minutes=5)),
        alert(id="c", ts=far),                 # too far -> new group
        alert(id="d", ts=far, agent_id="003"),  # other agent -> new group
    ]
    groups = ueba._group_signals(alerts)
    assert [len(g) for g in groups] == [2, 1, 1]


def test_grouping_bounds_the_total_duration():
    """Chaining is step-by-step: without a cap, a host emitting one alert every
    50 min agglomerates its whole day into a single signal."""
    step = timedelta(minutes=config.UEBA_WINDOW_MINUTES - 1)
    n = int(config.UEBA_SIGNAL_MAX_HOURS * 60 / (step.seconds / 60)) + 3
    alerts = [alert(id=str(i), ts=T0 + step * i) for i in range(n)]
    groups = ueba._group_signals(alerts)
    assert len(groups) > 1
    for g in groups:
        span = g[-1]["ts"] - g[0]["ts"]
        assert span <= timedelta(hours=config.UEBA_SIGNAL_MAX_HOURS)


def test_signal_score_saturates_repetitions():
    """Forty times the same rare binary is not worth forty times the score."""
    trait = {"trait": "exe", "value": "/opt/impl", "scope": "host",
             "bits": 12.0, "note": "jamais vu"}
    one = ueba.score_group([alert(ueba_traits=[trait])])[0]
    forty = ueba.score_group(
        [alert(id=str(i), ueba_traits=[trait]) for i in range(40)])[0]
    assert one == forty


def test_signal_score_accumulates_distinct_traits():
    a = alert(ueba_traits=[{"trait": "exe", "value": "/opt/impl",
                             "scope": "host", "bits": 12.0, "note": ""}])
    b = alert(id="2", ueba_traits=[{"trait": "country", "value": "Russia",
                                     "scope": "host", "bits": 9.0, "note": ""}])
    score, patterns = ueba.score_group([a, b])
    assert score == pytest.approx(21.0)
    assert {m["trait"] for m in patterns} == {"exe", "country"}


def test_signal_score_adds_the_chain_bonus():
    traits = [{"trait": "exe", "value": "/opt/impl", "scope": "host",
               "bits": 12.0, "note": ""}]
    without = ueba.score_group([alert(ueba_traits=traits)])[0]
    withit, patterns = ueba.score_group([
        alert(ueba_traits=traits, mitre_tactics=["Initial Access"]),
        alert(id="2", mitre_tactics=["Persistence"], ueba_traits=[]),
        alert(id="3", mitre_tactics=["Exfiltration"], ueba_traits=[]),
    ])
    assert withit > without
    assert any(m["trait"] == "mitre_chain" for m in patterns)


# --- Prompt integration: rendering, pseudonymisation, leak guardrail ----------

def _incident_ueba():
    return {
        "id": 1, "agent_id": "002", "agent_name": "debian-vm",
        "first_seen": T0, "last_seen": T0 + timedelta(minutes=10),
        "alert_count": 6, "max_level": 5, "mitre_tactics": ["Execution"],
        "entities": [], "ueba": True, "ueba_score": 41.5,
        "ueba_patterns": [
            {"trait": "exe", "value": "/home/jdupont/.cache/impl",
             "scope": "host", "bits": 12.0,
             "note": "jamais vu ici ni ailleurs sur la flotte"},
            {"trait": "account", "value": "jdupont", "scope": "host",
             "bits": 7.2, "note": "rare : 2x sur 4000 observations"},
            {"trait": "srcip", "value": "192.168.10.12", "scope": "host",
             "bits": 6.0, "note": "inédit ici"},
            {"trait": "country", "value": "Russia", "scope": "host",
             "bits": 9.0, "note": "jamais vu ici ni ailleurs sur la flotte"},
        ],
    }


def test_rendering_explains_why_a_level_5_incident_is_opened():
    """Without this, the model sees level 5 and mechanically concludes FP."""
    text = render(_incident_ueba(), [alert(id="a")])
    assert "UEBA" in text
    assert "41.5" in text
    assert "jamais vu ici ni ailleurs" in text


def test_ueba_patterns_pseudonymised_before_cloud_submission():
    """The patterns carry RAW log values: paths, accounts, IPs.

    Without pseudonymisation, `check_leak` (fail-closed) would refuse the
    incident and EVERYTHING the engine surfaces would be silently dropped from
    triage.
    """
    anon = Anonymizer()
    alerts = [alert(id="a", srcuser="jdupont", srcip="192.168.10.12",
                      entity="/home/jdupont/.cache/impl")]
    inc, alerts_to, forbidden = anonymize(anon, _incident_ueba(), alerts)

    text = render(inc, alerts_to)
    check_leak(text, forbidden)   # must not raise

    assert "jdupont" not in text
    assert "192.168.10.12" not in text
    # The ATTRIBUTE stays: it carries the signal and identifies no one.
    assert "Russia" in text


def test_country_and_attributes_not_tokenised():
    anon = Anonymizer()
    inc, _, _ = anonymize(anon, _incident_ueba(), [])
    by_trait = {m["trait"]: m["value"] for m in inc["ueba_patterns"]}
    assert by_trait["country"] == "Russia"
    assert by_trait["account"].startswith("<COMPTE_")
    assert by_trait["srcip"].startswith("<IP_")


# --- Remediation guardrail ----------------------------------------------------

def test_ueba_incident_does_not_trigger_autonomous_remediation(monkeypatch):
    """The pipeline acts alone because it starts from a Wazuh rule of level >= 12.

    A UEBA incident starts from an UNCALIBRATED statistical score: letting it
    isolate a host would mean handing production over to a threshold we never
    measured.
    """
    from soc_agent import iris

    monkeypatch.setattr(config, "UEBA_MITIGATE", False)
    assert iris._remediation_allowed(
        {"id": 1, "ueba": True, "ueba_score": 41}) is False
    # The normal pipeline (level >= 12 seed) is NOT affected: it keeps acting
    # autonomously, which is the whole point of the project.
    assert iris._remediation_allowed({"id": 1, "ueba": False}) is True


def test_ueba_remediation_reactivatable_by_configuration(monkeypatch):
    from soc_agent import iris

    monkeypatch.setattr(config, "UEBA_MITIGATE", True)
    assert iris._remediation_allowed({"id": 1, "ueba": True}) is True


# --- Cardinality guardrail -----------------------------------------------------

def test_trait_with_explosive_cardinality_is_muted():
    """LVM archives, timestamped paths, GUIDs: unseen BY CONSTRUCTION.

    Measured at commissioning: the LVM archives of the Proxmox host alone gave
    a signal at 1434 points, forty times the floor.
    """
    explosive = {"total": 5_000, "distinct_values": 4_900}
    assert ueba.usable_cardinality(explosive) is False
    bits, _ = ueba._trait_bits(None, explosive, 0, mature=True)
    assert bits == 0.0


def test_normal_trait_stays_scorable():
    normal = {"total": 5_000, "distinct_values": 60}
    assert ueba.usable_cardinality(normal) is True
    bits, _ = ueba._trait_bits(None, normal, 0, mature=True)
    assert bits == config.UEBA_FIRSTSEEN_BITS


def test_cardinality_does_not_conclude_without_enough_history():
    """Few observations: we do not exclude a trait for lack of data."""
    assert ueba.usable_cardinality({"total": 10, "distinct_values": 10}) is True
    assert ueba.usable_cardinality(None) is True


def test_exe_does_not_take_fim_paths():
    """`entity` is syscheck.path: a registry key on Windows, an LVM archive on
    Proxmox. Neither is an executable."""
    a = alert(entity=r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Run")
    traits_ = ueba.traits(a)
    assert not [t for t in traits_ if t[2] == "exe"]
    # Kept, but as a `file` trait, weighing less and subject to the
    # cardinality guardrail.
    assert [t for t in traits_ if t[2] == "file"]


def test_every_non_attribute_trait_is_pseudonymised():
    """Non-regression lock on adding a new trait.

    The `file` trait was added to ueba.py without being declared here: paths
    went out in clear text, `check_leak` refused the incident (fail-closed)
    and UEBA triage went silent. Pseudonymisation therefore works by an
    EXCLUSION list — an unknown trait is masked, not let through.
    """
    from soc_agent.anonymize import UEBA_TRAIT_ATTRIBUTES

    unknown = [t for t in ueba.WEIGHT if t not in UEBA_TRAIT_ATTRIBUTES]
    patterns = [{"trait": t, "value": r"C:\Users\jdupont\secret.exe",
               "scope": "host", "bits": 9.0, "note": ""} for t in unknown]
    patterns.append({"trait": "trait_invented_tomorrow",
                   "value": "/home/jdupont/x.sh", "scope": "host",
                   "bits": 9.0, "note": ""})

    inc = dict(_incident_ueba(), ueba_patterns=patterns)
    anon = Anonymizer()
    inc_a, _, forbidden = anonymize(anon, inc, [])

    text = render(inc_a, [])
    check_leak(text, forbidden)      # must not raise
    assert "jdupont" not in text
    assert "secret" not in text


def test_machine_account_carries_no_trait():
    """An AD machine account (`WIN-DC$`) is not a person.

    It authenticates continuously on behalf of services: profiling it amounts
    to profiling the machine's background noise. Measured in production:
    incident #2550 (IRIS case #193) counted 4598 alerts, of which 3856 carried
    by `WIN-DC$` — domain controller session open/close events, told by the
    LLM as a confirmed compromise.
    """
    for account in ("WIN-DC$", "WIN-DC$@LAB.LOCAL", "SERVICE LOCAL",
                   "Système", "ANONYMOUS LOGON"):
        traits_ = ueba.traits(alert(srcuser=account))
        assert not [t for t in traits_ if t[2] == "account"], account
        # The `user@host` scope also disappears: it would aggregate all the
        # machine's service traffic under a single identity.
        assert not [t for t in traits_ if t[0] == "user@host"], account


def test_person_account_stays_scored():
    """The guardrail must not sweep away real accounts — that is where lateral
    movement lives (a legitimate account on a host it never served on)."""
    traits_ = ueba.traits(alert(srcuser="j.dupont"))
    assert [t for t in traits_ if t[2] == "account"]
    assert [t for t in traits_ if t[0] == "user@host"]
