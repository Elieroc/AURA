"""UEBA engine — surfacing the LOW/MEDIUM alerts that deserve it.

The pipeline only opens an incident from level 12 up (`MIN_LEVEL`). Below that
everything is ingested but nothing seeds: an intrusion emitting only level 3-11
(enumeration, execution of a dropped binary, login from a country never seen,
quiet persistence) is invisible. Raising the raw threshold would drown the SOC
and the LLM bill.

This module is the third reduction stage, between the noise filter and the VT
filter on one side, and the LLM on the other:

    noise filter -> VT filter -> **UEBA (0 tokens)** -> correlation -> LLM

It does not judge: it **ranks**. Every low alert gets a score in BITS of
information, neighbouring alerts of the same agent are grouped into a "signal",
and only the best-scoring signals — within an explicit BUDGET — are promoted to
incident seeds. From there the path is everyone's: `correlate` -> `triage`
(TP/FP verdict by the LLM) -> IRIS case. The LLM never sees an isolated low
alert, it sees an incident already formed, already scored, with the explanation
of the score.

Three primitives, all deterministic and explainable to an analyst (the same
requirement as `correlate.py`):

1. **Rarity (surprisal)** — `-log2(p)` of the value observed in its scope. In
   bits: that is what makes the components SUMMABLE. Summing "points" makes no
   sense, summing bits of information does.
2. **First seen** — the value does not exist in a MATURE profile. Ceiling score,
   MODULATED by the rarity across the fleet: a binary unseen on this host but
   present on 10 others is an admin rollout, not an intrusion. That is the
   module's main anti-false-positive.
3. **MITRE chain** — several distinct tactics inside the window, weighted
   (credential-access weighs more than discovery) and bonused when they progress
   along the kill chain order.

No unsupervised ML (isolation forest, autoencoder): without a labelled set we
could not measure its drift, and an unexplainable score can neither be argued
with by an analyst nor justify a remediation. Surprisal gives the same result and
reads in one sentence.

    python -m soc_agent.ueba --state
    python -m soc_agent.ueba --simulation
"""

import argparse
import json
import math
import re
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row

from . import alerts as alerts_mod
from . import assets, config

# --- Observed traits ---------------------------------------------------------
#
# Deliberately few. Each must answer "what does it change to the verdict that
# this value is unseen?"; a trait with no answer only brings noise and cost.
#
# The WEIGHT multiplies the trait's bits. `parent_child` weighs more than `exe`:
# an `sh` alone is mundane, an `nginx -> sh` is a webshell. `hour` weighs little
# — an unusual time is a hint, never proof.
WEIGHT = {
    "exe":          1.0,   # executed binary
    "file":         0.8,   # object of an integrity alert (FIM)
    "parent_child": 1.3,   # parent -> child pair (Windows/Sysmon)
    "srcip":        0.9,   # source IP of the event
    "country":      1.0,   # GeoIP country of the source IP
    "dst_port":     0.7,   # destination port (Suricata)
    "account":      1.0,   # account involved
    "rule_id":      0.5,   # rule that fired
    "hour":         0.4,   # time slot (business hours / outside)
}

# Scopes: what the frequency is relative to.
#   'host'      -> agent_id. The behaviour of the MACHINE.
#   'user@host' -> account + agent_id. The behaviour of the PERSON on that
#                  machine — that is where lateral movement lives (a legitimate
#                  account appearing on a host it never served on).
# We keep `agent_id` and not `agent_name`: the name can change, the id cannot.

# Canonical kill chain order. Used by the order bonus: the same SET of tactics is
# worth more when it PROGRESSES (access -> execution -> persistence ->
# credentials -> exfiltration) than when observed out of order.
TACTICS_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

# Weight per tactic. Three `Discovery` are administration noise; `Credential
# Access` + `Persistence` + `Exfiltration` are an intrusion. Without this
# weighting, "3 distinct tactics" mostly surfaces false positives.
TACTICS_WEIGHT = {
    "Reconnaissance": 1.0, "Resource Development": 1.0, "Initial Access": 3.0,
    "Execution": 2.0, "Persistence": 4.0, "Privilege Escalation": 4.0,
    "Defense Evasion": 3.0, "Credential Access": 5.0, "Discovery": 1.0,
    "Lateral Movement": 4.0, "Collection": 2.0, "Command and Control": 4.0,
    "Exfiltration": 5.0, "Impact": 5.0,
}

# Values too common to carry signal, even when unseen on a host: scoring them
# would surface the first `bash` of a freshly observed machine. Same logic as
# `correlate.ENTITIES_GENERIC`, applied to traits.
VALUES_IGNORED = {
    "/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh", "/usr/bin/dash",
    "/bin/dash", "/usr/bin/zsh", "-", "", "unknown", "n/a", "none",
}

# Accounts that do NOT designate a person: Active Directory machine accounts
# (`WIN-DC$`, `WIN-DC$@LAB.LOCAL` — the trailing `$` is the AD convention) and
# operating system pseudo-accounts. They authenticate constantly, on behalf of
# services, and their volume crushes everything else.
#
# Measured in production: incident #2550 (IRIS case #193) counted 4598 alerts, of
# which 3856 carried by `WIN-DC$`, that is 85 % of domain controller session
# open/close events. The signal promoted it, the LLM told it as a confirmed
# compromise, and `mark_tp` then froze `WIN-DC$` at 12 bits FOR LIFE — the loop
# closed on itself.
#
# The `user@host` scope also disappears for those accounts: profiling "the
# behaviour of the person WIN-DC$" makes no sense, and that scope would aggregate
# all the machine's service traffic under a single identity.
_RE_ACCOUNT_MACHINE = re.compile(r"\$(@|$)")
ACCOUNTS_NON_PERSON = {
    "system", "système", "local system", "système local",
    "local service", "service local", "network service", "service réseau",
    "anonymous logon", "connexion anonyme", "nt authority\\system",
}

_WIN_SEP = re.compile(r"[\\/]+")


def _norm_account(value) -> str | None:
    """Normalised account, or None when it is not a person's identity."""
    v = _norm(value)
    if v is None:
        return None
    if _RE_ACCOUNT_MACHINE.search(v) or v.lower() in ACCOUNTS_NON_PERSON:
        return None
    return v


def _norm(value) -> str | None:
    """Normalised value, or None when it carries nothing usable."""
    if value is None:
        return None
    v = str(value).strip()
    if not v or v.lower() in VALUES_IGNORED:
        return None
    return v[:400]


def _raw(a: dict) -> dict:
    r = a.get("raw")
    if isinstance(r, dict):
        return r
    try:
        return json.loads(r) if r else {}
    except (TypeError, ValueError):
        return {}


def traits(a: dict) -> list[tuple[str, str, str, str]]:
    """(scope, scope_key, trait, value) observed in an alert.

    Nothing extra is collected here: everything comes from `alerts` and
    `alerts.raw`, already in database. UEBA adds no ingestion, only a read.
    """
    raw = _raw(a)
    data = raw.get("data") or {}
    win = (data.get("win") or {}).get("eventdata") or {}
    audit = data.get("audit") or {}
    geo = raw.get("GeoLocation") or {}

    agent = str(a.get("agent_id") or "?")
    account = _norm_account(a.get("srcuser"))
    host = ("host", agent)
    # The user scope only exists when the event carries an account. Otherwise we
    # fall back on the machine scope alone: inventing an "unknown@host" would
    # create a catch-all profile where everything would end up looking normal.
    personal = ("user@host", f"{account}@{agent}") if account else None

    out: list[tuple[str, str, str, str]] = []

    def add(trait: str, value, on_personal: bool = True) -> None:
        v = _norm(value)
        if v is None:
            return
        out.append((host[0], host[1], trait, v))
        if personal and on_personal:
            out.append((personal[0], personal[1], trait, v))

    # Executed binary. ONLY auditd and Sysmon — definitely not the `entity`
    # fallback, which is `syscheck.path` for FIM alerts: on Windows a registry
    # key `HKEY_...`, on Proxmox an LVM archive `pve_19796-1149630808.vg`.
    # Neither is an executable, and the second is unique by construction — hence
    # "never seen" on every occurrence. Measured in staging: score 1434 on the
    # Proxmox host, made only of LVM archives.
    add("exe", audit.get("exe") or win.get("image"))

    # Object touched by an integrity alert (dropped file, modified key). A
    # separate trait, weighing less than `exe`: a file appearing is a hint, a
    # binary executing is a fact. The cardinality guardrail below neutralises the
    # timestamped/rotating paths.
    add("file", a.get("entity"))

    # Parent -> child pair. Windows/Sysmon only: auditd does not give the
    # parent's name, only its pid, which cannot be resolved after the fact.
    parent, child = win.get("parentImage"), win.get("image")
    if parent and child:
        add("parent_child",
                f"{_WIN_SEP.split(parent)[-1]}>{_WIN_SEP.split(child)[-1]}")

    add("srcip", a.get("srcip"))
    add("country", geo.get("country_name"))
    add("dst_port", data.get("dstport"))
    # The account is a trait OF THE MACHINE SCOPE only: on the `user@host` scope
    # it is already in the key, observing it would be tautological.
    add("account", account, on_personal=False)
    add("rule_id", a.get("rule_id"))

    ts = a.get("ts")
    if isinstance(ts, datetime):
        # A coarse slot and not the exact hour: 24 values per profile take
        # months to mature, 4 are enough to tell "3 a.m. on a Sunday" from office
        # activity.
        business = ts.weekday() < 5 and 7 <= ts.hour < 20
        add("hour", "business" if business else "off_hours")

    return out


# --- Scoring -----------------------------------------------------------------

def surprisal(count: int, total: int, distinct: int) -> float:
    """Information carried by a value seen `count` times out of `total`, in bits.

    Laplace smoothing (alpha=0.5): without it a value never seen gives a
    probability of zero, hence infinite bits. The smoothing also bounds the score
    of a still-thin profile, which is exactly what we want — few observations,
    little confidence.
    """
    alpha = 0.5
    denom = total + alpha * max(distinct, 1)
    if denom <= 0:
        return 0.0
    p = (count + alpha) / denom
    return max(0.0, -math.log2(min(p, 1.0)))


def usable_cardinality(stats: dict | None) -> bool:
    """Does the trait carry information, or change value every single time?

    A trait where nearly every observation is a new value (timestamped paths,
    rotating archives, GUIDs, session identifiers) is unseen by construction:
    "never seen" means nothing there. Without this guardrail, those traits
    saturate the score permanently and crush everything else.

    We judge on the RATIO of distinct values to observations, not on a list of
    patterns: no blacklist can anticipate what an estate produces, whereas the
    statistic corrects itself when the behaviour changes.
    """
    if not stats or stats.get("total", 0) < config.UEBA_CARDINALITY_MIN_OBS:
        return True   # too few observations to conclude: we do not exclude
    return (stats["distinct_values"] / stats["total"]) <= config.UEBA_CARDINALITY_MAX


def _trait_bits(profil: dict | None, stats: dict | None, fleet: int,
                mature: bool) -> tuple[float, str]:
    """A trait's bits plus the sentence explaining it. (0.0, "") if unscorable.

    The explanation stays in French: it lands in `ueba_traits`, then in the
    prompt and in the IRIS case, which analysts read.
    """
    if profil is not None and profil.get("seen_in_tp"):
        # Trait already involved in a true positive: it can NOT become a habit,
        # whatever its frequency. Otherwise a patient attacker normalises their
        # own tooling by running it every day.
        return config.UEBA_FIRSTSEEN_BITS, "déjà vu dans un vrai positif"

    if not usable_cardinality(stats):
        # The trait is unique BY CONSTRUCTION on this scope: nearly every
        # observation brings a new value (timestamped paths, rotating archives,
        # session identifiers, GUIDs). "Never seen" therefore means nothing, and
        # the surprisal is permanently maximal. Measured in staging: the LVM
        # archives of the Proxmox host alone gave a score of 1434, forty times
        # the floor.
        #
        # A GENERAL guardrail and not a blacklist: one cannot enumerate in
        # advance everything an estate produces with high cardinality, and a
        # blacklist ages badly. The statistic corrects itself.
        return 0.0, ""

    if not mature:
        # Profile too young: EVERYTHING is unseen in it. Scoring now would send
        # the whole fleet to the LLM on day one. We observe, we do not judge
        # yet — the same philosophy as training mode.
        return 0.0, ""

    if profil is None:
        # First seen. Modulated by the fleet: unseen here but mundane elsewhere
        # = rollout/administration, not intrusion.
        bits = config.UEBA_FIRSTSEEN_BITS
        if fleet >= config.UEBA_FLEET_COMMON:
            bits *= 0.2
            note = f"inédit ici mais présent sur {fleet} hôtes"
        elif fleet >= 1:
            bits *= 0.6
            note = f"inédit ici, vu sur {fleet} autre(s) hôte(s)"
        else:
            note = "jamais vu ici ni ailleurs sur la flotte"
        return bits, note

    if stats is None:
        return 0.0, ""

    if profil["days_seen"] >= config.UEBA_DAYS_USUAL:
        # Seen on enough DISTINCT days to be a habit. The number of occurrences
        # is not enough: 500 executions in a single day is an incident, not a
        # baseline.
        return 0.0, ""

    bits = surprisal(profil["total"], stats["total"], stats["distinct_values"])
    if bits < config.UEBA_BITS_MIN_RARITY:
        return 0.0, ""
    return bits, (f"rare : {profil['total']}x sur {stats['total']} "
                  f"observations, {profil['days_seen']} jour(s)")


class _State:
    """Profiles plus scope statistics loaded in memory for one batch.

    We score EVERY alert against the state BEFORE it, then absorb it. The order
    is critical: absorbing first would make every first-seen disappear (the value
    would already be known when scoring it). It is also what makes the second
    occurrence of the same value inside one batch no longer worth the full score.
    """

    def __init__(self, profiles: dict, stats: dict, fleet: dict, maturity: dict):
        self.profiles = profiles    # (scope, key, trait, value) -> {...}
        self.stats = stats          # (scope, key, trait) -> {total, distinct}
        self.fleet = fleet          # (trait, value) -> number of distinct hosts
        self.maturity = maturity    # (scope, key, trait) -> bool
        self.affected: set[tuple] = set()
        self.obs: dict[tuple, int] = {}   # (scope,key,trait,value,day) -> n

    def mature(self, scope: str, key: str, trait: str) -> bool:
        return self.maturity.get((scope, key, trait), False)

    def absorb(self, scope: str, key: str, trait: str, value: str,
                 ts: datetime) -> None:
        profile_key = (scope, key, trait, value)
        p = self.profiles.get(profile_key)
        day = ts.date()
        if p is None:
            self.profiles[profile_key] = {"total": 1, "days_seen": 1,
                                 "first_seen": ts, "last_seen": ts,
                                 "days": {day}, "seen_in_tp": False}
            self.fleet[(trait, value)] = self.fleet.get((trait, value), 0) + (
                1 if scope == "host" else 0)
        else:
            p["total"] += 1
            p["last_seen"] = max(p.get("last_seen") or ts, ts)
            days = p.setdefault("days", set())
            if day not in days:
                days.add(day)
                p["days_seen"] = p.get("days_seen", 0) + 1
        s = self.stats.setdefault((scope, key, trait),
                                  {"total": 0, "distinct_values": 0,
                                   "first_obs": ts})
        s["total"] += 1
        if p is None:
            s["distinct_values"] += 1
        self.affected.add(profile_key)
        self.obs[(scope, key, trait, value, day)] = (
            self.obs.get((scope, key, trait, value, day), 0) + 1)


SELECT_TO_OBSERVE = """
SELECT id, ts, agent_id, agent_name, rule_id, rule_level, rule_groups,
       mitre_tactics, srcip, srcuser, entity, raw
  FROM alerts
 WHERE NOT ueba_seen AND NOT suppressed
 ORDER BY ts, id
 LIMIT %s
"""


def _load_state(conn, keys: set[tuple]) -> _State:
    """One round trip per table, never one query per alert."""
    profiles: dict[tuple, dict] = {}
    stats: dict[tuple, dict] = {}
    fleet: dict[tuple, int] = {}
    maturity: dict[tuple, bool] = {}
    if not keys:
        return _State(profiles, stats, fleet, maturity)

    # Materialised lists: the four columns passed to `unnest` must be aligned
    # row by row. Iterating a `set` four times would give the same order in
    # practice, but nothing guarantees it — so we freeze it.
    keys_l = sorted(keys)
    scopes = sorted({(s, k, t) for s, k, t, _ in keys})
    values = sorted({(t, v) for _, _, t, v in keys})

    lines = conn.execute(
        "SELECT scope, scope_key, trait, value, total, days_seen, first_seen,"
        "       last_seen, seen_in_tp FROM ueba_profiles "
        " WHERE (scope, scope_key, trait, value) IN "
        "       (SELECT * FROM unnest(%s::text[], %s::text[], %s::text[], %s::text[]))",
        ([c[0] for c in keys_l], [c[1] for c in keys_l],
         [c[2] for c in keys_l], [c[3] for c in keys_l])).fetchall()
    for l in lines:
        profiles[(l["scope"], l["scope_key"], l["trait"], l["value"])] = dict(l)

    lines = conn.execute(
        "SELECT scope, scope_key, trait, total, distinct_values, first_obs "
        "  FROM ueba_scopes WHERE (scope, scope_key, trait) IN "
        "       (SELECT * FROM unnest(%s::text[], %s::text[], %s::text[]))",
        ([s[0] for s in scopes], [s[1] for s in scopes],
         [s[2] for s in scopes])).fetchall()
    threshold = datetime.now(timezone.utc) - timedelta(days=config.UEBA_MATURITY_DAYS)
    for l in lines:
        key = (l["scope"], l["scope_key"], l["trait"])
        stats[key] = dict(l)
        maturity[key] = (l["first_obs"] is not None
                         and l["first_obs"] <= threshold
                         and l["total"] >= config.UEBA_MATURITY_MIN_OBS)

    # Fleet rarity: on how many distinct HOSTS is this value known? The 'host'
    # scope only — counting the user scopes would inflate the figure without
    # saying anything about the real spread.
    lines = conn.execute(
        "SELECT trait, value, count(DISTINCT scope_key) AS n "
        "  FROM ueba_profiles WHERE scope = 'host' AND (trait, value) IN "
        "       (SELECT * FROM unnest(%s::text[], %s::text[])) "
        " GROUP BY trait, value",
        ([v[0] for v in values], [v[1] for v in values])).fetchall()
    for l in lines:
        fleet[(l["trait"], l["value"])] = l["n"]

    return _State(profiles, stats, fleet, maturity)


def observe(limit: int | None = None) -> tuple[int, int]:
    """Scores the alerts not yet seen, then absorbs them into the baseline.

    Returns (alerts observed, alerts with a non-zero score).
    """
    limit = limit or config.UEBA_BATCH
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alerts = conn.execute(SELECT_TO_OBSERVE, (limit,)).fetchall()
        if not alerts:
            return 0, 0

        by_alert = {a["id"]: traits(a) for a in alerts}
        keys = {t for ts_ in by_alert.values() for t in ts_}
        state = _load_state(conn, keys)

        n_scored = 0
        for a in alerts:
            total_bits = 0.0
            details: list[dict] = []
            for scope, key, trait, value in by_alert[a["id"]]:
                bits, note = _trait_bits(
                    state.profiles.get((scope, key, trait, value)),
                    state.stats.get((scope, key, trait)),
                    state.fleet.get((trait, value), 0),
                    state.mature(scope, key, trait))
                if bits > 0:
                    weighted = min(bits * WEIGHT.get(trait, 1.0),
                                  config.UEBA_CAP_TRAIT)
                    total_bits += weighted
                    details.append({"trait": trait, "value": value,
                                    "scope": scope, "bits": round(weighted, 2),
                                    "note": note})
                # Absorbed AFTER the score, including when it is zero.
                state.absorb(scope, key, trait, value, a["ts"])

            total_bits = min(total_bits, config.UEBA_CAP_ALERT)
            details.sort(key=lambda d: -d["bits"])
            if total_bits > 0:
                n_scored += 1
            conn.execute(
                "UPDATE alerts SET ueba_seen = true, ueba_score = %s, "
                "ueba_traits = %s WHERE id = %s",
                (round(total_bits, 2),
                 json.dumps(details[:6], ensure_ascii=False, default=str),
                 a["id"]))

        _persist(conn, state)
        conn.commit()
    return len(alerts), n_scored


def _persist(conn, state: _State) -> None:
    """Writes observations, profiles and scope statistics.

    `days_seen` is RECOMPUTED from `ueba_observations` and not incremented
    blindly: replaying a batch must not inflate the number of distinct days,
    otherwise a replayed value would pass for a habit.
    """
    for (scope, key, trait, value, day), n in state.obs.items():
        conn.execute(
            "INSERT INTO ueba_observations (scope, scope_key, trait, value, "
            "day, count) VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (scope, scope_key, trait, value, day) DO UPDATE "
            "SET count = ueba_observations.count + EXCLUDED.count",
            (scope, key, trait, value, day, n))

    for key in state.affected:
        scope, key, trait, value = key
        conn.execute(
            "INSERT INTO ueba_profiles (scope, scope_key, trait, value, total,"
            " days_seen, first_seen, last_seen) "
            "SELECT %s, %s, %s, %s, sum(count), count(*), min(day), max(day) "
            "  FROM ueba_observations "
            " WHERE scope=%s AND scope_key=%s AND trait=%s AND value=%s "
            "ON CONFLICT (scope, scope_key, trait, value) DO UPDATE "
            "   SET total = EXCLUDED.total, days_seen = EXCLUDED.days_seen, "
            "       first_seen = EXCLUDED.first_seen, "
            "       last_seen = GREATEST(ueba_profiles.last_seen, "
            "                            EXCLUDED.last_seen)",
            (scope, key, trait, value, scope, key, trait, value))

    for (scope, key, trait) in {(c[0], c[1], c[2]) for c in state.affected}:
        conn.execute(
            "INSERT INTO ueba_scopes (scope, scope_key, trait, total, distinct_values,"
            " first_obs, last_obs) "
            "SELECT %s, %s, %s, coalesce(sum(total),0), count(*), "
            "       min(first_seen), max(last_seen) FROM ueba_profiles "
            " WHERE scope=%s AND scope_key=%s AND trait=%s "
            "ON CONFLICT (scope, scope_key, trait) DO UPDATE "
            "   SET total = EXCLUDED.total, distinct_values = EXCLUDED.distinct_values, "
            "       first_obs = EXCLUDED.first_obs, "
            "       last_obs = EXCLUDED.last_obs",
            (scope, key, trait, scope, key, trait))


# --- Signals: grouping and MITRE chain ---------------------------------------

# `ueba_signal_id IS NULL` and not `NOT ueba_seed`: an alert that has ALREADY
# belonged to a signal is consumed, definitively. `ueba_seed` says "correlatable
# as a seed" and `correlate` can set it back to false when it drops the group
# (score below the floor); using it as a filter here would make those alerts
# candidates again, and the daily budget would go round in circles on the same
# noise on every cycle.
SELECT_CANDIDATES = """
SELECT id, ts, agent_id, agent_name, rule_id, rule_level, mitre_tactics,
       srcuser, ueba_score, ueba_traits
  FROM alerts
 WHERE ueba_seen AND NOT suppressed AND ueba_signal_id IS NULL
   AND incident_id IS NULL
   AND ueba_score > 0
   AND rule_level < %s
   AND ts >= now() - make_interval(hours => %s)
 ORDER BY agent_id, ts, id
"""


def chain_bonus(ordered_tactics: list[str]) -> tuple[float, str | None]:
    """Bonus tied to the diversity AND the progression of the MITRE tactics.

    A plain "3 techniques from 3 tactics" mostly surfaces `Discovery` x3, that
    is, an admin inventorying their machine. Hence two corrections:
      - every DISTINCT tactic brings its weight (credential-access = 5,
        discovery = 1);
      - a bonus is added when the tactics progress along the kill chain order —
        that is the strongest signal obtainable without an LLM.

    The returned sentence stays French: it lands in the prompt and in the case.
    """
    distinct = []
    for t in ordered_tactics:
        if t not in distinct:
            distinct.append(t)
    if len(distinct) < config.UEBA_MIN_TACTICS:
        return 0.0, None

    bonus = sum(TACTICS_WEIGHT.get(t, 1.0) for t in distinct)

    # Longest increasing subsequence in the canonical order: a measure of
    # progression, insensitive to tactics outside the chain.
    ranks = [TACTICS_ORDER.index(t) for t in ordered_tactics
             if t in TACTICS_ORDER]
    best = 0
    lengths: list[int] = []
    for i, r in enumerate(ranks):
        lengths.append(1 + max([lengths[j] for j in range(i)
                                  if ranks[j] < r] or [0]))
        best = max(best, lengths[-1])
    progression = ""
    if best >= config.UEBA_MIN_TACTICS:
        bonus += config.UEBA_BONUS_ORDER * (best - config.UEBA_MIN_TACTICS + 1)
        progression = f", progression kill-chain sur {best} étapes"

    return bonus, (f"{len(distinct)} tactiques MITRE distinctes "
                   f"({', '.join(distinct)}){progression}")


def _group_signals(alerts: list[dict]) -> list[list[dict]]:
    """Chains the alerts of one agent separated by less than the window.

    Same spirit as `correlate._group`, far simpler: here we are not looking for
    nameable common ground (low alerts often share none), we are looking for an
    abnormal CONCENTRATION in time on one machine. The common ground is the
    machine and the window.
    """
    gap = timedelta(minutes=config.UEBA_WINDOW_MINUTES)
    max_duration = timedelta(hours=config.UEBA_SIGNAL_MAX_HOURS)
    groups: list[list[dict]] = []
    current: list[dict] = []
    for a in alerts:
        # Step-by-step chaining: a quiet intrusion is SLOW, and it is precisely
        # what we are looking for. But without a duration cap, a chatty host
        # emitting one alert every 50 minutes glues its whole day into a single
        # signal — the score swells by accumulation rather than by anomaly, and
        # the prompt leaves with hours of noise.
        if (current and a["agent_id"] == current[-1]["agent_id"]
                and a["ts"] - current[-1]["ts"] <= gap
                and a["ts"] - current[0]["ts"] <= max_duration):
            current.append(a)
        else:
            if current:
                groups.append(current)
            current = [a]
    if current:
        groups.append(current)
    return groups


def score_group(group: list[dict]) -> tuple[float, list[dict]]:
    """Score of a group plus the patterns making it up.

    A sum capped PER TRAIT and not raw: forty executions of the same rare binary
    are not worth forty times the score, otherwise a rare scheduled task crushes
    everything else. We keep the best of each trait, plus a decreasing share of
    the repetitions.
    """
    best_per_trait: dict[str, dict] = {}
    for a in group:
        for d in (a.get("ueba_traits") or []):
            key = f"{d['trait']}:{d['value']}"
            guard = best_per_trait.get(key)
            if guard is None or d["bits"] > guard["bits"]:
                best_per_trait[key] = dict(d)

    patterns = sorted(best_per_trait.values(), key=lambda d: -d["bits"])
    score = sum(min(d["bits"], config.UEBA_CAP_TRAIT) for d in patterns)

    tactics = [t for a in group for t in (a.get("mitre_tactics") or [])]
    bonus, phrase = chain_bonus(tactics)
    if bonus:
        score += bonus
        patterns.append({"trait": "mitre_chain", "value": "", "scope": "host",
                       "bits": round(bonus, 2), "note": phrase})

    return score, patterns[:8]


def _remaining_budget(conn) -> int:
    """Promotion slots left over the last 24 hours.

    The score threshold is not enough to bound the bill: the alert volume varies
    by a factor of ten between a quiet day and a campaign. The budget, in
    contrast, is a number we decide. A signal not promoted is not lost — it is
    re-evaluated on the next cycle, and its score will have grown if it
    continues.
    """
    n = conn.execute(
        "SELECT count(*) AS n FROM ueba_signals "
        " WHERE status = 'promoted' AND created_at >= now() - interval '24 hours'"
    ).fetchone()["n"]
    return max(0, config.UEBA_BUDGET_PER_DAY - n)


def evaluate(simulation: bool = False) -> list[dict]:
    """Groups, scores, and promotes the best signals within the budget.

    Returns the list of promoted signals.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alerts = conn.execute(
            SELECT_CANDIDATES,
            (config.MIN_LEVEL, config.UEBA_RETENTION_HOURS)).fetchall()
        if not alerts:
            return []

        signals = []
        for group in _group_signals(alerts):
            score, patterns = score_group(group)
            signals.append({
                "agent_id": group[0]["agent_id"],
                "agent_name": group[0]["agent_name"],
                "start_ts": group[0]["ts"], "end_ts": group[-1]["ts"],
                "score": round(score, 2), "patterns": patterns,
                "alert_ids": [a["id"] for a in group],
            })
        # A very tight budget (UEBA_BUDGET_PER_CYCLE = 2): the ordering decides
        # what becomes an incident today. At a sufficient score, the most
        # critical asset goes first — the floor stays the only judge of
        # eligibility, the priority only arbitrates between already eligible
        # signals.
        for s in signals:
            s["priority"] = assets.agent_priority(
                conn, s["agent_id"])["priority"]
        signals.sort(key=lambda s: (s["priority"], -s["score"]))

        # Signals not promoted are recomputed on every pass: we delete the
        # "pending" ones of the previous round rather than update them, since
        # their scope may have changed (newly attached alerts).
        conn.execute("DELETE FROM ueba_signals WHERE status = 'pending'")

        budget = min(_remaining_budget(conn), config.UEBA_BUDGET_PER_CYCLE)
        promoted: list[dict] = []
        for s in signals:
            eligible = (s["score"] >= config.UEBA_SCORE_FLOOR
                        and len(promoted) < budget and not simulation)
            status = "promoted" if eligible else "pending"
            sid = conn.execute(
                "INSERT INTO ueba_signals (agent_id, agent_name, start_ts, end_ts, "
                " score, patterns, alert_ids, status) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (s["agent_id"], s["agent_name"], s["start_ts"], s["end_ts"],
                 s["score"], json.dumps(s["patterns"], ensure_ascii=False,
                                        default=str),
                 s["alert_ids"], status)).fetchone()["id"]
            if eligible:
                # Promotion does not manufacture an incident: it makes the
                # alerts SEEDABLE. `correlate` then decides the slicing, with its
                # own rules — a single grouping logic in the project.
                conn.execute(
                    "UPDATE alerts SET ueba_seed = true, ueba_signal_id = %s "
                    " WHERE id = ANY(%s)", (sid, s["alert_ids"]))
                s["id"] = sid
                promoted.append(s)
        conn.commit()
    return promoted


def mark_tp(incident_id: int) -> int:
    """Forbids the baseline from absorbing the traits of a true positive.

    Without it, a patient attacker normalises their own tooling: running it every
    day is enough for it to become "usual" and stop being scored. The same
    guardrail as the automatic whitelist, which refuses any signature already
    seen in a true positive.
    """
    n = 0
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        # Bounded: `mark_tp` is called on case creation, hence also on flood
        # incidents (see alerts.py).
        alerts = alerts_mod.load_bounded(
            conn, incident_id, alerts_mod.COLUMNS_UEBA, "ueba mark_tp")
        keys = {t for a in alerts for t in traits(a)}
        for scope, key, trait, value in keys:
            n += conn.execute(
                "UPDATE ueba_profiles SET seen_in_tp = true "
                " WHERE scope=%s AND scope_key=%s AND trait=%s AND value=%s "
                "   AND NOT seen_in_tp",
                (scope, key, trait, value)).rowcount
        conn.commit()
    return n


def purge() -> int:
    """Ages the baseline.

    A profile that never ages freezes the behaviour of six months ago: a
    reinstalled server would stay "normal" on its old binaries, and a workstation
    whose usage changed would produce endless noise. We delete the observations
    past the window, then RECOMPUTE the profiles from what is left — never a
    blind decrement.
    """
    with psycopg.connect(config.PG_DSN) as conn:
        n = conn.execute(
            "DELETE FROM ueba_observations WHERE day < current_date - %s",
            (config.UEBA_MEMORY_DAYS,)).rowcount
        if n:
            conn.execute("""
                UPDATE ueba_profiles p
                   SET total = a.total, days_seen = a.days,
                       first_seen = a.start_ts, last_seen = a.end_ts
                  FROM (SELECT scope, scope_key, trait, value, sum(count) total,
                               count(*) days, min(day) start_ts, max(day) end_ts
                          FROM ueba_observations
                         GROUP BY 1,2,3,4) a
                 WHERE p.scope=a.scope AND p.scope_key=a.scope_key
                   AND p.trait=a.trait AND p.value=a.value""")
            # Profiles with no observation left. `seen_in_tp` is preserved: a
            # trait seen in a true positive must never become blank again through
            # mere expiry.
            conn.execute(
                "DELETE FROM ueba_profiles p WHERE NOT p.seen_in_tp AND NOT EXISTS "
                "(SELECT 1 FROM ueba_observations o WHERE o.scope=p.scope "
                " AND o.scope_key=p.scope_key AND o.trait=p.trait "
                " AND o.value=p.value)")
        conn.commit()
    return n


def run() -> tuple[int, int, list[dict]]:
    """One full pass: observation, scoring, promotion. Called by cycle.py."""
    if not config.UEBA_ENABLED:
        return 0, 0, []
    seen, scored = observe()
    promoted = evaluate()
    # Ageing of the baseline. Called on every pass rather than by a dedicated
    # job: the DELETE is indexed on `day` and returns nothing most of the time;
    # the profile recomputation only happens when it actually purged.
    purge()
    return seen, scored, promoted


# --- CLI ---------------------------------------------------------------------

def state_report(signals_limit: int = 15) -> dict:
    """Baseline maturity, promotion budget, latest signals."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        r = conn.execute(
            "SELECT count(*) AS profiles, count(DISTINCT scope_key) AS scopes, "
            "       coalesce(sum(total),0) AS obs FROM ueba_profiles").fetchone()
        mature_scopes = conn.execute(
            "SELECT count(*) AS n FROM ueba_scopes "
            " WHERE first_obs <= now() - make_interval(days => %s) "
            "   AND total >= %s",
            (config.UEBA_MATURITY_DAYS, config.UEBA_MATURITY_MIN_OBS)
        ).fetchone()["n"]
        total_scopes = conn.execute(
            "SELECT count(*) AS n FROM ueba_scopes").fetchone()["n"]
        remains = conn.execute(
            "SELECT count(*) AS n FROM alerts WHERE NOT ueba_seen AND NOT suppressed"
        ).fetchone()["n"]
        budget = _remaining_budget(conn)
        signals = conn.execute(
            "SELECT id, agent_id, agent_name, score, status, start_ts, end_ts, patterns "
            "  FROM ueba_signals ORDER BY created_at DESC LIMIT %s",
            (signals_limit,)).fetchall()

    return {
        "profiles": r["profiles"],
        "scopes": r["scopes"],
        "observations": r["obs"],
        "mature_scopes": mature_scopes,
        "total_scopes": total_scopes,
        "maturity_days": config.UEBA_MATURITY_DAYS,
        "maturity_min_obs": config.UEBA_MATURITY_MIN_OBS,
        "alerts_to_observe": remains,
        "remaining_budget": budget,
        "daily_budget": config.UEBA_BUDGET_PER_DAY,
        "score_floor": config.UEBA_SCORE_FLOOR,
        "signals": [
            {"id": s["id"], "agent_id": s["agent_id"],
             "agent_name": s["agent_name"], "score": float(s["score"]),
             "status": s["status"], "start_ts": s["start_ts"].isoformat(),
             "end_ts": s["end_ts"].isoformat() if s["end_ts"] else None,
             "patterns": s["patterns"] or []}
            for s in signals
        ],
    }


def state() -> None:
    r = state_report()
    print(f"profiles: {r['profiles']} ({r['scopes']} scopes, "
          f"{r['observations']} observations)")
    print(f"mature scopes: {r['mature_scopes']}/{r['total_scopes']} "
          f"(>= {r['maturity_days']} d and {r['maturity_min_obs']} observations)")
    print(f"alerts to observe: {r['alerts_to_observe']}")
    print(f"budget: {r['remaining_budget']}/{r['daily_budget']} "
          "promotions left over 24 h")
    for s in r["signals"]:
        phrases = "; ".join(
            f"{m['trait']}={m['value']} +{m['bits']}" for m in s["patterns"][:3])
        print(f"  #{s['id']:<5} {s['status']:<11} {s['score']:6.1f} "
              f"{str(s['agent_name'] or '?'):<14} "
              f"{s['start_ts'][5:16].replace('T', ' ')}  {phrases}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state", action="store_true",
                    help="profile maturity, budget, latest signals")
    ap.add_argument("--simulation", action="store_true",
                    help="scores and records the signals WITHOUT promoting "
                         "anything (floor calibration, zero tokens spent)")
    ap.add_argument("--purge", action="store_true",
                    help="ages the baseline (UEBA_MEMORY_DAYS)")
    args = ap.parse_args()

    if args.state:
        state()
        return
    if args.purge:
        print(f"{purge()} stale observation(s) deleted.")
        return

    seen, scored, _ = (0, 0, [])
    seen, scored = observe()
    print(f"observation: {seen} alerts, {scored} with a non-zero score")
    promoted = evaluate(simulation=args.simulation)
    if args.simulation:
        print("simulation: no signal promoted.")
    for s in promoted:
        print(f"  signal #{s['id']} {s['agent_name']} score {s['score']} "
              f"-> {len(s['alert_ids'])} seed alerts")
    if not promoted and not args.simulation:
        print("no signal above the floor (or budget exhausted).")


if __name__ == "__main__":
    main()
