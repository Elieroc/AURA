"""Grouping alerts into incidents.

The heart of phase 1: 25 "canary altered" alerts on the same host in the same
second are one ransomware incident, not 25 incidents. That is what makes LLM
triage affordable — we pay ~20 s per incident, not per alert.

Method: proximity chaining, agent by agent, in chronological order. Two alerts
close in time AND sharing common ground join the same incident. No model, no
learned threshold — rules that can be explained to an analyst, and that they can
argue with.

    python -m soc_agent.correlate
"""

import argparse
import json
import re
from datetime import timedelta

import psycopg
from psycopg.rows import dict_row

from . import assets, config

# Groups present on half the Wazuh rules: keeping them as common ground would
# merge alerts with nothing to do with each other.
GROUPS_GENERIC = {
    "syscheck", "ossec", "linux", "windows", "syslog", "authentication_failed",
    "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13",
}

# Groups that NEVER characterise an intrusion on their own: compliance posture
# (SCA/CIS), host integrity check (rootcheck), vulnerability inventory,
# successful login. An alert purely of that kind must not OPEN an incident — even
# if a low-level pass pushes it above the seed threshold. It stays eligible as an
# ATTACHED alert (context of a real intrusion: a successful login in the middle
# of a reverse shell counts).
GROUPS_NON_SEED = {
    "sca", "rootcheck", "vulnerability-detector", "cis",
    "authentication_success", "policy_monitoring",
}
# State changes of a Wazuh agent (connected/started/stopped/disconnected):
# operational, never an incident seed. Spotted on the description, since the
# groups of those rules are too generic ("ossec") to discriminate.
_RE_STATUS_AGENT = re.compile(
    r"\bagent (?:connected|started|stopped|disconnected|removed|restarted)\b",
    re.I)

# Exception to _RE_STATUS_AGENT: our self-monitoring rules (100803/100804)
# describe the SAME event, but deliberately as a possible tampering with the SOC
# (T1562.001) — stopping the agent is the first action of an attacker who got
# root. They must be able to seed an incident.
# The filter above is written in English because it targets the native ruleset's
# descriptions; ever since our local rules are in English too, it caught them as
# a side effect and made them unable to open a case, silently. Hence this
# explicit list, by identifier and not by text.
SIDS_STATUS_AGENT_SEED = {"100803", "100804"}


def _is_valid_seed(a: dict) -> bool:
    """Can an alert OPEN an incident (be a seed)?

    False for structural noise (SCA/CIS, rootcheck, vulnerability inventory,
    successful login, agent status): those alerts are not intrusions, they must
    not found a case. They stay attachable to a nearby real incident (context),
    but they do not seed it.
    """
    if set(a.get("rule_groups") or []) & GROUPS_NON_SEED:
        return False
    if (str(a.get("rule_id")) not in SIDS_STATUS_AGENT_SEED
            and _RE_STATUS_AGENT.search(a.get("rule_desc") or "")):
        return False
    return True

# Ubiquitous shell binaries: keeping them as "same object" would merge two
# distinct intrusions (or an intrusion and normal shell activity) on the mere
# fact that they all go through bash. The uid and the real objects (dropped
# files, IPs) stay valid links.
ENTITIES_GENERIC = {
    "/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh",
    "/usr/bin/dash", "/bin/dash",
}

# Executables too common to link two alerts or merge two hosts: an admin hop
# (powershell, cmd, net) or a shell would otherwise link the whole fleet.
# Campaign #4 wrongly merged two hosts on
# `...\WindowsPowerShell\v1.0\powershell.exe`. We compare on the file NAME, with
# the eventchannel's doubled backslashes folded — a real attacker marker
# (mimikatz.exe, a created account, a C2 IP) does stay discriminant.
NAMES_GENERIC = {
    "bash", "sh", "dash", "zsh",
    "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "net.exe",
    "net1.exe", "wsmprovhost.exe", "svchost.exe", "explorer.exe",
    "rundll32.exe", "wmiprvse.exe", "reg.exe", "dllhost.exe",
}


def generic_entity(entity: str | None) -> bool:
    """True if the entity is too generic to link/merge (basename)."""
    if not entity:
        return True
    e = entity.replace("\\\\", "\\").replace("\\", "/").lower().rstrip("/")
    if e in ENTITIES_GENERIC:
        return True
    return e.rsplit("/", 1)[-1] in NAMES_GENERIC


def common_ground(a: dict, b: dict) -> tuple[str, bool] | None:
    """What links two alerts of the same agent: (label, strong_link).

    Temporal proximity alone is not enough: on an active host, two unrelated
    events constantly fall in the same window. An explicit link is needed, and it
    must be nameable in the report.

    A link is called STRONG when it points at the same concrete object — the same
    source IP, the same file, the same account. Those links support a far wider
    window: a hostile IP coming back three times in a day is one campaign, not
    three incidents. Weak links (MITRE tactic, rule group) are hints of kinship,
    not identities: giving them the same width would merge anything with
    anything.
    """
    # Same UEBA signal: the strongest link of the lot, and the first examined.
    # The behavioural engine has ALREADY decided those alerts form a whole;
    # letting them be re-split here on generic criteria crumbles them. Measured
    # at go-live: a 239-alert signal came out as 8 incidents, hence 8 LLM triages
    # instead of one, each cut off from the others' context and carrying a score
    # unrelated to the signal's (115, then 2.5 and 3.3). The windows already
    # match: UEBA_SIGNAL_MAX_HOURS = 6 = MAX_INCIDENT_HOURS, and the strong link
    # reaches up to ENTITY_GAP_MINUTES.
    if a.get("ueba_signal_id") and a["ueba_signal_id"] == b.get("ueba_signal_id"):
        return "same UEBA signal", True
    if a["srcip"] and a["srcip"] == b["srcip"]:
        return "same source IP", True
    if (a["entity"] and a["entity"] == b["entity"]
            and not generic_entity(a["entity"])):
        return "same object", True
    if a["srcuser"] and a["srcuser"] == b["srcuser"]:
        return "same account", True
    if a["mitre_tactics"] and set(a["mitre_tactics"]) & set(b["mitre_tactics"]):
        return "MITRE tactic", False
    common = (set(a["rule_groups"]) & set(b["rule_groups"])) - GROUPS_GENERIC
    if common:
        return f"group {sorted(common)[0]}", False
    return None


SELECT_NON_ATTACHED = """
SELECT id, ts, agent_id, agent_name, container, rule_id, rule_level, rule_desc,
       rule_groups, mitre_tactics, srcip, srcuser, entity, audit_uid,
       ueba_seed, ueba_score, ueba_traits, ueba_signal_id
  FROM alerts
 WHERE incident_id IS NULL AND NOT suppressed
   AND (rule_level >= %s OR ueba_seed)
 ORDER BY agent_id, ts, id
"""

# Incidents of an agent still "openable": their last alert is not too old to
# take in a new burst. We also load their aggregates, updated in Python on
# attachment.
SELECT_INCIDENTS_OPENABLE = """
SELECT id, agent_id, first_seen, last_seen, alert_count, max_level,
       rule_ids, mitre_tactics, entities, priority
  FROM incidents
 WHERE agent_id = ANY(%s) AND last_seen >= %s
 ORDER BY last_seen DESC
"""

# Members of an openable incident, BOUNDED to the last MEMBERS_RECENT of each
# incident. `_attach_existing` only looks at the tail (`members[-20:]`) to find
# common ground anyway, and the START date comes from the incident
# (`first_seen`), not from the first row loaded.
#
# Without this bound, every cycle re-read ALL the alerts of every openable
# incident — 126,508 rows for a single pfSense incident on 2026-08-14, every 5
# minutes, to use 20 of them.
MEMBERS_RECENT = 50

SELECT_MEMBERS = """
SELECT id, ts, agent_id, rule_id, rule_level, rule_groups, mitre_tactics,
       srcip, srcuser, entity, audit_uid, incident_id, ueba_signal_id
  FROM (SELECT *, row_number() OVER (PARTITION BY incident_id
                                         ORDER BY ts DESC, id DESC) rang
          FROM alerts WHERE incident_id = ANY(%s)) t
 WHERE rang <= %s
 ORDER BY ts
"""

INSERT_INCIDENT = """
INSERT INTO incidents (agent_id, agent_name, first_seen, last_seen,
                       alert_count, max_level, rule_ids, mitre_tactics, entities,
                       ueba, ueba_score, ueba_patterns, priority, severity,
                       asset_role)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
RETURNING id
"""


def _group(alerts: list[dict]) -> list[list[dict]]:
    """Chains alerts into incidents. A pure function, hence testable alone."""
    small_gap = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    large_gap = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    max_duration = timedelta(hours=config.MAX_INCIDENT_HOURS)

    incidents: list[list[dict]] = []

    # SEVERAL incidents open simultaneously per agent, not just one. With a
    # single one, an unrelated alert slipping in closes the current incident: two
    # alerts from the same hostile IP separated by a foreign event ended up in
    # two distinct incidents. On an active host, interleaving is the normal case,
    # not the exception.
    #
    # Agents stay partitioned: an alert on one endpoint has no business joining
    # an incident of another agent.
    open_incidents: dict[str, list[list[dict]]] = {}
    max_window = max(large_gap, small_gap)

    for a in alerts:
        groups = open_incidents.setdefault(a["agent_id"], [])

        # Close the incidents out of reach. Alerts being sorted by date, they
        # can no longer take anything in.
        groups[:] = [
            g for g in groups
            if a["ts"] - g[-1]["ts"] <= max_window
            and a["ts"] - g[0]["ts"] <= max_duration
        ]

        target = None
        for g in groups:
            since_last = a["ts"] - g[-1]["ts"]
            # We only compare against the last 20: beyond that the cost turns
            # quadratic without changing anything, the chaining being
            # step by step.
            for member in g[-20:]:
                link = common_ground(a, member)
                if link is None:
                    continue
                _, high = link
                if since_last <= (large_gap if high else small_gap):
                    target = g
                    break
            if target is not None:
                break

        if target is None:
            target = []
            groups.append(target)
            incidents.append(target)
        target.append(a)

    return incidents


def _uids_incident(inc: list[dict]) -> set[str]:
    """auditd UIDs under which the incident's seed fired.

    It is the uid of the compromised account. A SUID privesc keeps the account's
    real uid (only the euid becomes 0), so the attacker's root actions stay
    tagged with that uid. We drop root (0) when a non-root account is present:
    keeping 0 would let in every root daemon and the system noise.
    """
    uids = {str(m["audit_uid"]) for m in inc if m.get("audit_uid") is not None}
    non_root = uids - {"0"}
    return non_root or uids


def _enrich(incidents: list[list[dict]], candidates: list[dict]) -> int:
    """Attaches mid-severity alerts to the incidents already formed.

    A HIGH seed has already confirmed the incident; we glue back onto it the
    alerts of the same agent that REALLY belong to the same intrusion —
    otherwise the reverse shell is seen alone and the privesc/persistence stay
    invisible.

    Attachment requires a real link, never mere temporal coincidence (which would
    suck in the host's legitimate noise — daemons, login sessions, admin
    activity). Two grounds, within the time window:
      - SAME auditd UID as the seed: the compromised account and its descendants
        (SUID privesc included) run under that uid; that is what separates
        enumeration/exploitation (audit level 3) from the background noise;
      - nameable COMMON GROUND with a member (same IP/object/account/tactic),
        which extends the reach to the strong window (a hostile IP coming back
        hours later is still the same incident).

    A candidate with no link stays unattached: the case only holds the alerts of
    the intrusion, not the machine's legitimate false positives.
    """
    small_gap = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    large_gap = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    attached = 0
    uids_by_inc = [_uids_incident(inc) for inc in incidents]

    for c in candidates:
        best = None
        best_dist = None
        for inc, uids in zip(incidents, uids_by_inc):
            if inc[0]["agent_id"] != c["agent_id"]:
                continue
            start = min(m["ts"] for m in inc)
            end = max(m["ts"] for m in inc)
            in_window = (start - small_gap) <= c["ts"] <= (end + small_gap)

            title = False
            # Link by uid: within the window and same compromised account.
            if (in_window and uids and c.get("audit_uid") is not None
                    and str(c["audit_uid"]) in uids):
                title = True
            # Link by STRONG IDENTITY only (same source IP, or same concrete
            # non-generic object — a dropped file). We EXCLUDE the weak links
            # here (MITRE tactic, rule group) and the account: they chain the
            # host's legitimate activity (the admin's sudo sessions, rules
            # sharing "Privilege Escalation"...) into the incident. The case must
            # only hold the intrusion, not the machine's FPs.
            if not title and min(abs(c["ts"] - start),
                                 abs(c["ts"] - end)) <= large_gap:
                for member in inc:
                    same_ip = c["srcip"] and c["srcip"] == member["srcip"]
                    same_object = (c["entity"] and c["entity"] == member["entity"]
                                  and not generic_entity(c["entity"]))
                    if same_ip or same_object:
                        title = True
                        break
            if not title:
                continue

            # Tie-break: the incident closest in time.
            if start <= c["ts"] <= end:
                dist = timedelta(0)
            else:
                dist = min(abs(c["ts"] - start), abs(c["ts"] - end))
            if best_dist is None or dist < best_dist:
                best, best_dist = inc, dist

        if best is not None:
            best.append(c)
            attached += 1

    return attached


def _attach_existing(conn, alerts: list[dict]) -> tuple[list[dict], dict[int, list[dict]]]:
    """Glues the unattached alerts back onto the incidents ALREADY in database.

    This is the duplicate-case fix. The cycle runs every 5 min and only sees the
    freshly ingested alerts on each round: without this catch-up, every burst of
    an ONGOING intrusion reopens a fresh incident, hence one more IRIS case —
    nine "reverse shell" cases for a single attack. So we first attach each new
    alert to a recent incident of the same agent, with EXACTLY the proximity
    rules of `_group` (the only gap between the two was the batch boundary).

    Returns (remaining, {incident_id: [alerts added]}, {incident_id: inc}).
    Persists nothing: the caller writes in the same transaction as the rest.
    """
    if not alerts:
        return alerts, {}, {}

    small_gap = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    large_gap = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    max_duration = timedelta(hours=config.MAX_INCIDENT_HOURS)
    max_window = max(large_gap, small_gap)

    agents = list({a["agent_id"] for a in alerts})
    ts_min = min(a["ts"] for a in alerts)
    incs = conn.execute(SELECT_INCIDENTS_OPENABLE,
                        (agents, ts_min - max_window)).fetchall()
    incs_by_id = {i["id"]: i for i in incs}
    if not incs:
        return alerts, {}, incs_by_id

    members = conn.execute(SELECT_MEMBERS,
                           ([i["id"] for i in incs], MEMBERS_RECENT)).fetchall()
    by_inc: dict[int, dict] = {i["id"]: {"inc": i, "members": []} for i in incs}
    for m in members:
        by_inc[m["incident_id"]]["members"].append(m)

    remaining: list[dict] = []
    additions: dict[int, list[dict]] = {}
    # Chronological order: an attached alert becomes a member for the next one,
    # which chains a burst step by step across the batch.
    for a in sorted(alerts, key=lambda x: (x["ts"], x["id"])):
        target = None
        target_dist = None
        for iid, e in by_inc.items():
            if e["inc"]["agent_id"] != a["agent_id"] or not e["members"]:
                continue
            # Start read from the INCIDENT, not from the first row loaded: the
            # members are bounded to the most recent ones (see SELECT_MEMBERS),
            # so their head is no longer the start of the incident.
            start = e["inc"]["first_seen"]
            last = e["members"][-1]["ts"]
            if a["ts"] - start > max_duration:
                continue
            since = abs(a["ts"] - last)
            for m in e["members"][-20:]:
                link = common_ground(a, m)
                if link is None:
                    continue
                _, high = link
                if since <= (large_gap if high else small_gap):
                    if target_dist is None or since < target_dist:
                        target, target_dist = iid, since
                    break
        if target is None:
            remaining.append(a)
        else:
            by_inc[target]["members"].append(a)
            additions.setdefault(target, []).append(a)

    return remaining, additions, incs_by_id


def _signal_decisive(old_rules: set, new: list[dict],
                    max_old: int) -> bool:
    """Does an attached burst bring a new decisive signal?

    True when the max level rises, OR when a novel NON-structural rule appears.
    False for a repetition of noise (same rules already present, or structural
    SCA/rootcheck/agent-status alerts — see _is_valid_seed): it then does NOT
    re-trigger triage plus the LLM report (fix #2, the regeneration loop behind
    the token explosion of 2026-07-30)."""
    if max([max_old] + [a["rule_level"] for a in new]) > max_old:
        return True
    return any(a["rule_id"] not in old_rules and _is_valid_seed(a)
               for a in new)


def _apply_additions(conn, incs_by_id: dict[int, dict],
                      additions: dict[int, list[dict]]) -> None:
    """Persists the attachments to existing incidents and sets needs_refresh.

    Updates the incident's aggregates (window, count, max level, unions of
    rules/tactics/objects). `needs_refresh` is only set when the burst brings a
    NEW DECISIVE SIGNAL (fix #2, token explosion of 2026-07-30): a novel
    NON-structural rule, or a rise of the max level. A repetition of noise (same
    rules, or structural SCA/rootcheck/agent-status alerts) no longer re-triggers
    triage plus the LLM report — that was the loop regenerating the report for
    nothing on every cycle (5 min). We never downgrade a refresh already pending
    (`OR` in SQL).
    """
    for iid, new in additions.items():
        inc = incs_by_id[iid]
        conn.execute("UPDATE alerts SET incident_id = %s WHERE id = ANY(%s)",
                     (iid, [a["id"] for a in new]))
        old_rules = set(inc["rule_ids"])
        rules = sorted(old_rules | {a["rule_id"] for a in new})
        tacs = sorted(set(inc["mitre_tactics"])
                      | {t for a in new for t in (a["mitre_tactics"] or [])})
        ents = sorted(set(inc["entities"])
                      | {a["entity"] for a in new if a["entity"]})[:50]
        new_max = max([inc["max_level"]] + [a["rule_level"] for a in new])
        signal = _signal_decisive(old_rules, new, inc["max_level"])
        # The incident's priority does NOT move (it is the asset's at opening
        # time, see schema.sql); the severity does — it follows the max level.
        # Priority missing on incidents predating the CMDB: we fall back on the
        # default rather than writing NULL.
        priority = inc.get("priority") or config.DEFAULT_PRIORITY
        conn.execute(
            "UPDATE incidents SET last_seen = %s, first_seen = %s, "
            "alert_count = alert_count + %s, max_level = %s, rule_ids = %s, "
            "mitre_tactics = %s, entities = %s, severity = %s, "
            "needs_refresh = needs_refresh OR %s WHERE id = %s",
            (max([inc["last_seen"]] + [a["ts"] for a in new]),
             min([inc["first_seen"]] + [a["ts"] for a in new]),
             len(new), new_max,
             rules, tacs, ents, assets.severity(new_max, priority),
             signal, iid))


def correlate(min_level: int, attach_min_level: int | None = None) -> tuple[int, int]:
    if attach_min_level is None:
        attach_min_level = config.ATTACH_MIN_LEVEL
    # We can only attach below the seed threshold; above it, the alert is
    # already a seed in its own right.
    floor = min(attach_min_level, min_level) if attach_min_level else min_level

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alerts = conn.execute(SELECT_NON_ATTACHED, (floor,)).fetchall()
        if not alerts:
            return 0, 0

        # 1) Catch-up: glue back onto the incidents already in database
        # (case anti-duplicate). What remains is grouped into fresh incidents
        # below.
        alerts, additions, incs_by_id = _attach_existing(conn, alerts)
        _apply_additions(conn, incs_by_id, additions)

        # 2) New incidents from the rest. Structural noise (SCA/rootcheck/agent
        # status/successful login) can NOT be a seed, even pushed above the
        # threshold: it does not open a case. Two grounds to be a seed: the Wazuh
        # level (>= min_level), or promotion by the UEBA engine (`ueba_seed`, set
        # by ueba.evaluate on an abnormal behavioural concentration). The
        # structural filter `_is_valid_seed` applies to BOTH: an SCA or an agent
        # status does not found a case, however statistically rare.
        seed_ids = {a["id"] for a in alerts
                       if (a["rule_level"] >= min_level or a.get("ueba_seed"))
                       and _is_valid_seed(a)}
        seeds = [a for a in alerts if a["id"] in seed_ids]
        candidates = [a for a in alerts if a["id"] not in seed_ids]

        incidents = _group(seeds)
        if candidates and incidents:
            _enrich(incidents, candidates)

        # A single transaction: on failure the alerts simply stay unattached
        # and a new pass takes the work back up.
        created: list[list[dict]] = []
        for group in incidents:
            tactics = sorted({t for a in group for t in a["mitre_tactics"]})
            entities = sorted({a["entity"] for a in group if a["entity"]})
            # Explicit min/max: enrichment appends members at the end of the
            # list with no guarantee of chronological order.
            # UEBA origin: the incident was not opened by a level >= 12 rule but
            # by a behavioural score. Triage must know (its max_level is low, it
            # would otherwise be out of the batch), the prompt must explain it,
            # and autonomous remediation is bounded on it (UEBA_MITIGATE).
            # The score and the patterns are recomputed by the SAME function as
            # the engine's (`ueba.score_group`) rather than re-aggregated here:
            # correlate's slicing is not the signal's, and two formulas for the
            # same quantity would end up diverging — the incident would show a
            # score nothing could tie back to the original signal's. Deferred
            # import: ueba does not need correlate, but we keep the module
            # loadable without it.
            ueba_alerts = [a for a in group if a.get("ueba_seed")]
            score_ueba, patterns = (0.0, [])
            if ueba_alerts:
                from . import ueba as _ueba
                score_ueba, patterns = _ueba.score_group(ueba_alerts)

            # Score floor on the INCIDENT, and not only on the signal. The UEBA
            # engine promotes a whole signal; the slicing here can detach a
            # fragment whose own score has nothing to do with the one that
            # justified the promotion. Without this guardrail, a 2-alert fragment
            # at 3.3 bits opened a full incident, LLM triage and IRIS case — that
            # is the origin of case #192 ("PHANTOM ALERT", scheduling of the
            # Software Protection service).
            #
            # Applies only to groups founded SOLELY by UEBA: as soon as an alert
            # of level >= min_level is present, the incident stands on its own
            # ground and the behavioural score is merely an enrichment.
            #
            # The dropped alerts lose `ueba_seed`: without that they stay
            # eligible as a seed on EVERY cycle (SELECT_NON_ATTACHED reads
            # `rule_level >= floor OR ueba_seed`) and the same group comes back
            # indefinitely. They keep `ueba_signal_id`, which is what
            # `ueba.SELECT_CANDIDATES` relies on never to re-promote them:
            # consumed by the budget once, for good.
            if (ueba_alerts and score_ueba < config.UEBA_SCORE_FLOOR
                    and max(a["rule_level"] for a in group) < min_level):
                conn.execute(
                    "UPDATE alerts SET ueba_seed = false WHERE id = ANY(%s)",
                    ([a["id"] for a in ueba_alerts],))
                print(f"  UEBA: group of {len(group)} alerts dropped "
                      f"(score {score_ueba:.1f} < floor "
                      f"{config.UEBA_SCORE_FLOOR:.0f}) — no incident")
                continue

            # Priority of the affected asset. The originating container wins
            # over the agent when the alert comes from a host sensor: the LXC is
            # the real machine, not the hypervisor watching it (see
            # assets.agent_priority).
            max_level = max(a["rule_level"] for a in group)
            container = next((a.get("container") for a in group
                              if a.get("container")), None)
            prio = assets.agent_priority(conn, group[0]["agent_id"], container)

            inc_id = conn.execute(INSERT_INCIDENT, (
                group[0]["agent_id"],
                group[0]["agent_name"],
                min(a["ts"] for a in group),
                max(a["ts"] for a in group),
                len(group),
                max_level,
                sorted({a["rule_id"] for a in group}),
                tactics,
                entities[:50],   # bounded: a ransomware touches thousands of files
                bool(ueba_alerts),
                round(score_ueba, 2) or None,
                json.dumps(patterns, ensure_ascii=False) if patterns else None,
                prio["priority"],
                assets.severity(max_level, prio["priority"]),
                # The role AS IT COUNTED, not the CMDB's: on a sensor the
                # priority falls back and the role is "sensor".
                prio["role"],
            )).fetchone()["id"]

            conn.execute(
                "UPDATE alerts SET incident_id = %s WHERE id = ANY(%s)",
                (inc_id, [a["id"] for a in group]),
            )
            created.append(group)
        conn.commit()

    attached = sum(len(v) for v in additions.values())
    correlated = sum(len(g) for g in created) + attached
    return len(created), correlated


def restart() -> None:
    """Detaches every alert and deletes the incidents.

    Used to replay correlation after a parameter change. Goes through a DELETE
    and not a TRUNCATE: `TRUNCATE incidents CASCADE` would also empty `alerts`,
    because of the foreign key — which would force a full re-ingest.
    """
    with psycopg.connect(config.PG_DSN) as conn:
        # An incident already pushed to IRIS left a case there. Deleting it
        # here breaks the iris_case_id link: the next IRIS pass would recreate a
        # duplicate case. We warn rather than clean up blindly on the IRIS side —
        # the decision belongs to the analyst.
        orphans = conn.execute(
            "SELECT count(*) FROM incidents WHERE iris_case_id IS NOT NULL"
        ).fetchone()[0]
        if orphans:
            print(f"WARNING: {orphans} incident(s) have an IRIS case. Deleting "
                  "them here orphans those cases (duplicates on the next cycle). "
                  "Remove them from IRIS by hand if needed.")
        conn.execute("UPDATE alerts SET incident_id = NULL")
        conn.execute("DELETE FROM incidents")
        conn.commit()
    print("Incidents deleted, alerts detached.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--min-level", type=int, default=config.MIN_LEVEL,
                    help="minimum Wazuh level to OPEN an incident (seed)")
    ap.add_argument("--attach-min-level", type=int, default=config.ATTACH_MIN_LEVEL,
                    help="minimum level of the alerts attached to an existing "
                         "incident (0 to disable enrichment)")
    ap.add_argument("--restart", action="store_true",
                    help="starts over from scratch (keeps the alerts)")
    args = ap.parse_args()

    if args.restart:
        restart()

    n_inc, n_alerts = correlate(args.min_level, args.attach_min_level)
    if n_alerts and n_inc:
        print(f"{n_alerts} alerts -> {n_inc} fresh incidents "
              f"(factor {n_alerts / n_inc:.1f}), attachments to existing ones "
              "included")
    elif n_alerts:
        print(f"{n_alerts} alerts attached to existing incidents, no fresh "
              "incident.")
    else:
        print("No alert to correlate.")


if __name__ == "__main__":
    main()
