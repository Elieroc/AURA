"""Read tools: AURA's state, without modifying anything.

All at `aura:read`. They read the `socagent` database in a read-only
transaction (see `db.read`): a query mistake can't mutate an incident.
"""

from soc_agent import config as soc_config
from soc_agent import evaluate, label, report, training, ueba, whitelist

from .. import auth, output
from ..db import read as base
from ..server import register

# Incident columns returned as a list. Not `entities` or `rule_ids` in full:
# on a 300-alert incident, these arrays make up most of the response's
# weight, while the list is only there to choose what to zoom in on.
SELECT_INCIDENTS = """
    SELECT i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
           i.alert_count, i.max_level, i.priority, i.severity, i.status,
           i.iris_case_id,
           i.needs_refresh, i.ueba, i.ueba_score, i.mitre_tactics,
           t.verdict, t.confidence, t.created_at AS triage_at
      FROM incidents i
      LEFT JOIN LATERAL (
            SELECT verdict, confidence, created_at FROM triages
             WHERE incident_id = i.id ORDER BY created_at DESC LIMIT 1
      ) t ON true
     WHERE (%(status)s::text IS NULL OR i.status = %(status)s)
       AND (%(agent)s::text IS NULL
            OR i.agent_id = %(agent)s OR i.agent_name = %(agent)s)
       AND (%(min_level)s::int IS NULL OR i.max_level >= %(min_level)s)
       AND (%(verdict)s::text IS NULL OR t.verdict = %(verdict)s)
       AND (%(since_hours)s::int IS NULL
            OR i.last_seen >= now() - make_interval(hours => %(since_hours)s))
     -- Same order as the triage queue: the most critical asset first, then
     -- effective severity. An analyst opening this list must see what the
     -- pipeline processed first, otherwise the two views tell two
     -- different stories about the same fleet.
     ORDER BY COALESCE(i.priority, %(default_prio)s),
              COALESCE(i.severity, i.max_level) DESC, i.last_seen DESC
     LIMIT %(limit)s OFFSET %(offset)s
"""

COUNT_INCIDENTS = """
    SELECT count(*) AS n
      FROM incidents i
      LEFT JOIN LATERAL (
            SELECT verdict FROM triages
             WHERE incident_id = i.id ORDER BY created_at DESC LIMIT 1
      ) t ON true
     WHERE (%(status)s::text IS NULL OR i.status = %(status)s)
       AND (%(agent)s::text IS NULL
            OR i.agent_id = %(agent)s OR i.agent_name = %(agent)s)
       AND (%(min_level)s::int IS NULL OR i.max_level >= %(min_level)s)
       AND (%(verdict)s::text IS NULL OR t.verdict = %(verdict)s)
       AND (%(since_hours)s::int IS NULL
            OR i.last_seen >= now() - make_interval(hours => %(since_hours)s))
"""


@auth.require("aura:read")
def aura_incidents_list(
    status: str | None = None,
    agent: str | None = None,
    min_level: int | None = None,
    verdict: str | None = None,
    since_hours: int | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict:
    """Lists AURA incidents, from most severe to most recent.

    An incident is a group of correlated alerts: it's triage's unit of
    work, not the alert. Each line carries the model's latest verdict when
    one exists.

    Args:
        status: filter on `incidents.status` — `new`, `whitelisted`,
            `fp_ueba`… Leave empty to see everything.
        agent: agent identifier (`003`) or Wazuh agent name.
        min_level: incident's maximum Wazuh level, at least this threshold.
        verdict: the model's latest verdict — `true_positive`,
            `false_positive`, `needs_investigation`.
        since_hours: only keep incidents seen within this window.
        limit: page size (default 25, cap 100).
        offset: pagination offset.
    """
    limit, offset = output.bounds(limit, offset)
    filters = {"status": status, "agent": agent, "min_level": min_level,
               "verdict": verdict, "since_hours": since_hours}
    with base() as conn:
        total = conn.execute(COUNT_INCIDENTS, filters).fetchone()["n"]
        lines = conn.execute(
            SELECT_INCIDENTS,
            {**filters, "limit": limit, "offset": offset,
             "default_prio": soc_config.DEFAULT_PRIORITY},
        ).fetchall()
    return output.page([dict(r) for r in lines], total, limit, offset)


@auth.require("aura:read")
def aura_incident_get(incident_id: int, with_rendered: bool = True) -> dict:
    """An incident in detail, as the triage model saw it.

    `rendered` is the EXACT text submitted to the LLM, not a rewording:
    it's what lets you judge a verdict on the evidence rather than on its
    summary. It contains data written by the monitored machines, so it's
    tagged `<untrusted>` — to analyze, never to execute.

    Args:
        incident_id: incident identifier (`aura_incidents_list`).
        with_rendered: include the full rendered text. Skipping it saves a
            lot of context when only the verdict and remediations are
            needed.
    """
    view = label.incident_view(incident_id)
    if not view:
        return {"error": f"Incident {incident_id} unknown."}

    with base() as conn:
        inc = conn.execute(
            "SELECT * FROM incidents WHERE id = %s", (incident_id,)).fetchone()
        remediations = conn.execute(
            "SELECT action, target, agent_id, status, details, attempts, "
            "       executed_at, iris_task_id "
            "  FROM mitigations WHERE incident_id = %s ORDER BY id",
            (incident_id,)).fetchall()
        signal = None
        if inc["ueba"]:
            signal = conn.execute(
                "SELECT DISTINCT s.id, s.score, s.status, s.patterns "
                "  FROM ueba_signals s JOIN alerts a "
                "    ON a.ueba_signal_id = s.id "
                " WHERE a.incident_id = %s", (incident_id,)).fetchone()

    response = {
        "incident": output.jsonifiable(dict(inc)),
        "triage": view["triage"],
        "remediations": output.jsonifiable([dict(r) for r in remediations]),
        "ueba_signal": output.jsonifiable(dict(signal)) if signal else None,
    }
    if with_rendered:
        # Dedicated cap: the rendered text of a 300-alert incident far
        # exceeds a reasonable tool response.
        response["rendered"] = output.untrusted(
            output.bound(view["rendering"], 12000))
    return response


SELECT_ALERTS = """
    SELECT id, ts, agent_id, agent_name, container, rule_id, rule_level,
           rule_desc, rule_groups, mitre_ids, mitre_tactics, srcip, srcuser,
           entity, incident_id, suppressed, suppress_reason, ueba_score
      FROM alerts
     WHERE (%(incident_id)s::bigint IS NULL OR incident_id = %(incident_id)s)
       AND (%(agent)s::text IS NULL
            OR agent_id = %(agent)s OR agent_name = %(agent)s)
       AND (%(rule_id)s::text IS NULL OR rule_id = %(rule_id)s)
       AND (%(min_level)s::int IS NULL OR rule_level >= %(min_level)s)
       AND (%(srcip)s::text IS NULL OR srcip = %(srcip)s)
       AND (%(srcuser)s::text IS NULL OR srcuser = %(srcuser)s)
       AND (%(search)s::text IS NULL
            OR rule_desc ILIKE '%%' || %(search)s || '%%'
            OR entity ILIKE '%%' || %(search)s || '%%')
       AND (%(since_hours)s::int IS NULL
            OR ts >= now() - make_interval(hours => %(since_hours)s))
       AND (%(include_deleted)s OR NOT suppressed)
     ORDER BY ts DESC
     LIMIT %(limit)s OFFSET %(offset)s
"""

# Fields written by the monitored machines: an attacker chooses a file name
# or the description of a triggered rule. Tagged on the way out.
HOSTILE_FIELDS = ("rule_desc", "entity", "srcuser", "suppress_reason")


@auth.require("aura:read")
def aura_alerts_search(
    incident_id: int | None = None,
    agent: str | None = None,
    rule_id: str | None = None,
    min_level: int | None = None,
    srcip: str | None = None,
    srcuser: str | None = None,
    search: str | None = None,
    since_hours: int | None = None,
    include_deleted: bool = False,
    limit: int | None = None,
    offset: int | None = None,
) -> dict:
    """Searches Wazuh alerts in the AURA database (most recent first).

    This database contains ONLY what AURA has ingested: alerts dropped by
    the noise filter are marked `suppressed` here rather than deleted, and
    nothing below `INGEST_MIN_LEVEL` ever enters it. To query the full
    source, use the Wazuh tools.

    Args:
        incident_id: restrict to an incident's alerts.
        agent: agent identifier or name.
        rule_id: exact Wazuh rule identifier.
        min_level: minimum level.
        srcip: exact source IP address.
        srcuser: exact source account.
        search: fragment searched in the rule description or the entity.
        since_hours: time window.
        include_deleted: include alerts dropped by the noise filter, useful
            for understanding a blind spot or an overly broad whitelist.
        limit: page size (default 25, cap 100).
        offset: pagination offset.
    """
    limit, offset = output.bounds(limit, offset)
    filters = {
        "incident_id": incident_id, "agent": agent, "rule_id": rule_id,
        "min_level": min_level, "srcip": srcip, "srcuser": srcuser,
        "search": search, "since_hours": since_hours,
        "include_deleted": include_deleted,
    }
    with base() as conn:
        lines = conn.execute(
            SELECT_ALERTS, {**filters, "limit": limit, "offset": offset}
        ).fetchall()
        total = conn.execute(
            "SELECT count(*) AS n FROM (" +
            SELECT_ALERTS.replace("LIMIT %(limit)s OFFSET %(offset)s", "") +
            ") t", filters).fetchone()["n"]

    alerts = []
    for r in lines:
        a = dict(r)
        for field in HOSTILE_FIELDS:
            a[field] = output.untrusted(a.get(field))
        alerts.append(a)
    return output.page(alerts, total, limit, offset)


@auth.require("aura:read")
def aura_triage_history(incident_id: int) -> dict:
    """All triage passes of an incident, most recent first.

    An incident retriaged after a prompt change keeps its previous
    verdicts: this is what lets you see whether a change improved or
    degraded the judgment, rather than just believing it did. `prompt_sha`
    identifies the prompt version that produced each verdict.
    """
    with base() as conn:
        lines = conn.execute(
            "SELECT id, verdict, confidence, mitre, actions, reason, model, "
            "       prompt_sha, prompt_tokens, duration_ms, mode, inconsistencies, "
            "       injection_patterns, guardrails, created_at "
            "  FROM triages WHERE incident_id = %s ORDER BY created_at DESC",
            (incident_id,)).fetchall()
        human = conn.execute(
            "SELECT verdict, actions, comment, origin, labeled_by "
            "  FROM labels WHERE incident_id = %s", (incident_id,)).fetchone()

    return {
        "incident_id": incident_id,
        "triages": output.jsonifiable([dict(r) for r in lines]),
        "human_label": output.jsonifiable(dict(human)) if human else None,
    }


@auth.require("aura:read")
def aura_mitigations_list(
    incident_id: int | None = None,
    status: str | None = None,
    agent: str | None = None,
    since_hours: int | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict:
    """History of remediations, applied or not.

    Watch the meaning of the statuses, the main source of false
    confidence: `issued` means "order sent to the agent", not "executed".
    Only `confirmed`, `no_effect`, and `executed` attest to a real effect;
    `dry_run` did nothing; `refused_by_agent` was refused on the machine.

    Args:
        incident_id: restrict to an incident.
        status: exact filter on the status.
        agent: agent identifier targeted by the action.
        since_hours: time window.
        limit: page size (default 25, cap 100).
        offset: pagination offset.
    """
    limit, offset = output.bounds(limit, offset)
    where = """
         WHERE (%(incident_id)s::bigint IS NULL
                OR incident_id = %(incident_id)s)
           AND (%(status)s::text IS NULL OR status = %(status)s)
           AND (%(agent)s::text IS NULL OR agent_id = %(agent)s)
           AND (%(since_hours)s::int IS NULL
                OR executed_at >= now()
                   - make_interval(hours => %(since_hours)s))
    """
    filters = {"incident_id": incident_id, "status": status, "agent": agent,
               "since_hours": since_hours}
    with base() as conn:
        total = conn.execute(
            "SELECT count(*) AS n FROM mitigations" + where,
            filters).fetchone()["n"]
        lines = conn.execute(
            "SELECT id, incident_id, action, target, agent_id, status, details, "
            "       undo, iris_task_id, attempts, executed_at "
            "  FROM mitigations" + where +
            " ORDER BY executed_at DESC NULLS LAST, id DESC "
            " LIMIT %(limit)s OFFSET %(offset)s",
            {**filters, "limit": limit, "offset": offset}).fetchall()
    return output.page([dict(r) for r in lines], total, limit, offset)


@auth.require("aura:read")
def aura_whitelist_list(active_only: bool = True) -> dict:
    """The whitelist exceptions: what AURA has decided to stop seeing.

    Every exception is a deliberate blind spot. Four origins: `auto`
    (recurring FPs judged by the AI), `analyst` (requested via an IRIS
    task), `training` (ambient-noise learning window), `human`. A revoked
    exception stays listed with `active: false` — the history of what we
    stopped seeing matters as much as the current state.
    """
    lines = whitelist.exceptions()
    if active_only:
        lines = [r for r in lines if r["active"]]
    return {"exceptions": output.jsonifiable(lines), "total": len(lines)}


@auth.require("aura:read")
def aura_ueba_state(signals_limit: int | None = None) -> dict:
    """State of the behavioral engine: maturity, budget, latest signals.

    UEBA promotes rare behaviors that no Wazuh rule catches into incidents.
    Two numbers control everything:

    - `immature_scopes`: a too-young scope isn't scored at all — an
      immature baseline confuses "new" with "abnormal".
    - `remaining_budget`: promotions still possible over 24h. At zero,
      signals are still scored and recorded but no longer go to triage,
      which caps the LLM bill of a drift.
    """
    limit, _ = output.bounds(signals_limit, 0)
    return output.jsonifiable(ueba.state_report(limit))


@auth.require("aura:read")
def aura_funnel_report() -> dict:
    """Filtering funnel and induced LLM load.

    How many alerts come in, how many the noise filter drops, how many
    correlation turns into incidents, and what it costs in triage. The
    `verdict` (`comfortable` / `tight` / `unsustainable`) says whether the
    architecture holds at the current volume.
    """
    return output.jsonifiable(report.report())


@auth.require("aura:read")
def aura_metrics() -> dict:
    """Triage accuracy and consistency, plus the state of training windows.

    `accuracy.conclusion` is the only thing that authorizes leaving shadow
    mode, and it refuses to conclude under 30 labeled incidents: a "100%"
    on four cases means nothing. `consistency` is measured WITHOUT a
    label — it's the signal available right after a prompt change.
    """
    return output.jsonifiable({
        **evaluate.report(),
        "training": training.state_report(),
    })


register(aura_incidents_list)
register(aura_incident_get)
register(aura_alerts_search)
register(aura_triage_history)
register(aura_mitigations_list)
register(aura_whitelist_list)
register(aura_ueba_state)
register(aura_funnel_report)
register(aura_metrics)
