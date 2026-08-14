"""Training mode: learning an estate's ambient noise before unleashing the SOC.

A SOC plugged into an estate already in production first fires on everything
that moves: backups, admin scripts and compliance scanners raise perfectly
legitimate HIGH/CRITICAL alerts. Without a learning period, the autonomous XDR
opens dozens of cases and REMEDIATES that noise — it isolates healthy servers on
day one.

Training mode is a **window of trust declared by the administrator** at SOC
launch: for N days (`TRAINING_DAYS`, default 7), every HIGH/CRITICAL alert
observed is deemed ambient noise and becomes a whitelist exception. It is a
deliberate choice — an intrusion under way at launch time would be learned as
noise. Hence the closure through a "TRAINING" IRIS case: every exception is a
task there, and the analyst undoes the ones that do not belong by moving the task
to 'Canceled'.

During the window the rest of the pipeline is SUSPENDED (`cycle.py` tests
`in_progress()`): no LLM triage, no case, no remediation. Only ingestion carries
on, so the alerts are in database and serve the learning. On closing, the noise
filter is reapplied to everything already stored (`ingest.reapply_filter`): the
learned noise is marked suppressed and no longer seeds any incident when
correlation resumes.

The IRIS case and its tasks stay in French: analysts read them.

    python -m soc_agent.training --tick    # loop of the soc-training container
    python -m soc_agent.training --start   # opens a window (or --days N)
    python -m soc_agent.training --close   # early end
    python -m soc_agent.training --state
"""

import argparse
import json
import logging
import os
import sys

import psycopg
from psycopg.rows import dict_row

from . import config, ingest
from .noise import _value_field
from .whitelist import DISCRIMINANT_FIELDS, _canonical

log = logging.getLogger("training")

# Dedicated advisory lock: 0x50CA1 cycle, 0x50CA2 reconcile, 0x50CA3
# whitelist_task.
_LOCK_TRAINING = 0x50CA4

# Prefix of the IRIS tasks of the TRAINING case. Deliberately DIFFERENT from
# "WHITELIST": `whitelist_task.py` picks up any task whose title starts with
# WHITELIST and moves to 'To do', it must not confuse ours with an analyst's
# exception request.
_TITLE_PREFIX = "TRAINING — whitelist"
_STATUS_PLACED = "Done"
_STATUS_CANCELED = "Canceled"

# IRIS classification of the TRAINING case: "other:other" (id 36). This case is
# not an incident — filing it as an intrusion would skew any statistic drawn from
# the classifications.
CLASSIF_TRAINING = int(os.environ.get("TRAINING_IRIS_CLASSIFICATION", "36"))


# --- window ------------------------------------------------------------------

def current_run(conn) -> dict | None:
    """The open training window, or None.

    The criterion is the STATUS, not `ends_at`: between the deadline expiring and
    the actual closure (filter reapplied plus IRIS case), the pipeline must stay
    suspended. Otherwise the first cycle passing in that interval would correlate
    the raw backlog, before the learned noise is marked.
    """
    return conn.execute(
        "SELECT id, started_at, ends_at, days, status, iris_case_id "
        "  FROM training_runs WHERE status = 'running' "
        " ORDER BY id DESC LIMIT 1").fetchone()


def in_progress(conn) -> bool:
    """Must the pipeline stay suspended? (called by `cycle.py`)"""
    return conn.execute(
        "SELECT 1 FROM training_runs WHERE status = 'running' LIMIT 1"
    ).fetchone() is not None


def start(conn, days: int) -> dict | None:
    """Opens a training window. None if one is already open."""
    if current_run(conn):
        return None
    run = conn.execute("""
        INSERT INTO training_runs (ends_at, days)
        VALUES (now() + make_interval(days => %s), %s)
        RETURNING id, started_at, ends_at, days, status, iris_case_id
    """, (days, days)).fetchone()
    conn.commit()
    log.info("training: window #%s opened for %d day(s), ending %s",
             run["id"], days, run["ends_at"])
    return run


# --- learning ----------------------------------------------------------------

SELECT_ALERTS = """
SELECT id, rule_id, rule_level, rule_desc, agent_name, agent_id, raw
  FROM alerts
 WHERE ts >= %(since)s
   AND rule_level >= %(min_level)s
   AND NOT suppressed
"""


def _training_signature(raw_alerts: list[dict], rule_id: str,
                        agent_name: str | None) -> dict:
    """Signature of a group of alerts (same rule, same machine).

    Differs from `whitelist._signature` on two deliberate points:

    - `agent_name` is ALWAYS part of the signature. Ambient noise belongs to one
      machine (it is that server running that script); whitelisting it everywhere
      would blind detection across the whole fleet.
    - the absence of a discriminant (account / command / file) is NOT a refusal.
      Much infrastructure noise has no discriminant field at all, and
      `rule_id + agent_name` stays bounded to one machine — where `rule_id`
      alone, refused by the automatic whitelist, would neutralise the rule across
      the whole estate.

    Discriminants constant over the whole group are added: they narrow the
    signature further when they exist.
    """
    signature = {"rule_id": str(rule_id)}
    if agent_name:
        signature["agent_name"] = agent_name
    for field in DISCRIMINANT_FIELDS:
        values = {v for a in raw_alerts
                   if (v := _value_field(a, field)) is not None}
        if len(values) == 1:
            signature[field] = str(next(iter(values)))
    return signature


def learn(conn, run: dict) -> list[dict]:
    """Turns the observed HIGH/CRITICAL noise into whitelist exceptions.

    Entirely DETERMINISTIC: no LLM call. Grouped by (rule, machine), one
    exception per group. Idempotent — signatures already known are ignored
    (uniqueness constraint).
    """
    lines = conn.execute(SELECT_ALERTS, {
        "since": run["started_at"], "min_level": config.TRAINING_MIN_LEVEL,
    }).fetchall()
    if not lines:
        return []

    groups: dict[tuple, list[dict]] = {}
    for l in lines:
        groups.setdefault((l["rule_id"], l["agent_name"]), []).append(l)

    existing = {r["signature"] for r in conn.execute(
        "SELECT signature FROM whitelist_rules").fetchall()}

    created: list[dict] = []
    for (rule_id, agent_name), group in sorted(
            groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        level = max(l["rule_level"] for l in group)
        if level > config.TRAINING_MAX_LEVEL:
            log.info("training: level %d > %d, rule %s@%s not whitelisted",
                     level, config.TRAINING_MAX_LEVEL, rule_id, agent_name)
            continue
        raws = [l["raw"] if isinstance(l["raw"], dict) else json.loads(l["raw"])
                for l in group]
        signature = _training_signature(raws, rule_id, agent_name)
        canon = _canonical(signature)
        if canon in existing:
            continue

        desc = next((l["rule_desc"] for l in group if l["rule_desc"]), "")
        reason = (f"ambient noise learned in training (window #{run['id']}, "
                  f"{len(group)} alert(s), max level {level}) — "
                  f"{desc or canon}")
        conn.execute("""
            INSERT INTO whitelist_rules
                (signature, match_all, reason, source, fp_count, training_run_id)
            VALUES (%s, %s, %s, 'training', %s, %s)
            ON CONFLICT (signature) DO NOTHING
        """, (canon, json.dumps(signature), reason, len(group), run["id"]))
        conn.commit()
        existing.add(canon)
        created.append({"signature": canon, "match_all": signature,
                       "alerts": len(group), "level": level,
                       "rule_desc": desc})
        log.info("training: exception learned %s (%d alerts)",
                 canon, len(group))
    return created


# --- closure -----------------------------------------------------------------

def _case_description(run: dict, rules: list[dict]) -> str:
    start = run["started_at"].strftime("%Y-%m-%d %H:%M")
    end = run["ends_at"].strftime("%Y-%m-%d %H:%M")
    return (
        f"Fenêtre d'apprentissage du bruit ambiant #{run['id']} : "
        f"{start} → {end} (UTC).\n\n"
        f"Pendant cette fenêtre, le triage LLM, la création de cases et la "
        f"remédiation autonome étaient SUSPENDUS. Toute alerte de niveau "
        f"≥ {config.TRAINING_MIN_LEVEL} observée a été considérée comme du "
        f"bruit légitime du SI et transformée en exception de whitelist : "
        f"{len(rules)} exception(s).\n\n"
        f"Chaque exception est une tâche de ce case. **Passer une tâche en "
        f"'Canceled' désactive l'exception correspondante** (traitement "
        f"cyclique par soc_agent.training, ~5 min) : les alertes qu'elle "
        f"masquait redeviennent visibles pour le pipeline.\n\n"
        f"Une intrusion déjà en cours au lancement du SOC aurait été apprise "
        f"comme du bruit — c'est la limite assumée du mode training. Revoir "
        f"cette liste est le contrôle qui la rattrape.")


def _task_description(rule: dict) -> str:
    """IRIS task description, from the `whitelist_rules` row as it stands."""
    return (
        f"Exception créée automatiquement pendant le training.\n\n"
        f"```json\n"
        f"{json.dumps(rule['match_all'], ensure_ascii=False, indent=2)}\n"
        f"```\n\n"
        f"{rule['reason']}\n\n"
        f"Passer cette tâche en 'Canceled' pour DÉSACTIVER l'exception : les "
        f"alertes qu'elle masque redeviendront visibles pour le pipeline.")


def close(conn, run: dict) -> dict:
    """Closes the window: filter reapplied, "TRAINING" IRIS case, status frozen.

    The order is mandatory: the filter is reapplied BEFORE flipping the status,
    because the status is what unblocks the pipeline. The other way round would
    let a cycle correlate the unfiltered backlog.
    """
    # Final learning pass: the alerts of the very last minutes.
    learn(conn, run)

    rules = conn.execute("""
        SELECT id, signature, match_all, reason, fp_count
          FROM whitelist_rules
         WHERE training_run_id = %s AND active
         ORDER BY id
    """, (run["id"],)).fetchall()

    deleted, seen = ingest.reapply_filter()
    log.info("training: filter reapplied, %d/%d alerts suppressed",
             deleted, seen)

    case_id = None
    try:
        case_id = _create_iris_case(conn, run, rules)
    except Exception as e:  # noqa: BLE001 — an unavailable IRIS must not leave
        # the window open forever: the exceptions are created, the pipeline must
        # resume. The case is retried on the next tick.
        log.error("training: IRIS case not created (%s) — retrying on the next "
                  "pass", e)

    if case_id is None:
        return {"case_id": None, "rules": len(rules),
                "suppressed": deleted}

    conn.execute("UPDATE training_runs SET status = 'finished', "
                 "finished_at = now(), iris_case_id = %s WHERE id = %s",
                 (case_id, run["id"]))
    conn.commit()
    log.info("training: window #%s closed -> IRIS case #%s (%d exceptions)",
             run["id"], case_id, len(rules))
    return {"case_id": case_id, "rules": len(rules),
            "suppressed": deleted}


def _create_iris_case(conn, run: dict, rules: list[dict]) -> int:
    # Deferred import: `iris` pulls in the whole pipeline, no point loading it
    # for a tick that only learns.
    from .iris import _client

    case = _client()
    start = run["started_at"].strftime("%Y-%m-%d")
    r = case.add_case(
        case_name=f"TRAINING — bruit ambiant du SI ({start}, "
                  f"{run['days']} j)",
        case_description=_case_description(run, rules),
        case_customer=config.IRIS_CUSTOMER,
        case_classification=CLASSIF_TRAINING,
        soc_id=f"Aura-SOC-TRAINING-{run['id']}",
    )
    if not r.is_success():
        raise RuntimeError(f"TRAINING case creation failed: {r.get_msg()}")
    case_id = r.get_data()["case_id"]

    for rule in rules:
        title = f"{_TITLE_PREFIX} : {rule['signature']}"
        try:
            rt = case.add_task(
                title=title[:250],
                status=_STATUS_PLACED,
                assignees=[],
                description=_task_description(rule),
                tags=["training", "whitelist", "auto"],
                cid=case_id)
            task_id = rt.get_data().get("id") if rt.is_success() else None
        except Exception as e:  # noqa: BLE001 — one failed task does not stop
            # the others; the exception already exists in database.
            log.warning("training: task for %s not created: %s",
                        rule["signature"], e)
            continue
        if task_id:
            conn.execute("UPDATE whitelist_rules SET iris_task_id = %s "
                         "WHERE id = %s", (task_id, rule["id"]))
            conn.commit()
    return case_id


# --- revocation: task moved to 'Canceled' ------------------------------------

def reconcile(conn) -> list[dict]:
    """Disables the exceptions whose IRIS task moved to 'Canceled'.

    Symmetric to `mitigate.reconcile` for remediations. One-way: moving the task
    back to 'Done' does NOT re-enable the exception — an exception removed by an
    analyst must be recreated explicitly, not at the whim of a status click.
    """
    runs = conn.execute(
        "SELECT id, iris_case_id FROM training_runs "
        "WHERE iris_case_id IS NOT NULL").fetchall()
    if not runs:
        return []

    active = conn.execute("""
        SELECT id, signature, iris_task_id, training_run_id
          FROM whitelist_rules
         WHERE active AND iris_task_id IS NOT NULL
           AND training_run_id IS NOT NULL
    """).fetchall()
    if not active:
        return []
    by_task = {r["iris_task_id"]: r for r in active}

    from .iris import _client
    from .mitigate import _comment_task
    case = _client()

    removed: list[dict] = []
    for run in runs:
        cid = run["iris_case_id"]
        try:
            tasks = (case.list_tasks(cid).get_data() or {}).get("tasks") or []
        except Exception as e:  # noqa: BLE001 — IRIS down never breaks the tick
            log.warning("training: list_tasks case #%s: %s", cid, e)
            continue
        for t in tasks:
            if (t.get("status_name") or "") != _STATUS_CANCELED:
                continue
            rule = by_task.get(t.get("task_id"))
            if not rule:
                continue
            conn.execute("UPDATE whitelist_rules SET active = false "
                         "WHERE id = %s", (rule["id"],))
            conn.commit()
            removed.append({"signature": rule["signature"],
                             "task_id": t["task_id"], "case_id": cid})
            log.info("training: exception %s disabled (IRIS task #%s "
                     "Canceled)", rule["signature"], t["task_id"])
            _comment_task(case, cid, t["task_id"],
                "🤖 Exception de training DÉSACTIVÉE : les alertes "
                f"`{rule['signature']}` redeviennent visibles pour le "
                "pipeline (triage, case, remédiation).")

    if removed:
        # The alerts those exceptions masked must become correlatable again:
        # without this re-evaluation they would stay marked `suppressed` in
        # database and the revocation would have no visible effect.
        deleted, seen = ingest.reapply_filter()
        log.info("training: filter reapplied after revocation "
                 "(%d/%d suppressed)", deleted, seen)
    return removed


# --- loop --------------------------------------------------------------------

def tick() -> dict:
    """One pass of the soc-training container. Idempotent.

    Automatic start: only when `TRAINING_ENABLED` and NO window has ever been
    opened. Training is a commissioning phase, not a recurring mode — reopening a
    window later is an explicit decision (`--start`).
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)", (_LOCK_TRAINING,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("training: pass already running, skipping this round")
            return {"state": "locked"}
        try:
            run = current_run(conn)
            if run is None:
                already = conn.execute(
                    "SELECT 1 FROM training_runs LIMIT 1").fetchone()
                if config.TRAINING_ENABLED and not already:
                    run = start(conn, config.TRAINING_DAYS)
                else:
                    # Window closed (or never opened): what is left is listening
                    # for the analyst's revocations on the TRAINING case.
                    return {"state": "inactive",
                            "revoked": reconcile(conn)}

            expired = conn.execute(
                "SELECT now() >= %s AS done", (run["ends_at"],)).fetchone()["done"]
            if expired:
                return {"state": "closing", **close(conn, dict(run))}

            created = learn(conn, run)
            return {"state": "learning", "run": run["id"],
                    "created": len(created), "ends_at": run["ends_at"]}
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_TRAINING,))


def state_report() -> list[dict]:
    """The training windows, most recent first, with their exceptions."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        runs = conn.execute(
            "SELECT * FROM training_runs ORDER BY id DESC").fetchall()
        output = []
        for r in runs:
            n = conn.execute(
                "SELECT count(*) FILTER (WHERE active) AS a, count(*) AS t "
                "FROM whitelist_rules WHERE training_run_id = %s",
                (r["id"],)).fetchone()
            output.append({
                "id": r["id"], "status": r["status"], "days": r["days"],
                "started_at": r["started_at"].isoformat(),
                "ends_at": r["ends_at"].isoformat(),
                "finished_at": (r["finished_at"].isoformat()
                                if r["finished_at"] else None),
                "iris_case_id": r["iris_case_id"],
                "active_exceptions": n["a"], "total_exceptions": n["t"],
            })
    return output


def state() -> None:
    runs = state_report()
    if not runs:
        print("No training window.")
        return
    for r in runs:
        print(f"  #{r['id']} [{r['status']}] {r['started_at'][:16]}"
              f" → {r['ends_at'][:16]} ({r['days']} j)"
              f"  case IRIS {r['iris_case_id'] or '—'}"
              f"  exceptions {r['active_exceptions']}/{r['total_exceptions']} "
              f"active")


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stderr)
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tick", action="store_true",
                    help="one full pass (the container loop)")
    ap.add_argument("--start", action="store_true",
                    help="opens a training window")
    ap.add_argument("--days", type=int, default=config.TRAINING_DAYS)
    ap.add_argument("--close", action="store_true",
                    help="closes the current window without waiting for its end")
    ap.add_argument("--state", action="store_true")
    args = ap.parse_args()

    if args.state:
        state()
        return

    if args.start:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            run = start(conn, args.days)
        if run is None:
            print("A training window is already open.")
        else:
            print(f"Window #{run['id']} open until {run['ends_at']}.")
        return

    if args.close:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            run = current_run(conn)
            if run is None:
                print("No training window open.")
                return
            res = close(conn, dict(run))
        print(f"Window closed: {res['rules']} exception(s), "
              f"IRIS case #{res['case_id']}.")
        return

    res = tick()
    print(res)


if __name__ == "__main__":
    main()
