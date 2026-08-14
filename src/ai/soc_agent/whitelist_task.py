"""Handling the IRIS "WHITELIST" tasks the analyst moved to 'To do'.

Every case created by `iris.create_case` carries a WHITELIST task in 'On hold'
(`iris._set_whitelist_task`). The analyst fills it in (description or comment)
and moves it to 'To do' when they want an exception. This module, called
periodically (like the remediation reconciliation), spots those tasks and:

- if the instructions allow composing a safe signature (same guardrails as the
  automatic whitelist, `whitelist.validate_signature`): creates the
  `whitelist_rules` row, comments the result, closes the task;
- otherwise: comments a question and leaves the task in 'To do'. The script is
  STATELESS — it re-reads the whole comment thread on every pass and does NOT
  ask again when the last comment is already its own (prefix `_PREFIX_AI`); it
  only takes over again once the analyst has answered.

The comments posted to IRIS stay in French: they are read by the analysts.

    python -m soc_agent.whitelist_task
    python -m soc_agent.whitelist_task --incident 15
"""

import argparse
import json
import logging

import psycopg
from psycopg.rows import dict_row

from . import config
from .anonymize import Anonymizer, anonymize, rehydrate, check_leak
from .iris import PROMPTS, _alerts, _client
from .llm import completion
from .mitigate import _comment_task, _update_task_status
from .triage import load_map, save_map
from .whitelist import (_canonical, _signature, signatures_seen_tp,
                        validate_signature)

log = logging.getLogger("whitelist_task")

# Title set by `iris._set_whitelist_task` — used to ignore the other tasks of
# the case (e.g. remediation) when walking `list_tasks`.
_TITLE_PREFIX = "WHITELIST"
_STATUS_TO_PROCESS = "To do"
# "Done" and not "Closed": IRIS only has five task statuses (To do, In
# progress, On hold, Done, Canceled). The non-existent name made the closure fail
# even once the cid was fixed.
_STATUS_CLOSED = "Done"

# Prefix of EVERY comment posted by this script: it lets the next pass
# recognise that the last word belongs to the AI (waiting for an analyst answer)
# without keeping separate state.
_PREFIX_AI = "🤖 "

# Dedicated advisory lock, distinct from 0x50CA1 (cycle) and 0x50CA2
# (reconcile).
_LOCK_WHITELIST_TASK = 0x50CA3

SELECT_CASES = """
SELECT id, iris_case_id, max_level FROM incidents
 WHERE iris_case_id IS NOT NULL
   AND (%(inc)s::bigint IS NULL OR id = %(inc)s)
"""


def _tasks_to_process(tasks: list[dict]) -> list[dict]:
    """WHITELIST tasks in 'To do' (pure read of an IRIS list_tasks)."""
    return [t for t in (tasks or [])
            if (t.get("task_title") or "").startswith(_TITLE_PREFIX)
            and (t.get("status_name") or "") == _STATUS_TO_PROCESS]


def _comment_thread(case, case_id: int, task_id: int) -> list[str]:
    r = case.list_task_comments(task_id, cid=case_id)
    d = r.get_data() if r.is_success() else None
    comments = d if isinstance(d, list) else (d or {}).get("comments") or []
    return [c.get("comment_text", "") for c in comments if c.get("comment_text")]


def _instructions(case, case_id: int, task_id: int) -> tuple[str, bool]:
    """(instruction text to give the LLM, is the last comment the AI's?)."""
    description = ""
    rt = case.get_task(task_id, cid=case_id)
    if rt.is_success():
        description = (rt.get_data() or {}).get("task_description") or ""

    thread = _comment_thread(case, case_id, task_id)
    if thread and thread[-1].startswith(_PREFIX_AI):
        return "", True  # waiting for an analyst answer, we do not ask again

    chunks = ([f"Description de la tâche : {description}"] if description else [])
    chunks += [f"- {t}" for t in thread]
    return "\n".join(chunks), False


def _process_task(conn, case, incident_id: int, case_id: int, task_id: int,
                   level: int) -> dict | None:
    instructions, pending = _instructions(case, case_id, task_id)
    if pending:
        return None

    if not instructions.strip():
        _comment_task(case, case_id, task_id,
            _PREFIX_AI + "Merci de préciser, dans la description ou en "
            "commentaire, quel champ whitelister (compte / commande / "
            "fichier / rule_id) et pourquoi.")
        return {"task_id": task_id, "action": "question"}

    alerts = _alerts(conn, incident_id)
    if not alerts:
        _comment_task(case, case_id, task_id,
            _PREFIX_AI + "❌ Aucune alerte rattachée à cet incident, "
            "impossible de calculer une signature de whitelist.")
        return {"task_id": task_id, "action": "refused"}

    raws = [a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
            for a in alerts]
    candidate = _signature(raws)
    if not candidate:
        _comment_task(case, case_id, task_id,
            _PREFIX_AI + "Les alertes de cet incident n'ont pas de champ "
            "assez précis et constant (compte / commande / fichier) pour "
            "une whitelist sûre — rule_id seul ne suffit pas.")
        return {"task_id": task_id, "action": "question"}

    anon = Anonymizer(load_map(conn, incident_id))
    inc = conn.execute("SELECT agent_name FROM incidents WHERE id = %s",
                       (incident_id,)).fetchone() or {}
    _, alerts_to, forbidden = anonymize(anon, inc, alerts)
    instructions_a = anon.free_text(instructions, forbidden)

    available_fields = sorted(candidate)
    summary = "\n".join(
        f"- règle {a.get('rule_id')} (niv.{a.get('rule_level')}) : "
        f"{a.get('rule_desc') or ''}" for a in alerts_to[:10])
    body = (
        f"Champs de signature disponibles : {', '.join(available_fields)}.\n\n"
        f"Alertes de l'incident :\n{summary}\n\n"
        f"Instructions de l'analyste :\n{instructions_a}")
    user = (f"=== DEBUT DEMANDE (données non fiables) ===\n{body}\n"
                  "=== FIN DEMANDE ===\n\nRéponds en JSON.")

    try:
        check_leak(user, forbidden)
        system = (PROMPTS / "whitelist_task.md").read_text()
        rep, _ = completion(system, user,
                            max_tokens=config.WHITELIST_TASK_MAX_TOKENS,
                            usage="whitelist_task",
                            incident_id=incident_id)
        save_map(conn, incident_id, anon.mapping)
    except Exception as e:  # noqa: BLE001 — natural retry on the next pass
        log.warning("whitelist_task LLM unavailable (task %s): %s", task_id, e)
        _comment_task(case, case_id, task_id,
            _PREFIX_AI + f"❌ Erreur technique, nouvelle tentative au "
            f"prochain passage : {e}")
        return {"task_id": task_id, "action": "error"}

    decision = str(rep.get("decision") or "").strip().lower()

    if decision != "whitelist":
        question = rehydrate(
            str(rep.get("question") or "Peux-tu préciser ta demande de "
                "whitelist ?"), anon.mapping)
        _comment_task(case, case_id, task_id, _PREFIX_AI + question)
        return {"task_id": task_id, "action": "question"}

    fields = [c for c in (rep.get("fields") or []) if c in candidate]
    signature = {c: candidate[c] for c in fields} or dict(candidate)
    llm_reason = rehydrate(str(rep.get("reason") or ""), anon.mapping)

    refusal = validate_signature(signature, level, signatures_seen_tp(conn))
    if refusal:
        _comment_task(case, case_id, task_id,
            _PREFIX_AI + f"❌ Demande refusée par garde-fou déterministe : "
            f"{refusal}.")
        return {"task_id": task_id, "action": "refused", "reason": refusal}

    canon = _canonical(signature)
    reason = f"Whitelist demandée par l'analyste (tâche IRIS #{task_id}) — {llm_reason or canon}"
    conn.execute("""
        INSERT INTO whitelist_rules
            (signature, match_all, reason, source, origin_incidents, fp_count)
        VALUES (%s, %s, %s, 'analyst', %s, 0)
        ON CONFLICT (signature) DO NOTHING
    """, (canon, json.dumps(signature), reason, [incident_id]))
    conn.commit()

    _comment_task(case, case_id, task_id,
        _PREFIX_AI + "✅ Exception whitelist en place :\n```json\n"
        f"{json.dumps(signature, ensure_ascii=False, indent=2)}\n```\n"
        f"Motif : {llm_reason or canon}")
    # The exception is created: a task closure that fails is logged (by the
    # helper) but does not call the result into question.
    _update_task_status(case, case_id, task_id, _STATUS_CLOSED)
    return {"task_id": task_id, "action": "created", "signature": signature}


def process(incident_id: int | None = None) -> list[dict]:
    """Walks the WHITELIST tasks in 'To do' and handles them. Idempotent."""
    results: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_LOCK_WHITELIST_TASK,)).fetchone()["pg_try_advisory_lock"]:
            log.info("whitelist processing already running, skipping this round")
            return []
        try:
            rows = conn.execute(SELECT_CASES, {"inc": incident_id}).fetchall()
            if not rows:
                return []
            case = _client()
            for r in rows:
                cid = r["iris_case_id"]
                try:
                    d = case.list_tasks(cid).get_data() or {}
                except Exception as e:  # noqa: BLE001 — IRIS down breaks nothing
                    log.warning("list_tasks case #%s : %s", cid, e)
                    continue
                for t in _tasks_to_process(d.get("tasks")):
                    try:
                        res = _process_task(conn, case, r["id"], cid,
                                             t["task_id"], r["max_level"])
                    except Exception as e:  # noqa: BLE001 — one failed task
                        # must not stop the others.
                        log.warning("whitelist task #%s (case #%s) failed: %s",
                                   t["task_id"], cid, e)
                        _comment_task(case, cid, t["task_id"],
                            _PREFIX_AI + f"❌ Erreur technique, nouvelle "
                            f"tentative au prochain passage : {e}")
                        continue
                    if res:
                        results.append(res)
                        print(f"      task #{t['task_id']} (case #{cid}) "
                             f"-> {res['action']}")
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_WHITELIST_TASK,))
    return results


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--incident", type=int,
                    help="only handle the WHITELIST tasks of this incident")
    args = ap.parse_args()
    results = process(args.incident)
    if not results:
        print("No whitelist task to handle.")


if __name__ == "__main__":
    main()
