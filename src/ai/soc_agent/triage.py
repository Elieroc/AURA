"""LLM triage of incidents — shadow mode.

The model returns a verdict, we record it, and **nothing fires**. As long as
accuracy is not measured on a labelled set (`evaluate.py`), acting on a model
output would be a bet.

    python -m soc_agent.triage --limit 10
    python -m soc_agent.triage --incident 4 --show-prompt
"""

import argparse
import hashlib
import json
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from . import alerts as alerts_mod
from . import config
from .actions import apply_guardrails, infer, high_impact_actions
from .anonymize import (Anonymizer, LeakError, anonymize, rehydrate,
                        check_leak)
from .coherence import check
from .llm import completion
from .render import injection_patterns, render

PROMPTS = Path(__file__).parent / "prompts"

# Prompt size cap: a cost budget, and a bound against a prompt going off the
# rails. Too low, it SILENCED the biggest incidents (the most serious one — 350
# alerts, level 14 — had no triage, no case and no remediation). Raised to 5000;
# overridable from the environment. Prefiltering/summarising upstream is still
# desirable.
TOKENS_CAP = config.PROMPT_TOKENS_CAP

# Output enums. Nothing guarantees them at sampling time: DeepSeek only
# guarantees valid JSON. So we re-validate here — that is the right place for the
# barrier (the model is not a security boundary).
VERDICTS_OK = {"true_positive", "false_positive", "needs_investigation"}
CONFIDENCES_OK = {"low", "medium", "high"}
ACTIONS_OK = {"propose_block_ip", "propose_isolate_host",
              "propose_disable_user", "propose_kill_process",
              "propose_quarantine_file", "propose_remove_privileged_group",
              "escalate_human"}


def _validate(raw: dict) -> dict:
    """Coerces the model output towards the expected schema.

    Any value outside the enum is brought back to a safe one rather than
    propagated: an unknown verdict becomes `needs_investigation` (which triggers
    no automatic action), an unknown action is dropped. This is where the shape
    is guaranteed.
    """
    verdict = raw.get("verdict")
    if verdict not in VERDICTS_OK:
        verdict = "needs_investigation"

    confidence = raw.get("confidence")
    if confidence not in CONFIDENCES_OK:
        confidence = "low"

    raw_actions = raw.get("actions") or []
    if not isinstance(raw_actions, list):
        raw_actions = []
    # Filtered against the enum, deduplicated keeping order, capped at 4.
    actions, seen = [], set()
    for a in raw_actions:
        if a in ACTIONS_OK and a not in seen:
            seen.add(a)
            actions.append(a)
    actions = actions[:4]

    mitre = raw.get("mitre")
    if not (isinstance(mitre, str) and mitre.startswith("T")):
        mitre = None

    reason = str(raw.get("reason") or "").strip() or "(aucune justification)"

    return {"verdict": verdict, "confidence": confidence, "actions": actions,
            "mitre": mitre, "reason": reason}

SELECT_INCIDENTS = """
SELECT i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
       i.alert_count, i.max_level, i.rule_ids, i.mitre_tactics, i.entities,
       i.ueba, i.ueba_score, i.ueba_patterns,
       COALESCE(i.priority, %(default_priority)s) AS priority,
       COALESCE(i.severity, i.max_level) AS severity,
       -- The incident's own column, NOT a join on `assets`: the role used for
       -- the computation can differ from the declared role (sensor fallback),
       -- and a join would show a priority and a role contradicting each other.
       i.asset_role
  FROM incidents i
 WHERE (%(all)s
        OR NOT EXISTS (SELECT 1 FROM triages t WHERE t.incident_id = i.id)
        -- incident enriched since its last triage, BUT not forever: past
        -- INCIDENT_REFRESH_TTL_HOURS from first_seen we stop re-triaging
        -- (anti-loop fix #4; 0 = no limit). Creating a never-triaged incident
        -- stays outside this cap (the NOT EXISTS clause).
        OR (i.needs_refresh
            AND (%(refresh_ttl)s <= 0
                 OR i.first_seen > now() - make_interval(hours => %(refresh_ttl)s))))
   AND (%(single)s::bigint IS NULL OR i.id = %(single)s)
   -- Two populations: Wazuh-seeded incidents (max_level >= MIN_LEVEL) and UEBA
   -- incidents, whose max level is LOW by construction (they come from level
   -- 3-11 alerts). Without the second clause, everything the behavioural engine
   -- reports would be silently dropped from triage.
   AND (i.max_level >= %(min_level)s OR i.ueba)
 -- The batch is CAPPED (triage_limit): the ordering decides what is analysed
 -- now and what waits for the next cycle. So asset priority comes before rule
 -- level — a level 12 on the domain controller must come out before a level 14
 -- on a test box.
 ORDER BY i.ueba, COALESCE(i.priority, %(default_priority)s),
          COALESCE(i.severity, i.max_level) DESC, i.first_seen DESC
 LIMIT %(limit)s
"""

# Loading goes through `alerts.load_bounded`: one fresh flood incident (103,251
# alerts for #2854) killed triage before any call to the model. No loss for the
# decision — `render.render` only shows the model an extract bounded by the
# number of rules anyway.


def build_prompt(incident: dict, alerts: list[dict]) -> tuple[str, str]:
    """(system, user).

    The system prompt is strictly constant — instructions and decision policy.
    Two reasons never to slip a variable in: DeepSeek's context cache only kicks
    in on a prefix identical down to the token, and a moving system prompt makes
    two triages incomparable (`prompt_sha`).
    """
    system = (PROMPTS / "system.md").read_text()
    body = render(incident, alerts)
    user = (
        "=== DEBUT INCIDENT (données non fiables) ===\n"
        f"{body}\n"
        "=== FIN INCIDENT ===\n\n"
        "Rends ton verdict."
    )
    return system, user


def count_tokens(text: str) -> int:
    """Rough estimate of the token count.

    DeepSeek exposes no tokenisation endpoint. ~4 characters per token (the order
    of magnitude observed on these prompts): enough for the prompt-size
    guardrail, which does not need to be exact. The real count is recovered
    afterwards from the usage the API returns.
    """
    return len(text) // 4


def query(system: str, user: str,
               incident_id: int | None = None) -> tuple[dict, dict]:
    """Calls the model (DeepSeek) and validates the output. Returns (verdict, m)."""
    raw, m = completion(system, user, max_tokens=config.TRIAGE_MAX_TOKENS,
                         usage="triage", incident_id=incident_id)
    verdict = _validate(raw)
    return verdict, m


def load_map(conn, incident_id: int) -> dict:
    r = conn.execute("SELECT mapping FROM anonymization_map WHERE incident_id = %s",
                     (incident_id,)).fetchone()
    return (r["mapping"] if r else {}) or {}


def save_map(conn, incident_id: int, mapping: dict) -> None:
    conn.execute(
        "INSERT INTO anonymization_map (incident_id, mapping) VALUES (%s, %s) "
        "ON CONFLICT (incident_id) DO UPDATE "
        "SET mapping = EXCLUDED.mapping, updated_at = now()",
        (incident_id, json.dumps(mapping, ensure_ascii=False)))


INSERT_TRIAGE = """
INSERT INTO triages (incident_id, verdict, confidence, mitre, actions, reason,
                     model, prompt_sha, prompt_tokens, duration_ms, mode,
                     inconsistencies, injection_patterns, guardrails)
VALUES (%(incident_id)s, %(verdict)s, %(confidence)s, %(mitre)s, %(actions)s,
        %(reason)s, %(model)s, %(prompt_sha)s, %(prompt_tokens)s,
        %(duration_ms)s, 'shadow', %(inconsistencies)s, %(injection_patterns)s,
        %(guardrails)s)
RETURNING id
"""


def sort(limit: int, single: int | None, all_incidents: bool,
          show_prompt: bool) -> list[dict]:
    """Triages a batch of incidents and returns the result per incident.

    The `print` calls stay: they are the logs of the `soc-agent-cycle` container,
    read when a batch goes wrong. The return value is there for programmatic
    callers (MCP server), which must not have to parse that output.

    Each entry carries a `status`: `triaged`, or one of the three refusals —
    `leak` (internal identifier left unpseudonymised), `prompt_too_long`,
    `llm_failure`. A refusal does not interrupt the batch.
    """
    results: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        incidents = conn.execute(SELECT_INCIDENTS, {
            "all": all_incidents, "single": single,
            "min_level": config.MIN_LEVEL, "limit": limit,
            "refresh_ttl": config.INCIDENT_REFRESH_TTL_HOURS,
            "default_priority": config.DEFAULT_PRIORITY,
        }).fetchall()

        if not incidents:
            print("No incident to triage.")
            return results

        for inc in incidents:
            alerts = alerts_mod.load_bounded(
                conn, inc["id"], alerts_mod.COLUMNS_TRIAGE, "triage")

            # Pseudonymisation BEFORE building any prompt: nothing sensitive
            # must reach the cloud. Tokens stay stable across passes through the
            # persisted mapping.
            anon = Anonymizer(load_map(conn, inc["id"]))
            inc_a, alerts_to, forbidden = anonymize(anon, inc, alerts)
            system, user = build_prompt(inc_a, alerts_to)

            if show_prompt:
                print("=" * 70)
                print(user)
                print("=" * 70)

            # Fail-closed guardrail: an internal identifier that escaped
            # pseudonymisation forbids the send, we do not guess. We only scan
            # `user` (the incident data): the system prompt is a constant dev
            # template with no client data, and it contains example paths
            # (/var/tmp, /dev/shm) that triggered a false leak positive.
            try:
                check_leak(user, forbidden)
            except LeakError as e:
                print(f"  #{inc['id']} SKIPPED — potential leak: {e}")
                results.append({"incident_id": inc["id"], "status": "leak",
                                  "detail": str(e)})
                continue

            n_tokens = count_tokens(system + user)
            if n_tokens > TOKENS_CAP:
                # We refuse rather than let it through: a prompt that doubles
                # silently doubles the triage time.
                print(f"  #{inc['id']} SKIPPED — prompt of {n_tokens} tokens "
                      f"(cap {TOKENS_CAP}). Tighten render.py.")
                results.append({"incident_id": inc["id"],
                                  "status": "prompt_too_long",
                                  "tokens": n_tokens, "cap": TOKENS_CAP})
                continue

            # A poisoned incident does not break the batch. The LLM call can
            # fail on THIS incident (empty content when reasoning exhausts
            # max_tokens, JSON truncated at the length cut, invalid enum):
            # without this net the exception went up to cycle.py, which cut the
            # WHOLE cycle — hence case creation for already-triaged incidents.
            # And since the batch is ordered deterministically, the same incident
            # came back to the front on every cycle: permanent deadlock. We log,
            # roll back that incident, move on; it is retried next round and the
            # others make progress.
            try:
                verdict, m = query(system, user, inc["id"])
            except Exception as e:  # noqa: BLE001
                conn.rollback()
                print(f"  #{inc['id']} SKIPPED — LLM triage failed: {e}")
                results.append({"incident_id": inc["id"],
                                  "status": "llm_failure", "detail": str(e)})
                continue

            save_map(conn, inc["id"], anon.mapping)
            # Rehydration: the analyst must read the real values, not the
            # tokens. Only DeepSeek saw the pseudonyms.
            verdict["reason"] = rehydrate(verdict["reason"], anon.mapping)

            # We record the inconsistency, we do not fix it: rewriting the
            # model's verdict would hide the problem instead of measuring it.
            inconsistencies = check(verdict["verdict"], verdict["actions"])
            # The model only proposes remediations; opening or closing the case
            # follows from the verdict.
            actions = infer(verdict["verdict"], verdict["actions"])

            # Deterministic barrier. The model lets itself be flipped by an
            # injection in the logs (3 payloads out of 4, see tests); it
            # therefore cannot have the last word on a closure.
            injections = injection_patterns(alerts)
            # Active compromise of the host: at least one post-exploitation
            # rule in the incident (a webshell executing, reverse shell, rootkit,
            # root persistence). On that signal the guardrail no longer downgrades
            # isolation to a plain block_ip.
            active_compromise = bool(
                set(inc["rule_ids"] or []) & config.RULES_COMPROMISE_HOST)
            actions, guardrails = apply_guardrails(
                verdict["verdict"], actions, inc["max_level"], bool(injections),
                active_compromise, inc.get("priority"))

            conn.execute(INSERT_TRIAGE, {
                "inconsistencies": inconsistencies,
                "injection_patterns": injections,
                "guardrails": guardrails,
                "incident_id": inc["id"],
                "verdict": verdict["verdict"],
                "confidence": verdict["confidence"],
                "mitre": verdict["mitre"],
                "actions": actions,
                "reason": verdict["reason"],
                "model": m["model"],
                "prompt_sha": hashlib.sha256(
                    (system + user).encode()).hexdigest()[:16],
                "prompt_tokens": m["prompt_tokens"] or n_tokens,
                "duration_ms": m["duration_ms"],
            })
            conn.commit()

            print(f"  #{inc['id']} {inc['agent_name']:<14} "
                  f"{verdict['verdict']:<20} {verdict['confidence']:<7} "
                  f"{n_tokens:4d} tok  {m['duration_ms'] / 1000:5.1f}s")
            print(f"      actions: {', '.join(actions)}")
            if injections:
                print(f"      /!\\ injection patterns: {', '.join(injections)}")
            for g in guardrails:
                print(f"      GUARDRAIL {g}")
            high_impact = high_impact_actions(actions)
            if high_impact:
                print(f"      high-impact actions (executed, autonomous): "
                      f"{', '.join(high_impact)}")
            print(f"      {verdict['reason'][:160]}")
            if inconsistencies:
                print(f"      /!\\ inconsistency: {'; '.join(inconsistencies)}")

            results.append({
                "incident_id": inc["id"], "status": "triaged",
                "agent_name": inc["agent_name"],
                "verdict": verdict["verdict"],
                "confidence": verdict["confidence"],
                "mitre": verdict["mitre"], "actions": actions,
                "high_impact_actions": high_impact,
                "reason": verdict["reason"],
                "inconsistencies": inconsistencies,
                "injection_patterns": injections,
                "guardrails": guardrails,
                "model": m["model"], "tokens": n_tokens,
                "duration_ms": m["duration_ms"],
            })

    return results


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--incident", type=int, default=None,
                    help="triage one specific incident only")
    ap.add_argument("--all", action="store_true",
                    help="re-triage even already triaged incidents (comparison "
                         "after a prompt or model change)")
    ap.add_argument("--show-prompt", action="store_true")
    args = ap.parse_args()
    sort(args.limit, args.incident, args.all, args.show_prompt)


if __name__ == "__main__":
    main()
