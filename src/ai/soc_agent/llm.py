"""Generic call to the model — DeepSeek (cloud API, OpenAI-compatible).

DeepSeek accepts no grammar constraint; we force valid JSON through
`response_format={"type": "json_object"}`. That guarantees *syntactically* valid
JSON, NOT that the schema or the enum is respected — that guarantee is pushed
into the calling code (coercion in triage.py) and into the deterministic
guardrails of actions.py.

Security note: everything passing through here leaves for the cloud. The text
must be anonymised upstream (sanitize.py). The LLM is not a security boundary.

Always `/chat/completions` (chat template), never a raw endpoint: the template
changes the verdict (measured).
"""

import json
import logging
import re
import time

import requests

from . import config

log = logging.getLogger(__name__)


def _record(usage: str, model: str, max_tokens: int, duration_ms: int,
                 metrics: dict | None, incident_id: int | None,
                 error: str | None) -> None:
    """Records the call in `llm_calls`. NEVER fails towards the caller.

    Single choke point: instrumenting here rather than in every caller
    guarantees a new use of the model is counted without anyone thinking about
    it. And a lost metric beats a lost verdict — hence the broad try/except.

    psycopg imported inside: `llm.py` must stay usable without a database
    (tests, one-off calls).
    """
    try:
        import psycopg
        m = metrics or {}
        with psycopg.connect(config.PG_DSN) as conn:
            conn.execute(
                "INSERT INTO llm_calls (usage, model, prompt_tokens, "
                "completion_tokens, cache_hit_tokens, cache_miss_tokens, "
                "max_tokens, duration_ms, incident_id, ok, error) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (usage, m.get("model") or model, m.get("prompt_tokens"),
                 m.get("completion_tokens"), m.get("cache_hit_tokens"),
                 m.get("cache_miss_tokens"), max_tokens, duration_ms,
                 incident_id, error is None, error))
            conn.commit()
    except Exception as e:                                   # noqa: BLE001
        log.debug("LLM metric not recorded: %s", e)


# Backslash that does NOT open a valid JSON escape sequence. That is exactly
# what a model produces when it copies a Windows path into its justification:
# `C:\Windows\System32` comes out as-is, and `\W` is not a legal escape.
_BARE_BACKSLASH = re.compile(r'\\(?!["\\/bfnrtu])')


def _load_json(content: str) -> dict:
    """Parses the model's answer, repairing unescaped backslashes.

    `response_format=json_object` was supposed to guarantee valid JSON. It does
    not, and it is measured: on a Windows incident (`C:\\...` paths all over the
    context), DeepSeek returned "Invalid \\escape: line 2 column 68". Without
    repair the incident fails on EVERY cycle — the batch being ordered
    deterministically, it comes back to the front indefinitely.

    The repair is deliberately narrow: we only double the backslashes that open
    no legal escape sequence. Already-correct JSON is untouched (it passes the
    first `loads` and never reaches the regex), and a real API outage still
    surfaces.
    """
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        repaired = _BARE_BACKSLASH.sub(r"\\\\", content)
        obj = json.loads(repaired)   # still failing -> genuinely unusable output
        log.warning("model JSON repaired (unescaped backslashes)")
        return obj


def completion(system: str, user: str, usage: str,
               max_tokens: int = 500, temperature: float = 0.2,
               incident_id: int | None = None) -> tuple[dict, dict]:
    """Returns (parsed JSON object, metrics).

    `response_format` json_object requires the word "json" to appear in the
    messages — the system prompts mention it explicitly ("objet JSON").

    `usage` names the caller ('triage', 'report', ...): it is the dimension the
    AI dashboard then reads consumption by. Failed calls are counted too — a
    timeout or too small a budget costs time, and sometimes tokens, even without
    a usable answer.

    MANDATORY parameter, deliberately placed before the optional ones: with a
    default value a new caller who forgets it goes unnoticed and its consumption
    lands in an "unknown" bucket of the dashboard — which is exactly what
    happened. With no default, forgetting it is a TypeError on the first call.
    """
    start = time.monotonic()
    try:
        return _completion(system, user, max_tokens, temperature,
                           usage, incident_id, start)
    except Exception as e:                                   # noqa: BLE001
        _record(usage, config.DEEPSEEK_MODEL, max_tokens,
                     int((time.monotonic() - start) * 1000), None,
                     incident_id, f"{type(e).__name__}: {e}"[:500])
        raise


def _completion(system: str, user: str, max_tokens: int,
                temperature: float, usage: str, incident_id: int | None,
                start: float) -> tuple[dict, dict]:
    rep = requests.post(
        f"{config.DEEPSEEK_URL}/chat/completions",
        headers={"Authorization": f"Bearer {config.DEEPSEEK_API_KEY}"},
        json={
            "model": config.DEEPSEEK_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens,
            # Low temperature for a verdict as stable as possible. DeepSeek
            # does not guarantee reproducibility by seed (unsupported), unlike
            # the local setup did.
            "temperature": temperature,
            "stream": False,
        },
        # (connect, read) explicit: the second is an INACTIVITY delay, not a
        # total duration. The cycle holds its advisory lock for its whole run —
        # a provider answering slowly must not tie it up (see
        # config.LLM_TIMEOUT_*).
        timeout=(config.LLM_TIMEOUT_CONNECT_S, config.LLM_TIMEOUT_READ_S),
    )
    rep.raise_for_status()
    body = rep.json()
    duration_ms = int((time.monotonic() - start) * 1000)

    choice = body["choices"][0]
    content = choice["message"].get("content") or ""
    # Reasoning models (deepseek-v4-*): the reasoning is charged against
    # max_tokens. If it exhausts it, finish_reason=length and content is EMPTY —
    # the verdict was never written. An explicit error rather than an opaque
    # JSONDecodeError: the fix is to raise TRIAGE_MAX_TOKENS.
    if not content.strip():
        raise RuntimeError(
            f"answer with no content (finish_reason={choice.get('finish_reason')}, "
            f"reasoning exhausting max_tokens={max_tokens}?) — raise the budget")

    obj = _load_json(content)
    consumption = body.get("usage", {})
    # DeepSeek splits the input between cache hit and cache miss, and the hit
    # is billed 50x cheaper. Without that split the cost is overestimated: the
    # system prompt is constant from one incident to the next, so it is almost
    # always served from cache.
    metrics = {"duration_ms": duration_ms,
                 "prompt_tokens": consumption.get("prompt_tokens"),
                 "completion_tokens": consumption.get("completion_tokens"),
                 "cache_hit_tokens": consumption.get("prompt_cache_hit_tokens"),
                 "cache_miss_tokens": consumption.get("prompt_cache_miss_tokens"),
                 "model": body.get("model", config.DEEPSEEK_MODEL)}
    _record(usage, config.DEEPSEEK_MODEL, max_tokens, duration_ms,
                 metrics, incident_id, None)
    return obj, metrics
