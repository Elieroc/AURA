"""Formatting of tool responses.

A tool response lands in an LLM's context. Two constraints that don't exist
for a regular API:

1. **Size is a cost.** A 200 KB `full_log` or 3,000 alerts don't make the
   client more lucid, they saturate its window. Everything is bounded and
   paginated, and a truncation is always announced within the data itself.
2. **The content is hostile.** `rule_desc`, `full_log`, a file name, a
   command line: all of this is written by whatever runs on the monitored
   machines, so possibly by an attacker who knows an AI is going to read it.
   It is tagged `<untrusted>` so the client knows it is looking at evidence,
   not instructions.

The tagging isn't a protection — a model can still fall for it anyway (3
payloads out of 4 in the pipeline's tests). The real barrier stays
deterministic and server-side: `soc_agent.actions.apply_guardrails`.
"""

from datetime import date, datetime

from . import config

START = "<untrusted>"
END = "</untrusted>"


def untrusted(value):
    """Tags a string coming from the monitored machines, bounding it too.

    `None` and non-strings pass through unchanged: a rule level or an agent
    ID is produced by Wazuh, not by the attacker.
    """
    if not isinstance(value, str) or not value:
        return value
    return f"{START}{bound(value)}{END}"


def bound(text: str, maximum: int | None = None) -> str:
    """Truncates while saying so. A silent truncation would lead to a wrong conclusion."""
    maximum = maximum or config.MAX_TEXT
    if len(text) <= maximum:
        return text
    return (f"{text[:maximum]}\n[…truncated, {len(text) - maximum} more "
            f"characters — request the full source if needed]")


def jsonifiable(value):
    """Makes datetime/date serializable, recursively."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: jsonifiable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonifiable(v) for v in value]
    return value


def bounds(limit: int | None, offset: int | None) -> tuple[int, int]:
    """Normalizes a pagination request within the server's caps."""
    limit = config.DEFAULT_PAGE if limit is None else limit
    limit = max(1, min(int(limit), config.MAX_PAGE))
    return limit, max(0, int(offset or 0))


def page(lines: list, total: int, limit: int, offset: int) -> dict:
    """Uniform paginated envelope.

    `remaining` rather than a plain `total`: the client must know at a
    glance whether it has seen everything, without redoing the subtraction —
    that's what keeps it from concluding on a partial page.
    """
    return {
        "results": jsonifiable(lines),
        "total": total,
        "offset": offset,
        "limit": limit,
        "remaining": max(0, total - offset - len(lines)),
    }
