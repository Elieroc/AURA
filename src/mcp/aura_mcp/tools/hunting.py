"""Threat hunting tools: bringing an archive back online to hunt in it.

Alerts leave the indexer after 90 days (retention) and survive twelve
months in an encrypted S3 archive (catalog and on-demand creation:
`aura_archives_list` / `aura_archive_create` in `tools/archiving.py`). These
tools are the bridge: bring a month back into `wazuh-hunting-*`, hunt in it
from Discover, then free up the space.

What these tools do NOT do, and it's what makes them safe for an
unsupervised AI agent: **restored data doesn't enter the pipeline.**
`wazuh-hunting-*` is excluded by negation from what ingestion reads
(`routing.indices_read`), so alerts brought back online are neither
correlated, nor triaged, nor remediated. Without this separation, restoring
March 2026 would make AURA replay a ten-month-old attack — with host
isolation and IP blocking at the end of it, since remediation is
autonomous.

The caps (documents, indices, bytes, disk threshold) live in
`soc_agent.hunting`, upstream: this layer doesn't replay them and can't
disable them. "Restore everything for me to look" is refused by the code.
"""

from soc_agent import hunting

from .. import auth, output
from ..server import register


@auth.require("aura:read")
def aura_hunting_state() -> dict:
    """What's occupying the hunting space, and what's left before the caps.

    To read BEFORE a restore: the caps are returned here, so you know
    whether the operation will pass without having to try it. `disk_pct` is
    the hardest guardrail — beyond the watchdog's alert threshold, every
    restore is refused, because a full disk flips the indexer to read-only
    and stops ingestion for the whole fleet.

    The listed indices are COPIES: deleting them loses nothing, the S3
    archive remains. They are purged on their own after
    `retention_days`.
    """
    return output.jsonifiable(hunting.state())


@auth.require("aura:write")
def aura_hunting_restore(index_set: str, period: str,
                         apply: bool = False) -> dict:
    """Brings a cold archive back into `wazuh-hunting-*` for analysis.

    Downloads the S3 object, decrypts it with the SOC's key, and
    reinjects the documents into `wazuh-hunting-<source>-<YYYY-MM>`. The
    original `_id` is kept: replaying the restore overwrites the same
    documents instead of duplicating them.

    **Restored data doesn't enter the pipeline.** No correlation, no
    triage, no IRIS case, no remediation: it's a READ space, queryable in
    Discover via the `wazuh-hunting-*` index pattern. This is a structural
    separation, not a setting — without it, restoring an old month would
    make AURA replay a past attack and trigger real remediations.

    In dry-run (default), returns what would be done AND the guardrails'
    verdict, without downloading anything. Possible refusals, all applied
    server-side: disk above the alert threshold, archive bigger than
    `HUNTING_MAX_DOCS`, index cap reached, byte cap exceeded. For an
    archive that's too big, the right move is to restore it as an NDJSON
    file and filter it with `jq` rather than indexing the whole thing.

    The restored index is automatically deleted after
    `HUNTING_RETENTION_DAYS` (30 by default); the S3 archive itself stays.

    Args:
        index_set: original index set (`wazuh-firewall`), as returned by
            `aura_archives_list`.
        period: month in `YYYY-MM` format (`2026-03`).
        apply: actually execute. `False` returns the plan and the
            guardrails' verdict.
    """
    return output.jsonifiable(hunting.restore(index_set, period, apply))


@auth.require("aura:write")
def aura_hunting_purge(index: str, confirm: bool = False) -> dict:
    """Deletes a hunting index to free up space.

    Safe by construction: the tool REFUSES any name that doesn't start
    with the hunting prefix, and refuses wildcards and lists. It therefore
    can't touch a production alert index. What it deletes is a copy — the
    S3 archive remains and the restore can be replayed.

    Args:
        index: full index name (`wazuh-hunting-firewall-2026-03`).
        confirm: execute. `False` returns what would be deleted.
    """
    return output.jsonifiable(hunting.purge(index, confirm))


register(aura_hunting_state)
register(aura_hunting_restore)
register(aura_hunting_purge)
