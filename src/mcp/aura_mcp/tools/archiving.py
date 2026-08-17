"""Archive catalog and on-demand archiving.

Cold archiving (`docs/ARCHIVAGE.md`) normally runs on `soc-agent-archive`'s
own daily pass: closed months, all index sets, no human in the loop. These
tools are the manual door onto the same code path — reading the catalog, and
forcing a pass scoped to one index set, one period window, or everything —
for the cases the daily pass doesn't cover on its own: an index set that
needs archiving right before a retention change, a gap noticed by
`archivage:trou` that turns out to still be within `ARCHIVE_DELAY_DAYS`, a
drill or a demo that wants a fresh archive without waiting for tonight.

What `aura_archive_create` does NOT do, on purpose: it never widens what
`soc_agent.archive` considers archivable. A month still open
(`ARCHIVE_DELAY_DAYS`) or already archived is skipped exactly as in the
periodic pass — there is no `force` here. Forcing an incomplete month would
produce an archive that believes itself complete, which is the one failure
mode the whole module is built to avoid (see `archive.export`).
"""

from soc_agent import archive
from soc_agent import config as soc_config

from .. import auth, output
from ..db import read as base
from ..server import register


@auth.require("aura:read")
def aura_archives_list(index_set: str | None = None,
                       limit: int | None = None,
                       offset: int | None = None) -> dict:
    """The cold archives available, with their verification state.

    This is the catalog of what's restorable: one month of one index set
    per line. The source of truth is Postgres, not S3 — an unresponsive S3
    must not translate into "there is no archive".

    `verify_state` deserves a look before concluding on a restore:

    - `ok`: the archive was re-downloaded, decrypted, and recounted;
    - `null`: never verified since it was written;
    - anything else (`missing`, `sha256-mismatch`, `document-count-mismatch`):
      the archive isn't reliable, and the original data has very likely
      already been purged from the indexer. Restoring is still possible and
      worthwhile to see what's left of it, but don't conclude on a partial
      copy while believing you hold the truth.

    Args:
        index_set: filter on an index set (`wazuh-firewall`).
        limit: lines per page.
        offset: pagination offset.
    """
    limit, offset = output.bounds(limit, offset)
    where = ("WHERE format_version = %(fv)s "
             "  AND (%(base)s::text IS NULL OR index_base = %(base)s)")
    params = {"fv": soc_config.ARCHIVE_FORMAT_VERSION, "base": index_set,
              "limit": limit, "offset": offset}
    with base() as conn:
        total = conn.execute(
            f"SELECT count(*) AS n FROM archives_s3 {where}",
            params).fetchone()["n"]
        lines = conn.execute(
            f"""SELECT index_base, period, documents, plain_bytes,
                       object_bytes, indices, archived_at, verified_at,
                       verify_state, verify_full, object_lock_until
                  FROM archives_s3 {where}
                 ORDER BY index_base, period DESC
                 LIMIT %(limit)s OFFSET %(offset)s""", params).fetchall()
    return output.page([dict(l) for l in lines], total, limit, offset)


@auth.require("aura:write")
def aura_archive_create(index_set: str | None = None,
                        period_from: str | None = None,
                        period_to: str | None = None,
                        apply: bool = False) -> dict:
    """Forces an archiving pass instead of waiting for tonight's.

    Same code as the periodic pass (`soc_agent.archive.run`): scroll-export
    the closed months not archived yet, compress with `zstd`, encrypt with
    `age` for the SOC's key, upload to B2, read the object back before
    recording it in `archives_s3`. Real cost: DeepSeek isn't involved, but a
    large month means minutes of scroll plus a real upload.

    Scoping, all optional and combinable:

    - `index_set` alone: only this index set (`wazuh-firewall`), every
      closed month it has that isn't archived yet;
    - `period_from`/`period_to` (`YYYY-MM`, inclusive): only months in this
      window, across whichever index sets are given (or all of them);
    - none of the three: everything the periodic pass would have done —
      every index set, every closed month not yet archived.

    In dry-run (default), returns the batches that WOULD be archived — same
    `batches_to_archive` computation, nothing exported, nothing uploaded.
    Use it first to see the volume before spending the minutes on a real
    export.

    A month still inside `ARCHIVE_DELAY_DAYS` (late-indexed alerts still
    catching up) or already in `archives_s3` is silently skipped — on
    demand exactly as in the periodic pass. There is no way to force an
    incomplete or duplicate archive from here: that guardrail lives in
    `soc_agent.archive` and this tool doesn't replay it.

    Args:
        index_set: restrict to one index set, as returned by
            `aura_archives_list`.
        period_from: restrict to months >= this one (`2026-03`).
        period_to: restrict to months <= this one (`2026-06`).
        apply: actually export and upload. `False` (default) returns the
            plan only.
    """
    result = archive.run(not apply, index_set, period_from, period_to)
    return {"apply": apply, **output.jsonifiable(result)}


register(aura_archives_list)
register(aura_archive_create)
