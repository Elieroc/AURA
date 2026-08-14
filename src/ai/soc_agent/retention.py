"""SOC data retention: what ages ends up being deleted.

On 2026-08-14 the production disk was at 66 % without a single alert ever having
said so. None of that data was Wazuh logs — the indexer weighed 470 MB. It was
three things growing without bound:

- the MISP audit log (12.75 GB in two days, 49 M rows written by the feed
  ingestion) — handled at the source by turning the writes off;
- the IRIS Evidence pieces re-posted on every cycle (8.3 GB, a duplication factor
  of 14) — handled at the source in `iris._evidences`;
- the residues of Wazuh's CVE feed update (6.7 GB of decompressed JSON that no
  cleanup ever comes back for) — handled HERE.

This module carries what cannot be handled at the source: the ageing of what is
legitimately written. Three targets:

- `alerts`: the fastest-growing table of the pipeline (~150 MB/day). Purged past
  `RETENTION_ALERTS_DAYS`, PRESERVING the alerts attached to an unclosed
  incident — evidence does not vanish from under an open case.
- `vd_updater/tmp` residues of the Wazuh manager, mounted as a volume.
- the indexer ISM policy, (re)applied on every pass: it is declarative, setting
  it is idempotent, and a reinstalled indexer gets it back with no manual step.

What is NOT here, and why:

- MISP. Its database is large (15 GB) but it is legitimate CTI data, not a log:
  the 21 M attributes come from the URLhaus history. Purging it would be a CTI
  coverage decision, not a retention one.
- The docker images. Pruning them from a container would require giving it the
  docker socket in write mode, that is root on the host, to reclaim ~2 GB. That
  is done from the host (see docs/RETENTION.md).
- The manager's alert files (`/var/ossec/logs/alerts`): Wazuh already rotates
  and purges them on its own (`monitord.keep_log_days`, 31 days).

    python -m soc_agent.retention            # one pass
    python -m soc_agent.retention --dry-run  # what would be deleted
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)

# Advisory lock: same family as the other periodic jobs (0x50CA*).
_LOCK_RETENTION = 0x50CA5

# --------------------------------------------------------------------------
# Indexer ISM policy
# --------------------------------------------------------------------------
#
# The Wazuh indices are DATED (one per day): they have neither alias nor
# rollover, the rotation is already done by the name. So the policy has one job —
# delete past the retention age.
#
# `wazuh-voc-vulns` is deliberately OUTSIDE the policy. It is the only undated
# index of the lot: one document per vulnerability, rewritten on every pass,
# carrying the life cycle and hence the MTTR (see docs/VOC.md). A retention by
# date would erase the history of the debt there. Hence explicit patterns rather
# than a `wazuh-*` that would swallow it.
#
# The ISM STATE names ("actif", "suppression") stay in French on purpose: they
# are stored inside the policy in OpenSearch and referenced by every index
# already managed. Renaming them would strand those indices on a state that no
# longer exists, and retention would stop silently — exactly the failure this
# module exists to prevent.
ISM_POLICY_ID = "aura-retention"

ISM_PATTERNS = [
    "wazuh-alerts-*", "wazuh-archives-*", "wazuh-linux-*", "wazuh-windows-*",
    "wazuh-web-*", "wazuh-firewall-*", "wazuh-proxy-*", "wazuh-jellyfin-*",
    "wazuh-vpn-*", "wazuh-dns-*", "wazuh-yara-*", "wazuh-ai-*",
    # VOC time series only: `wazuh-voc-20*` matches `wazuh-voc-2026.08.14` and
    # NEVER `wazuh-voc-vulns`.
    "wazuh-voc-20*",
]


def ism_patterns() -> list[str]:
    """Static patterns UNION the index sets created by `routing.py`.

    An index set created without retention grows forever, and a full disk is the
    outage that stops the WHOLE SOC (indexer read-only, Postgres refusing to
    write). Reading the table rather than adding a line here on every creation
    makes forgetting impossible.

    Falls back to the static patterns alone when the database does not answer:
    better a policy covering the essentials than a retention job not running at
    all.
    """
    try:
        import psycopg
        from psycopg.rows import dict_row

        from . import routing
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            learned = routing.applied_patterns(conn)
    except Exception as e:                                    # noqa: BLE001
        log.warning("routing patterns unreadable (%s): ISM policy limited to "
                    "the static ones", e)
        learned = []
    return list(dict.fromkeys(ISM_PATTERNS + learned))


def ism_policy() -> dict:
    return {
        "policy": {
            "description": (
                f"AURA — suppression des index datés au-delà de "
                f"{config.RETENTION_INDEX_DAYS} jours. wazuh-voc-vulns est "
                f"exclu : index d'état, non daté."),
            "default_state": "actif",
            "states": [
                {"name": "actif",
                 "actions": [],
                 "transitions": [{
                     "state_name": "suppression",
                     "conditions": {
                         "min_index_age": f"{config.RETENTION_INDEX_DAYS}d"},
                 }]},
                {"name": "suppression",
                 "actions": [{"delete": {}}],
                 "transitions": []},
            ],
            "ism_template": [{
                "index_patterns": ism_patterns(),
                "priority": 100,
            }],
        }
    }


# A SEPARATE policy for the threat hunting space (see hunting.py). Two policies
# rather than one average duration, because it is not the same data:
# `wazuh-hunting-*` holds COPIES restored from the S3 archives, which live twelve
# months on their own. Losing them loses nothing, and workspace lying around is
# the simplest way to fill the SOC disk.
#
# The patterns of the two policies do not overlap: an index can only carry ONE
# ISM policy, and two competing `ism_template` at the same priority would give an
# arbitrary attachment.
ISM_HUNTING_ID = "aura-hunting"


def ism_policy_hunting() -> dict:
    return {
        "policy": {
            "description": (
                f"AURA — espace de threat hunting : suppression au-delà de "
                f"{config.HUNTING_RETENTION_DAYS} jours. Ce sont des copies "
                f"restaurées depuis les archives S3, pas des originaux."),
            "default_state": "actif",
            "states": [
                {"name": "actif",
                 "actions": [],
                 "transitions": [{
                     "state_name": "suppression",
                     "conditions": {
                         "min_index_age":
                             f"{config.HUNTING_RETENTION_DAYS}d"},
                 }]},
                {"name": "suppression",
                 "actions": [{"delete": {}}],
                 "transitions": []},
            ],
            "ism_template": [{
                "index_patterns": [f"{config.HUNTING_INDEX_BASE}-*"],
                "priority": 150,
            }],
        }
    }


def _indexer(method: str, path: str, body: dict | None = None):
    check = config.INDEXER_CA or config.INDEXER_VERIFY_TLS
    return requests.request(
        method, f"{config.INDEXER_URL}{path}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=body, verify=check, timeout=30)


def _set_policy(policy_id: str, body: dict) -> str:
    """Writes an ISM policy, on creation or on concurrent update.

    The `if_seq_no`/`if_primary_term` pair is what makes two simultaneous passes
    harmless: the second is refused by the indexer instead of overwriting a
    policy it never read.
    """
    lu = _indexer("GET", f"/_plugins/_ism/policies/{policy_id}")
    if lu.status_code == 200:
        seq = lu.json()["_seq_no"]
        prim = lu.json()["_primary_term"]
        r = _indexer("PUT", f"/_plugins/_ism/policies/{policy_id}"
                            f"?if_seq_no={seq}&if_primary_term={prim}", body)
        state = "updated"
    else:
        r = _indexer("PUT", f"/_plugins/_ism/policies/{policy_id}", body)
        state = "created"
    if not r.ok:
        raise RuntimeError(
            f"ISM policy {policy_id} refused ({r.status_code}): {r.text}")
    return state


def _attach(policy_id: str, patterns: list[str]) -> int:
    """Attaches the policy to the indices that ALREADY exist.

    `ism_template` only applies to indices created AFTERWARDS: without this call,
    a policy set today would never see yesterday's indices — that is, precisely
    the ones it is meant to delete.

    Indices already managed answer with a "failure" and an explicit reason: that
    is not an error, it is the normal state from the 2nd pass on.
    """
    r = _indexer("POST", "/_plugins/_ism/add/" + ",".join(patterns),
                 {"policy_id": policy_id})
    return r.json().get("updated_indices", 0) if r.ok else 0


def apply_ism() -> str:
    """Sets BOTH policies: the alerts one and the hunting one."""
    state = _set_policy(ISM_POLICY_ID, ism_policy())
    added = _attach(ISM_POLICY_ID, ism_patterns())
    log.info("ISM policy \"%s\" %s (%s days), %s index/indices attached",
             ISM_POLICY_ID, state, config.RETENTION_INDEX_DAYS, added)

    # The hunting space has its own duration and its own pattern. A separate
    # best-effort: its failure must not take down the alert retention, which is
    # the one protecting the disk.
    try:
        state_h = _set_policy(ISM_HUNTING_ID, ism_policy_hunting())
        patterns_h = [f"{config.HUNTING_INDEX_BASE}-*"]
        log.info("ISM policy \"%s\" %s (%s days), %s index/indices attached",
                 ISM_HUNTING_ID, state_h, config.HUNTING_RETENTION_DAYS,
                 _attach(ISM_HUNTING_ID, patterns_h))
    except Exception as e:                                    # noqa: BLE001
        log.warning("ISM policy \"%s\" not applied: %s — the hunting indices "
                    "will not be purged automatically.", ISM_HUNTING_ID, e)
    return state


# --------------------------------------------------------------------------
# Purging the alerts
# --------------------------------------------------------------------------

# Alerts attached to an incident still OPEN are spared whatever their age: they
# are the substance of the case the analyst has in front of them. A slow
# intrusion (persistence installed four months ago, woken yesterday) sits in an
# incident whose first alerts are outside the window — deleting them would empty
# the case of its beginning.
PURGE_ALERTS = """
DELETE FROM alerts a
 WHERE a.ts < now() - make_interval(days => %s)
   AND (a.incident_id IS NULL
        OR EXISTS (SELECT 1 FROM incidents i
                    WHERE i.id = a.incident_id
                      AND i.status IN ('case_open', 'fp_classified')
                      AND i.last_seen < now() - make_interval(days => %s)))
"""


def purge_alerts(conn, days: int, dry_run: bool = False) -> int:
    if dry_run:
        sql = PURGE_ALERTS.replace("DELETE FROM alerts a", "SELECT count(*) c FROM alerts a")
        return conn.execute(sql, (days, days)).fetchone()["c"]
    n = conn.execute(PURGE_ALERTS, (days, days)).rowcount
    conn.commit()
    if n:
        log.info("%d alerte(s) de plus de %d jours supprimée(s)", n, days)
    return n


def purge_orphan_evidences(conn, dry_run: bool = False) -> int:
    """Evidence markers whose incident no longer exists.

    The FK constraint is ON DELETE CASCADE, so this case should not exist —
    except for rows written before it was added. Cheap to check, and a marker
    table that lies would re-post evidence.
    """
    sql = ("SELECT count(*) c FROM iris_evidences e WHERE NOT EXISTS "
           "(SELECT 1 FROM incidents i WHERE i.id = e.incident_id)")
    if dry_run:
        return conn.execute(sql).fetchone()["c"]
    n = conn.execute(
        "DELETE FROM iris_evidences e WHERE NOT EXISTS "
        "(SELECT 1 FROM incidents i WHERE i.id = e.incident_id)").rowcount
    conn.commit()
    return n


# --------------------------------------------------------------------------
# Residues of the CVE feed update (Wazuh)
# --------------------------------------------------------------------------

def purge_vd_residues(dry_run: bool = False) -> tuple[int, int]:
    """Files left by the vd_updater in its working directory.

    The vulnerability detection module decompresses the feed into
    `queue/vd_updater/tmp/contents` and does not empty it when the update is
    interrupted. 6.7 GB had been sleeping there since the day before on
    2026-08-14.

    The minimum age is not cosmetic: it guarantees we do not delete the files of
    an update UNDER WAY (those last a few minutes, the threshold is in hours).
    Returns (files, bytes).
    """
    base = Path(config.WAZUH_QUEUE_DIR) / "vd_updater" / "tmp"
    if not base.is_dir():
        log.debug("vd_updater directory missing (%s): nothing to purge", base)
        return 0, 0
    limit = time.time() - config.RETENTION_VD_TMP_HOURS * 3600
    n, byte_count = 0, 0
    for f in base.rglob("*"):
        if not f.is_file():
            continue
        try:
            st = f.stat()
            if st.st_mtime >= limit:
                continue
            if not dry_run:
                f.unlink()
            n += 1
            byte_count += st.st_size
        except OSError as e:
            log.debug("vd residue %s not deleted: %s", f, e)
    if n:
        log.info("%d CVE feed residue(s) deleted (%.1f GB)",
                 n, byte_count / 1073741824)
    return n, byte_count


# --------------------------------------------------------------------------

def run(dry_run: bool = False) -> dict:
    """One full pass. Every target is independent: one failing must not stop the
    others — this is a housekeeping job, not a transaction.
    """
    summary: dict = {"dry_run": dry_run}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_LOCK_RETENTION,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("retention: pass already running, skipping this round")
            return {"state": "locked"}
        try:
            summary["alerts"] = purge_alerts(
                conn, config.RETENTION_ALERTS_DAYS, dry_run)
            summary["orphan_evidences"] = purge_orphan_evidences(
                conn, dry_run)
        finally:
            # Rollback BEFORE the unlock: inside an aborted transaction
            # Postgres refuses every command, including this one, and the second
            # exception would replace the first — the useful diagnosis would
            # disappear (observed on archiving, see archive._unlock). The lock is
            # session-scoped, hence released when the connection closes anyway:
            # failing here has no consequence, hiding the cause does.
            for step in (conn.rollback,
                          lambda: conn.execute(
                              "SELECT pg_advisory_unlock(%s)",
                              (_LOCK_RETENTION,))):
                try:
                    step()
                except Exception as e:                            # noqa: BLE001
                    log.debug("releasing the retention lock: %s", e)

    files, byte_count = purge_vd_residues(dry_run)
    summary["vd_residues"] = files
    summary["vd_residue_bytes"] = byte_count

    if config.RETENTION_ISM_ENABLED and not dry_run:
        try:
            summary["ism"] = apply_ism()
        except Exception as e:  # noqa: BLE001 — the indexer never blocks the rest
            log.warning("ISM policy not applied: %s", e)
            summary["ism"] = f"failed: {e}"

    # Archiving guardrail, AFTER setting the policy and never before.
    #
    # `apply_ism()` attaches the indices by PATTERN (`_ism/add`): protecting
    # first then applying would undo the protection a second later. That is
    # exactly the class of bug that has already been costly here — an order of
    # operations silently cancelling the previous one.
    #
    # And DETACHING is required: merely not re-setting the policy would protect
    # nothing, it is already attached to the existing indices and would delete
    # them at the planned time.
    if config.ARCHIVING_ENABLED and not dry_run:
        try:
            from . import archive
            with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
                risk = archive.indices_at_risk(conn)
            summary["archiving_at_risk"] = [i["index"] for i in risk]
            if risk:
                summary["archiving_protected"] = archive.protect(
                    [i["index"] for i in risk])
        except Exception as e:  # noqa: BLE001
            # The worst case: we failed to check the archiving coverage AND the
            # deletion policy has just been (re)applied. Saying it loudly is all
            # we can do here — the watchdog will pick the finding up and open the
            # IRIS alert.
            log.error("ARCHIVING COVERAGE NOT VERIFIED (%s): the deletion "
                      "policy is active and nothing guarantees a copy exists.",
                      e)
            summary["archiving_at_risk"] = f"undetermined: {e}"
    return summary


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true",
                   help="count without deleting")
    p.add_argument("--ism", action="store_true",
                   help="set the ISM policy alone and exit")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.ism:
        print(f"ISM policy \"{ISM_POLICY_ID}\": {apply_ism()}")
        return
    print(json.dumps(run(args.dry_run), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
