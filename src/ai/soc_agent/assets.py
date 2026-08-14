"""CMDB: role and priority of the monitored machines.

The pipeline only knew `rule_level` — a property of the RULE. Two level-12
incidents, one on the domain controller and one on a test box, landed in the
same queue, in the same order, with the same guardrails. This module brings the
other half of the information: *on what*.

Source of truth: the **Wazuh groups** prefixed `role-` (see
`config.CMDB_GROUP_PREFIX`). It is the native inventory mechanism, it survives a
redeploy of the stack, and the operator enrolling a machine declares its role in
the same place as the rest of its configuration. The `assets` table is a
queryable MIRROR of it — never the other way round: what the manager says wins,
except on a row set by hand by the operator (`priority_source = 'operator'`).

    python -m soc_agent.assets --sync       # aligns the CMDB on the manager
    python -m soc_agent.assets --coverage   # inventory debt (P4 by default)
"""

import argparse
import logging

import psycopg
import requests
import urllib3
from psycopg.rows import dict_row

from . import config

log = logging.getLogger("assets")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Priority sources, strongest first. `operator` is an explicit human decision:
# the synchronisation never overwrites it, otherwise the next pass would erase
# the correction an analyst has just made.
SOURCES = ("operator", "group", "default")


# --------------------------------------------------------------------------
# Computing the priority
# --------------------------------------------------------------------------

def role_from_groups(groups) -> str | None:
    """Role declared by the agent's Wazuh groups, or None.

    A machine can carry several roles (`role-web` + `role-db` on a shared LAMP):
    the most critical one wins. Underestimating a mixed asset would be the worst
    of both worlds — we would treat it as its least important half.
    """
    prefix = config.CMDB_GROUP_PREFIX
    roles = [str(g).lower()[len(prefix):] for g in (groups or [])
             if str(g).lower().startswith(prefix)]
    known = [r for r in roles if r in config.PRIORITY_ROLES]
    if not known:
        return None
    return min(known, key=lambda r: config.PRIORITY_ROLES[r])


def role_priority(role: str | None) -> int:
    """Priority of a role, or DEFAULT_PRIORITY when it is unknown."""
    if not role:
        return config.DEFAULT_PRIORITY
    return config.PRIORITY_ROLES.get(str(role).lower(), config.DEFAULT_PRIORITY)


def severity(max_level: int, priority: int) -> int:
    """EFFECTIVE severity of an incident: Wazuh level corrected by the asset.

    A pure function, bounded to the Wazuh scale (1-15) so it stays readable next
    to `max_level` and comparable from one incident to the next. We never modify
    `max_level` itself: correlation, UEBA and `RULES_COMPROMISE_HOST` rely on it,
    and a silent shift would change the meaning of every existing threshold.
    """
    bonus = config.SEVERITY_BONUS_PRIORITY.get(priority, 0)
    return max(1, min(15, int(max_level) + bonus))


# Is the table there? Tested once per process, with a query that cannot FAIL
# (`to_regclass` returns NULL instead of raising). Without it, a deployment where
# the `schema.sql` migration was forgotten would see correlation raise on the
# first incident — hence no incidents at all, over a convenience column. A
# missing prioritisation must degrade the ordering, never stop the SOC.
_TABLE_READY: bool | None = None


def _available(conn) -> bool:
    global _TABLE_READY
    if _TABLE_READY is None:
        _TABLE_READY = bool(conn.execute(
            "SELECT to_regclass('public.assets') IS NOT NULL AS ok"
        ).fetchone()["ok"])
        if not _TABLE_READY:
            log.warning(
                "`assets` table missing: every incident will be born at P%d. "
                "Apply soc_agent/schema.sql (see docs/CMDB.md).",
                config.DEFAULT_PRIORITY)
    return _TABLE_READY


def agent_priority(conn, agent_id: str, container: str | None = None) -> dict:
    """Priority applying to this agent's alerts: {priority, role, source}.

    Two corrections on top of a raw CMDB read, in this order:

    1. **sensor agent** (`AGENTS_SENSORS`): its telemetry describes the activity
       of OTHER machines. The firewall carrying Suricata *is* a P1 asset, but the
       alert it reports talks about a LAN workstation. So we fall back to
       `PRIORITY_SENSOR`, unless the alert carries the originating container
       (`alerts.container`) — in which case THAT one is resolved and we are back
       to the normal case.
    2. **agent absent from the CMDB**: `DEFAULT_PRIORITY`, source `default`.
       Never an error — an agent enrolled outside AURA must pass, not block.
    """
    if not _available(conn):
        return {"priority": config.DEFAULT_PRIORITY, "role": None,
                "source": "default"}

    if container:
        line = _read(conn, name=container)
        if line:
            return {"priority": line["priority"], "role": line["role"],
                    "source": line["priority_source"]}

    if str(agent_id) in config.AGENTS_SENSORS:
        return {"priority": config.PRIORITY_SENSOR, "role": "sensor",
                "source": "sensor"}

    line = _read(conn, agent_id=str(agent_id))
    if line:
        return {"priority": line["priority"], "role": line["role"],
                "source": line["priority_source"]}
    return {"priority": config.DEFAULT_PRIORITY, "role": None,
            "source": "default"}


def _read(conn, agent_id: str | None = None, name: str | None = None):
    if agent_id is not None:
        return conn.execute(
            "SELECT agent_id, name, role, priority, priority_source "
            "  FROM assets WHERE agent_id = %s", (agent_id,)).fetchone()
    return conn.execute(
        "SELECT agent_id, name, role, priority, priority_source "
        "  FROM assets WHERE name = %s LIMIT 1", (name,)).fetchone()


def label(priority: int, role: str | None) -> str:
    """"P1 (dc)", for the prompt and the IRIS cases — French, like both."""
    return f"P{priority}" + (f" ({role})" if role else " (rôle non déclaré)")


# --------------------------------------------------------------------------
# Synchronisation from the Wazuh manager
# --------------------------------------------------------------------------
#
# Minimal API client, deliberately local to this module: `mitigate` has its own,
# but importing it from here would create a cycle (mitigate -> iris -> ...) for
# two read-only GET calls.

def _token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


def manager_inventory() -> list[dict]:
    """Agents known to the manager, with their groups. Read-only."""
    tok = _token()
    r = requests.get(
        f"{config.WAZUH_API_URL}/agents",
        params={"select": "id,name,ip,os.platform,group", "limit": 2000},
        headers={"Authorization": f"Bearer {tok}"},
        verify=False, timeout=30)
    r.raise_for_status()
    return r.json().get("data", {}).get("affected_items", []) or []


UPSERT = """
INSERT INTO assets (agent_id, name, ip, os, groups, role, priority,
                    priority_source, seen_at, updated_at)
VALUES (%(agent_id)s, %(name)s, %(ip)s, %(os)s, %(groups)s, %(role)s,
        %(priority)s, %(source)s, now(), now())
ON CONFLICT (agent_id) DO UPDATE SET
    name      = EXCLUDED.name,
    ip       = EXCLUDED.ip,
    os       = EXCLUDED.os,
    groups  = EXCLUDED.groups,
    seen_at     = now(),
    -- A priority set by hand by the operator is NEVER overwritten by the
    -- synchronisation: it expresses business knowledge the Wazuh groups do not
    -- have. To take it back, it must be removed explicitly.
    role     = CASE WHEN assets.priority_source = 'operator'
                    THEN assets.role ELSE EXCLUDED.role END,
    priority = CASE WHEN assets.priority_source = 'operator'
                    THEN assets.priority ELSE EXCLUDED.priority END,
    priority_source = CASE WHEN assets.priority_source = 'operator'
                    THEN 'operator' ELSE EXCLUDED.priority_source END,
    updated_at    = now()
RETURNING (xmax = 0) AS cree
"""


def sync() -> dict:
    """Aligns the CMDB on what the manager declares. Returns a summary.

    Best-effort by construction: called inside the cycle, an unreachable Wazuh
    API must not cost a pipeline round. The caller decides.
    """
    agents = manager_inventory()
    summary = {"seen": len(agents), "created": 0, "updated": 0, "by_priority": {}}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        for a in agents:
            groups = [str(g).lower() for g in (a.get("group") or [])]
            role = role_from_groups(groups)
            priority = role_priority(role)
            r = conn.execute(UPSERT, {
                "agent_id": str(a.get("id")),
                "name": a.get("name"),
                "ip": a.get("ip"),
                "os": ((a.get("os") or {}).get("platform")
                       if isinstance(a.get("os"), dict) else a.get("os")),
                "groups": groups,
                "role": role,
                "priority": priority,
                "source": "group" if role else "default",
            }).fetchone()
            summary["created" if r["cree"] else "updated"] += 1
            summary["by_priority"][priority] = (
                summary["by_priority"].get(priority, 0) + 1)
        conn.commit()
    return summary


def set_asset(agent_id: str, role: str | None = None,
              priority: int | None = None, notes: str | None = None,
              source: str = "operator") -> dict:
    """Sets or corrects an asset's priority. `role` OR `priority`.

    A priority set here is marked `operator` and survives synchronisations: it is
    the escape hatch when the Wazuh groups are not enough (a machine that cannot
    be grouped, a temporary exception).
    """
    if role is not None:
        role = str(role).lower()
        if role not in config.PRIORITY_ROLES:
            raise ValueError(
                f"unknown role: \"{role}\". Known roles: "
                f"{', '.join(sorted(config.PRIORITY_ROLES))} (add one through "
                f"PRIORITY_ROLES).")
        if priority is None:
            priority = config.PRIORITY_ROLES[role]
    if priority is None:
        raise ValueError("give at least a role or a priority")
    if not 1 <= int(priority) <= 4:
        raise ValueError(f"priority outside the P1-P4 scale: {priority}")

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        line = conn.execute(
            "INSERT INTO assets (agent_id, role, priority, priority_source, "
            "                    notes, seen_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, now(), now()) "
            # COALESCE on the role: forcing a priority alone (the
            # off-catalogue escape hatch) must not erase the role already known —
            # the asset would turn "undeclared" in the coverage report just as we
            # were classifying it.
            "ON CONFLICT (agent_id) DO UPDATE "
            "SET role = COALESCE(EXCLUDED.role, assets.role), "
            "  priority = EXCLUDED.priority, "
            "  priority_source = EXCLUDED.priority_source, "
            "  notes = COALESCE(EXCLUDED.notes, assets.notes), updated_at = now() "
            "RETURNING agent_id, name, role, priority, priority_source, notes",
            (str(agent_id), role, int(priority), source, notes)).fetchone()
        conn.commit()
    return dict(line)


def list_assets(priority: int | None = None) -> list[dict]:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT agent_id, name, ip, os, role, priority, priority_source, "
            "       groups, notes, seen_at "
            "  FROM assets WHERE (%s::int IS NULL OR priority = %s::int) "
            " ORDER BY priority, name", (priority, priority)).fetchall()]


def coverage() -> dict:
    """Inventory debt: what runs without a declared role.

    The indispensable counterpart of the "P4 by default" choice. Without this
    view, a critical machine that was never declared is treated as a disposable
    workstation, and nothing says so.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        by_prio = {r["priority"]: r["n"] for r in conn.execute(
            "SELECT priority, count(*) AS n FROM assets GROUP BY priority")}
        without_role = [dict(r) for r in conn.execute(
            "SELECT agent_id, name, ip, os FROM assets "
            " WHERE priority_source = 'default' ORDER BY name").fetchall()]
    return {"by_priority": by_prio, "without_declared_role": without_role,
            "debt": len(without_role)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sync", action="store_true",
                    help="aligns the CMDB on the Wazuh manager groups")
    ap.add_argument("--coverage", action="store_true",
                    help="agents with no declared role (handled at P%d)"
                         % config.DEFAULT_PRIORITY)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--set", metavar="AGENT_ID",
                    help="sets an operator priority on an agent")
    ap.add_argument("--role")
    ap.add_argument("--priority", type=int)
    ap.add_argument("--notes")
    args = ap.parse_args()

    if args.sync:
        r = sync()
        print(f"{r['seen']} agents: {r['created']} created, {r['updated']} updated")
        for p in sorted(r["by_priority"]):
            print(f"  P{p}: {r['by_priority'][p]}")
    if args.set:
        print(set_asset(args.set, args.role, args.priority, args.notes))
    if args.list:
        for a in list_assets():
            print(f"P{a['priority']} {a['name'] or a['agent_id']:<20} "
                  f"{a['role'] or '-':<12} {a['priority_source']}")
    if args.coverage:
        c = coverage()
        print("breakdown: "
              + ", ".join(f"P{p}={n}" for p, n in sorted(c["by_priority"].items())))
        if c["debt"]:
            print(f"\n{c['debt']} agent(s) with NO declared role — handled at "
                  f"P{config.DEFAULT_PRIORITY}, so at the back of the queue:")
            for a in c["without_declared_role"]:
                print(f"  {a['agent_id']:<5} {a['name'] or '?':<24} {a['ip'] or ''}")


if __name__ == "__main__":
    main()
