"""CMDB tools: who are the machines, and how much do they matter.

An asset's priority (P1-P4) governs the order in which its incidents are
analyzed, the severity they carry, and the threshold beyond which the model
no longer has the right to close them on its own. It's declared at
enrollment (`aura_enroll_agent(role=…)`); these two tools are for READING it
and CORRECTING it afterwards.

The correction is at `aura:write`, not `aura:admin`: it doesn't touch any
machine, only an asset's classification. It remains a decision that
matters — downgrading the domain controller to P4 is the best way to make
the SOC slow exactly where it should be fastest.
"""

from soc_agent import assets as soc_assets
from soc_agent import config as soc_config

from .. import auth, output
from ..server import register


@auth.require("aura:read")
def aura_assets_list(priority: int | None = None,
                     debt_only: bool = False) -> dict:
    """Inventory of monitored machines, with their SOC priority.

    `debt_only` answers the question that really matters: **which machines
    run without a declared role?** They're treated as P4 — so at the back
    of the queue — and nothing else signals it. A critical asset forgotten
    at enrollment is invisible until the incident that gets analyzed too
    late.

    Args:
        priority: only return assets at this priority (1 to 4).
        debt_only: only return assets without a declared role.
    """
    if priority is not None and not 1 <= int(priority) <= 4:
        return {"error": "priority outside the P1-P4 scale."}

    coverage = soc_assets.coverage()
    if debt_only:
        return output.jsonifiable({
            "debt": coverage["debt"],
            "applied_priority": soc_config.DEFAULT_PRIORITY,
            "assets": coverage["without_declared_role"],
            "fix": "aura_asset_set(agent_id, role=…) or, better, place the "
                      "machine in its role-<role> Wazuh group: the CMDB "
                      "realigns itself on its own at the next cycle.",
        })
    return output.jsonifiable({
        "assets": soc_assets.list_assets(priority),
        "breakdown": coverage["by_priority"],
        "debt": coverage["debt"],
        "known_roles": dict(sorted(soc_config.PRIORITY_ROLES.items(),
                                    key=lambda kv: (kv[1], kv[0]))),
    })


@auth.require("aura:write")
def aura_asset_set(agent_id: str, role: str | None = None,
                   priority: int | None = None,
                   notes: str | None = None) -> dict:
    """Classifies an asset: its role, hence its priority. Does NOT touch the machine.

    Passing `role` is the right way to do it: the priority follows from it
    and stays consistent with the catalog. `priority` alone is the escape
    hatch for a case the catalog doesn't cover — it will be marked
    `operator` and will never be recomputed from the Wazuh groups again.

    Args:
        agent_id: Wazuh identifier of the agent (`001`), not its name.
        role: role from the catalog (`dc`, `web`, `firewall`…).
        priority: 1 to 4, to force a classification outside the catalog.
        notes: justification, read by the next analyst who wonders why.
    """
    try:
        line = soc_assets.set_asset(agent_id, role=role, priority=priority,
                                   notes=notes)
    except ValueError as e:
        return {"error": str(e)}
    return output.jsonifiable({
        "asset": line,
        "effect": f"this agent's next incidents will be born at "
                 f"P{line['priority']}; incidents ALREADY open keep the "
                 f"priority they had (it's frozen at opening, so a case "
                 f"stays readable with its original context).",
    })


register(aura_assets_list)
register(aura_asset_set)
