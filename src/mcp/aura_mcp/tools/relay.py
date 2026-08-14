"""Relay to the Wazuh and DFIR-IRIS MCP servers.

Two tools per upstream server — one to discover, one to call — rather than
the thirty-odd relayed tools one by one. It's the same trade-off that
justifies the gateway: the upstream catalog represents 60 tools, i.e. the
bulk of a client's context before it has read a single alert. In two
steps, it only pays for what it uses, and the catalog stays filtered by
the allowlist.

The filter is applied **at call time**, not only at discovery: requesting a
masked tool is refused, even if its name was learned elsewhere.
"""

from .. import auth, gateway
from ..server import register

AR_DENIED = (
    "This tool acts directly on the Wazuh manager, without knowing AURA's "
    "policy: protected agents, infrastructure groups, system accounts, "
    "closure floor. It is deliberately masked. To remediate, go through "
    "aura_mitigate_execute, aura_isolate, or aura_unisolate, which apply "
    "these guardrails."
)


def _upstream(name: str) -> gateway.Upstream | None:
    return next((a for a in gateway.upstreams() if a.name == name), None)


async def _list(name: str) -> dict:
    upstream = _upstream(name)
    if not upstream:
        return {"available": False,
                "reason": f"No MCP server {name} configured "
                          f"(AURA_MCP_{name.upper()}_URL)."}
    tools = await upstream.tools()
    if not tools:
        return {"available": False,
                "reason": f"MCP server {name} unreachable — AURA stays "
                          f"queryable without it."}
    guards = [t for t in tools if gateway.allowed(upstream, t.name)]
    return {
        "available": True,
        "tools": [{"name": t.name, "description": t.description,
                    "arguments": t.input_schema} for t in guards],
        "upstream_total": len(tools),
        "relayed": len(guards),
        "note": f"{len(tools) - len(guards)} upstream tool(s) are not "
                f"relayed (outside the allowlist, or masked action).",
    }


async def _call(name: str, tool: str, arguments: dict | None) -> dict:
    upstream = _upstream(name)
    if not upstream:
        return {"error": f"No MCP server {name} configured."}
    if tool in gateway.WAZUH_MASKED:
        return {"error": f"Tool {tool} masked.", "explanation": AR_DENIED}
    if not gateway.allowed(upstream, tool):
        return {"error": f"Tool {tool} outside the {name} relay's "
                          f"allowlist.",
                "advice": f"List the relayed tools with "
                           f"{name}_tools_list."}
    try:
        return await upstream.call(tool, arguments or {})
    except Exception as e:  # noqa: BLE001
        return {"error": f"Call {name}.{tool} failed: {e}"}


@auth.require("aura:read")
async def wazuh_tools_list() -> dict:
    """The Wazuh tools relayed by AURA, with their arguments.

    Covers what the AURA database can't tell: the state of the agent
    fleet, alerts at the source (AURA doesn't ingest everything),
    vulnerabilities, the health of the detection infrastructure.

    The 19 active response tools of the Wazuh server are **masked**: they
    would act without AURA's guardrails. Remediation goes through the
    `aura_*` tools.
    """
    return await _list("wazuh")


@auth.require("aura:read")
async def wazuh_call(tool: str, arguments: dict | None = None) -> dict:
    """Calls a relayed Wazuh tool.

    Args:
        tool: exact name returned by `wazuh_tools_list`.
        arguments: tool arguments, as described by its schema.
    """
    return await _call("wazuh", tool, arguments)


@auth.require("aura:read")
async def iris_tools_list() -> dict:
    """The relayed DFIR-IRIS tools: cases, notes, IOCs, assets, tasks.

    AURA creates and updates its own cases through `aura_iris_case_sync` —
    these tools are for analyst work on a case: adding a note, a manually
    discovered IOC, a task.
    """
    return await _list("iris")


@auth.require("aura:write")
async def iris_call(tool: str, arguments: dict | None = None) -> dict:
    """Calls a relayed DFIR-IRIS tool.

    At `aura:write`: these tools write into cases. It's reversible and has
    no effect on machines, but it isn't reading.

    Args:
        tool: exact name returned by `iris_tools_list`.
        arguments: tool arguments, as described by its schema.
    """
    return await _call("iris", tool, arguments)


register(wazuh_tools_list)
register(wazuh_call)
register(iris_tools_list)
register(iris_call)
