"""Relay for the upstream MCP servers: Wazuh and DFIR-IRIS.

Why relay instead of letting the client declare three servers:

1. **Context budget.** The Wazuh MCP server exposes 54 tools, IRIS about a
   dozen. Added to AURA's 25, the inventory becomes the bulk of a client's
   context before it has read a single alert. An allowlist keeps around
   thirty, chosen.

2. **Guardrails must not be bypassable.** The Wazuh server exposes 19 active
   response tools — `wazuh_isolate_host`, `wazuh_kill_process`,
   `wazuh_disable_user`… — which talk directly to the manager's API, knowing
   nothing about AURA's protected agents, system accounts, or closure floor.
   A client that sees them can isolate the firewall. **They are therefore
   masked**, no exceptions: remediation goes through the `aura_*` tools,
   which apply the policy.

3. **A single authentication and audit point.**

A missing upstream server doesn't prevent startup: its tools are simply
missing, the server logs it, and everything else keeps working. AURA must
stay queryable even when a component is down — that's often precisely when
it's needed.
"""

import logging
import os

log = logging.getLogger("aura_mcp.gateway")

# --- Upstream servers --------------------------------------------------------
WAZUH_URL = os.environ.get("AURA_MCP_WAZUH_URL", "")
WAZUH_TOKEN = os.environ.get("AURA_MCP_WAZUH_TOKEN", "")
IRIS_URL = os.environ.get("AURA_MCP_IRIS_URL", "")
IRIS_TOKEN = os.environ.get("AURA_MCP_IRIS_TOKEN", "")

# Cap on a relayed tool's response, wider than an alert field's: these
# responses are inventories (agents, vulnerabilities), not log fragments.
RELAY_CAP = int(os.environ.get("AURA_MCP_RELAI_MAX", "12000"))

# --- What we relay -----------------------------------------------------------
# ALLOWLIST, never a denylist: a tool added upstream by a version bump
# doesn't appear on its own for clients. A new action tool that would slip
# through a forgotten denylist, would.
WAZUH_ALLOWED = {
    # Fleet state — what the AURA database can't tell
    "get_wazuh_agents", "get_wazuh_running_agents", "check_agent_health",
    "get_agent_configuration", "get_agent_ports", "get_agent_processes",
    # Alerts at the source (AURA doesn't ingest everything)
    "get_wazuh_alerts", "get_wazuh_alert_summary", "get_alerts_aggregated",
    "search_security_events", "analyze_alert_patterns",
    "get_top_security_threats",
    # Vulnerabilities and compliance
    "get_wazuh_vulnerabilities", "get_wazuh_critical_vulnerabilities",
    "get_wazuh_vulnerability_summary", "get_sca_policy_checks",
    "run_compliance_check",
    # Health of the detection infrastructure
    "get_wazuh_cluster_health", "get_wazuh_cluster_nodes",
    "get_wazuh_statistics", "get_wazuh_log_collector_stats",
    "get_wazuh_remoted_stats", "get_wazuh_manager_error_logs",
    "search_wazuh_manager_logs", "get_wazuh_rules_summary",
    "validate_wazuh_connection",
}

IRIS_ALLOWED = {
    "list_cases", "get_case", "add_note", "add_ioc", "add_asset", "add_task",
    "add_event", "list_ioc_types", "list_severities",
}

# Explicitly masked, so the reason is readable in the code and not only in
# the absence of an entry. These are the tools that would act on production
# by short-circuiting AURA's policy.
WAZUH_MASKED = {
    "wazuh_active_response", "wazuh_isolate_host", "wazuh_unisolate_host",
    "wazuh_check_agent_isolation", "wazuh_block_ip", "wazuh_check_blocked_ip",
    "wazuh_firewall_drop", "wazuh_firewall_allow", "wazuh_host_deny",
    "wazuh_host_allow", "wazuh_kill_process", "wazuh_check_process",
    "wazuh_quarantine_file", "wazuh_restore_file",
    "wazuh_check_file_quarantine", "wazuh_disable_user", "wazuh_enable_user",
    "wazuh_check_user_status", "wazuh_restart",
}

# All relayed tools are read-only: writes go through the `aura_*` tools.
# IRIS is the exception — creating a note or an IOC in a case is analyst
# work, reversible, and has no effect on machines.
SCOPE_WAZUH = "aura:read"
SCOPE_IRIS = "aura:write"


class Upstream:
    """An upstream MCP server, reached over streamable HTTP.

    One session per call rather than a long-lived session: the relay is a
    cold path (a handful of calls per investigation), and a long-lived
    session would need reconnecting on every upstream restart — complexity
    for nothing.
    """

    def __init__(self, name: str, url: str, token: str, prefix: str):
        self.name = name
        self.url = url
        self.token = token
        self.prefix = prefix

    async def _session(self):
        import httpx2
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        http = httpx2.AsyncClient(headers=headers, timeout=60)
        flow = streamable_http_client(self.url, http_client=http)
        return http, flow, ClientSession

    async def tools(self) -> list:
        """Upstream inventory. Empty list if it's unreachable."""
        try:
            http, flow, ClientSession = await self._session()
            async with http, flow as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return list((await session.list_tools()).tools)
        except Exception as e:  # noqa: BLE001
            log.warning("MCP server %s unreachable (%s): its tools won't be "
                        "relayed", self.name, e)
            return []

    async def call(self, tool: str, arguments: dict) -> dict:
        http, flow, ClientSession = await self._session()
        async with http, flow as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments)
                texts = [getattr(b, "text", str(b)) for b in result.content]
                # Bounded like everything else: a `get_wazuh_agents` on a
                # fleet of 16 machines already returns 8 KB of JSON. Relaying
                # without a limit would defeat the gateway's whole point —
                # the client's context budget.
                from . import output
                return {"upstream": self.name, "tool": tool,
                        "error": result.is_error,
                        "result": output.bound("\n".join(texts),
                                                  RELAY_CAP)}


def upstreams() -> list[Upstream]:
    """The configured upstream servers. Empty = gateway disabled."""
    items = []
    if WAZUH_URL:
        items.append(Upstream("wazuh", WAZUH_URL, WAZUH_TOKEN, "wazuh_"))
    if IRIS_URL:
        items.append(Upstream("iris", IRIS_URL, IRIS_TOKEN, "iris_"))
    return items


def allowed(upstream: Upstream, name: str) -> bool:
    """Should this upstream tool be relayed?

    The name is compared both bare AND prefixed: upstream servers don't name
    their tools the same way (`get_wazuh_agents` for one, `wazuh_block_ip`
    for the other, for the same family).
    """
    if upstream.name == "wazuh":
        if name in WAZUH_MASKED or name.replace("wazuh_", "") in {
                m.replace("wazuh_", "") for m in WAZUH_MASKED}:
            return False
        return name in WAZUH_ALLOWED
    return name in IRIS_ALLOWED
