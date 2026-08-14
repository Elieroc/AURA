"""Configuration for the AURA MCP server.

Everything comes from the root `.env`, like the rest of the stack — a single
secrets file on the host. This module configures ONLY the server: the
pipeline thresholds (MIN_LEVEL, UEBA_*, MITIGATE_EXECUTE…) stay in
`soc_agent.config`, which is imported as-is. Duplicating a value here would
make it diverge from what the pipeline actually applies.
"""

import os
import sys

# --- Listening --------------------------------------------------------------
# The container runs in network_mode: host, so `ports:` isn't available in
# the compose file: it's up to the code not to expose itself. Default
# loopback, and it's deliberate — exposing the MCP on the LAN would give
# anyone who reaches it the SOC's host-isolation rights.
HOST = os.environ.get("AURA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("AURA_MCP_PORT", "3100"))
PATH = os.environ.get("AURA_MCP_PATH", "/mcp")

# --- Authentication ---------------------------------------------------------
# JWT HS256, same scheme as the upstream Wazuh MCP (shared secret, tokens
# issued offline by scripts/aura-mcp-token.py). No OAuth: there are no users,
# only declared AI clients.
SECRET = os.environ.get("AURA_MCP_SECRET", "")
ISSUER = os.environ.get("AURA_MCP_ISSUER", "aura")
AUDIENCE = os.environ.get("AURA_MCP_AUDIENCE", "aura-mcp")

# Without a secret, refuse to start rather than serve in the clear: an open
# server would hand isolate/kill to anyone reaching the port.
if not SECRET:
    print("AURA_MCP_SECRET missing — the MCP server refuses to start without "
          "authentication.", file=sys.stderr)
    sys.exit(1)

# --- Scopes ------------------------------------------------------------------
# Fail-closed: a token without a `scope` claim gets nothing at all (the
# upstream Wazuh MCP grants read by default; here even reading exposes
# incident logs, so nothing is granted implicitly).
READ = "aura:read"
WRITE = "aura:write"
ADMIN = "aura:admin"

# Inclusion order: admin implies write, write implies read. An admin token
# therefore doesn't have to list all three.
IMPLIES = {
    ADMIN: {ADMIN, WRITE, READ},
    WRITE: {WRITE, READ},
    READ: {READ},
}

# --- DNS anti-rebinding ------------------------------------------------------
# The SDK's comparison is on the RAW `Host` header, port included: a client
# calling http://127.0.0.1:3100/mcp sends `127.0.0.1:3100`, which
# "127.0.0.1" alone doesn't cover (421 Misdirected Request, with no hint on
# the client side). Both forms are therefore generated for each name.
def _with_port(names: list[str]) -> list[str]:
    return [f"{n}:{PORT}" for n in names]


_NAMES = [n.strip() for n in os.environ.get(
    "AURA_MCP_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if n.strip()]
HOSTS = _NAMES + _with_port(_NAMES)

_ORIGINS = [o.strip() for o in os.environ.get(
    "AURA_MCP_ALLOWED_ORIGINS",
    "http://localhost,http://127.0.0.1").split(",") if o.strip()]
ORIGINS = _ORIGINS + [f"{o}:{PORT}" for o in _ORIGINS]

# --- Rate limiting -----------------------------------------------------------
# Per source IP, one-minute sliding window. Doesn't protect against a chatty
# legitimate client: it protects against an AI agent looping and calling the
# same tool in a burst (seen on other MCP servers: 200 calls/min on a
# timeout).
MAX_RATE = int(os.environ.get("AURA_MCP_RATE_LIMIT", "120"))

# --- Response caps ------------------------------------------------------------
# A tool response lands in an LLM's context. A 200 KB `full_log` or 5,000
# alerts don't help it, they choke it. These bounds are hard: a tool that has
# more to return returns one page and says so.
MAX_PAGE = int(os.environ.get("AURA_MCP_PAGE_MAX", "100"))
DEFAULT_PAGE = int(os.environ.get("AURA_MCP_PAGE_DEFAUT", "25"))
MAX_TEXT = int(os.environ.get("AURA_MCP_TEXTE_MAX", "4000"))
