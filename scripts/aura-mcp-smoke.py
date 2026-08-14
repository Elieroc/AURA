#!/usr/bin/env python3
"""Checks that an MCP client really talks to the AURA server.

    docker run --rm --network host -v /opt/AURA:/w -w /w aura-mcp:latest \\
        python scripts/aura-mcp-smoke.py --jeton "$(cat /tmp/tok.txt)"

The container healthcheck only proves "the process is alive". This script
proves the full chain: MCP handshake, authentication, tool inventory, and a
real call that touches the database. This is what gets replayed after every
change to the base image.

With `--outil` / `--args`, it also serves as a command-line client to call
any tool without going through an AI client.
"""

import argparse
import asyncio
import json
import os
import sys

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def run(url: str, token: str, tool: str | None,
                   arguments: dict) -> int:
    # The 2.0 SDK no longer takes `headers=`: authentication goes through the
    # HTTP client we hand it.
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(headers=headers, timeout=60) as http:
        async with streamable_http_client(url, http_client=http) as (
                read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                print(f"connected: {init.server_info.name} "
                      f"{init.server_info.version}")

                catalog = await session.list_tools()
                print(f"tools: {len(catalog.tools)}")
                for t in catalog.tools:
                    print(f"  - {t.name}")

                if not tool:
                    return 0

                print(f"\ncalling {tool}("
                      f"{json.dumps(arguments, ensure_ascii=False)})")
                result = await session.call_tool(tool, arguments)
                if result.is_error:
                    print("FAILED:", file=sys.stderr)
                for block in result.content:
                    print(getattr(block, "text", block))
                return 1 if result.is_error else 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get(
        "AURA_MCP_URL", "http://127.0.0.1:3100/mcp"))
    ap.add_argument("--jeton", default=os.environ.get("AURA_MCP_TOKEN", ""))
    ap.add_argument("--outil", help="tool to call (default: inventory only)")
    ap.add_argument("--args", default="{}", help="JSON arguments for the tool")
    args = ap.parse_args()

    if not args.jeton:
        sys.exit("Token required: --jeton or AURA_MCP_TOKEN. Issue one:\n"
                 "  python3 scripts/aura-mcp-token.py --sujet smoke "
                 "--scope aura:read")

    sys.exit(asyncio.run(run(args.url, args.jeton, args.outil,
                                  json.loads(args.args))))


if __name__ == "__main__":
    main()
