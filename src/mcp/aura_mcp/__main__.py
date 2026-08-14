"""Entry point for the AURA MCP server.

    python -m aura_mcp

Listens by default on 127.0.0.1:3100/mcp. The container runs in
`network_mode: host`: the compose file can't restrict exposure with
`ports:`, this listen address is what does it instead.
"""

import logging
import sys

import uvicorn

from . import config
from .server import build


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr)
    logging.getLogger("aura_mcp").info(
        "AURA MCP server on http://%s:%d%s", config.HOST, config.PORT,
        config.PATH)
    uvicorn.run(build(), host=config.HOST, port=config.PORT,
                log_level="info")


if __name__ == "__main__":
    main()
