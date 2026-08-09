"""Point d'entrée du serveur MCP AURA.

    python -m aura_mcp

Écoute par défaut sur 127.0.0.1:3100/mcp. Le conteneur tourne en
`network_mode: host` : le compose ne peut pas restreindre l'exposition avec
`ports:`, c'est cette adresse d'écoute qui le fait.
"""

import logging
import sys

import uvicorn

from . import config
from .serveur import construire


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr)
    logging.getLogger("aura_mcp").info(
        "serveur MCP AURA sur http://%s:%d%s", config.HOST, config.PORT,
        config.PATH)
    uvicorn.run(construire(), host=config.HOST, port=config.PORT,
                log_level="info")


if __name__ == "__main__":
    main()
