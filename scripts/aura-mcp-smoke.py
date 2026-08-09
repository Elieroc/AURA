#!/usr/bin/env python3
"""Vérifie qu'un client MCP parle vraiment au serveur AURA.

    docker run --rm --network host -v /opt/AURA:/w -w /w aura-mcp:latest \\
        python scripts/aura-mcp-smoke.py --jeton "$(cat /tmp/tok.txt)"

Le healthcheck du conteneur ne prouve que « le process est vivant ». Ce script
prouve la chaîne complète : poignée de main MCP, authentification, inventaire
des outils, et un appel réel qui touche la base. C'est ce qu'on rejoue après
chaque changement du socle.

Avec `--outil` / `--args`, sert aussi de client en ligne de commande pour
appeler n'importe quel outil sans passer par un client IA.
"""

import argparse
import asyncio
import json
import os
import sys

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def executer(url: str, jeton: str, outil: str | None,
                   arguments: dict) -> int:
    # Le SDK 2.0 ne prend plus de `headers=` : l'authentification passe par le
    # client HTTP qu'on lui fournit.
    entetes = {"Authorization": f"Bearer {jeton}"}
    async with httpx2.AsyncClient(headers=entetes, timeout=60) as http:
        async with streamable_http_client(url, http_client=http) as (
                lire, ecrire):
            async with ClientSession(lire, ecrire) as session:
                init = await session.initialize()
                print(f"connecté : {init.server_info.name} "
                      f"{init.server_info.version}")

                catalogue = await session.list_tools()
                print(f"outils : {len(catalogue.tools)}")
                for t in catalogue.tools:
                    print(f"  - {t.name}")

                if not outil:
                    return 0

                print(f"\nappel {outil}("
                      f"{json.dumps(arguments, ensure_ascii=False)})")
                resultat = await session.call_tool(outil, arguments)
                if resultat.is_error:
                    print("ÉCHEC :", file=sys.stderr)
                for bloc in resultat.content:
                    print(getattr(bloc, "text", bloc))
                return 1 if resultat.is_error else 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get(
        "AURA_MCP_URL", "http://127.0.0.1:3100/mcp"))
    ap.add_argument("--jeton", default=os.environ.get("AURA_MCP_TOKEN", ""))
    ap.add_argument("--outil", help="outil à appeler (défaut : inventaire seul)")
    ap.add_argument("--args", default="{}", help="arguments JSON de l'outil")
    args = ap.parse_args()

    if not args.jeton:
        sys.exit("Jeton requis : --jeton ou AURA_MCP_TOKEN. En émettre un :\n"
                 "  python3 scripts/aura-mcp-token.py --sujet smoke "
                 "--scope aura:read")

    sys.exit(asyncio.run(executer(args.url, args.jeton, args.outil,
                                  json.loads(args.args))))


if __name__ == "__main__":
    main()
