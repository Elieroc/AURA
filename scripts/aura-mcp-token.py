#!/usr/bin/env python3
"""Émet un jeton d'accès au serveur MCP AURA.

    python3 scripts/aura-mcp-token.py --sujet claude-code --scope aura:read
    python3 scripts/aura-mcp-token.py --sujet elie --scope aura:admin --jours 30

Le jeton est signé avec `AURA_MCP_SECRET` (lu dans le `.env` racine). Il n'y a
pas de révocation : un jeton reste valable jusqu'à son expiration, la seule
façon de le tuer avant est de changer le secret — donc de tuer tous les autres
avec. D'où les durées courtes par défaut sur les scopes élevés.

Rappel des scopes, du plus faible au plus fort (chacun inclut le précédent) :

    aura:read    consulter incidents, triages, remédiations, UEBA, métriques
    aura:write   déclencher un cycle, un triage, une synchro IRIS
    aura:admin   remédier, isoler, whitelister, tuner les règles, enrôler
"""

import argparse
import datetime as dt
import os
import pathlib
import sys

import jwt

SCOPES = ("aura:read", "aura:write", "aura:admin")
# Un jeton d'admin peut isoler une machine de production. Sa durée de vie par
# défaut est courte pour cette raison, et non par principe.
DEFAULT_DURATION = {"aura:read": 180, "aura:write": 90, "aura:admin": 30}


def read_env(key: str) -> str | None:
    """Récupère une valeur du .env racine sans dépendance externe."""
    if os.environ.get(key):
        return os.environ[key]
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if not env.is_file():
        return None
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}=") and not line.startswith("#"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sujet", required=True,
                    help="qui utilise ce jeton (claude-code, elie, ci…) — "
                         "sert aussi de clé de limitation de débit")
    ap.add_argument("--scope", choices=SCOPES, default="aura:read")
    ap.add_argument("--jours", type=int, default=None,
                    help="durée de validité (défaut : 180 en lecture, "
                         "90 en écriture, 30 en admin)")
    args = ap.parse_args()

    secret = read_env("AURA_MCP_SECRET")
    if not secret:
        sys.exit("AURA_MCP_SECRET introuvable (.env racine). En générer un :\n"
                 "  openssl rand -hex 32")

    days = args.days if args.days is not None else DEFAULT_DURATION[args.scope]
    maintenant = dt.datetime.now(dt.timezone.utc)
    token = jwt.encode(
        {
            "sub": args.subject,
            "scope": args.scope,
            "iss": read_env("AURA_MCP_ISSUER") or "aura",
            "aud": read_env("AURA_MCP_AUDIENCE") or "aura-mcp",
            "iat": maintenant,
            "exp": maintenant + dt.timedelta(days=days),
        },
        secret, algorithm="HS256")

    print(token)
    print(f"\n# sujet {args.subject}, scope {args.scope}, expire le "
          f"{(maintenant + dt.timedelta(days=days)):%Y-%m-%d}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
