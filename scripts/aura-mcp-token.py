#!/usr/bin/env python3
"""Issues an access token for the AURA MCP server.

    python3 scripts/aura-mcp-token.py --sujet claude-code --scope aura:read
    python3 scripts/aura-mcp-token.py --sujet elie --scope aura:admin --jours 30

The token is signed with `AURA_MCP_SECRET` (read from the root `.env`). There
is no revocation: a token stays valid until it expires, the only way to kill
it early is to change the secret — which kills all the others with it. Hence
the short default durations on the higher scopes.

Reminder of the scopes, from weakest to strongest (each includes the
previous one):

    aura:read    view incidents, triages, remediations, UEBA, metrics
    aura:write   trigger a cycle, a triage, an IRIS sync
    aura:admin   remediate, isolate, whitelist, tune rules, enroll
"""

import argparse
import datetime as dt
import os
import pathlib
import sys

import jwt

SCOPES = ("aura:read", "aura:write", "aura:admin")
# An admin token can isolate a production machine. Its default lifetime is
# short for that reason, not as a matter of principle.
DEFAULT_DURATION = {"aura:read": 180, "aura:write": 90, "aura:admin": 30}


def read_env(key: str) -> str | None:
    """Fetches a value from the root .env without external dependency."""
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
                    help="who uses this token (claude-code, elie, ci...) - "
                         "also used as the rate-limiting key")
    ap.add_argument("--scope", choices=SCOPES, default="aura:read")
    ap.add_argument("--jours", type=int, default=None,
                    help="validity duration (default: 180 for read, "
                         "90 for write, 30 for admin)")
    args = ap.parse_args()

    secret = read_env("AURA_MCP_SECRET")
    if not secret:
        sys.exit("AURA_MCP_SECRET not found (root .env). Generate one:\n"
                 "  openssl rand -hex 32")

    days = args.jours if args.jours is not None else DEFAULT_DURATION[args.scope]
    now = dt.datetime.now(dt.timezone.utc)
    token = jwt.encode(
        {
            "sub": args.sujet,
            "scope": args.scope,
            "iss": read_env("AURA_MCP_ISSUER") or "aura",
            "aud": read_env("AURA_MCP_AUDIENCE") or "aura-mcp",
            "iat": now,
            "exp": now + dt.timedelta(days=days),
        },
        secret, algorithm="HS256")

    print(token)
    print(f"\n# subject {args.sujet}, scope {args.scope}, expires "
          f"{(now + dt.timedelta(days=days)):%Y-%m-%d}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
