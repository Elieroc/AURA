#!/usr/bin/env python3
"""Sets the bcrypt hash of an indexer account in internal_users.yml.

    python3 scripts/set-indexer-password.py kibanaserver
    python3 scripts/set-indexer-password.py admin

The password is NOT asked for on the keyboard: it is read from the root
`.env`, the only source of truth for the stack's secrets. The script only
derives the hash and writes it to `internal_users.yml`, so that the two
files cannot drift apart.

Why this script exists. `internal_users.yml` is mounted as-is into the
indexer: it is a versioned file, whereas the password lives in a `.env` that
is not. Without a tool, one is tempted to keep upstream's demo hash - which
leaves the account accessible with a publicly documented password. Here,
rotation = one command.

After running, restart the indexer and reload the security configuration:

    docker compose -p aura restart wazuh.indexer
    docker exec -i wazuh.indexer bash -c \\
        '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \\
         -f /usr/share/wazuh-indexer/opensearch-security/internal_users.yml \\
         -t internalusers -icl -nhnv \\
         -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \\
         -cert /usr/share/wazuh-indexer/certs/admin.pem \\
         -key /usr/share/wazuh-indexer/certs/admin-key.pem'

Without this reload, the indexer keeps serving the old user database from
its `.opendistro_security` index: the file has changed, not the state.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
USERS = ROOT / "src/wazuh/config/wazuh_indexer/internal_users.yml"

# Account -> .env variable holding its password.
ACCOUNTS = {
    "admin": "INDEXER_PASSWORD",
    "kibanaserver": "DASHBOARD_PASSWORD",
}


def read_env(key: str) -> str:
    if not ENV.is_file():
        exit_with(f"{ENV} not found - copy .env.example to .env first.")
    for line in ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    exit_with(f"{key} missing from {ENV}.")


def exit_with(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def hash(password: str) -> str:
    """Bcrypt hash, via the Python module if present, else via the indexer.

    The fallback is not a convenience: `bcrypt` is installed neither on the
    production host nor in the soc-agent venv, whereas the indexer image
    ships `hash.sh` - the tool that produced the original hashes. Without
    this fallback, rotation would require installing a dependency on the
    manager just to set a password.
    """
    try:
        import bcrypt
    except ImportError:
        return _hash_in_container(password)
    # rounds=12 and prefix 2b: what OpenSearch's hash.sh tool generates.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12, b"2b")).decode()


def _hash_in_container(password: str) -> str:
    """Delegates to `hash.sh` in the indexer container.

    The container is found via its compose label rather than a hardcoded
    name: the name depends on the project name (`aura-wazuh.indexer-1`),
    which is not the same everywhere.
    """
    import subprocess

    found = subprocess.run(
        ["docker", "ps", "--filter",
         "label=com.docker.compose.service=wazuh.indexer",
         "--format", "{{.Names}}"],
        capture_output=True, text=True)
    container = (found.stdout or "").split("\n")[0].strip()
    if not container:
        exit_with("neither the bcrypt module nor the wazuh.indexer container "
               "is available. Start the indexer, or: pip install bcrypt")

    # The password goes through the -p argument, so through the container's
    # command line. This is what OpenSearch documents, and the only possible
    # reader is root on this host - who already has the .env.
    r = subprocess.run(
        ["docker", "exec", "-e", "JAVA_HOME=/usr/share/wazuh-indexer/jdk",
         container,
         "bash", "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
                 "hash.sh", "-p", password],
        capture_output=True, text=True)
    if r.returncode != 0:
        exit_with(f"hash.sh failed in {container}: {r.stderr.strip()[:300]}")
    # hash.sh prints warnings before the hash: keep the last line that looks
    # like bcrypt.
    for line in reversed(r.stdout.splitlines()):
        line = line.strip()
        if line.startswith("$2"):
            return line
    exit_with(f"hash not found in hash.sh output: "
           f"{r.stdout.strip()[:300]}")


def set(account: str, hashing: str) -> None:
    text = USERS.read_text(encoding="utf-8")
    # Replaces the `hash:` line of THIS account's block only: anchored on
    # the account name so as not to overwrite its neighbor's.
    pattern = re.compile(
        rf"(^{re.escape(account)}:\n(?:[ \t]+.*\n)*?[ \t]+hash:[ \t]*)\S.*$",
        re.MULTILINE)
    new, n = pattern.subn(rf'\g<1>"{hashing}"', text)
    if n != 1:
        exit_with(f"block '{account}' not found (or duplicated) in {USERS}.")
    USERS.write_text(new, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ACCOUNTS:
        exit_with(f"usage: {sys.argv[0]} {{{'|'.join(ACCOUNTS)}}}")
    account = sys.argv[1]
    password = read_env(ACCOUNTS[account])
    if not password or password in ("changeme", "__CHANGE_ME__"):
        exit_with(f"{ACCOUNTS[account]} is '{password}' in {ENV} - "
               f"generate a real secret: openssl rand -hex 32")
    set(account, hash(password))
    print(f"{account}: hash set in {USERS.relative_to(ROOT)}")
    print("Reload the indexer's security configuration "
          "(see this script's header): without it, the indexer keeps "
          "serving the old user database.")


if __name__ == "__main__":
    main()
