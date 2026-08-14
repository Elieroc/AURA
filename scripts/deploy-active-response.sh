#!/usr/bin/env bash
#
# Deploys the Aura-SOC active-response scripts to already-installed Wazuh agents.
#
# Why this script exists: `install-agent.sh` did not deploy them, and an agent
# without these files makes EVERY remediation fail SILENTLY — the ar.conf
# pushed by the manager does declare `firewall-drop.sh`, the Wazuh API replies
# 200 (it only forwards the command), and the agent cannot find the
# executable. The only clue is the absence of a line in its
# /var/ossec/logs/active-responses.log. This is exactly what can make IP
# blocking silently inoperative.
#
# The native binaries shipped with the package are not enough: they read the
# target from the alert (alert.data.srcip / dstuser) and fail on any call
# driven by extra_args (API, MCP, soc-agent).
#
# Usage (from a machine that reaches the agents over SSH as root with a key):
#   ./deploy-active-response.sh <host> [<host> ...]
#   ./deploy-active-response.sh --local            # deploys the scripts on THIS machine
#
# Example (to run from a host that reaches all the agents):
#   ./deploy-active-response.sh 10.0.1.11 10.0.1.18 10.0.6.4
#
# End-to-end check afterwards (from the manager):
#   TOK=$(curl -sk -u "$API_USER:$API_PASS" -X POST \
#     "https://127.0.0.1:55000/security/user/authenticate?raw=true")
#   curl -sk -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
#     -X PUT "https://127.0.0.1:55000/active-response?agents_list=003" \
#     -d '{"command":"!firewall-drop.sh","arguments":["198.51.100.77"]}'
#   # then, on the agent: tail /var/ossec/logs/active-responses.log && iptables -S INPUT
#
# The `!` prefix is mandatory: it designates the literal FILE name. Without it
# the API resolves a `<command>` from ossec.conf and replies 1652 "command is
# not defined".

set -euo pipefail

AR_SRC="$(cd "$(dirname "$0")/../src/wazuh/active-response" && pwd)"
AR_DST="/var/ossec/active-response/bin"

[ $# -ge 1 ] || { grep '^#' "$0" | sed 's/^# \?//'; exit 1; }

deploy_local() {
  [ -d "$AR_DST" ] || { echo "ERROR: $AR_DST missing (Wazuh agent not installed?)" >&2; exit 1; }
  for f in "$AR_SRC"/*.sh; do
    install -m 750 -o root -g wazuh "$f" "$AR_DST/$(basename "$f")"
  done
  echo "  $(ls -1 "$AR_SRC"/*.sh | wc -l) script(s) deployed on $(hostname)"
}

if [ "$1" = "--local" ]; then
  deploy_local
  exit 0
fi

# Transfer via tar over stdin: a single SSH round trip per host, and the
# permissions (root:wazuh, 750) are set on arrival rather than inherited from
# the source.
for h in "$@"; do
  echo "== $h"
  tar -C "$AR_SRC" -czf - ./*.sh | ssh -o BatchMode=yes -o ConnectTimeout=10 "root@$h" '
    set -e
    [ -d /var/ossec/active-response/bin ] || { echo "  Wazuh agent absent, skipped" >&2; exit 1; }
    tar -xzf - -C /var/ossec/active-response/bin
    cd /var/ossec/active-response/bin
    chown root:wazuh ./*.sh && chmod 750 ./*.sh
    echo "  OK ($(ls -1 ./*.sh | wc -l) scripts)"
    # Without iptables or nft, firewall-drop.sh cannot block anything. It
    # still logs it, but it is worth seeing at deploy time.
    command -v iptables >/dev/null || command -v nft >/dev/null \
      || echo "  WARNING: neither iptables nor nft - IP blocking will fail"
  ' || echo "  FAILED on $h"
done
