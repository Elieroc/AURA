#!/bin/sh
# Wazuh active response: network isolation of the host (nftables).
#
# Cuts all traffic except:
#   - loopback
#   - agent -> Wazuh manager connection (tcp/1514) to keep control
#   - SSH from the Wazuh server (tcp/22) for administration/de-isolation
#
# Deployed in /var/ossec/active-response/bin/ on Linux agents.
# Receives the AR message (JSON) on stdin; only acts on "command": "add".
# De-isolation is done by host-unisolate.sh (table removal).

set -u

# Default overridden by /var/ossec/etc/soc-ai.conf (value edited in the root
# .env, deployed by generate-soc-ai-conf.sh):
# WAZUH_MANAGER_IP = manager IP as reached by agents. It is the
# only outbound path left open by isolation, so the only way to keep
# the agent controllable — a wrong value here cuts the agent off for good.
WAZUH_MANAGER_IP="192.168.60.1"
CONF_FILE="/var/ossec/etc/soc-ai.conf"
# shellcheck source=/dev/null
[ -r "$CONF_FILE" ] && . "$CONF_FILE"
MANAGER_IP="$WAZUH_MANAGER_IP"

NFT="/usr/sbin/nft"
TABLE="wazuh_isolation"
LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="host-isolate"
# Robust state marker. Two forms, complementary:
#  - MARKER: local file, ground truth inspectable even off the network (the
#    manager keeps SSH). Contains a JSON state + timestamp.
#  - the token Aura-SOC-ISOLATION-STATE=<state> written to active-responses.log,
#    ingested by Wazuh -> queryable remotely without touching the agent.
# The presence of the nftables table remains authoritative; the marker mirrors it.
MARKER="/var/ossec/isolated"

# Report target: the host itself is what's isolated (mirrors
# the $env:COMPUTERNAME used by win-host-isolate.ps1).
HOST_NAME=$(hostname 2>/dev/null || echo "unknown")

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-isolate: $1" >> "$LOG_FILE"
}

# Structured report, read by the Wazuh 100930 decoder and then by
# soc_agent.reconcile. status: applied | refused | noop | error.
ar_result() {   # $1 status  $2 target  $3 reason
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

# Atomically writes the isolation marker (state "isolated").
write_marker() {
    _tmp="${MARKER}.tmp.$$"
    printf '{"isolated":true,"since":"%s","manager":"%s","table":"%s"}\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$MANAGER_IP" "$TABLE" > "$_tmp" \
        && mv "$_tmp" "$MARKER"
    log "Aura-SOC-ISOLATION-STATE=isolated (marker $MARKER)"
}

# AR v2 message on stdin
read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        # No timeout handled here: de-isolation goes through host-unisolate.sh
        ar_result noop "$HOST_NAME" "delete command (timeout expiry), de-isolation goes through host-unisolate"
        exit 0
        ;;
    *)
        log "invalid command: '$COMMAND'"
        ar_result error "$HOST_NAME" "invalid command: $COMMAND"
        exit 1
        ;;
esac

if [ ! -x "$NFT" ]; then
    log "ERROR: $NFT not found, isolation impossible"
    ar_result error "$HOST_NAME" "$NFT not found, isolation impossible"
    exit 1
fi

# Refusal carried by the machine itself. `SOC_AI_NO_ISOLATE=1` in
# /var/ossec/etc/soc-ai.conf marks an INFRASTRUCTURE host — firewall, reverse
# proxy, DNS resolver, VPN gateway. These machines route other hosts' traffic:
# isolating them doesn't contain an incident, it causes a general outage, and
# on a firewall it cuts the very link through which it would be restored.
#
# Deliberate duplicate of the Python guardrail (Wazuh groups, cf.
# mitigate.not_isolatable_reason): the AR is also reachable via the Wazuh API and
# the MCP server, which don't go through this code. And this one survives an
# inventory error on the manager side, since the machine itself carries its
# own refusal.
if [ "${SOC_AI_NO_ISOLATE:-0}" = "1" ]; then
    log "REFUSED: infrastructure host (SOC_AI_NO_ISOLATE=1 in $CONF_FILE) — isolation refused"
    ar_result refused "$HOST_NAME" "infrastructure host (SOC_AI_NO_ISOLATE=1)"
    exit 1
fi

# Refuse self-isolation of the manager. If MANAGER_IP is a LOCAL address, this
# script is running ON the manager (agent 000): isolating it would cut off
# collection for the whole fleet, the API, and the console — i.e. the only
# channel through which it could be de-isolated. The ruleset below only opens
# an exception "toward the manager", which is meaningless when we ARE the
# manager.
#
# Deliberate duplicate of the Python guardrail (config.AGENTS_PROTECTED): the
# AR is also reachable via the Wazuh API and the MCP server, which don't go
# through this code.
if [ -n "$MANAGER_IP" ] && command -v ip >/dev/null 2>&1 \
   && ip -o addr show 2>/dev/null | grep -qw "$MANAGER_IP"; then
    log "REFUSED: $MANAGER_IP is a local address — manager self-isolation refused"
    ar_result refused "$HOST_NAME" "manager self-isolation refused ($MANAGER_IP is local)"
    exit 1
fi

# Idempotent: table already in place = already isolated. We (re)write the
# marker in case it went missing (agent restarted, marker deleted), so it
# always reflects the actual state of the table.
if "$NFT" list table inet "$TABLE" >/dev/null 2>&1; then
    write_marker
    log "already isolated (table $TABLE present)"
    ar_result noop "$HOST_NAME" "already isolated (table $TABLE present)"
    exit 0
fi

"$NFT" -f - <<EOF
table inet $TABLE {
    chain input {
        type filter hook input priority -50; policy drop;
        iif "lo" accept
        ct state established,related accept
        ip saddr $MANAGER_IP tcp dport 22 accept
    }
    chain output {
        type filter hook output priority -50; policy drop;
        oif "lo" accept
        ct state established,related accept
        ip daddr $MANAGER_IP tcp dport 1514 accept
        ip daddr $MANAGER_IP tcp dport 1515 accept
    }
    chain forward {
        type filter hook forward priority -50; policy drop;
    }
}
EOF

if [ $? -eq 0 ]; then
    write_marker
    log "host isolated from the network (exceptions: lo, manager $MANAGER_IP 1514/1515, SSH from manager)"
    ar_result applied "$HOST_NAME" "isolated (exceptions: lo, manager $MANAGER_IP 1514/1515, SSH from manager)"
    exit 0
else
    log "ERROR: failed to apply the nftables ruleset"
    ar_result error "$HOST_NAME" "failed to apply the nftables ruleset"
    exit 1
fi
