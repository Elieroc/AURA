#!/bin/sh
# Wazuh active response: block a hostile IP.
#
# Replaces the native `firewall-drop` binary, which reads the IP from
# alert.data.srcip and therefore fails on any driven call ("Cannot read
# 'srcip' from data"): soc-agent and the MCP server pass the IP via
# extra_args, not through an alert. Same flaw, same fix as disable-account.sh.
#
# Symmetric with firewall-allow.sh, which removes exactly the rule set here
# (iptables -D INPUT -s <ip> -j DROP).
#
# Deployed in /var/ossec/active-response/bin/ on Linux agents.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="firewall-drop"
IPT="/usr/sbin/iptables"
IPT6="/usr/sbin/ip6tables"
NFT="/usr/sbin/nft"
# nftables table dedicated to IP blocking, distinct from `wazuh_isolation`
# (host-isolate.sh): a de-isolation removes its entire table, and must not
# take the separately-set IP blocks down with it.
NFT_TABLE="soc_ai_block"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') firewall-drop: $1" >> "$LOG_FILE"
}

# Structured report, read by the Wazuh 100930 decoder and then by
# soc_agent.reconcile. status: applied | refused | noop | error.
ar_result() {   # $1 status  $2 target  $3 reason
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    # execd emits "delete" when the timeout expires. We do not lift the block
    # on our own: only firewall-allow.sh does, on explicit request.
    delete)
        ar_result noop "" "delete command (timeout expiry), only firewall-allow lifts the block"
        exit 0
        ;;
    *)
        log "invalid command: '$COMMAND'"
        ar_result error "" "invalid command: $COMMAND"
        exit 1
        ;;
esac

IP=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
# Tolerates the "-srcip <ip>" form inherited from the native binary.
IP=$(echo "$IP" | sed 's/^-srcip[[:space:]]*//')

if [ -z "$IP" ]; then
    log "ERROR: no IP provided (empty extra_args)"
    ar_result error "" "no IP provided (empty extra_args)"
    exit 1
fi

case "$IP" in
    *[!0-9.:a-fA-F]*)
        log "ERROR: invalid IP '$IP'"
        ar_result error "$IP" "invalid IP"
        exit 1
        ;;
esac

# Local guardrail, in addition to those in soc-agent (actions.apply_guardrails):
# the AR is also reachable via the Wazuh API and the MCP server, which don't
# go through this code. Blocking loopback or the manager would cut the agent
# off from its own supervision — and thus from any way to unblock it remotely.
case "$IP" in
    127.*|::1|0.0.0.0)
        log "REFUSED: blocking '$IP' (loopback) refused"
        ar_result refused "$IP" "loopback"
        exit 1
        ;;
esac

MANAGER=$(sed -n 's/.*<address>\([^<]*\)<\/address>.*/\1/p' "$OSSEC_CONF" 2>/dev/null | head -1)
if [ -n "$MANAGER" ] && [ "$IP" = "$MANAGER" ]; then
    log "REFUSED: blocking the manager '$IP' refused (would cut off supervision)"
    ar_result refused "$IP" "Wazuh manager IP"
    exit 1
fi

case "$IP" in
    *:*) BIN="$IPT6"; FAM="ip6" ;;
    *)   BIN="$IPT";  FAM="ip"  ;;
esac

# nftables fallback: recent Debian hosts (e.g. adguard-home) only ship `nft`,
# without the iptables shim. Without this fallback, blocking failed silently
# on these agents — and the failure only shows up in active-responses.log.
if [ ! -x "$BIN" ]; then
    if [ ! -x "$NFT" ]; then
        log "ERROR: neither $BIN nor $NFT found"
        ar_result error "$IP" "neither $BIN nor $NFT found"
        exit 1
    fi
    "$NFT" list table inet "$NFT_TABLE" >/dev/null 2>&1 \
        || "$NFT" add table inet "$NFT_TABLE" 2>/dev/null
    # priority -10: ahead of the usual filter (priority 0), so the DROP takes
    # precedence over an ACCEPT set by the host's own firewall.
    "$NFT" add chain inet "$NFT_TABLE" input \
        '{ type filter hook input priority -10 ; policy accept ; }' 2>/dev/null

    if "$NFT" list chain inet "$NFT_TABLE" input 2>/dev/null \
            | grep -q "$FAM saddr $IP drop"; then
        log "IP '$IP' already blocked (nft), nothing to do"
        ar_result noop "$IP" "already blocked (nft rule present)"
        exit 0
    fi
    if ! "$NFT" add rule inet "$NFT_TABLE" input "$FAM" saddr "$IP" drop 2>/dev/null; then
        log "ERROR: failed to add the nft drop rule for '$IP'"
        ar_result error "$IP" "failed to add nft drop rule"
        exit 1
    fi
    log "IP '$IP' blocked (nft inet $NFT_TABLE input drop)"
    ar_result applied "$IP" "blocked (nft inet $NFT_TABLE input drop)"
    exit 0
fi

# Idempotent: an already-blocked IP does not get a second rule. Otherwise an
# incident that removes the same IP several times would stack rules, and
# firewall-allow.sh would have to loop to remove them all.
if "$BIN" -C INPUT -s "$IP" -j DROP >/dev/null 2>&1; then
    log "IP '$IP' already blocked, nothing to do"
    ar_result noop "$IP" "already blocked (iptables rule present)"
    exit 0
fi

if ! "$BIN" -I INPUT -s "$IP" -j DROP >/dev/null 2>&1; then
    log "ERROR: failed to add the DROP rule for '$IP'"
    ar_result error "$IP" "failed to add INPUT DROP rule"
    exit 1
fi

log "IP '$IP' blocked (INPUT DROP)"
ar_result applied "$IP" "blocked (INPUT DROP)"
exit 0
