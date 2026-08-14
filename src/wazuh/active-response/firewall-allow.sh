#!/bin/sh
# Wazuh active response: removal of a block set by firewall-drop.
#
# The MCP server's upstream rollback calls firewall-drop with a "delete"
# argument, but the Wazuh binary expects the "delete" command in the AR
# message and reads the IP from alert.data.srcip — unusable via the API. This
# script does the removal explicitly, with the IP passed in extra_args[0].
#
# Deployed in /var/ossec/active-response/bin/ on Linux agents.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="firewall-allow"
IPT="/usr/sbin/iptables"
IPT6="/usr/sbin/ip6tables"
NFT="/usr/sbin/nft"
NFT_TABLE="soc_ai_block"   # cf. firewall-drop.sh

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') firewall-allow: $1" >> "$LOG_FILE"
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
    delete)
        ar_result noop "" "delete command (timeout expiry), no action"
        exit 0
        ;;
    *)
        log "invalid command: '$COMMAND'"
        ar_result error "" "invalid command: $COMMAND"
        exit 1
        ;;
esac

IP=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
# Tolerates the "-srcip <ip>" form used by firewall-drop.
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

case "$IP" in
    *:*) BIN="$IPT6"; FAM="ip6" ;;
    *)   BIN="$IPT";  FAM="ip"  ;;
esac

# nftables fallback, symmetric with firewall-drop.sh (hosts without an
# iptables shim).
if [ ! -x "$BIN" ]; then
    if [ ! -x "$NFT" ]; then
        log "ERROR: neither $BIN nor $NFT found"
        ar_result error "$IP" "neither $BIN nor $NFT found"
        exit 1
    fi
    REMOVED=0
    # Handles shift after each removal: we re-read the chain on every
    # iteration instead of collecting the list once and for all.
    i=0
    while [ $i -lt 20 ]; do
        H=$("$NFT" -a list chain inet "$NFT_TABLE" input 2>/dev/null \
            | sed -n "s/.*$FAM saddr $IP drop # handle \([0-9]*\).*/\1/p" | head -1)
        [ -z "$H" ] && break
        "$NFT" delete rule inet "$NFT_TABLE" input handle "$H" 2>/dev/null || break
        REMOVED=$((REMOVED + 1))
        i=$((i + 1))
    done
    if [ "$REMOVED" -eq 0 ]; then
        log "no nft drop rule for '$IP', nothing to do"
        ar_result noop "$IP" "no nft drop rule for this IP"
        exit 0
    fi
    log "IP '$IP' unblocked (nft, $REMOVED rule(s) removed)"
    ar_result applied "$IP" "unblocked (nft, $REMOVED rule(s) removed)"
    exit 0
fi

REMOVED=0
# The same IP may have been blocked several times: loop until the rule no
# longer exists, with a bound so it doesn't run forever.
i=0
while [ $i -lt 20 ] && "$BIN" -C INPUT -s "$IP" -j DROP >/dev/null 2>&1; do
    "$BIN" -D INPUT -s "$IP" -j DROP >/dev/null 2>&1 || break
    REMOVED=$((REMOVED + 1))
    i=$((i + 1))
done

if [ "$REMOVED" -eq 0 ]; then
    log "no DROP rule for '$IP', nothing to do"
    ar_result noop "$IP" "no iptables DROP rule for this IP"
    exit 0
fi

log "IP '$IP' unblocked ($REMOVED rule(s) removed)"
ar_result applied "$IP" "unblocked ($REMOVED rule(s) removed)"
exit 0
