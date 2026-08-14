#!/bin/sh
# Wazuh active response: removal of an entry set by host-deny.
#
# Same issue as firewall-allow.sh: the upstream rollback passes "delete" as an
# argument, which the host-deny binary does not interpret. The IP is read from
# extra_args[0] and the "ALL:<ip>" line is removed from /etc/hosts.deny.
#
# Deployed in /var/ossec/active-response/bin/ on Linux agents.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
HOSTS_DENY="/etc/hosts.deny"
SCRIPT_NAME="host-allow"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-allow: $1" >> "$LOG_FILE"
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

if [ ! -f "$HOSTS_DENY" ]; then
    log "$HOSTS_DENY absent, nothing to do"
    ar_result noop "$IP" "$HOSTS_DENY absent"
    exit 0
fi

if ! grep -q "^ALL:$IP\$" "$HOSTS_DENY"; then
    log "no entry for '$IP', nothing to do"
    ar_result noop "$IP" "no ALL:$IP entry in $HOSTS_DENY"
    exit 0
fi

TMP=$(mktemp) || {
    log "ERROR: mktemp failed"
    ar_result error "$IP" "mktemp failed"
    exit 1
}
grep -v "^ALL:$IP\$" "$HOSTS_DENY" > "$TMP" || true
cat "$TMP" > "$HOSTS_DENY"
rm -f "$TMP"

log "entry 'ALL:$IP' removed from $HOSTS_DENY"
ar_result applied "$IP" "entry ALL:$IP removed from $HOSTS_DENY"
exit 0
