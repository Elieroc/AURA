#!/bin/sh
# Wazuh active response: network de-isolation of the host.
# Removes the nftables table set up by host-isolate.sh.

set -u

NFT="/usr/sbin/nft"
TABLE="wazuh_isolation"
LOG_FILE="/var/ossec/logs/active-responses.log"
# Mirrors the marker set by host-isolate.sh. Removed on de-isolation so the
# local file and the nftables table stay consistent.
MARKER="/var/ossec/isolated"
SCRIPT_NAME="host-unisolate"
# Report target: the host itself (mirrors win-host-unisolate.ps1).
HOST_NAME=$(hostname 2>/dev/null || echo "unknown")

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-unisolate: $1" >> "$LOG_FILE"
}

# Structured report, read by the Wazuh 100930 decoder and then by
# soc_agent.reconcile. status: applied | refused | noop | error.
ar_result() {   # $1 status  $2 target  $3 reason
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

clear_marker() {
    rm -f "$MARKER"
    log "Aura-SOC-ISOLATION-STATE=cleared (marker $MARKER removed)"
}

read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        ar_result noop "$HOST_NAME" "delete command (timeout expiry), no action"
        exit 0
        ;;
    *)
        log "invalid command: '$COMMAND'"
        ar_result error "$HOST_NAME" "invalid command: $COMMAND"
        exit 1
        ;;
esac

if ! "$NFT" list table inet "$TABLE" >/dev/null 2>&1; then
    clear_marker
    log "nothing to do (table $TABLE absent)"
    ar_result noop "$HOST_NAME" "host not isolated (table $TABLE absent)"
    exit 0
fi

if "$NFT" delete table inet "$TABLE"; then
    clear_marker
    log "host de-isolated (table $TABLE removed)"
    ar_result applied "$HOST_NAME" "de-isolated (table $TABLE removed)"
    exit 0
else
    log "ERROR: failed to remove table $TABLE"
    ar_result error "$HOST_NAME" "failed to remove table $TABLE"
    exit 1
fi
