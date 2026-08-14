#!/bin/sh
# Wazuh active response: "host-isolation" wrapper for the MCP server.
#
# The MCP server (Wazuh-MCP-Server) calls a single AR command named
# "host-isolation": isolation when extra_args is empty, de-isolation when
# extra_args[0] == "undo". Our native scripts are separate (host-isolate.sh /
# host-unisolate.sh); this wrapper routes to the right one, passing the
# original AR message back on stdin.
#
# Deployed in /var/ossec/active-response/bin/ on Linux agents.

set -u

BIN_DIR="$(dirname "$0")"
LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="host-isolation"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-isolation: $1" >> "$LOG_FILE"
}

# Structured report, read by the Wazuh 100930 decoder and then by
# soc_agent.reconcile. status: applied | refused | noop | error.
#
# This script is only a router: on both paths that delegate, it's the called
# script (host-isolate / host-unisolate) that writes ITS ar-result line. We
# don't write a second one here, otherwise reconcile would see two reports
# for a single action. Only the invalid-argument path, which delegates to
# nothing, produces its own line.
ar_result() {   # $1 status  $2 target  $3 reason
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

read -r INPUT_JSON

ARG=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

case "$ARG" in
    undo|UNDO)
        log "routing -> host-unisolate.sh"
        echo "$INPUT_JSON" | "$BIN_DIR/host-unisolate.sh"
        ;;
    "")
        log "routing -> host-isolate.sh"
        echo "$INPUT_JSON" | "$BIN_DIR/host-isolate.sh"
        ;;
    *)
        log "ERROR: unexpected argument '$ARG' (expected: empty or 'undo')"
        ar_result error "$ARG" "unexpected argument (expected: empty or undo)"
        exit 1
        ;;
esac
