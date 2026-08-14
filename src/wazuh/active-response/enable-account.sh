#!/bin/sh
# Wazuh active response: re-enable an account disabled by disable-account.
#
# The MCP server calls the "enable-account" AR command with
# extra_args = ["<user>"]. Native Wazuh only ships disable-account (which
# re-enables on "command": "delete"); this script does the explicit rollback.
#
# Deployed in /var/ossec/active-response/bin/ on Linux agents.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="enable-account"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') enable-account: $1" >> "$LOG_FILE"
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

USER=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$USER" ]; then
    log "ERROR: no user provided (empty extra_args)"
    ar_result error "" "no user provided (empty extra_args)"
    exit 1
fi

case "$USER" in
    root)
        log "REFUSED: re-enabling root refused"
        ar_result refused "$USER" "protected account (root)"
        exit 1
        ;;
esac

if ! id "$USER" >/dev/null 2>&1; then
    log "ERROR: user '$USER' does not exist"
    ar_result noop "$USER" "account does not exist on this host"
    exit 1
fi

# usermod -U lifts the password lock; chage -E -1 cancels the expiry
# set by disable-account.
if command -v usermod >/dev/null 2>&1; then
    usermod -U "$USER" >/dev/null 2>&1
fi
if command -v chage >/dev/null 2>&1; then
    chage -E -1 "$USER" >/dev/null 2>&1
fi

log "account '$USER' re-enabled"
ar_result applied "$USER" "account re-enabled (usermod -U, chage -E -1)"
exit 0
