#!/bin/sh
# Wazuh active response: disable a compromised account.
#
# Replaces the native `disable-account` binary, which reads the user from
# alert.data.dstuser and therefore fails on any driven call ("Cannot read
# 'dstuser' from data"): soc-agent and the MCP server pass the account via
# extra_args, not through an alert. Six attempts, six silent failures — the
# database said `executed` while no account was ever actually disabled.
#
# Same input contract as enable-account.sh (extra_args = ["<user>"]) and
# EXACTLY the symmetric reverse: what is set here (usermod -L, chage -E 1) is
# lifted by enable-account.sh (usermod -U, chage -E -1). The native binary
# set something different, so re-enabling did not restore the same state.
#
# Deployed in /var/ossec/active-response/bin/ on Linux agents.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="disable-account"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') disable-account: $1" >> "$LOG_FILE"
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
    # execd emits "delete" when the timeout expires. An account disablement
    # must NOT be lifted on its own: only enable-account.sh undoes it.
    delete)
        ar_result noop "" "delete command (timeout expiry), only enable-account lifts the lock"
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

# Local guardrail, in addition to those in soc-agent (actions.apply_guardrails):
# the AR is also reachable via the Wazuh API and the MCP server, which don't
# go through this code. Locking root or the Wazuh service account would cut
# off administration and the agent itself.
case "$USER" in
    root|wazuh|wazuh-admin)
        log "REFUSED: disabling protected account '$USER' refused"
        ar_result refused "$USER" "protected account (root/wazuh/wazuh-admin)"
        exit 1
        ;;
esac

if ! id "$USER" >/dev/null 2>&1; then
    log "ERROR: user '$USER' does not exist"
    ar_result noop "$USER" "account does not exist on this host"
    exit 1
fi

# usermod -L locks the password, chage -E 1 expires the account (the lock
# alone doesn't prevent an SSH-key or service login).
DONE=""
if command -v usermod >/dev/null 2>&1; then
    if usermod -L "$USER" >/dev/null 2>&1; then
        DONE="${DONE} usermod -L"
    else
        log "ERROR: usermod -L failed on '$USER'"
        ar_result error "$USER" "usermod -L failed"
        exit 1
    fi
fi
if command -v chage >/dev/null 2>&1; then
    if chage -E 1 "$USER" >/dev/null 2>&1; then
        DONE="${DONE} chage -E 1"
    else
        log "ERROR: chage -E 1 failed on '$USER'"
        ar_result error "$USER" "chage -E 1 failed"
        exit 1
    fi
fi

if [ -z "$DONE" ]; then
    log "ERROR: neither usermod nor chage available, account '$USER' NOT disabled"
    ar_result error "$USER" "neither usermod nor chage available"
    exit 1
fi

log "account '$USER' disabled ($DONE)"
ar_result applied "$USER" "account disabled ($DONE)"
exit 0
