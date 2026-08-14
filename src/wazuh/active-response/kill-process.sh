#!/bin/sh
# Wazuh active response: kill a process by exact name (pkill -x) on the host.
#
# Receives the AR v1/v2 message (JSON) on stdin; only acts on "command": "add".
# The exact process name (comm, not a command line) is passed in
# parameters.extra_args[0]. Deployed in /var/ossec/active-response/bin/ on
# Linux agents.
#
# pkill -x (exact name match) rather than -f (substring over the whole
# command line): avoids killing a process whose command line contains the
# target name as a substring (e.g. targeting "app" must not kill
# "backup-app-monitor").
#
# Deterministic guardrail: refuses to kill critical processes (safelist) to
# avoid cutting off the Wazuh agent itself, sshd, or the system. It is this
# guardrail IN CODE that bounds the autonomous action (cf. CLAUDE.md —
# autonomous XDR), not a human validation step.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="kill-process"
SAFELIST="sshd wazuh-agentd wazuh-modulesd wazuh-execd wazuh-logcollector wazuh-syscheckd systemd init"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') kill-process: $1" >> "$LOG_FILE"
}

# Structured report, read by the Wazuh 100930 decoder and then by
# soc_agent.reconcile. status: applied | refused | noop | error.
ar_result() {   # $1 status  $2 target  $3 reason
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

# AR message on stdin
read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        # No possible "unkill": irreversible action, no rollback to handle.
        ar_result noop "" "delete command (timeout expiry), no rollback"
        exit 0
        ;;
    *)
        log "invalid command: '$COMMAND'"
        ar_result error "" "invalid command: $COMMAND"
        exit 1
        ;;
esac

# extra_args[0] = exact name of the target process (comm, e.g. "malware_bin"),
# or a numeric PID (the MCP server sends a PID). A PID is resolved to a name
# via /proc/<pid>/comm so the safelist applies in both cases.
PROC=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$PROC" ]; then
    log "ERROR: no process name provided (empty extra_args)"
    ar_result error "" "no process name provided (empty extra_args)"
    exit 1
fi

TARGET_PID=""
case "$PROC" in
    ''|*[!0-9]*) ;;
    *)
        if [ ! -r "/proc/$PROC/comm" ]; then
            log "pid $PROC not found, nothing to do"
            ar_result noop "$PROC" "pid not found"
            exit 0
        fi
        TARGET_PID="$PROC"
        PROC=$(cat "/proc/$PROC/comm")
        log "pid $TARGET_PID resolved to process '$PROC'"
        ;;
esac

for safe in $SAFELIST; do
    if [ "$PROC" = "$safe" ]; then
        log "REFUSED: '$PROC' is in the safelist (critical process), kill cancelled"
        ar_result refused "$PROC" "critical process in safelist"
        exit 1
    fi
done

# Target designated by PID: only that PID is killed, not every namesake.
if [ -n "$TARGET_PID" ]; then
    if kill -TERM "$TARGET_PID" 2>/dev/null; then
        log "process '$PROC' (pid $TARGET_PID) killed"
        ar_result applied "$PROC" "SIGTERM sent to pid $TARGET_PID"
        exit 0
    fi
    log "ERROR: failed to kill pid $TARGET_PID ('$PROC')"
    ar_result error "$PROC" "failed to kill pid $TARGET_PID"
    exit 1
fi

if ! pgrep -x "$PROC" >/dev/null 2>&1; then
    log "process '$PROC' not found, nothing to do"
    ar_result noop "$PROC" "no process with this name running"
    exit 0
fi

PIDS=$(pgrep -x "$PROC" | tr '\n' ' ')
pkill -x "$PROC"

if [ $? -eq 0 ]; then
    log "process '$PROC' killed (pid(s): $PIDS)"
    ar_result applied "$PROC" "pkill -x succeeded (pid(s): $PIDS)"
    exit 0
else
    log "ERROR: failed to kill '$PROC' (pid(s): $PIDS)"
    ar_result error "$PROC" "pkill -x failed (pid(s): $PIDS)"
    exit 1
fi
