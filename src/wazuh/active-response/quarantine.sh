#!/bin/sh
# Wazuh active response: quarantine / restore of a file.
#
# Called by the MCP server via the "quarantine" AR command:
#   extra_args = ["/file/path"]            -> quarantine
#   extra_args = ["restore", "/file/path"] -> restore
#
# The file is moved (not copied) into QUARANTINE_DIR, mode 000, with a
# .path sidecar file that remembers the original path for restoration.
# Deployed in /var/ossec/active-response/bin/ on Linux agents.

set -u

QUARANTINE_DIR="/var/ossec/quarantine"
LOG_FILE="/var/ossec/logs/active-responses.log"
# Paths never quarantined: breaking these renders the host or the agent unusable.
PROTECTED="/bin /sbin /lib /lib64 /usr/bin /usr/sbin /usr/lib /etc /boot /var/ossec/bin"
SCRIPT_NAME="quarantine"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine: $1" >> "$LOG_FILE"
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
        ar_result noop "" "delete command (timeout expiry), only restore takes a file out of quarantine"
        exit 0
        ;;
    *)
        log "invalid command: '$COMMAND'"
        ar_result error "" "invalid command: $COMMAND"
        exit 1
        ;;
esac

# extra_args: extract the full list, then its first two elements.
ARGS=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')
ARG1=$(echo "$ARGS" | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p')
ARG2=$(echo "$ARGS" | sed -n 's/^[[:space:]]*"[^"]*"[[:space:]]*,[[:space:]]*"\([^"]*\)".*/\1/p')

if [ "$ARG1" = "restore" ]; then
    ACTION="restore"
    TARGET="$ARG2"
else
    ACTION="quarantine"
    TARGET="$ARG1"
fi

if [ -z "$TARGET" ]; then
    log "ERROR: no file path provided"
    ar_result error "" "no file path provided ($ACTION)"
    exit 1
fi

case "$TARGET" in
    /*) ;;
    *)
        log "ERROR: non-absolute path refused: '$TARGET'"
        ar_result error "$TARGET" "non-absolute path ($ACTION)"
        exit 1
        ;;
esac

# The PROTECTED list below is a PREFIX test: a single ".." segment is enough
# to bypass it (/var/tmp/../../etc/shadow doesn't start with any protected
# directory, and `mv` resolves it anyway). We therefore refuse any
# non-canonical path rather than trying to resolve it — this AR runs as
# root, and a path we can't name exactly isn't a path we act on.
case "$TARGET" in
    */../*|*/..|../*|..)
        log "REFUSED: non-canonical path (.. segment): '$TARGET'"
        ar_result refused "$TARGET" "non-canonical path (.. segment)"
        exit 1
        ;;
esac

# Storage name: absolute path with '/' replaced by '_'.
STORED="$QUARANTINE_DIR/$(echo "$TARGET" | sed 's|^/||; s|/|_|g')"

if [ "$ACTION" = "quarantine" ]; then
    for dir in $PROTECTED; do
        case "$TARGET" in
            "$dir"/*)
                log "REFUSED: '$TARGET' is under a protected system directory ($dir)"
                ar_result refused "$TARGET" "protected system directory ($dir)"
                exit 1
                ;;
        esac
    done

    if [ ! -f "$TARGET" ]; then
        log "file '$TARGET' not found, nothing to do"
        ar_result noop "$TARGET" "file not found on this host"
        exit 0
    fi

    mkdir -p "$QUARANTINE_DIR" && chmod 700 "$QUARANTINE_DIR"

    if ! mv "$TARGET" "$STORED"; then
        log "ERROR: failed to move '$TARGET'"
        ar_result error "$TARGET" "failed to move to $STORED"
        exit 1
    fi
    chmod 000 "$STORED"
    echo "$TARGET" > "$STORED.path"
    log "file '$TARGET' quarantined ($STORED)"
    ar_result applied "$TARGET" "quarantined ($STORED)"
    exit 0
fi

# restore
if [ ! -f "$STORED" ]; then
    log "ERROR: '$TARGET' not in quarantine"
    ar_result noop "$TARGET" "not in quarantine, nothing to restore"
    exit 1
fi

ORIG=$(cat "$STORED.path" 2>/dev/null || echo "$TARGET")
if [ -e "$ORIG" ]; then
    log "ERROR: '$ORIG' already exists, restore cancelled"
    ar_result error "$ORIG" "original path already exists, restore cancelled"
    exit 1
fi

if ! mv "$STORED" "$ORIG"; then
    log "ERROR: failed to restore to '$ORIG'"
    ar_result error "$ORIG" "failed to move out of quarantine"
    exit 1
fi
chmod 600 "$ORIG"
rm -f "$STORED.path"
log "file '$ORIG' restored from quarantine"
ar_result applied "$ORIG" "restored from quarantine"
exit 0
