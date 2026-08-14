#!/bin/sh
# Forensic collection - runs ON THE MANAGER HOST (not on the suspect machine).
#
#   forensic-pull.sh <agent_host> [ram|disk|full]
#
# Pulls the evidence from the agent (SSH, forced command forensic-source.sh)
# and pushes it to the evidence server, in a single pipe. The bytes transit
# through the manager's memory, they NEVER land on its disk: the manager is a
# relay, not an evidence storage location.
#
# Called by Shuffle via `run_ssh_command`, itself restricted by a forced
# command on the manager side (see shuffle/README.md).
#
# ---------------------------------------------------------------------------
# DIRECTION OF THE FLOW: the manager pulls, the agent pushes nothing
#
# Previous version: the agent pushed to the repository, so a private key sat
# on the suspect machine. Root on the agent = read the key = write to the
# evidence repository (tampering with other incidents, pivoting).
#
# Here the three keys live off the suspect machine:
#   K1  Shuffle  -> manager   (forced command: this script)
#   K2  manager  -> agent     (forced command: forensic-source.sh)
#   K3  manager  -> repository (dedicated account, write-only)
# The agent only holds a public key and has no outbound access.
#
# Accepted trade-off: the manager holds a key TOWARD the agent. This is the
# usual administration direction, and the forced command bounds it to three
# keywords that only produce bytes. But reading a raw disk means reading the
# whole disk: this key remains a first-order secret.
#
# ---------------------------------------------------------------------------
# NETWORK ISOLATION: nothing to do
#
# host-isolate.sh already lets INBOUND SSH from the manager through (input:
# `ip saddr $MANAGER_IP tcp dport 22 accept`) and the outbound replies
# (output: `ct state established,related accept`). The evidence flow rides
# this established connection. The "push" version instead had to punch a
# hole in the isolation to get out - that workaround disappears.
#
# ORDER OF VOLATILITY (RFC 3227): RAM before disk. A disk image keeps the
# machine running long enough to overwrite part of the memory.
# ---------------------------------------------------------------------------

set -u

# --- Configuration ----------------------------------------------------------
# Defaults defined BEFORE the source, so that `set -u` holds if the conf is missing.
AGENT_SSH_USER="forensic"
AGENT_SSH_KEY="/etc/soc-ai/forensic_agent_ed25519"
AGENT_KNOWN_HOSTS="/etc/soc-ai/known_hosts_agents"

EVIDENCE_HOST=""
EVIDENCE_USER="forensics"
EVIDENCE_PATH="/var/lib/forensics"
EVIDENCE_SSH_KEY="/etc/soc-ai/forensic_evidence_ed25519"
EVIDENCE_KNOWN_HOSTS="/etc/soc-ai/known_hosts_evidence"

CONF_FILE="/etc/soc-ai/soc-ai.conf"
# shellcheck source=/dev/null
[ -r "$CONF_FILE" ] && . "$CONF_FILE"

LOG_FILE="/var/log/soc-ai-forensic.log"
LOCK_ROOT="/var/lock"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') forensic-pull: $1" >> "$LOG_FILE" 2>/dev/null
    echo "$(date '+%Y/%m/%d %H:%M:%S') forensic-pull: $1"
}

SSH_AGENT_OPTS="-i $AGENT_SSH_KEY -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$AGENT_KNOWN_HOSTS -o BatchMode=yes -o ConnectTimeout=15"
SSH_EVID_OPTS="-i $EVIDENCE_SSH_KEY -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$EVIDENCE_KNOWN_HOSTS -o BatchMode=yes -o ConnectTimeout=15"

# StrictHostKeyChecking=yes + pinned known_hosts on both sides: without this,
# a MITM on a compromised agent's network could impersonate the agent (and
# fabricate the evidence) or the repository (and collect it).

ssh_agent() {
    # shellcheck disable=SC2086
    ssh $SSH_AGENT_OPTS "${AGENT_SSH_USER}@${AGENT_HOST}" "$@"
}

ssh_evidence() {
    # shellcheck disable=SC2086
    ssh $SSH_EVID_OPTS "${EVIDENCE_USER}@${EVIDENCE_HOST}" "$@"
}

# ===========================================================================
# WORKER MODE: the actual collection
# ===========================================================================
if [ "${1:-}" = "--worker" ]; then
    AGENT_HOST="$2"
    SCOPE="$3"
    CASE_ID="$4"
    REMOTE_DIR="${EVIDENCE_PATH}/${CASE_ID}"
    LOCK_DIR="${LOCK_ROOT}/forensic-pull-${AGENT_HOST}.lock"

    trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT INT TERM

    if ! ssh_evidence "mkdir -p '$REMOTE_DIR'" 2>/dev/null; then
        log "ERROR: repository ${EVIDENCE_USER}@${EVIDENCE_HOST} unreachable, collection $CASE_ID aborted"
        exit 1
    fi
    log "collection $CASE_ID started (agent: $AGENT_HOST, scope: $SCOPE) -> ${EVIDENCE_USER}@${EVIDENCE_HOST}:$REMOTE_DIR"

    # --- Manifest (chain of custody) ----------------------------------------
    # Written first: if the rest fails, we keep the trace of what was
    # attempted, on which machine and in what state.
    META=$(ssh_agent meta 2>/dev/null)
    if [ -z "$META" ]; then
        log "ERROR: agent $AGENT_HOST unreachable or forced command missing, collection aborted"
        exit 1
    fi
    printf '%s\n' "$META" | ssh_evidence "cat > '$REMOTE_DIR/manifest.json'"

    # --- One stream = one file + its hash -----------------------------------
    # The sha256 is computed on the fly on the received stream, via FIFO: a
    # second read of the agent's disk would give a different hash (the
    # medium moves under the read) and would prove nothing. The hash thus
    # attests to the transfer, not a frozen state of the medium.
    pull_stream() {
        _kw="$1"          # keyword sent to the forced command (ram|disk)
        _name="$2"        # name of the file dropped (without .gz)
        _fifo="/tmp/.fpull-$$-$_kw"

        rm -f "$_fifo"
        mkfifo -m 600 "$_fifo" || return 1
        ( sha256sum < "$_fifo" | cut -d' ' -f1 > "${_fifo}.sha" ) &
        _hashpid=$!

        # gzip -1: the bottleneck is the network, not the CPU; -1 is enough
        # to crush the large runs of zeros in a disk image.
        ssh_agent "$_kw" | tee "$_fifo" | gzip -1 | ssh_evidence "cat > '$REMOTE_DIR/${_name}.gz'"
        _rc=$?

        wait "$_hashpid"
        _hash=$(cat "${_fifo}.sha" 2>/dev/null)
        rm -f "$_fifo" "${_fifo}.sha"

        if [ "$_rc" -ne 0 ] || [ -z "$_hash" ]; then
            return 1
        fi
        echo "$_hash  $_name" | ssh_evidence "cat > '$REMOTE_DIR/${_name}.sha256'"
        log "$_name deposited (stream sha256: $_hash)"
        return 0
    }

    # === 1. RAM (before disk: order of volatility) =========================
    if [ "$SCOPE" = "ram" ] || [ "$SCOPE" = "full" ]; then
        if pull_stream ram memory.lime; then
            log "RAM captured"
        else
            log "ERROR: RAM capture failed (see agent stderr)"
        fi
    fi

    # === 2. Disk image ======================================================
    if [ "$SCOPE" = "disk" ] || [ "$SCOPE" = "full" ]; then
        if pull_stream disk disk.raw; then
            log "disk image deposited"
        else
            log "ERROR: disk image failed"
        fi
    fi

    log "collection $CASE_ID finished"
    exit 0
fi

# ===========================================================================
# CALL MODE: validation, lock, detach
# ===========================================================================
# Called by Shuffle as a forced command: the arguments arrive in
# SSH_ORIGINAL_COMMAND. In direct (manual) invocation, they arrive in $@.
if [ $# -eq 0 ] && [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    # Split on spaces only, never a shell eval: the string comes from
    # Shuffle and must never be able to become a command.
    set -- $SSH_ORIGINAL_COMMAND
fi

AGENT_HOST="${1:-}"
SCOPE="${2:-full}"

# Closed character set: a hostname or an IP, nothing that could escape into
# the remote shell.
case "$AGENT_HOST" in
    '') log "ERROR: missing agent host (usage: forensic-pull.sh <agent_host> [ram|disk|full])"; exit 1 ;;
    *[!a-zA-Z0-9.:_-]*) log "ERROR: invalid host '$AGENT_HOST' (rejected characters)"; exit 1 ;;
esac

case "$SCOPE" in
    ram|disk|full) ;;
    *) log "ERROR: invalid scope '$SCOPE' (expected: ram, disk or full)"; exit 1 ;;
esac

# Per-agent lock: two simultaneous collections on the same machine would
# fight over bandwidth and corrupt both captures.
LOCK_DIR="${LOCK_ROOT}/forensic-pull-${AGENT_HOST}.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "REFUSED: a collection is already in progress on $AGENT_HOST (lock $LOCK_DIR)"
    exit 1
fi

CASE_ID="${AGENT_HOST}-$(date -u '+%Y%m%dT%H%M%SZ')"

# Detach: a disk image takes minutes to hours, while Shuffle's SSH call waits
# for the command to end. We return control right away with the collection
# ID; follow-up happens in $LOG_FILE.
setsid "$0" --worker "$AGENT_HOST" "$SCOPE" "$CASE_ID" </dev/null >/dev/null 2>&1 &

log "collection $CASE_ID launched in the background (agent: $AGENT_HOST, scope: $SCOPE)"
echo "case_id=$CASE_ID"
exit 0
