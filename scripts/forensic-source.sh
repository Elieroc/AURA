#!/bin/sh
# Forensic collection source - runs ON THE AGENT (suspect machine).
#
# Deployed at /usr/local/sbin/forensic-source.sh and called ONLY as an SSH
# forced command from the manager host:
#
#   agent's authorized_keys:
#     command="sudo /usr/local/sbin/forensic-source.sh",no-port-forwarding,\
#     no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... manager-forensic
#
# ---------------------------------------------------------------------------
# WHY THIS DIRECTION (agent -> manager, never the reverse)
#
# The first version pushed evidence from the agent to the repository server,
# which required storing a PRIVATE KEY on the suspect machine. A root
# attacker there could read the key and gain write access to the evidence
# repository: enough to tamper with other incidents' evidence, or use it as
# a pivot. The direction is therefore reversed - here the agent only holds a
# PUBLIC key in authorized_keys, and has no outbound access to anything.
#
# This script is the remaining attack surface on the agent side: it takes NO
# argument from the caller besides the three keywords below, never
# interprets SSH_ORIGINAL_COMMAND as a command, and writes nothing anywhere.
# It only produces bytes on stdout.
#
# It runs as root (reading /dev/mem and the raw disk): any change must keep
# this property - no path, no file name, no option comes from the outside.
# ---------------------------------------------------------------------------

set -u

AVML="/usr/local/sbin/avml"

# The keyword arrives in SSH_ORIGINAL_COMMAND because the forced command
# overrides the requested command. We do not execute it: we compare it to a
# closed list. Any other value is rejected.
REQUEST="${SSH_ORIGINAL_COMMAND:-}"

# stderr goes out through the SSH channel and reaches the manager: it is the
# only usable error return, since stdout is reserved for evidence bytes.
fail() {
    echo "forensic-source: $1" >&2
    exit 1
}

resolve_disk() {
    # WHOLE disk, not the root partition: the partition table, the boot
    # sector and the inter-partition space are classic hiding spots.
    _src=$(findmnt -no SOURCE / 2>/dev/null)
    [ -n "$_src" ] || return 1
    _parent=$(lsblk -no PKNAME "$_src" 2>/dev/null | head -1 | tr -d ' ')
    if [ -n "$_parent" ]; then
        echo "/dev/$_parent"
    else
        echo "$_src"
    fi
}

case "$REQUEST" in
    ram)
        [ -x "$AVML" ] || fail "AVML missing ($AVML), RAM capture impossible"
        # AVML writes to a file, not to stdout: we go through a FIFO to stay
        # in a stream. Writing RAM to a local file is out of the question -
        # on disk it overwrites unallocated space (i.e. recoverable deleted
        # files), on tmpfs it consumes the very RAM we are trying to capture.
        FIFO="/tmp/.fsrc-ram-$$"
        rm -f "$FIFO"
        mkfifo -m 600 "$FIFO" || fail "could not create FIFO"
        "$AVML" --compress false "$FIFO" >&2 2>/dev/null &
        AVML_PID=$!
        cat "$FIFO"
        wait "$AVML_PID" 2>/dev/null
        AVML_RC=$?
        rm -f "$FIFO"
        [ "$AVML_RC" -eq 0 ] || fail "AVML failed (code $AVML_RC)"
        ;;
    disk)
        DISK=$(resolve_disk) || fail "disk device not found"
        [ -b "$DISK" ] || fail "$DISK is not a block device"
        # conv=noerror,sync: an unreadable sector must not interrupt the
        # copy; it is replaced with zeros and the offsets stay correct.
        dd if="$DISK" bs=4M conv=noerror,sync 2>/dev/null
        ;;
    meta)
        # State of the machine at collection time (chain of custody).
        # Reads only, no external parameter.
        printf '{\n'
        printf '  "hostname": "%s",\n' "$(hostname)"
        printf '  "collected_at_utc": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '  "kernel": "%s",\n' "$(uname -a | tr '"' "'")"
        printf '  "uptime_seconds": %s,\n' "$(cut -d. -f1 /proc/uptime)"
        printf '  "boot_id": "%s",\n' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
        printf '  "memory_total_kb": %s,\n' "$(awk '/MemTotal/{print $2}' /proc/meminfo)"
        printf '  "disk_device": "%s",\n' "$(resolve_disk 2>/dev/null)"
        printf '  "disk_bytes": %s\n' "$(blockdev --getsize64 "$(resolve_disk 2>/dev/null)" 2>/dev/null || echo 0)"
        printf '}\n'
        ;;
    *)
        fail "request refused: '$REQUEST' (expected: ram, disk or meta)"
        ;;
esac
