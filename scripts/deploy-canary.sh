#!/usr/bin/env bash
#
# Deploys (or removes) ransomware-detection canary files on an agent.
#
# Principle: a ransomware that encrypts a directory tree touches the
# canaries like any other document. No legitimate process, on the other
# hand, writes into them - reads (antivirus, updatedb, backup) do not
# trigger the Wazuh FIM, only writes / renames / deletions do. Hence a
# signal with near-zero false positives, with no threshold or time window
# to tune.
#
# Detail that matters:
#   - name prefixed with "000_": encryptors walk directories in the order
#     returned by readdir/scandir, often sorted - the canary gets hit early,
#     which leaves time to react;
#   - .xlsx / .docx / .pdf extensions: common families encrypt against a
#     whitelist of office-document extensions, a .txt or hidden file is
#     often ignored. The canary is therefore neither hidden nor exotic;
#   - nonzero size and compressible content: some families skip empty files
#     or files already at high entropy;
#   - owner = directory owner, mode 0644: the canary must be WRITABLE by
#     the account a ransomware would compromise, otherwise it is simply
#     skipped and detects nothing.
#
# The canaries are monitored in real time via the `restrict` attribute of
# the <syscheck> block in wazuh/config/wazuh_cluster/agent.conf (local rule
# 100670).
#
# Usage (as root on the target machine):
#   ./deploy-canary.sh                 # deploys to the default locations
#   ./deploy-canary.sh -d /data -d /mnt/share
#   ./deploy-canary.sh --remove        # removes all canaries
#   ./deploy-canary.sh --dry-run
#
set -euo pipefail

CANARY_TAG="CANARY_SOC_NE_PAS_TOUCHER"
EXTENSIONS=(xlsx docx pdf)

REMOVE=0
DRY_RUN=0
TARGETS=()

usage() {
    sed -n '2,30p' "$0" | sed 's/^#//; s/^ //'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir)   TARGETS+=("$2"); shift 2 ;;
        --remove)   REMOVE=1; shift ;;
        --dry-run)  DRY_RUN=1; shift ;;
        -h|--help)  usage 0 ;;
        *)          echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (it writes to /home, /srv, /root)." >&2
    exit 1
fi

# Default locations: the root of each data tree, plus the first level of
# subdirectories (a ransomware launched from a deep subfolder does not
# necessarily walk back up). Must stay consistent with the <directories>
# and their recursion_level in agent.conf.
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    for base in /home/* /srv /var/www /root; do
        [[ -d "$base" ]] || continue
        TARGETS+=("$base")
        while IFS= read -r sub; do
            TARGETS+=("$sub")
        done < <(find "$base" -mindepth 1 -maxdepth 1 -type d ! -name '.*' 2>/dev/null)
    done
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "No target directory found - nothing to do." >&2
    exit 0
fi

# Content: header consistent with the extension (some families check the
# magic bytes rather than the suffix) then repeated text, hence low entropy.
write_canary() {
    local path="$1" ext="$2"
    local magic
    case "$ext" in
        xlsx|docx) magic=$'PK\x03\x04' ;;   # OOXML container = ZIP archive
        pdf)       magic='%PDF-1.7' ;;
    esac
    {
        printf '%s' "$magic"
        printf '\n%s\n' "SOC canary file - do not modify, do not delete."
        printf '%s\n' "Any write to this file triggers a ransomware alert (100670)."
        # ~16 KB of padding: above the minimum size threshold of most
        # encryptors, and compressible (low entropy).
        for _ in $(seq 1 400); do
            printf '%s\n' "canary-soc-$CANARY_TAG-padding-0123456789abcdef"
        done
    } > "$path"
}

action=0
for dir in "${TARGETS[@]}"; do
    [[ -d "$dir" ]] || continue

    owner="$(stat -c '%u:%g' "$dir")"

    for ext in "${EXTENSIONS[@]}"; do
        file="${dir}/000_${CANARY_TAG}.${ext}"

        if [[ $REMOVE -eq 1 ]]; then
            [[ -e "$file" ]] || continue
            if [[ $DRY_RUN -eq 1 ]]; then
                echo "[dry-run] rm $file"
            else
                rm -f "$file"
                echo "removed: $file"
            fi
            action=$((action + 1))
            continue
        fi

        # Idempotent: do not rewrite an existing canary, otherwise every run
        # of the script would trigger the alert it is meant to detect.
        if [[ -e "$file" ]]; then
            continue
        fi

        if [[ $DRY_RUN -eq 1 ]]; then
            echo "[dry-run] create $file (owner $owner)"
        else
            write_canary "$file" "$ext"
            chown "$owner" "$file"
            chmod 0644 "$file"
            echo "deployed: $file"
        fi
        action=$((action + 1))
    done
done

if [[ $action -eq 0 ]]; then
    echo "Nothing to do (canaries already in place)."
else
    echo "---"
    echo "$action operation(s) on ${#TARGETS[@]} director(y/ies)."
fi

if [[ $REMOVE -eq 0 && $DRY_RUN -eq 0 ]]; then
    cat <<'EOF'

Next step: check that the agent is indeed watching the canaries.
  grep -c CANARY_SOC /var/ossec/etc/shared/agent.conf   # must be > 0
  systemctl restart wazuh-agent

Detection test (voluntarily triggers alert 100670):
  echo test >> /home/<user>/000_CANARY_SOC_NE_PAS_TOUCHER.xlsx
EOF
fi
