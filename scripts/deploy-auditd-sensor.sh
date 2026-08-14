#!/usr/bin/env bash
#
# Deploys the auditd SENSOR to an ALREADY ENROLLED Wazuh agent.
#
# Why this script exists separately from install-agent.sh: agents may have
# been enrolled WITHOUT auditd. One deployment lived through it: auditd
# absent across the whole fleet (0 execve/auditd events, see `alerts`), so
# the ~15 behavioral 1006xx/1007xx rules (reverse shell, fileless, privesc
# enumeration, credential access, suid, cve, exploit) NEVER had any
# telemetry - they were validated at logtest but dead in production.
#
# This script is the auditd excerpt from install-agent.sh, made idempotent
# and without the enrollment / admin user / AR scripts (already in place on
# a live agent).
#
# Usage (as root on the target machine, with zz-audit-wazuh.rules in the same
# folder OR in ../src/wazuh/config/agent/):
#   ./deploy-auditd-sensor.sh
#
# REBOOT: `-e 2` (last line of the rules) makes the audit config immutable.
# On the FIRST load, `augenrules --load` succeeds live. If it fails (audit
# already locked) OR if systemd-journald holds the audit netlink socket, the
# script flags it and a REBOOT is required to activate the sensor. Nothing
# else breaks.
set -euo pipefail

log() { printf '%s\n' "$*"; }

[ "$(id -u)" = "0" ] || { echo "ERROR: must run as root" >&2; exit 1; }

# Locates the rule set (next to the script, or in the repo tree)
HERE="$(cd "$(dirname "$0")" && pwd)"
for c in "$HERE/zz-audit-wazuh.rules" "$HERE/../src/wazuh/config/agent/zz-audit-wazuh.rules"; do
  [ -f "$c" ] && { RULES_SRC="$c"; break; }
done
[ -n "${RULES_SRC:-}" ] || { echo "ERROR: zz-audit-wazuh.rules not found" >&2; exit 1; }

log "[1/5] auditd package"
if ! command -v auditctl >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq auditd audispd-plugins >/dev/null
fi

log "[2/5] auditd rules -> /etc/audit/rules.d/zz-audit-wazuh.rules"
# zz- prefix MANDATORY: augenrules concatenates in C collation and Debian's
# audit.rules starts with -D (purge). A name < zz- would get wiped out on
# the next load.
install -m 640 -o root -g root "$RULES_SRC" /etc/audit/rules.d/zz-audit-wazuh.rules
rm -f /etc/audit/rules.d/audit-wazuh.rules   # old name loaded too early, if present

# /etc/ld.so.preload must EXIST to be watchable (a watch on an absent inode
# arms nothing; creation by a userland rootkit would go unnoticed).
[ -e /etc/ld.so.preload ] || { : > /etc/ld.so.preload; chmod 644 /etc/ld.so.preload; }

log "[3/5] local_internal_options: allows the <localfile><command> from agent.conf"
LIO="/var/ossec/etc/local_internal_options.conf"
grep -q "^logcollector.remote_commands=1" "$LIO" 2>/dev/null || \
  printf '# Aura-SOC: allows the <localfile><command> pushed by agent.conf\nlogcollector.remote_commands=1\n' >> "$LIO"

log "[4/5] ossec.conf: audit.log localfile"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
NEED_RESTART=0
if ! grep -q "log_format>audit<" "$OSSEC_CONF" 2>/dev/null; then
  python3 - "$OSSEC_CONF" <<'PYEOF'
import sys
path = sys.argv[1]
content = open(path).read()
insert = "  <localfile>\n    <log_format>audit</log_format>\n    <location>/var/log/audit/audit.log</location>\n  </localfile>\n\n"
marker = "</ossec_config>"
idx = content.rfind(marker)
open(path, "w").write(content[:idx] + insert + content[idx:])
PYEOF
  NEED_RESTART=1
fi

log "[5/5] auditd activation + rule loading"
systemctl enable --now auditd >/dev/null 2>&1 || true
REBOOT_REQUIRED=0
if ! augenrules --load >/dev/null 2>&1; then
  REBOOT_REQUIRED=1
fi
# Checks the real kernel state (the true judge, not the service)
ENABLED="$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')"
HAVE_EXECVE="$(auditctl -l 2>/dev/null | grep -c execveat || true)"
[ "$NEED_RESTART" = "1" ] && systemctl restart wazuh-agent >/dev/null 2>&1 || true

echo "---------------------------------------------"
echo "auditd service : $(systemctl is-active auditd 2>/dev/null || echo unknown)"
echo "kernel audit   : enabled=${ENABLED:-?}"
echo "execve rules   : ${HAVE_EXECVE} loaded"
if [ "$ENABLED" = "1" ] && [ "${HAVE_EXECVE:-0}" -ge 1 ]; then
  echo "RESULT         : sensor ACTIVE - the 1006xx/1007xx rules finally see the execve."
else
  echo "RESULT         : sensor NOT YET ACTIVE."
  echo "                 Likely cause: immutable audit (-e 2) or journald holds the netlink socket."
  echo "                 >>> REBOOT REQUIRED to activate the sensor. After reboot, re-check:"
  echo "                     auditctl -s | grep enabled ; auditctl -l | grep -c execveat"
fi
