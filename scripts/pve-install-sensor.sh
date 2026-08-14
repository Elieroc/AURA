#!/bin/sh
# Wazuh + auditd sensor on the Proxmox HOST (bare-metal). DETECTION ONLY.
#
# Why on the host and not in the containers: the whole fleet is LXC, where
# auditd is impossible (CAP_AUDIT_CONTROL refused - see
# src/wazuh/AUDITD-ROLLOUT.md). Since the kernel is shared, the host's
# auditd captures the execve of ALL containers: a single agent covers the
# fleet for the 1006xx/1007xx rules.
#
# NO wazuh-admin/sudo user and no active-response scripts: never autonomous
# remediation on the hypervisor (isolating the host would cut off the whole
# fleet).
#
# MANUAL enrollment via key (authd/1515 closed on the manager): pre-register
# the agent on the manager then extract the key:
#   docker exec <manager> /var/ossec/bin/manage_agents   # (A)dd -> name pve
#   docker exec <manager> /var/ossec/bin/manage_agents -e <id>   # extracts the key
#
# Usage (root on the host, with zz-audit-wazuh.rules in /tmp or nearby):
#   MGR=<MANAGER_IP> ./pve-install-sensor.sh '<AGENT_KEY_BASE64>'
set -e
KEY="$1"
MGR="${MGR:?MGR required (manager IP)}"
VER="${WAZUH_VERSION:-4.9.2-1}"
export DEBIAN_FRONTEND=noninteractive
[ -n "$KEY" ] || { echo "ERROR: missing agent key (arg 1)" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
for c in "/tmp/zz-audit-wazuh.rules" "$HERE/zz-audit-wazuh.rules" \
         "$HERE/../src/wazuh/config/agent/zz-audit-wazuh.rules"; do
  [ -f "$c" ] && { RULES="$c"; break; }
done
[ -n "${RULES:-}" ] || { echo "ERROR: zz-audit-wazuh.rules not found" >&2; exit 1; }

fetch() { if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"; else wget -qO- "$1"; fi; }

echo "[1/6] Repository + wazuh-agent package $VER"
if [ ! -x /var/ossec/bin/wazuh-control ]; then
  install -d -m 0755 /usr/share/keyrings
  fetch https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="$MGR" apt-get install -y -qq "wazuh-agent=$VER"
  apt-mark hold wazuh-agent >/dev/null
fi

echo "[2/6] Importing the key (manual enrollment)"
printf 'y\n' | /var/ossec/bin/manage_agents -i "$KEY" >/dev/null 2>&1 || true
sed -i "s#<address>[^<]*</address>#<address>$MGR</address>#" /var/ossec/etc/ossec.conf 2>/dev/null || true
systemctl daemon-reload

echo "[3/6] auditd + zz-audit rules"
apt-get install -y -qq auditd audispd-plugins >/dev/null
install -m 640 -o root -g root "$RULES" /etc/audit/rules.d/zz-audit-wazuh.rules
[ -e /etc/ld.so.preload ] || { : > /etc/ld.so.preload; chmod 644 /etc/ld.so.preload; }

echo "[4/6] remote_commands + localfile audit"
LIO=/var/ossec/etc/local_internal_options.conf
grep -q "^logcollector.remote_commands=1" "$LIO" 2>/dev/null || \
  printf 'logcollector.remote_commands=1\n' >> "$LIO"
OC=/var/ossec/etc/ossec.conf
if ! grep -q "log_format>audit<" "$OC" 2>/dev/null; then
  python3 - "$OC" <<'PY'
import sys
p=sys.argv[1]; c=open(p).read()
i="  <localfile>\n    <log_format>audit</log_format>\n    <location>/var/log/audit/audit.log</location>\n  </localfile>\n\n"
m="</ossec_config>"; x=c.rfind(m); open(p,"w").write(c[:x]+i+c[x:])
PY
fi

echo "[5/6] Activation (bare-metal: augenrules --load succeeds)"
systemctl enable --now auditd >/dev/null 2>&1 || true
augenrules --load 2>&1 | head -2 || true
systemctl enable --now wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent >/dev/null 2>&1 || true
sleep 3

echo "[6/6] Verification"
echo "  auditd        : $(systemctl is-active auditd 2>/dev/null)"
echo "  audit enabled : $(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')"
echo "  execve rules  : $(auditctl -l 2>/dev/null | grep -c execveat)"
echo "  agent         : $(systemctl is-active wazuh-agent 2>/dev/null)"
