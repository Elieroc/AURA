#!/usr/bin/env bash
#
# Installs a Wazuh agent + remote administration user.
#
# 1. Installs wazuh-agent (official apt repo, pinned version) enrolled on the manager.
# 2. Installs and configures auditd (execve rule + Wazuh localfile) for
#    detecting binary execution from /tmp, /var/tmp, /dev/shm (local rule 100625).
# 3. Creates a "wazuh-admin" user with sudo NOPASSWD, reachable only via SSH
#    key from the Wazuh server (password locked).
#
# NB: the user is named "wazuh-admin", not "wazuh" - the wazuh-agent package
# already creates a system user "wazuh" (nologin) used by the agent's
# daemons; giving it sudo/SSH would amount to elevating the daemons'
# privileges.
#
# Usage (as root on the target machine):
#   ./install-agent.sh -m <MANAGER_IP> -k "<SSH_PUBLIC_KEY>" [-n <AGENT_NAME>] \
#                      [-g <GROUP>] [-v <VERSION>]
#
# -g declares the machine's ROLE as a Wazuh group (role-dc, role-web,
# role-firewall...). This is what gives the asset its P1-P4 priority, hence
# the order in which its incidents get analyzed. Without -g, the machine is
# treated as P4, i.e. at the back of the queue.
#
# Example:
#   ./install-agent.sh -m 10.0.1.5 -k "ssh-ed25519 AAAA... soc" -n endpoint-01 -g role-endpoint

set -euo pipefail

WAZUH_VERSION="4.9.2"
AGENT_NAME="$(hostname)"
MANAGER_IP=""
SSH_PUBKEY=""
AGENT_GROUP=""
ADMIN_USER="wazuh-admin"

usage() { grep '^#' "$0" | sed 's/^# \?//'; exit 1; }

while getopts "m:k:n:g:v:h" opt; do
  case "$opt" in
    m) MANAGER_IP="$OPTARG" ;;
    k) SSH_PUBKEY="$OPTARG" ;;
    n) AGENT_NAME="$OPTARG" ;;
    g) AGENT_GROUP="$OPTARG" ;;
    v) WAZUH_VERSION="$OPTARG" ;;
    *) usage ;;
  esac
done

[ -z "$MANAGER_IP" ] && { echo "ERROR: -m MANAGER_IP required"; usage; }
[ -z "$SSH_PUBKEY" ] && { echo "ERROR: -k SSH_PUBLIC_KEY required"; usage; }
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must be run as root"; exit 1; }
command -v apt-get >/dev/null || { echo "ERROR: apt required (Debian/Ubuntu only)"; exit 1; }

echo "[1/6] Wazuh repository"
apt-get update -qq
apt-get install -y -qq gnupg curl sudo openssh-server >/dev/null
if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
fi

echo "[2/6] Wazuh agent ${WAZUH_VERSION} -> manager ${MANAGER_IP}"
if dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "  already installed ($(dpkg -s wazuh-agent | awk '/^Version/{print $2}')), skip"
else
  # WAZUH_AGENT_GROUP carries the machine's role (role-dc, role-web...): the
  # group is requested AT ENROLLMENT, so the manager classifies it from its
  # first connection. Declaring it afterward also works (API /agents/
  # {id}/group/{g}), but any incident occurring in the meantime is born P4.
  # if/fi and not `[ ... ] && ...`: under `set -e`, a false test at the end
  # of a line would exit the script with code 1.
  if [ -n "$AGENT_GROUP" ]; then export WAZUH_AGENT_GROUP="$AGENT_GROUP"; fi
  WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y -qq "wazuh-agent=${WAZUH_VERSION}-1" >/dev/null
  apt-mark hold wazuh-agent >/dev/null   # blocks auto-upgrade (must follow the manager)
fi
systemctl daemon-reload
systemctl enable --now wazuh-agent >/dev/null 2>&1

echo "[3/6] auditd (detection base for Wazuh rules 1006xx/1007xx)"
apt-get install -y -qq auditd audispd-plugins >/dev/null
# The rule set is versioned in src/wazuh/config/agent/zz-audit-wazuh.rules.
# The `zz-` prefix is MANDATORY: augenrules concatenates rules.d/*.rules in
# C collation, and Debian's audit.rules starts with `-D` (purge). A file
# named `audit-wazuh.rules` is loaded BEFORE this `-D` and gets silently
# wiped out - this is what left the agent without execve auditing.
AUDIT_RULES_SRC="$(dirname "$0")/../src/wazuh/config/agent/zz-audit-wazuh.rules"
if [ -f "$AUDIT_RULES_SRC" ]; then
  install -m 640 -o root -g root "$AUDIT_RULES_SRC" /etc/audit/rules.d/zz-audit-wazuh.rules
else
  echo "  ERROR: $AUDIT_RULES_SRC not found" >&2; exit 1
fi
rm -f /etc/audit/rules.d/audit-wazuh.rules   # old name, loaded too early

# /etc/ld.so.preload must EXIST to be watchable. inotify (FIM) as well as
# auditd watches target an inode: on an absent path, nothing is armed and
# the CREATION of the file - precisely the userland rootkit's action - goes
# unnoticed. An empty file has no effect on glibc.
[ -e /etc/ld.so.preload ] || { : > /etc/ld.so.preload; chmod 644 /etc/ld.so.preload; }

# The rule set ends with `-e 2` (immutable configuration). If audit is
# already locked by a previous load, `augenrules --load` fails and a
# restart is needed - we flag it instead of failing silently.
if ! augenrules --load >/dev/null 2>&1; then
  echo "  WARNING: audit rules not reloaded (audit is probably at -e 2)."
  echo "           Reboot the machine to apply the new version."
fi
systemctl enable --now auditd >/dev/null 2>&1

# Allows the <localfile><command> pushed by the manager's shared agent.conf.
# Without this setting (default 0), Wazuh SILENTLY IGNORES any command
# coming from a remote configuration - this is what carries the kernel
# audit heartbeat (rules 100801/100802). No widening of the trust surface:
# the active-response channel already gives the manager root execution on
# the agent.
LIO="/var/ossec/etc/local_internal_options.conf"
grep -q "^logcollector.remote_commands=1" "$LIO" 2>/dev/null || \
  printf '# Aura-SOC: allows the <localfile><command> pushed by agent.conf\nlogcollector.remote_commands=1\n' >> "$LIO"

OSSEC_CONF="/var/ossec/etc/ossec.conf"
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
  systemctl restart wazuh-agent >/dev/null 2>&1
fi

echo "[4/6] Active-response scripts (remediation)"
# Without these scripts on the agent, EVERY remediation fails SILENTLY: the
# ar.conf pushed by the manager does declare firewall-drop.sh and friends,
# the Wazuh API replies 200 (it only forwards), and nothing happens on the
# agent side - the only clue is the absence of a line in its
# active-responses.log. The native binaries shipped with the package do not
# replace these scripts: they read the target from the alert
# (alert.data.srcip / dstuser) and fail on any call driven by extra_args
# (see src/wazuh/active-response/README).
AR_SRC="$(dirname "$0")/../src/wazuh/active-response"
if [ -d "$AR_SRC" ]; then
  for f in "$AR_SRC"/*.sh; do
    install -m 750 -o root -g wazuh "$f" "/var/ossec/active-response/bin/$(basename "$f")"
  done
  echo "  $(ls -1 "$AR_SRC"/*.sh | wc -l) script(s) deployed"
else
  echo "  ERROR: $AR_SRC not found" >&2; exit 1
fi

echo "[5/6] User ${ADMIN_USER} (sudo, SSH key only)"
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$ADMIN_USER"
fi
passwd -l "$ADMIN_USER" >/dev/null            # no password auth
install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/${ADMIN_USER}/.ssh"
AUTH_KEYS="/home/${ADMIN_USER}/.ssh/authorized_keys"
touch "$AUTH_KEYS"
grep -qF "$SSH_PUBKEY" "$AUTH_KEYS" || echo "$SSH_PUBKEY" >> "$AUTH_KEYS"
chown "$ADMIN_USER:$ADMIN_USER" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

# passwordless sudo: required for automated mitigation actions
echo "${ADMIN_USER} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${ADMIN_USER}"
chmod 440 "/etc/sudoers.d/${ADMIN_USER}"
visudo -cf "/etc/sudoers.d/${ADMIN_USER}" >/dev/null || { echo "sudoers ERROR"; rm -f "/etc/sudoers.d/${ADMIN_USER}"; exit 1; }

echo "[6/6] Checks"
systemctl is-active wazuh-agent >/dev/null && echo "  agent: active" || echo "  agent: INACTIVE"
systemctl is-active auditd >/dev/null && echo "  auditd: active" || echo "  auditd: INACTIVE"
auditctl -l 2>/dev/null | grep -q "execveat" && echo "  audit rules: loaded ($(auditctl -l | wc -l))" || echo "  audit rules: MISSING"
[ "$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')" = "1" ] \
  && echo "  kernel audit: enabled" \
  || echo "  kernel audit: DISABLED (enabled != 1) - no 1006xx rule can trigger"
sudo -u "$ADMIN_USER" sudo -n true 2>/dev/null && echo "  sudo ${ADMIN_USER}: OK" || echo "  sudo ${ADMIN_USER}: FAILED"
[ -x /var/ossec/active-response/bin/firewall-drop.sh ] \
  && echo "  active-response: Aura-SOC scripts present" \
  || echo "  active-response: SCRIPTS MISSING - every remediation will fail silently"
echo
echo "Done. Test from the Wazuh server:"
echo "  ssh -i <private_key> ${ADMIN_USER}@$(hostname -I | awk '{print $1}') 'sudo -n whoami'"
