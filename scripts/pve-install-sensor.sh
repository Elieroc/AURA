#!/bin/sh
# Capteur Wazuh + auditd sur l'HÔTE Proxmox (bare-metal). DÉTECTION SEULE.
#
# Pourquoi sur l'hôte et pas dans les conteneurs : toute la flotte est en LXC, où
# auditd est impossible (CAP_AUDIT_CONTROL refusé — cf. wazuh/AUDITD-ROLLOUT.md).
# Le noyau étant partagé, l'auditd de l'hôte capture l'execve de TOUS les
# conteneurs : un seul agent couvre la flotte pour les règles 1006xx/1007xx.
#
# PAS de user wazuh-admin/sudo ni de scripts active-response : jamais de
# remédiation autonome sur l'hyperviseur (isoler pve couperait tout le lab).
#
# Enrôlement MANUEL par clé (authd/1515 fermé sur le manager) : pré-enregistrer
# l'agent sur le manager puis extraire la clé :
#   docker exec <manager> /var/ossec/bin/manage_agents   # (A)dd -> nom pve
#   docker exec <manager> /var/ossec/bin/manage_agents -e <id>   # extrait la clé
#
# Usage (root sur l'hôte, avec zz-audit-wazuh.rules dans /tmp ou à côté) :
#   MGR=192.168.10.5 ./pve-install-sensor.sh '<CLE_AGENT_BASE64>'
set -e
KEY="$1"
MGR="${MGR:-192.168.10.5}"
VER="${WAZUH_VERSION:-4.9.2-1}"
export DEBIAN_FRONTEND=noninteractive
[ -n "$KEY" ] || { echo "ERREUR: clé d'agent manquante (arg 1)" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
for c in "/tmp/zz-audit-wazuh.rules" "$HERE/zz-audit-wazuh.rules" \
         "$HERE/../wazuh/config/agent/zz-audit-wazuh.rules"; do
  [ -f "$c" ] && { RULES="$c"; break; }
done
[ -n "${RULES:-}" ] || { echo "ERREUR: zz-audit-wazuh.rules introuvable" >&2; exit 1; }

fetch() { if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"; else wget -qO- "$1"; fi; }

echo "[1/6] Dépôt + paquet wazuh-agent $VER"
if [ ! -x /var/ossec/bin/wazuh-control ]; then
  install -d -m 0755 /usr/share/keyrings
  fetch https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="$MGR" apt-get install -y -qq "wazuh-agent=$VER"
  apt-mark hold wazuh-agent >/dev/null
fi

echo "[2/6] Import de la clé (enrôlement manuel)"
printf 'y\n' | /var/ossec/bin/manage_agents -i "$KEY" >/dev/null 2>&1 || true
sed -i "s#<address>[^<]*</address>#<address>$MGR</address>#" /var/ossec/etc/ossec.conf 2>/dev/null || true
systemctl daemon-reload

echo "[3/6] auditd + règles zz-audit"
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

echo "[5/6] Activation (bare-metal : augenrules --load réussit)"
systemctl enable --now auditd >/dev/null 2>&1 || true
augenrules --load 2>&1 | head -2 || true
systemctl enable --now wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent >/dev/null 2>&1 || true
sleep 3

echo "[6/6] Vérification"
echo "  auditd        : $(systemctl is-active auditd 2>/dev/null)"
echo "  audit enabled : $(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')"
echo "  règles execve : $(auditctl -l 2>/dev/null | grep -c execveat)"
echo "  agent         : $(systemctl is-active wazuh-agent 2>/dev/null)"
