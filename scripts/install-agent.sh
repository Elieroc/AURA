#!/usr/bin/env bash
#
# Installation d'un agent Wazuh + user d'administration distante.
#
# 1. Installe wazuh-agent (repo apt officiel, version épinglée) enrôlé sur le manager.
# 2. Installe et configure auditd (règle execve + localfile Wazuh) pour la détection
#    d'exécution de binaire depuis /tmp, /var/tmp, /dev/shm (règle locale 100625).
# 3. Crée un user "wazuh-admin" avec sudo NOPASSWD, accessible uniquement en SSH
#    par clé depuis le serveur Wazuh (mot de passe verrouillé).
#
# NB : le user s'appelle "wazuh-admin" et non "wazuh" — le paquet wazuh-agent crée
# déjà un user système "wazuh" (nologin) utilisé par les daemons de l'agent ;
# lui donner sudo/SSH reviendrait à élever les privilèges des daemons.
#
# Usage (en root sur la machine cible) :
#   ./install-agent.sh -m <MANAGER_IP> -k "<CLE_PUBLIQUE_SSH>" [-n <AGENT_NAME>] [-v <VERSION>]
#
# Exemple :
#   ./install-agent.sh -m 192.168.60.1 -k "ssh-ed25519 AAAA... soc" -n debian-vm

set -euo pipefail

WAZUH_VERSION="4.9.2"
AGENT_NAME="$(hostname)"
MANAGER_IP=""
SSH_PUBKEY=""
ADMIN_USER="wazuh-admin"

usage() { grep '^#' "$0" | sed 's/^# \?//'; exit 1; }

while getopts "m:k:n:v:h" opt; do
  case "$opt" in
    m) MANAGER_IP="$OPTARG" ;;
    k) SSH_PUBKEY="$OPTARG" ;;
    n) AGENT_NAME="$OPTARG" ;;
    v) WAZUH_VERSION="$OPTARG" ;;
    *) usage ;;
  esac
done

[ -z "$MANAGER_IP" ] && { echo "ERREUR: -m MANAGER_IP requis"; usage; }
[ -z "$SSH_PUBKEY" ] && { echo "ERREUR: -k CLE_PUBLIQUE_SSH requise"; usage; }
[ "$(id -u)" -ne 0 ] && { echo "ERREUR: à lancer en root"; exit 1; }
command -v apt-get >/dev/null || { echo "ERREUR: apt requis (Debian/Ubuntu uniquement)"; exit 1; }

echo "[1/5] Dépôt Wazuh"
apt-get update -qq
apt-get install -y -qq gnupg curl sudo openssh-server >/dev/null
if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
fi

echo "[2/5] Agent Wazuh ${WAZUH_VERSION} -> manager ${MANAGER_IP}"
if dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "  déjà installé ($(dpkg -s wazuh-agent | awk '/^Version/{print $2}')), skip"
else
  WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y -qq "wazuh-agent=${WAZUH_VERSION}-1" >/dev/null
  apt-mark hold wazuh-agent >/dev/null   # bloque l'upgrade auto (doit suivre le manager)
fi
systemctl daemon-reload
systemctl enable --now wazuh-agent >/dev/null 2>&1

echo "[3/5] auditd (détection exec depuis /tmp,/var/tmp,/dev/shm — règle Wazuh 100625)"
apt-get install -y -qq auditd audispd-plugins >/dev/null
echo "-a always,exit -F arch=b64 -S execve -k audit-wazuh-c" > /etc/audit/rules.d/audit-wazuh.rules
augenrules --load >/dev/null 2>&1
systemctl enable --now auditd >/dev/null 2>&1

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

echo "[4/5] User ${ADMIN_USER} (sudo, SSH par clé uniquement)"
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$ADMIN_USER"
fi
passwd -l "$ADMIN_USER" >/dev/null            # pas d'auth par mot de passe
install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/${ADMIN_USER}/.ssh"
AUTH_KEYS="/home/${ADMIN_USER}/.ssh/authorized_keys"
touch "$AUTH_KEYS"
grep -qF "$SSH_PUBKEY" "$AUTH_KEYS" || echo "$SSH_PUBKEY" >> "$AUTH_KEYS"
chown "$ADMIN_USER:$ADMIN_USER" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

# sudo sans mot de passe : requis pour les actions de mitigation automatisées
echo "${ADMIN_USER} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${ADMIN_USER}"
chmod 440 "/etc/sudoers.d/${ADMIN_USER}"
visudo -cf "/etc/sudoers.d/${ADMIN_USER}" >/dev/null || { echo "ERREUR sudoers"; rm -f "/etc/sudoers.d/${ADMIN_USER}"; exit 1; }

echo "[5/5] Vérifications"
systemctl is-active wazuh-agent >/dev/null && echo "  agent: actif" || echo "  agent: INACTIF"
systemctl is-active auditd >/dev/null && echo "  auditd: actif" || echo "  auditd: INACTIF"
auditctl -l 2>/dev/null | grep -q "execve" && echo "  règle audit execve: chargée" || echo "  règle audit execve: ABSENTE"
sudo -u "$ADMIN_USER" sudo -n true 2>/dev/null && echo "  sudo ${ADMIN_USER}: OK" || echo "  sudo ${ADMIN_USER}: ECHEC"
echo
echo "Terminé. Test depuis le serveur Wazuh :"
echo "  ssh -i <clé_privée> ${ADMIN_USER}@$(hostname -I | awk '{print $1}') 'sudo -n whoami'"
