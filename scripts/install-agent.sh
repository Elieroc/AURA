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

echo "[1/6] Dépôt Wazuh"
apt-get update -qq
apt-get install -y -qq gnupg curl sudo openssh-server >/dev/null
if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
fi

echo "[2/6] Agent Wazuh ${WAZUH_VERSION} -> manager ${MANAGER_IP}"
if dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "  déjà installé ($(dpkg -s wazuh-agent | awk '/^Version/{print $2}')), skip"
else
  WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y -qq "wazuh-agent=${WAZUH_VERSION}-1" >/dev/null
  apt-mark hold wazuh-agent >/dev/null   # bloque l'upgrade auto (doit suivre le manager)
fi
systemctl daemon-reload
systemctl enable --now wazuh-agent >/dev/null 2>&1

echo "[3/6] auditd (socle de détection des règles Wazuh 1006xx/1007xx)"
apt-get install -y -qq auditd audispd-plugins >/dev/null
# Le jeu de règles est versionné dans src/wazuh/config/agent/zz-audit-wazuh.rules.
# Le préfixe `zz-` est OBLIGATOIRE : augenrules concatène rules.d/*.rules en
# collation C, et le audit.rules de Debian commence par `-D` (purge). Un fichier
# nommé `audit-wazuh.rules` est chargé AVANT ce `-D` et se fait effacer
# silencieusement — c'est ce qui a laissé l'agent sans audit execve.
AUDIT_RULES_SRC="$(dirname "$0")/../src/wazuh/config/agent/zz-audit-wazuh.rules"
if [ -f "$AUDIT_RULES_SRC" ]; then
  install -m 640 -o root -g root "$AUDIT_RULES_SRC" /etc/audit/rules.d/zz-audit-wazuh.rules
else
  echo "  ERREUR: $AUDIT_RULES_SRC introuvable" >&2; exit 1
fi
rm -f /etc/audit/rules.d/audit-wazuh.rules   # ancien nom, chargé trop tôt

# /etc/ld.so.preload doit EXISTER pour être surveillable. inotify (FIM) comme les
# watches auditd ciblent un inode : sur un chemin absent, rien n'est armé et la
# CRÉATION du fichier — c'est-à-dire précisément l'action du rootkit userland —
# passe inaperçue. Un fichier vide est sans effet pour glibc.
[ -e /etc/ld.so.preload ] || { : > /etc/ld.so.preload; chmod 644 /etc/ld.so.preload; }

# Le jeu de règles se termine par `-e 2` (configuration immuable). Si l'audit est
# déjà verrouillé par un chargement précédent, `augenrules --load` échoue et il
# faut redémarrer — on le signale au lieu d'échouer en silence.
if ! augenrules --load >/dev/null 2>&1; then
  echo "  AVERTISSEMENT: règles audit non rechargées (audit probablement en -e 2)."
  echo "                 Redémarrer la machine pour appliquer la nouvelle version."
fi
systemctl enable --now auditd >/dev/null 2>&1

# Autorise les <localfile><command> poussés par l'agent.conf partagé du manager.
# Sans ce réglage (défaut 0), Wazuh IGNORE silencieusement toute commande venant
# d'une configuration distante — c'est ce qui porte le heartbeat de l'audit noyau
# (règles 100801/100802). Pas d'élargissement de la surface de confiance : le
# canal active-response donne déjà au manager l'exécution root sur l'agent.
LIO="/var/ossec/etc/local_internal_options.conf"
grep -q "^logcollector.remote_commands=1" "$LIO" 2>/dev/null || \
  printf '# Aura-SOC : autorise les <localfile><command> poussés par agent.conf\nlogcollector.remote_commands=1\n' >> "$LIO"

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

echo "[4/6] Scripts active-response (remédiation)"
# Sans ces scripts sur l'agent, TOUTE remédiation échoue en SILENCE : l'ar.conf
# poussé par le manager déclare bien firewall-drop.sh & consorts, l'API Wazuh
# répond 200 (elle ne fait que transmettre), et rien ne se passe côté agent —
# le seul indice est l'absence de ligne dans son active-responses.log.
# Les binaires natifs livrés par le paquet ne remplacent pas ces scripts : ils
# lisent la cible dans l'alerte (alert.data.srcip / dstuser) et échouent sur
# tout appel piloté par extra_args (cf. src/wazuh/active-response/README).
AR_SRC="$(dirname "$0")/../src/wazuh/active-response"
if [ -d "$AR_SRC" ]; then
  for f in "$AR_SRC"/*.sh; do
    install -m 750 -o root -g wazuh "$f" "/var/ossec/active-response/bin/$(basename "$f")"
  done
  echo "  $(ls -1 "$AR_SRC"/*.sh | wc -l) script(s) déployé(s)"
else
  echo "  ERREUR: $AR_SRC introuvable" >&2; exit 1
fi

echo "[5/6] User ${ADMIN_USER} (sudo, SSH par clé uniquement)"
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

echo "[6/6] Vérifications"
systemctl is-active wazuh-agent >/dev/null && echo "  agent: actif" || echo "  agent: INACTIF"
systemctl is-active auditd >/dev/null && echo "  auditd: actif" || echo "  auditd: INACTIF"
auditctl -l 2>/dev/null | grep -q "execveat" && echo "  règles audit: chargées ($(auditctl -l | wc -l))" || echo "  règles audit: ABSENTES"
[ "$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')" = "1" ] \
  && echo "  audit noyau: activé" \
  || echo "  audit noyau: DÉSACTIVÉ (enabled != 1) — aucune règle 1006xx ne peut se déclencher"
sudo -u "$ADMIN_USER" sudo -n true 2>/dev/null && echo "  sudo ${ADMIN_USER}: OK" || echo "  sudo ${ADMIN_USER}: ECHEC"
[ -x /var/ossec/active-response/bin/firewall-drop.sh ] \
  && echo "  active-response: scripts Aura-SOC présents" \
  || echo "  active-response: SCRIPTS ABSENTS — toute remédiation échouera en silence"
echo
echo "Terminé. Test depuis le serveur Wazuh :"
echo "  ssh -i <clé_privée> ${ADMIN_USER}@$(hostname -I | awk '{print $1}') 'sudo -n whoami'"
