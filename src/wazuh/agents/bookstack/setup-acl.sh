#!/usr/bin/env bash
# ACL minimale pour que l'agent Wazuh (user "wazuh") lise les logs nginx de
# BookStack (image linuxserver.io) sans ouvrir /root en large.
#
# Usage, EN ROOT sur l'hôte BookStack :
#   scp setup-acl.sh root@<bookstack>:/tmp/
#   ssh root@<bookstack> 'bash /tmp/setup-acl.sh [/root/bookstack]'
set -euo pipefail

BS_DIR="${1:-/root/bookstack}"
LOG_DIR="$BS_DIR/config/log/nginx"

command -v setfacl >/dev/null || { apt-get update -qq && apt-get install -y -qq acl; }

setfacl -m u:wazuh:x /root
setfacl -m u:wazuh:rx "$BS_DIR"
setfacl -m u:wazuh:rx "$BS_DIR/config"
setfacl -m u:wazuh:rx "$BS_DIR/config/log"
setfacl -m u:wazuh:rx "$LOG_DIR"
setfacl -m u:wazuh:r "$LOG_DIR"/*.log 2>/dev/null || true
setfacl -d -m u:wazuh:r "$LOG_DIR"
setfacl -d -m u:wazuh:rx "$LOG_DIR"

echo "OK — test :"
sudo -u wazuh head -c1 "$LOG_DIR/access.log" 2>&1 | head -1 >/dev/null \
    && echo "  lecture confirmée pour l'utilisateur wazuh" \
    || echo "  ECHEC — vérifier que access.log existe déjà"
