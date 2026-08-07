#!/usr/bin/env bash
# ACL minimale pour que l'agent Wazuh (user "wazuh") lise les logs nginx de
# Nextcloud (image linuxserver.io) sans ouvrir /root en large.
#
# Usage, EN ROOT sur l'hôte Nextcloud :
#   scp setup-acl.sh root@<nextcloud>:/tmp/
#   ssh root@<nextcloud> 'bash /tmp/setup-acl.sh [/root/nextcloud]'
set -euo pipefail

NC_DIR="${1:-/root/nextcloud}"
LOG_DIR="$NC_DIR/config/log/nginx"

command -v setfacl >/dev/null || { apt-get update -qq && apt-get install -y -qq acl; }

setfacl -m u:wazuh:x /root
setfacl -m u:wazuh:rx "$NC_DIR"
setfacl -m u:wazuh:rx "$NC_DIR/config"
setfacl -m u:wazuh:rx "$NC_DIR/config/log"
setfacl -m u:wazuh:rx "$LOG_DIR"
setfacl -m u:wazuh:r "$LOG_DIR"/*.log 2>/dev/null || true
setfacl -d -m u:wazuh:r "$LOG_DIR"
setfacl -d -m u:wazuh:rx "$LOG_DIR"

echo "OK — test :"
sudo -u wazuh head -c1 "$LOG_DIR/access.log" 2>&1 | head -1 >/dev/null \
    && echo "  lecture confirmée pour l'utilisateur wazuh" \
    || echo "  ECHEC — vérifier que access.log existe déjà"
