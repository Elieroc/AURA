#!/usr/bin/env bash
# ACL minimale pour que l'agent Wazuh (user "wazuh") lise les logs de
# Jellyfin (image linuxserver.io) sans ouvrir /root en large.
#
# Usage, EN ROOT sur l'hôte Jellyfin :
#   scp setup-acl.sh root@<jellyfin>:/tmp/
#   ssh root@<jellyfin> 'bash /tmp/setup-acl.sh [/root/jellyfin]'
set -euo pipefail

JF_DIR="${1:-/root/jellyfin}"
LOG_DIR="$JF_DIR/config/log"

command -v setfacl >/dev/null || { apt-get update -qq && apt-get install -y -qq acl; }

setfacl -m u:wazuh:x /root
setfacl -m u:wazuh:rx "$JF_DIR"
setfacl -m u:wazuh:rx "$JF_DIR/config"
setfacl -m u:wazuh:rx "$LOG_DIR"
setfacl -m u:wazuh:r "$LOG_DIR"/*.log 2>/dev/null || true
setfacl -d -m u:wazuh:r "$LOG_DIR"
setfacl -d -m u:wazuh:rx "$LOG_DIR"

echo "OK — test :"
LATEST=$(ls -t "$LOG_DIR"/log_*.log 2>/dev/null | head -1)
sudo -u wazuh head -c1 "$LATEST" 2>&1 | head -1 >/dev/null \
    && echo "  lecture confirmée pour l'utilisateur wazuh" \
    || echo "  ECHEC — vérifier qu'un log_*.log existe déjà"
