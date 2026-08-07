#!/usr/bin/env bash
# ACL minimale pour que l'agent Wazuh (user "wazuh") lise les logs de
# Nginx Proxy Manager sans ouvrir /root en large (drwx------ root root par
# défaut sur Debian). setfacl -x traverse seulement le chemin exact ; pas de
# lecture/liste du reste de /root.
#
# Usage, EN ROOT sur l'hôte NPM (docker-compose install standard, données
# dans ~root/nginx-proxy-manager) :
#   scp setup-acl.sh root@<npm>:/tmp/
#   ssh root@<npm> 'bash /tmp/setup-acl.sh [/root/nginx-proxy-manager]'
set -euo pipefail

NPM_DIR="${1:-/root/nginx-proxy-manager}"
LOGS_DIR="$NPM_DIR/data/logs"

command -v setfacl >/dev/null || { apt-get update -qq && apt-get install -y -qq acl; }

setfacl -m u:wazuh:x /root
setfacl -m u:wazuh:rx "$NPM_DIR"
setfacl -m u:wazuh:rx "$NPM_DIR/data"
setfacl -m u:wazuh:rx "$LOGS_DIR"
setfacl -m u:wazuh:r "$LOGS_DIR"/*.log 2>/dev/null || true
# ACL par défaut : couvre les logs des futurs proxy hosts (NPM nomme ses
# fichiers proxy-host-<id>_*.log, la liste change à chaque host ajouté).
setfacl -d -m u:wazuh:r "$LOGS_DIR"
setfacl -d -m u:wazuh:rx "$LOGS_DIR"

echo "OK — test :"
sudo -u wazuh head -c1 "$LOGS_DIR"/*_access.log 2>&1 | head -1 >/dev/null \
    && echo "  lecture confirmée pour l'utilisateur wazuh" \
    || echo "  ECHEC — vérifier qu'au moins un fichier *_access.log existe déjà"
