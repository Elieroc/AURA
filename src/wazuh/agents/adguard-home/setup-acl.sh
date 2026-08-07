#!/usr/bin/env bash
# ACL minimale pour que l'agent Wazuh (user "wazuh") lise le query log
# AdGuard Home (0600 root:root par défaut) sans ouvrir /opt/AdGuardHome en large.
#
# Usage, EN ROOT sur l'hôte AdGuard Home :
#   scp setup-acl.sh root@<adguard>:/tmp/
#   ssh root@<adguard> 'bash /tmp/setup-acl.sh [/opt/AdGuardHome/data]'
set -euo pipefail

DATA_DIR="${1:-/opt/AdGuardHome/data}"

command -v setfacl >/dev/null || { apt-get update -qq && apt-get install -y -qq acl; }

setfacl -m u:wazuh:rx "$DATA_DIR"
setfacl -m u:wazuh:r "$DATA_DIR"/querylog.json* 2>/dev/null || true
# ACL par défaut : couvre la rotation (querylog.json.1 à la prochaine rotation).
setfacl -d -m u:wazuh:r "$DATA_DIR"
setfacl -d -m u:wazuh:rx "$DATA_DIR"

echo "OK — test :"
sudo -u wazuh head -c1 "$DATA_DIR/querylog.json" 2>&1 | head -1 >/dev/null \
    && echo "  lecture confirmée pour l'utilisateur wazuh" \
    || echo "  ECHEC — vérifier que querylog.json existe déjà"
