#!/bin/sh
# Active response Wazuh : dé-isolation réseau de l'hôte.
# Supprime la table nftables posée par host-isolate.sh.

set -u

NFT="/usr/sbin/nft"
TABLE="wazuh_isolation"
LOG_FILE="/var/ossec/logs/active-responses.log"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-unisolate: $1" >> "$LOG_FILE"
}

read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete) exit 0 ;;
    *)
        log "commande invalide: '$COMMAND'"
        exit 1
        ;;
esac

if ! "$NFT" list table inet "$TABLE" >/dev/null 2>&1; then
    log "rien à faire (table $TABLE absente)"
    exit 0
fi

if "$NFT" delete table inet "$TABLE"; then
    log "hôte dé-isolé (table $TABLE supprimée)"
    exit 0
else
    log "ERREUR: échec suppression table $TABLE"
    exit 1
fi
