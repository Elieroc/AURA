#!/bin/sh
# Active response Wazuh : dé-isolation réseau de l'hôte.
# Supprime la table nftables posée par host-isolate.sh.

set -u

NFT="/usr/sbin/nft"
TABLE="wazuh_isolation"
LOG_FILE="/var/ossec/logs/active-responses.log"
# Miroir du marqueur posé par host-isolate.sh. On le retire à la dé-isolation
# pour que fichier local et table nftables restent cohérents.
MARKER="/var/ossec/isolated"
SCRIPT_NAME="host-unisolate"
# Cible du compte rendu : l'hôte lui-même (miroir de win-host-unisolate.ps1).
HOST_NAME=$(hostname 2>/dev/null || echo "unknown")

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-unisolate: $1" >> "$LOG_FILE"
}

# Compte rendu structuré, lu par le decodeur Wazuh 100930 puis par
# soc_agent.reconcile. statut : applied | refused | noop | error.
ar_result() {   # $1 statut  $2 cible  $3 motif
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

lever_marqueur() {
    rm -f "$MARKER"
    log "SOC-AI-ISOLATION-STATE=cleared (marqueur $MARKER retiré)"
}

read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        ar_result noop "$HOST_NAME" "commande delete (expiration timeout), aucune action"
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        ar_result error "$HOST_NAME" "commande invalide: $COMMAND"
        exit 1
        ;;
esac

if ! "$NFT" list table inet "$TABLE" >/dev/null 2>&1; then
    lever_marqueur
    log "rien à faire (table $TABLE absente)"
    ar_result noop "$HOST_NAME" "hote non isole (table $TABLE absente)"
    exit 0
fi

if "$NFT" delete table inet "$TABLE"; then
    lever_marqueur
    log "hôte dé-isolé (table $TABLE supprimée)"
    ar_result applied "$HOST_NAME" "de-isole (table $TABLE supprimee)"
    exit 0
else
    log "ERREUR: échec suppression table $TABLE"
    ar_result error "$HOST_NAME" "echec suppression de la table $TABLE"
    exit 1
fi
