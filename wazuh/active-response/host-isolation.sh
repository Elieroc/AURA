#!/bin/sh
# Active response Wazuh : wrapper "host-isolation" pour le serveur MCP.
#
# Le serveur MCP (Wazuh-MCP-Server) appelle une seule commande AR nommée
# "host-isolation" : isolation quand extra_args est vide, dé-isolation quand
# extra_args[0] == "undo". Nos scripts natifs sont séparés (host-isolate.sh /
# host-unisolate.sh) ; ce wrapper route vers le bon en lui repassant le message
# AR original sur stdin.
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.

set -u

BIN_DIR="$(dirname "$0")"
LOG_FILE="/var/ossec/logs/active-responses.log"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-isolation: $1" >> "$LOG_FILE"
}

read -r INPUT_JSON

ARG=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

case "$ARG" in
    undo|UNDO)
        log "route -> host-unisolate.sh"
        echo "$INPUT_JSON" | "$BIN_DIR/host-unisolate.sh"
        ;;
    "")
        log "route -> host-isolate.sh"
        echo "$INPUT_JSON" | "$BIN_DIR/host-isolate.sh"
        ;;
    *)
        log "ERREUR: argument inattendu '$ARG' (attendu: vide ou 'undo')"
        exit 1
        ;;
esac
