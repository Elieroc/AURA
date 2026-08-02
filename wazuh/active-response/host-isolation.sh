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
SCRIPT_NAME="host-isolation"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-isolation: $1" >> "$LOG_FILE"
}

# Compte rendu structuré, lu par le decodeur Wazuh 100930 puis par
# soc_agent.reconcile. statut : applied | refused | noop | error.
#
# Ce script n'est qu'un routeur : sur les deux chemins qui délèguent, c'est le
# script appelé (host-isolate / host-unisolate) qui écrit SA ligne ar-result.
# On n'en écrit pas une seconde ici, sinon reconcile verrait deux comptes rendus
# pour une seule action. Seul le chemin d'argument invalide, qui ne délègue à
# personne, produit sa propre ligne.
ar_result() {   # $1 statut  $2 cible  $3 motif
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
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
        ar_result error "$ARG" "argument inattendu (attendu: vide ou undo)"
        exit 1
        ;;
esac
