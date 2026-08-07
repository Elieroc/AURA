#!/bin/sh
# Active response Wazuh : réactivation d'un compte désactivé par disable-account.
#
# Le serveur MCP appelle la commande AR "enable-account" avec
# extra_args = ["<user>"]. Wazuh natif ne fournit que disable-account (qui
# réactive sur "command": "delete") ; ce script fait le rollback explicite.
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="enable-account"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') enable-account: $1" >> "$LOG_FILE"
}

# Compte rendu structuré, lu par le decodeur Wazuh 100930 puis par
# soc_agent.reconcile. statut : applied | refused | noop | error.
ar_result() {   # $1 statut  $2 cible  $3 motif
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        ar_result noop "" "commande delete (expiration timeout), aucune action"
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        ar_result error "" "commande invalide: $COMMAND"
        exit 1
        ;;
esac

USER=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$USER" ]; then
    log "ERREUR: aucun utilisateur fourni (extra_args vide)"
    ar_result error "" "aucun utilisateur fourni (extra_args vide)"
    exit 1
fi

case "$USER" in
    root)
        log "REFUS: réactivation de root refusée"
        ar_result refused "$USER" "compte protege (root)"
        exit 1
        ;;
esac

if ! id "$USER" >/dev/null 2>&1; then
    log "ERREUR: utilisateur '$USER' inexistant"
    ar_result noop "$USER" "compte inexistant sur cet hote"
    exit 1
fi

# usermod -U lève le lock du mot de passe ; chage -E -1 annule l'expiration
# posée par disable-account.
if command -v usermod >/dev/null 2>&1; then
    usermod -U "$USER" >/dev/null 2>&1
fi
if command -v chage >/dev/null 2>&1; then
    chage -E -1 "$USER" >/dev/null 2>&1
fi

log "compte '$USER' réactivé"
ar_result applied "$USER" "compte reactive (usermod -U, chage -E -1)"
exit 0
