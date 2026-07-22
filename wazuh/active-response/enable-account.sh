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

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') enable-account: $1" >> "$LOG_FILE"
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

USER=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$USER" ]; then
    log "ERREUR: aucun utilisateur fourni (extra_args vide)"
    exit 1
fi

case "$USER" in
    root)
        log "REFUS: réactivation de root refusée"
        exit 1
        ;;
esac

if ! id "$USER" >/dev/null 2>&1; then
    log "ERREUR: utilisateur '$USER' inexistant"
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
exit 0
