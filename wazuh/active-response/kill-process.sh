#!/bin/sh
# Active response Wazuh : kill d'un process par nom exact (pkill -x) sur l'hôte.
#
# Reçoit le message AR v1/v2 (JSON) sur stdin ; n'agit que sur "command": "add".
# Le nom exact du process (comm, pas une ligne de commande) est passé dans
# parameters.extra_args[0]. Déployé dans /var/ossec/active-response/bin/ sur
# les agents Linux.
#
# pkill -x (match exact du nom) plutôt que -f (substring sur toute la ligne
# de commande) : évite de tuer un process dont la commande contient le nom
# cible en sous-chaîne (ex: cibler "app" ne doit pas tuer "backup-app-monitor").
#
# Garde-fou : refuse de killer les process critiques (safelist) pour éviter
# de couper l'agent Wazuh lui-même, sshd, ou le système (cf. CLAUDE.md —
# décision humaine, jamais d'action automatique non validée).

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SAFELIST="sshd wazuh-agentd wazuh-modulesd wazuh-execd wazuh-logcollector wazuh-syscheckd systemd init"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') kill-process: $1" >> "$LOG_FILE"
}

# Message AR sur stdin
read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        # Pas de "unkill" possible : action irréversible, pas de rollback à gérer.
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        exit 1
        ;;
esac

# extra_args[0] = nom exact du process cible (comm, ex: "malware_bin")
PROC=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$PROC" ]; then
    log "ERREUR: aucun nom de process fourni (extra_args vide)"
    exit 1
fi

for safe in $SAFELIST; do
    if [ "$PROC" = "$safe" ]; then
        log "REFUS: '$PROC' est dans la safelist (process critique), kill annulé"
        exit 1
    fi
done

if ! pgrep -x "$PROC" >/dev/null 2>&1; then
    log "process '$PROC' introuvable, rien à faire"
    exit 0
fi

PIDS=$(pgrep -x "$PROC" | tr '\n' ' ')
pkill -x "$PROC"

if [ $? -eq 0 ]; then
    log "process '$PROC' tué (pid(s): $PIDS)"
    exit 0
else
    log "ERREUR: échec kill de '$PROC' (pid(s): $PIDS)"
    exit 1
fi
