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
# Garde-fou déterministe : refuse de killer les process critiques (safelist)
# pour éviter de couper l'agent Wazuh lui-même, sshd, ou le système. C'est ce
# garde-fou EN CODE qui borne l'action autonome (cf. CLAUDE.md — XDR autonome),
# pas une validation humaine.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="kill-process"
SAFELIST="sshd wazuh-agentd wazuh-modulesd wazuh-execd wazuh-logcollector wazuh-syscheckd systemd init"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') kill-process: $1" >> "$LOG_FILE"
}

# Compte rendu structuré, lu par le decodeur Wazuh 100930 puis par
# soc_agent.reconcile. statut : applied | refused | noop | error.
ar_result() {   # $1 statut  $2 cible  $3 motif
    printf '%s ar-result: script=%s status=%s target="%s" reason="%s"\n' \
        "$(date '+%Y/%m/%d %H:%M:%S')" "$SCRIPT_NAME" "$1" \
        "$(printf '%s' "$2" | tr -d '\r\n"')" \
        "$(printf '%s' "$3" | tr -d '\r\n"')" >> "$LOG_FILE"
}

# Message AR sur stdin
read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        # Pas de "unkill" possible : action irréversible, pas de rollback à gérer.
        ar_result noop "" "commande delete (expiration timeout), aucun rollback"
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        ar_result error "" "commande invalide: $COMMAND"
        exit 1
        ;;
esac

# extra_args[0] = nom exact du process cible (comm, ex: "malware_bin"), ou un
# PID numérique (le serveur MCP envoie un PID). Un PID est résolu en nom via
# /proc/<pid>/comm pour que la safelist s'applique dans les deux cas.
PROC=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$PROC" ]; then
    log "ERREUR: aucun nom de process fourni (extra_args vide)"
    ar_result error "" "aucun nom de process fourni (extra_args vide)"
    exit 1
fi

TARGET_PID=""
case "$PROC" in
    ''|*[!0-9]*) ;;
    *)
        if [ ! -r "/proc/$PROC/comm" ]; then
            log "pid $PROC introuvable, rien à faire"
            ar_result noop "$PROC" "pid introuvable"
            exit 0
        fi
        TARGET_PID="$PROC"
        PROC=$(cat "/proc/$PROC/comm")
        log "pid $TARGET_PID résolu en process '$PROC'"
        ;;
esac

for safe in $SAFELIST; do
    if [ "$PROC" = "$safe" ]; then
        log "REFUS: '$PROC' est dans la safelist (process critique), kill annulé"
        ar_result refused "$PROC" "process critique en safelist"
        exit 1
    fi
done

# Cible désignée par PID : on ne tue que ce PID, pas tous les homonymes.
if [ -n "$TARGET_PID" ]; then
    if kill -TERM "$TARGET_PID" 2>/dev/null; then
        log "process '$PROC' (pid $TARGET_PID) tué"
        ar_result applied "$PROC" "SIGTERM envoye au pid $TARGET_PID"
        exit 0
    fi
    log "ERREUR: échec kill du pid $TARGET_PID ('$PROC')"
    ar_result error "$PROC" "echec kill du pid $TARGET_PID"
    exit 1
fi

if ! pgrep -x "$PROC" >/dev/null 2>&1; then
    log "process '$PROC' introuvable, rien à faire"
    ar_result noop "$PROC" "aucun process de ce nom en cours"
    exit 0
fi

PIDS=$(pgrep -x "$PROC" | tr '\n' ' ')
pkill -x "$PROC"

if [ $? -eq 0 ]; then
    log "process '$PROC' tué (pid(s): $PIDS)"
    ar_result applied "$PROC" "pkill -x reussi (pid(s): $PIDS)"
    exit 0
else
    log "ERREUR: échec kill de '$PROC' (pid(s): $PIDS)"
    ar_result error "$PROC" "echec pkill -x (pid(s): $PIDS)"
    exit 1
fi
