#!/bin/sh
# Active response Wazuh : retrait d'une entrée posée par host-deny.
#
# Même problème que firewall-allow.sh : le rollback upstream passe "delete" en
# argument, ce que le binaire host-deny n'interprète pas. L'IP est lue dans
# extra_args[0] et la ligne "ALL:<ip>" est retirée de /etc/hosts.deny.
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
HOSTS_DENY="/etc/hosts.deny"
SCRIPT_NAME="host-allow"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-allow: $1" >> "$LOG_FILE"
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

IP=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
IP=$(echo "$IP" | sed 's/^-srcip[[:space:]]*//')

if [ -z "$IP" ]; then
    log "ERREUR: aucune IP fournie (extra_args vide)"
    ar_result error "" "aucune IP fournie (extra_args vide)"
    exit 1
fi

case "$IP" in
    *[!0-9.:a-fA-F]*)
        log "ERREUR: IP invalide '$IP'"
        ar_result error "$IP" "IP invalide"
        exit 1
        ;;
esac

if [ ! -f "$HOSTS_DENY" ]; then
    log "$HOSTS_DENY absent, rien à faire"
    ar_result noop "$IP" "$HOSTS_DENY absent"
    exit 0
fi

if ! grep -q "^ALL:$IP\$" "$HOSTS_DENY"; then
    log "aucune entrée pour '$IP', rien à faire"
    ar_result noop "$IP" "aucune entree ALL:$IP dans $HOSTS_DENY"
    exit 0
fi

TMP=$(mktemp) || {
    log "ERREUR: mktemp a échoué"
    ar_result error "$IP" "mktemp a echoue"
    exit 1
}
grep -v "^ALL:$IP\$" "$HOSTS_DENY" > "$TMP" || true
cat "$TMP" > "$HOSTS_DENY"
rm -f "$TMP"

log "entrée 'ALL:$IP' retirée de $HOSTS_DENY"
ar_result applied "$IP" "entree ALL:$IP retiree de $HOSTS_DENY"
exit 0
