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

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-allow: $1" >> "$LOG_FILE"
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

IP=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
IP=$(echo "$IP" | sed 's/^-srcip[[:space:]]*//')

if [ -z "$IP" ]; then
    log "ERREUR: aucune IP fournie (extra_args vide)"
    exit 1
fi

case "$IP" in
    *[!0-9.:a-fA-F]*)
        log "ERREUR: IP invalide '$IP'"
        exit 1
        ;;
esac

if [ ! -f "$HOSTS_DENY" ]; then
    log "$HOSTS_DENY absent, rien à faire"
    exit 0
fi

if ! grep -q "^ALL:$IP\$" "$HOSTS_DENY"; then
    log "aucune entrée pour '$IP', rien à faire"
    exit 0
fi

TMP=$(mktemp) || {
    log "ERREUR: mktemp a échoué"
    exit 1
}
grep -v "^ALL:$IP\$" "$HOSTS_DENY" > "$TMP" || true
cat "$TMP" > "$HOSTS_DENY"
rm -f "$TMP"

log "entrée 'ALL:$IP' retirée de $HOSTS_DENY"
exit 0
