#!/bin/sh
# Active response Wazuh : retrait d'un blocage posé par firewall-drop.
#
# Le rollback upstream du serveur MCP appelle firewall-drop avec un argument
# "delete", mais le binaire Wazuh attend la commande "delete" dans le message AR
# et lit l'IP dans alert.data.srcip — inutilisable via l'API. Ce script fait le
# retrait explicitement, l'IP étant passée dans extra_args[0].
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
IPT="/usr/sbin/iptables"
IPT6="/usr/sbin/ip6tables"
NFT="/usr/sbin/nft"
NFT_TABLE="soc_ai_block"   # cf. firewall-drop.sh

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') firewall-allow: $1" >> "$LOG_FILE"
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
# Tolère la forme "-srcip <ip>" utilisée par firewall-drop.
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

case "$IP" in
    *:*) BIN="$IPT6"; FAM="ip6" ;;
    *)   BIN="$IPT";  FAM="ip"  ;;
esac

# Repli nftables, symétrique de firewall-drop.sh (hôtes sans shim iptables).
if [ ! -x "$BIN" ]; then
    if [ ! -x "$NFT" ]; then
        log "ERREUR: ni $BIN ni $NFT trouvés"
        exit 1
    fi
    REMOVED=0
    # Les handles se décalent après chaque suppression : on relit la chaîne à
    # chaque tour plutôt que de collecter la liste une fois pour toutes.
    i=0
    while [ $i -lt 20 ]; do
        H=$("$NFT" -a list chain inet "$NFT_TABLE" input 2>/dev/null \
            | sed -n "s/.*$FAM saddr $IP drop # handle \([0-9]*\).*/\1/p" | head -1)
        [ -z "$H" ] && break
        "$NFT" delete rule inet "$NFT_TABLE" input handle "$H" 2>/dev/null || break
        REMOVED=$((REMOVED + 1))
        i=$((i + 1))
    done
    if [ "$REMOVED" -eq 0 ]; then
        log "aucune règle nft drop pour '$IP', rien à faire"
        exit 0
    fi
    log "IP '$IP' débloquée (nft, $REMOVED règle(s) supprimée(s))"
    exit 0
fi

REMOVED=0
# Une même IP peut avoir été bloquée plusieurs fois : on boucle jusqu'à ce que
# la règle n'existe plus, avec une borne pour ne pas tourner indéfiniment.
i=0
while [ $i -lt 20 ] && "$BIN" -C INPUT -s "$IP" -j DROP >/dev/null 2>&1; do
    "$BIN" -D INPUT -s "$IP" -j DROP >/dev/null 2>&1 || break
    REMOVED=$((REMOVED + 1))
    i=$((i + 1))
done

if [ "$REMOVED" -eq 0 ]; then
    log "aucune règle DROP pour '$IP', rien à faire"
    exit 0
fi

log "IP '$IP' débloquée ($REMOVED règle(s) supprimée(s))"
exit 0
