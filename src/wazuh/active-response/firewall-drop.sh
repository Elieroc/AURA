#!/bin/sh
# Active response Wazuh : blocage d'une IP hostile.
#
# Remplace le binaire natif `firewall-drop`, qui lit l'IP dans alert.data.srcip
# et échoue donc sur tout appel piloté (« Cannot read 'srcip' from data ») : le
# soc-agent et le serveur MCP passent l'IP en extra_args, pas via une alerte.
# Même défaut, même correctif que disable-account.sh.
#
# Symétrique de firewall-allow.sh, qui retire exactement la règle posée ici
# (iptables -D INPUT -s <ip> -j DROP).
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="firewall-drop"
IPT="/usr/sbin/iptables"
IPT6="/usr/sbin/ip6tables"
NFT="/usr/sbin/nft"
# Table nftables dédiée au blocage d'IP, distincte de `wazuh_isolation`
# (host-isolate.sh) : une dé-isolation supprime sa table entière, elle ne doit
# pas emporter les blocages d'IP posés séparément.
NFT_TABLE="soc_ai_block"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') firewall-drop: $1" >> "$LOG_FILE"
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
    # execd émet "delete" à l'expiration du timeout. On ne lève pas le blocage
    # tout seul : seul firewall-allow.sh le fait, sur demande explicite.
    delete)
        ar_result noop "" "commande delete (expiration timeout), seul firewall-allow leve le blocage"
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        ar_result error "" "commande invalide: $COMMAND"
        exit 1
        ;;
esac

IP=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
# Tolère la forme "-srcip <ip>" héritée du binaire natif.
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

# Garde-fou local, en plus de ceux du soc-agent (actions.appliquer_garde_fous) :
# l'AR est aussi joignable par l'API Wazuh et le serveur MCP, qui ne passent pas
# par ce code. Bloquer la loopback ou le manager coupe l'agent de sa supervision
# — et donc de toute possibilité de débloquer à distance.
case "$IP" in
    127.*|::1|0.0.0.0)
        log "REFUS: blocage de '$IP' (loopback) refusé"
        ar_result refused "$IP" "loopback"
        exit 1
        ;;
esac

MANAGER=$(sed -n 's/.*<address>\([^<]*\)<\/address>.*/\1/p' "$OSSEC_CONF" 2>/dev/null | head -1)
if [ -n "$MANAGER" ] && [ "$IP" = "$MANAGER" ]; then
    log "REFUS: blocage du manager '$IP' refusé (couperait la supervision)"
    ar_result refused "$IP" "IP du manager Wazuh"
    exit 1
fi

case "$IP" in
    *:*) BIN="$IPT6"; FAM="ip6" ;;
    *)   BIN="$IPT";  FAM="ip"  ;;
esac

# Repli nftables : les hôtes Debian récents (ex. adguard-home) n'embarquent que
# `nft`, sans le shim iptables. Sans ce repli, le blocage échouait sur ces
# agents — et l'échec ne remonte que dans active-responses.log.
if [ ! -x "$BIN" ]; then
    if [ ! -x "$NFT" ]; then
        log "ERREUR: ni $BIN ni $NFT trouvés"
        ar_result error "$IP" "ni $BIN ni $NFT trouves"
        exit 1
    fi
    "$NFT" list table inet "$NFT_TABLE" >/dev/null 2>&1 \
        || "$NFT" add table inet "$NFT_TABLE" 2>/dev/null
    # priority -10 : avant le filtre habituel (priority 0), pour que le DROP
    # prime sur un ACCEPT posé par le pare-feu de l'hôte.
    "$NFT" add chain inet "$NFT_TABLE" input \
        '{ type filter hook input priority -10 ; policy accept ; }' 2>/dev/null

    if "$NFT" list chain inet "$NFT_TABLE" input 2>/dev/null \
            | grep -q "$FAM saddr $IP drop"; then
        log "IP '$IP' déjà bloquée (nft), rien à faire"
        ar_result noop "$IP" "deja bloquee (regle nft presente)"
        exit 0
    fi
    if ! "$NFT" add rule inet "$NFT_TABLE" input "$FAM" saddr "$IP" drop 2>/dev/null; then
        log "ERREUR: échec de l'ajout de la règle nft drop pour '$IP'"
        ar_result error "$IP" "echec ajout regle nft drop"
        exit 1
    fi
    log "IP '$IP' bloquée (nft inet $NFT_TABLE input drop)"
    ar_result applied "$IP" "bloquee (nft inet $NFT_TABLE input drop)"
    exit 0
fi

# Idempotent : une IP déjà bloquée ne reçoit pas une seconde règle. Sinon un
# incident qui retire plusieurs fois la même IP empile les règles, et
# firewall-allow.sh doit boucler pour toutes les retirer.
if "$BIN" -C INPUT -s "$IP" -j DROP >/dev/null 2>&1; then
    log "IP '$IP' déjà bloquée, rien à faire"
    ar_result noop "$IP" "deja bloquee (regle iptables presente)"
    exit 0
fi

if ! "$BIN" -I INPUT -s "$IP" -j DROP >/dev/null 2>&1; then
    log "ERREUR: échec de l'ajout de la règle DROP pour '$IP'"
    ar_result error "$IP" "echec ajout regle INPUT DROP"
    exit 1
fi

log "IP '$IP' bloquée (INPUT DROP)"
ar_result applied "$IP" "bloquee (INPUT DROP)"
exit 0
