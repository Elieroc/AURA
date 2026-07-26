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
IPT="/usr/sbin/iptables"
IPT6="/usr/sbin/ip6tables"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') firewall-drop: $1" >> "$LOG_FILE"
}

read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    # execd émet "delete" à l'expiration du timeout. On ne lève pas le blocage
    # tout seul : seul firewall-allow.sh le fait, sur demande explicite.
    delete) exit 0 ;;
    *)
        log "commande invalide: '$COMMAND'"
        exit 1
        ;;
esac

IP=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
# Tolère la forme "-srcip <ip>" héritée du binaire natif.
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

# Garde-fou local, en plus de ceux du soc-agent (actions.appliquer_garde_fous) :
# l'AR est aussi joignable par l'API Wazuh et le serveur MCP, qui ne passent pas
# par ce code. Bloquer la loopback ou le manager coupe l'agent de sa supervision
# — et donc de toute possibilité de débloquer à distance.
case "$IP" in
    127.*|::1|0.0.0.0)
        log "REFUS: blocage de '$IP' (loopback) refusé"
        exit 1
        ;;
esac

MANAGER=$(sed -n 's/.*<address>\([^<]*\)<\/address>.*/\1/p' "$OSSEC_CONF" 2>/dev/null | head -1)
if [ -n "$MANAGER" ] && [ "$IP" = "$MANAGER" ]; then
    log "REFUS: blocage du manager '$IP' refusé (couperait la supervision)"
    exit 1
fi

case "$IP" in
    *:*) BIN="$IPT6" ;;
    *)   BIN="$IPT" ;;
esac

if [ ! -x "$BIN" ]; then
    log "ERREUR: $BIN introuvable"
    exit 1
fi

# Idempotent : une IP déjà bloquée ne reçoit pas une seconde règle. Sinon un
# incident qui retire plusieurs fois la même IP empile les règles, et
# firewall-allow.sh doit boucler pour toutes les retirer.
if "$BIN" -C INPUT -s "$IP" -j DROP >/dev/null 2>&1; then
    log "IP '$IP' déjà bloquée, rien à faire"
    exit 0
fi

if ! "$BIN" -I INPUT -s "$IP" -j DROP >/dev/null 2>&1; then
    log "ERREUR: échec de l'ajout de la règle DROP pour '$IP'"
    exit 1
fi

log "IP '$IP' bloquée (INPUT DROP)"
exit 0
