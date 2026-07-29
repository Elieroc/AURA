#!/bin/sh
# Active response Wazuh : isolation réseau de l'hôte (nftables).
#
# Coupe tout le trafic sauf :
#   - loopback
#   - connexion agent -> manager Wazuh (tcp/1514) pour garder le contrôle
#   - SSH depuis le serveur Wazuh (tcp/22) pour l'administration/dé-isolation
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.
# Reçoit le message AR (JSON) sur stdin ; n'agit que sur "command": "add".
# La dé-isolation est faite par host-unisolate.sh (suppression de la table).

set -u

# Défaut surchargé par /var/ossec/etc/soc-ai.conf (cf. config/soc-ai.conf.example) :
# WAZUH_MANAGER_IP = IP du manager telle que les agents la joignent. C'est la
# seule sortie laissée ouverte par l'isolation, donc la seule façon de garder
# l'agent pilotable — une valeur fausse ici coupe l'agent définitivement.
WAZUH_MANAGER_IP="192.168.122.1"
CONF_FILE="/var/ossec/etc/soc-ai.conf"
# shellcheck source=/dev/null
[ -r "$CONF_FILE" ] && . "$CONF_FILE"
MANAGER_IP="$WAZUH_MANAGER_IP"

NFT="/usr/sbin/nft"
TABLE="wazuh_isolation"
LOG_FILE="/var/ossec/logs/active-responses.log"
# Marqueur d'état robuste. Deux formes, complémentaires :
#  - MARKER : fichier local, vérité terrain inspectable même hors réseau (le
#    manager garde SSH). Contient un JSON état + horodatage.
#  - le token SOC-AI-ISOLATION-STATE=<état> écrit dans active-responses.log,
#    ingéré par Wazuh -> interrogeable à distance sans toucher l'agent.
# La présence de la table nftables reste l'autorité ; le marqueur la reflète.
MARKER="/var/ossec/isolated"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') host-isolate: $1" >> "$LOG_FILE"
}

# Écrit le marqueur d'isolation (état "isolated") de façon atomique.
poser_marqueur() {
    _tmp="${MARKER}.tmp.$$"
    printf '{"isolated":true,"since":"%s","manager":"%s","table":"%s"}\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$MANAGER_IP" "$TABLE" > "$_tmp" \
        && mv "$_tmp" "$MARKER"
    log "SOC-AI-ISOLATION-STATE=isolated (marqueur $MARKER)"
}

# Message AR v2 sur stdin
read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        # Pas de timeout géré ici : la dé-isolation passe par host-unisolate.sh
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        exit 1
        ;;
esac

if [ ! -x "$NFT" ]; then
    log "ERREUR: $NFT introuvable, isolation impossible"
    exit 1
fi

# Refus d'auto-isolation du manager. Si MANAGER_IP est une adresse LOCALE, c'est
# que ce script tourne SUR le manager (agent 000) : l'isoler couperait la
# collecte de tout le parc, l'API et la console — donc le seul canal par lequel
# on pourrait le dé-isoler. Le ruleset ci-dessous n'ouvre d'exception que « vers
# le manager », ce qui ne veut rien dire quand on EST le manager.
#
# Doublon assumé du garde-fou Python (config.AGENTS_PROTEGES) : l'AR est aussi
# joignable par l'API Wazuh et le serveur MCP, qui ne passent pas par ce code.
if [ -n "$MANAGER_IP" ] && command -v ip >/dev/null 2>&1 \
   && ip -o addr show 2>/dev/null | grep -qw "$MANAGER_IP"; then
    log "REFUS: $MANAGER_IP est une adresse locale — auto-isolation du manager refusée"
    exit 1
fi

# Idempotent : table déjà en place = déjà isolé. On (re)pose le marqueur au cas
# où il aurait disparu (agent redémarré, marqueur effacé), pour qu'il reflète
# toujours l'état réel de la table.
if "$NFT" list table inet "$TABLE" >/dev/null 2>&1; then
    poser_marqueur
    log "déjà isolé (table $TABLE présente)"
    exit 0
fi

"$NFT" -f - <<EOF
table inet $TABLE {
    chain input {
        type filter hook input priority -50; policy drop;
        iif "lo" accept
        ct state established,related accept
        ip saddr $MANAGER_IP tcp dport 22 accept
    }
    chain output {
        type filter hook output priority -50; policy drop;
        oif "lo" accept
        ct state established,related accept
        ip daddr $MANAGER_IP tcp dport 1514 accept
        ip daddr $MANAGER_IP tcp dport 1515 accept
    }
    chain forward {
        type filter hook forward priority -50; policy drop;
    }
}
EOF

if [ $? -eq 0 ]; then
    poser_marqueur
    log "hôte isolé du réseau (exceptions: lo, manager $MANAGER_IP 1514/1515, SSH depuis manager)"
    exit 0
else
    log "ERREUR: échec application ruleset nftables"
    exit 1
fi
