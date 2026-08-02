#!/bin/sh
# Active response Wazuh : désactivation d'un compte compromis.
#
# Remplace le binaire natif `disable-account`, qui lit l'utilisateur dans
# alert.data.dstuser et échoue donc sur tout appel piloté (« Cannot read
# 'dstuser' from data ») : le soc-agent et le serveur MCP passent le compte en
# extra_args, pas via une alerte. Six tentatives, six échecs silencieux — la
# base disait `exécuté` alors qu'aucun compte n'a jamais été désactivé.
#
# Même contrat d'entrée que enable-account.sh (extra_args = ["<user>"]) et
# reverse EXACTEMENT symétrique : ce que l'on pose ici (usermod -L, chage -E 1),
# enable-account.sh le lève (usermod -U, chage -E -1). Le natif posait autre
# chose, donc la réactivation ne restaurait pas le même état.
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.

set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="disable-account"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') disable-account: $1" >> "$LOG_FILE"
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
    # execd émet "delete" à l'expiration du timeout. Une désactivation de compte
    # ne doit PAS se lever toute seule : seul enable-account.sh la défait.
    delete)
        ar_result noop "" "commande delete (expiration timeout), seul enable-account leve le verrou"
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

# Garde-fou local, en plus de ceux du soc-agent (actions.appliquer_garde_fous) :
# l'AR est aussi joignable par l'API Wazuh et le serveur MCP, qui ne passent pas
# par ce code. Verrouiller root ou le compte de service Wazuh coupe
# l'administration et l'agent lui-même.
case "$USER" in
    root|wazuh|wazuh-admin)
        log "REFUS: désactivation du compte protégé '$USER' refusée"
        ar_result refused "$USER" "compte protege (root/wazuh/wazuh-admin)"
        exit 1
        ;;
esac

if ! id "$USER" >/dev/null 2>&1; then
    log "ERREUR: utilisateur '$USER' inexistant"
    ar_result noop "$USER" "compte inexistant sur cet hote"
    exit 1
fi

# usermod -L verrouille le mot de passe, chage -E 1 fait expirer le compte (le
# lock seul n'empêche pas une connexion par clé SSH ou par un service).
FAIT=""
if command -v usermod >/dev/null 2>&1; then
    if usermod -L "$USER" >/dev/null 2>&1; then
        FAIT="${FAIT} usermod -L"
    else
        log "ERREUR: usermod -L a échoué sur '$USER'"
        ar_result error "$USER" "usermod -L a echoue"
        exit 1
    fi
fi
if command -v chage >/dev/null 2>&1; then
    if chage -E 1 "$USER" >/dev/null 2>&1; then
        FAIT="${FAIT} chage -E 1"
    else
        log "ERREUR: chage -E 1 a échoué sur '$USER'"
        ar_result error "$USER" "chage -E 1 a echoue"
        exit 1
    fi
fi

if [ -z "$FAIT" ]; then
    log "ERREUR: ni usermod ni chage disponibles, compte '$USER' NON désactivé"
    ar_result error "$USER" "ni usermod ni chage disponibles"
    exit 1
fi

log "compte '$USER' désactivé ($FAIT)"
ar_result applied "$USER" "compte desactive ($FAIT)"
exit 0
