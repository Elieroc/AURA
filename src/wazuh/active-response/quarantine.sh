#!/bin/sh
# Active response Wazuh : mise en quarantaine / restauration d'un fichier.
#
# Appelé par le serveur MCP via la commande AR "quarantine" :
#   extra_args = ["/chemin/fichier"]            -> quarantaine
#   extra_args = ["restore", "/chemin/fichier"] -> restauration
#
# Le fichier est déplacé (pas copié) dans QUARANTINE_DIR, mode 000, avec un
# fichier .path à côté qui mémorise le chemin d'origine pour la restauration.
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.

set -u

QUARANTINE_DIR="/var/ossec/quarantine"
LOG_FILE="/var/ossec/logs/active-responses.log"
# Chemins jamais mis en quarantaine : casser ça rend l'hôte ou l'agent inutilisable.
PROTECTED="/bin /sbin /lib /lib64 /usr/bin /usr/sbin /usr/lib /etc /boot /var/ossec/bin"
SCRIPT_NAME="quarantine"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine: $1" >> "$LOG_FILE"
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
        ar_result noop "" "commande delete (expiration timeout), seul restore sort de quarantaine"
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        ar_result error "" "commande invalide: $COMMAND"
        exit 1
        ;;
esac

# extra_args : on extrait la liste complète puis les deux premiers éléments.
ARGS=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')
ARG1=$(echo "$ARGS" | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p')
ARG2=$(echo "$ARGS" | sed -n 's/^[[:space:]]*"[^"]*"[[:space:]]*,[[:space:]]*"\([^"]*\)".*/\1/p')

if [ "$ARG1" = "restore" ]; then
    ACTION="restore"
    TARGET="$ARG2"
else
    ACTION="quarantine"
    TARGET="$ARG1"
fi

if [ -z "$TARGET" ]; then
    log "ERREUR: aucun chemin de fichier fourni"
    ar_result error "" "aucun chemin de fichier fourni ($ACTION)"
    exit 1
fi

case "$TARGET" in
    /*) ;;
    *)
        log "ERREUR: chemin non absolu refusé: '$TARGET'"
        ar_result error "$TARGET" "chemin non absolu ($ACTION)"
        exit 1
        ;;
esac

# La liste PROTECTED plus bas est un test de PRÉFIXE : un segment « .. » suffit
# à la contourner (/var/tmp/../../etc/shadow ne commence par aucun répertoire
# protégé, et `mv` le résout quand même). On refuse donc tout chemin non
# canonique plutôt que de tenter de le résoudre — cet AR tourne en root, et un
# chemin qu'on ne sait pas nommer exactement n'est pas un chemin sur lequel on
# agit.
case "$TARGET" in
    */../*|*/..|../*|..)
        log "REFUS: chemin non canonique (segment ..) : '$TARGET'"
        ar_result refused "$TARGET" "chemin non canonique (segment ..)"
        exit 1
        ;;
esac

# Nom de stockage : chemin absolu avec les '/' remplacés par '_'.
STORED="$QUARANTINE_DIR/$(echo "$TARGET" | sed 's|^/||; s|/|_|g')"

if [ "$ACTION" = "quarantine" ]; then
    for dir in $PROTECTED; do
        case "$TARGET" in
            "$dir"/*)
                log "REFUS: '$TARGET' est dans un répertoire système protégé ($dir)"
                ar_result refused "$TARGET" "repertoire systeme protege ($dir)"
                exit 1
                ;;
        esac
    done

    if [ ! -f "$TARGET" ]; then
        log "fichier '$TARGET' introuvable, rien à faire"
        ar_result noop "$TARGET" "fichier introuvable sur cet hote"
        exit 0
    fi

    mkdir -p "$QUARANTINE_DIR" && chmod 700 "$QUARANTINE_DIR"

    if ! mv "$TARGET" "$STORED"; then
        log "ERREUR: échec du déplacement de '$TARGET'"
        ar_result error "$TARGET" "echec du deplacement vers $STORED"
        exit 1
    fi
    chmod 000 "$STORED"
    echo "$TARGET" > "$STORED.path"
    log "fichier '$TARGET' mis en quarantaine ($STORED)"
    ar_result applied "$TARGET" "mis en quarantaine ($STORED)"
    exit 0
fi

# restore
if [ ! -f "$STORED" ]; then
    log "ERREUR: '$TARGET' absent de la quarantaine"
    ar_result noop "$TARGET" "absent de la quarantaine, rien a restaurer"
    exit 1
fi

ORIG=$(cat "$STORED.path" 2>/dev/null || echo "$TARGET")
if [ -e "$ORIG" ]; then
    log "ERREUR: '$ORIG' existe déjà, restauration annulée"
    ar_result error "$ORIG" "le chemin d'origine existe deja, restauration annulee"
    exit 1
fi

if ! mv "$STORED" "$ORIG"; then
    log "ERREUR: échec de la restauration vers '$ORIG'"
    ar_result error "$ORIG" "echec du deplacement depuis la quarantaine"
    exit 1
fi
chmod 600 "$ORIG"
rm -f "$STORED.path"
log "fichier '$ORIG' restauré depuis la quarantaine"
ar_result applied "$ORIG" "restaure depuis la quarantaine"
exit 0
