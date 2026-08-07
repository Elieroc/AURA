#!/bin/sh
# Collecte forensique — s'exécute SUR L'HÔTE MANAGER (pas sur la machine suspecte).
#
#   forensic-pull.sh <agent_host> [ram|disk|full]
#
# Tire les preuves de l'agent (SSH, forced command forensic-source.sh) et les
# pousse vers le serveur de dépôt, en un seul tuyau. Les octets transitent par
# la mémoire du manager, ils n'atterrissent JAMAIS sur son disque : le manager
# est un relais, pas un lieu de stockage de preuves.
#
# Appelé par Shuffle via `run_ssh_command`, lui-même restreint par forced
# command côté manager (cf. shuffle/README.md).
#
# ---------------------------------------------------------------------------
# SENS DU FLUX : le manager tire, l'agent ne pousse rien
#
# Version précédente : l'agent poussait vers le dépôt, donc une clé privée
# dormait sur la machine suspecte. Root sur l'agent = lecture de la clé =
# écriture dans le dépôt de preuves (altération des autres incidents, rebond).
#
# Ici les trois clés vivent hors de la machine suspecte :
#   K1  Shuffle  -> manager   (forced command: ce script)
#   K2  manager  -> agent     (forced command: forensic-source.sh)
#   K3  manager  -> dépôt     (compte dédié, écriture seule)
# L'agent ne détient qu'une clé publique et n'a aucun accès sortant.
#
# Contrepartie assumée : le manager détient une clé VERS l'agent. C'est le sens
# d'administration habituel, et la forced command la borne à trois mots-clés
# qui ne produisent que des octets. Mais lire un disque brut, c'est lire tout le
# disque : cette clé reste un secret de premier ordre.
#
# ---------------------------------------------------------------------------
# ISOLATION RÉSEAU : rien à faire
#
# host-isolate.sh laisse déjà passer le SSH ENTRANT depuis le manager (input:
# `ip saddr $MANAGER_IP tcp dport 22 accept`) et les réponses sortantes (output:
# `ct state established,related accept`). Le flux de preuves emprunte cette
# connexion établie. La version « push » devait au contraire percer un trou
# dans l'isolation pour sortir — ce bricolage disparaît.
#
# ORDRE DE VOLATILITÉ (RFC 3227) : RAM avant disque. Une image disque fait
# tourner la machine assez longtemps pour écraser une partie de la mémoire.
# ---------------------------------------------------------------------------

set -u

# --- Configuration ----------------------------------------------------------
# Défauts définis AVANT le source, pour que `set -u` tienne si la conf manque.
AGENT_SSH_USER="forensic"
AGENT_SSH_KEY="/etc/soc-ai/forensic_agent_ed25519"
AGENT_KNOWN_HOSTS="/etc/soc-ai/known_hosts_agents"

EVIDENCE_HOST=""
EVIDENCE_USER="forensics"
EVIDENCE_PATH="/var/lib/forensics"
EVIDENCE_SSH_KEY="/etc/soc-ai/forensic_evidence_ed25519"
EVIDENCE_KNOWN_HOSTS="/etc/soc-ai/known_hosts_evidence"

CONF_FILE="/etc/soc-ai/soc-ai.conf"
# shellcheck source=/dev/null
[ -r "$CONF_FILE" ] && . "$CONF_FILE"

LOG_FILE="/var/log/soc-ai-forensic.log"
LOCK_ROOT="/var/lock"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') forensic-pull: $1" >> "$LOG_FILE" 2>/dev/null
    echo "$(date '+%Y/%m/%d %H:%M:%S') forensic-pull: $1"
}

SSH_AGENT_OPTS="-i $AGENT_SSH_KEY -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$AGENT_KNOWN_HOSTS -o BatchMode=yes -o ConnectTimeout=15"
SSH_EVID_OPTS="-i $EVIDENCE_SSH_KEY -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$EVIDENCE_KNOWN_HOSTS -o BatchMode=yes -o ConnectTimeout=15"

# StrictHostKeyChecking=yes + known_hosts épinglés des deux côtés : sans ça, un
# MITM sur le réseau d'un agent compromis se ferait passer pour l'agent (et
# fabriquerait les preuves) ou pour le dépôt (et les récupérerait).

ssh_agent() {
    # shellcheck disable=SC2086
    ssh $SSH_AGENT_OPTS "${AGENT_SSH_USER}@${AGENT_HOST}" "$@"
}

ssh_evidence() {
    # shellcheck disable=SC2086
    ssh $SSH_EVID_OPTS "${EVIDENCE_USER}@${EVIDENCE_HOST}" "$@"
}

# ===========================================================================
# MODE WORKER : la collecte réelle
# ===========================================================================
if [ "${1:-}" = "--worker" ]; then
    AGENT_HOST="$2"
    SCOPE="$3"
    CASE_ID="$4"
    REMOTE_DIR="${EVIDENCE_PATH}/${CASE_ID}"
    LOCK_DIR="${LOCK_ROOT}/forensic-pull-${AGENT_HOST}.lock"

    trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT INT TERM

    if ! ssh_evidence "mkdir -p '$REMOTE_DIR'" 2>/dev/null; then
        log "ERREUR: dépôt ${EVIDENCE_USER}@${EVIDENCE_HOST} injoignable, collecte $CASE_ID abandonnée"
        exit 1
    fi
    log "collecte $CASE_ID démarrée (agent: $AGENT_HOST, périmètre: $SCOPE) -> ${EVIDENCE_USER}@${EVIDENCE_HOST}:$REMOTE_DIR"

    # --- Manifeste (chain of custody) --------------------------------------
    # Écrit en premier : si la suite échoue, on garde la trace de ce qui a été
    # tenté, sur quelle machine et dans quel état.
    META=$(ssh_agent meta 2>/dev/null)
    if [ -z "$META" ]; then
        log "ERREUR: agent $AGENT_HOST injoignable ou forced command absente, collecte abandonnée"
        exit 1
    fi
    printf '%s\n' "$META" | ssh_evidence "cat > '$REMOTE_DIR/manifest.json'"

    # --- Un flux = un fichier + son hash ------------------------------------
    # Le sha256 est calculé au vol sur le flux reçu, via FIFO : une seconde
    # lecture du disque de l'agent donnerait un hash différent (le support bouge
    # sous la lecture) et ne prouverait rien. Le hash atteste donc le transfert,
    # pas un état figé du support.
    pull_stream() {
        _kw="$1"          # mot-clé envoyé à la forced command (ram|disk)
        _name="$2"        # nom du fichier déposé (sans .gz)
        _fifo="/tmp/.fpull-$$-$_kw"

        rm -f "$_fifo"
        mkfifo -m 600 "$_fifo" || return 1
        ( sha256sum < "$_fifo" | cut -d' ' -f1 > "${_fifo}.sha" ) &
        _hashpid=$!

        # gzip -1 : le goulot est le réseau, pas le CPU ; -1 suffit à écraser
        # les grandes plages de zéros d'une image disque.
        ssh_agent "$_kw" | tee "$_fifo" | gzip -1 | ssh_evidence "cat > '$REMOTE_DIR/${_name}.gz'"
        _rc=$?

        wait "$_hashpid"
        _hash=$(cat "${_fifo}.sha" 2>/dev/null)
        rm -f "$_fifo" "${_fifo}.sha"

        if [ "$_rc" -ne 0 ] || [ -z "$_hash" ]; then
            return 1
        fi
        echo "$_hash  $_name" | ssh_evidence "cat > '$REMOTE_DIR/${_name}.sha256'"
        log "$_name déposé (sha256 du flux: $_hash)"
        return 0
    }

    # === 1. RAM (avant le disque : ordre de volatilité) ====================
    if [ "$SCOPE" = "ram" ] || [ "$SCOPE" = "full" ]; then
        if pull_stream ram memory.lime; then
            log "RAM capturée"
        else
            log "ERREUR: échec de la capture RAM (voir stderr de l'agent)"
        fi
    fi

    # === 2. Image disque ===================================================
    if [ "$SCOPE" = "disk" ] || [ "$SCOPE" = "full" ]; then
        if pull_stream disk disk.raw; then
            log "image disque déposée"
        else
            log "ERREUR: échec de l'image disque"
        fi
    fi

    log "collecte $CASE_ID terminée"
    exit 0
fi

# ===========================================================================
# MODE APPEL : validation, verrou, détachement
# ===========================================================================
# Appelé par Shuffle en forced command : les arguments arrivent dans
# SSH_ORIGINAL_COMMAND. En appel direct (manuel), ils arrivent en $@.
if [ $# -eq 0 ] && [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    # Découpage sur les espaces uniquement, jamais d'évaluation shell : la
    # chaîne vient de Shuffle et ne doit pas pouvoir devenir une commande.
    set -- $SSH_ORIGINAL_COMMAND
fi

AGENT_HOST="${1:-}"
SCOPE="${2:-full}"

# Liste fermée de caractères : un nom d'hôte ou une IP, rien qui puisse
# s'échapper vers le shell distant.
case "$AGENT_HOST" in
    '') log "ERREUR: hôte de l'agent manquant (usage: forensic-pull.sh <agent_host> [ram|disk|full])"; exit 1 ;;
    *[!a-zA-Z0-9.:_-]*) log "ERREUR: hôte invalide '$AGENT_HOST' (caractères refusés)"; exit 1 ;;
esac

case "$SCOPE" in
    ram|disk|full) ;;
    *) log "ERREUR: périmètre invalide '$SCOPE' (attendu: ram, disk ou full)"; exit 1 ;;
esac

# Verrou par agent : deux collectes simultanées sur la même machine se
# disputeraient la bande passante et fausseraient les deux captures.
LOCK_DIR="${LOCK_ROOT}/forensic-pull-${AGENT_HOST}.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "REFUS: une collecte est déjà en cours sur $AGENT_HOST (verrou $LOCK_DIR)"
    exit 1
fi

CASE_ID="${AGENT_HOST}-$(date -u '+%Y%m%dT%H%M%SZ')"

# Détachement : une image disque dure des minutes à des heures, alors que
# l'appel SSH de Shuffle attend la fin de la commande. On rend la main tout de
# suite avec l'identifiant de collecte ; le suivi se fait dans $LOG_FILE.
setsid "$0" --worker "$AGENT_HOST" "$SCOPE" "$CASE_ID" </dev/null >/dev/null 2>&1 &

log "collecte $CASE_ID lancée en arrière-plan (agent: $AGENT_HOST, périmètre: $SCOPE)"
echo "case_id=$CASE_ID"
exit 0
