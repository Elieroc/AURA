#!/bin/sh
# Active response Wazuh : collecte forensique (RAM + image disque) d'un agent.
#
# Reçoit le message AR v1/v2 (JSON) sur stdin ; n'agit que sur "command": "add".
# parameters.extra_args[0] = périmètre : "ram" | "disk" | "full" (défaut: full).
#
# Déployé dans /var/ossec/active-response/bin/ sur les agents Linux.
#
# ---------------------------------------------------------------------------
# ARCHITECTURE : l'AR ne collecte PAS, elle détache un worker et rend la main
#
# wazuh-execd attend la fin du script AR et journalise un échec s'il traîne :
# une image disque prend des minutes à des heures. Le script se ré-exécute donc
# lui-même en arrière-plan (setsid, mode --worker) et sort immédiatement. Le
# suivi se fait dans active-responses.log, remonté au manager par le localfile.
#
# ORDRE DE VOLATILITÉ (RFC 3227) : la RAM est capturée AVANT le disque. Une
# image disque de plusieurs Go fait tourner le système assez longtemps pour
# écraser une partie de la mémoire recherchée. L'inverse ne coûte rien.
#
# RIEN N'EST ÉCRIT SUR LE DISQUE LOCAL : tout est streamé vers le serveur de
# preuves. Écrire une image de plusieurs Go sur la machine analysée écraserait
# l'espace non alloué — donc les fichiers supprimés récupérables, souvent la
# partie la plus intéressante de l'image.
#
# ---------------------------------------------------------------------------
# LIMITES ASSUMÉES (à connaître avant de plaider sur ces preuves)
#
# 1. L'image disque est prise à chaud, système monté : elle est incohérente
#    ("smear") — les fichiers écrits pendant la copie sont capturés dans un
#    état intermédiaire. C'est inhérent à l'acquisition live. Pour une image
#    réellement cohérente sur une VM libvirt, il faut passer par l'hyperviseur
#    (snapshot qcow2 + virsh dump), hors périmètre de cette AR.
# 2. La collecte s'exécute sur la machine suspecte, avec son noyau et ses
#    binaires. Un rootkit noyau peut mentir aux deux captures. Une capture qui
#    ne trouve rien ne prouve donc pas l'absence de compromission.
# 3. Le hash est calculé sur le flux émis (source-side), pas sur le disque :
#    re-hasher un disque live donnerait une valeur différente à chaque passe.
#    Il atteste l'intégrité du transfert, pas un état figé du support.
# ---------------------------------------------------------------------------

set -u

# --- Configuration ----------------------------------------------------------
# Valeurs par défaut, surchargées par /var/ossec/etc/soc-ai.conf (déployé
# depuis config/soc-ai.conf du repo). Défauts définis AVANT le source pour que
# `set -u` tienne même si le fichier est absent ou incomplet.
EVIDENCE_HOST="192.168.60.1"
EVIDENCE_USER="forensics"
EVIDENCE_PATH="/var/lib/forensics"
EVIDENCE_SSH_KEY="/var/ossec/active-response/.ssh/forensic_ed25519"
EVIDENCE_KNOWN_HOSTS="/var/ossec/active-response/.ssh/known_hosts"

CONF_FILE="/var/ossec/etc/soc-ai.conf"
# shellcheck source=/dev/null
[ -r "$CONF_FILE" ] && . "$CONF_FILE"

AVML="/var/ossec/active-response/bin/avml"
LOG_FILE="/var/ossec/logs/active-responses.log"
LOCK_DIR="/var/run/forensic-collect.lock"
NFT="/usr/sbin/nft"
ISOLATION_TABLE="wazuh_isolation"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') forensic-collect: $1" >> "$LOG_FILE"
}

SSH_OPTS="-i $EVIDENCE_SSH_KEY -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$EVIDENCE_KNOWN_HOSTS -o BatchMode=yes -o ConnectTimeout=15"

ssh_evidence() {
    # shellcheck disable=SC2086
    ssh $SSH_OPTS "${EVIDENCE_USER}@${EVIDENCE_HOST}" "$@"
}

# ===========================================================================
# MODE WORKER : la collecte réelle, lancée détachée par le mode AR ci-dessous
# ===========================================================================
if [ "${1:-}" = "--worker" ]; then
    SCOPE="${2:-full}"
    CASE_ID="${3:-unknown}"
    REMOTE_DIR="${EVIDENCE_PATH}/${CASE_ID}"

    NFT_RULE_ADDED=0

    cleanup() {
        # Retire l'exception nftables si on l'a posée (et seulement dans ce cas)
        if [ "$NFT_RULE_ADDED" = "1" ]; then
            HANDLE=$("$NFT" -a list chain inet "$ISOLATION_TABLE" output 2>/dev/null \
                | sed -n "s/.*ip daddr $EVIDENCE_HOST tcp dport 22 accept # handle \([0-9]*\)/\1/p" \
                | head -1)
            if [ -n "$HANDLE" ]; then
                "$NFT" delete rule inet "$ISOLATION_TABLE" output handle "$HANDLE" 2>/dev/null \
                    && log "exception nftables retirée (isolation restaurée telle quelle)"
            fi
        fi
        rmdir "$LOCK_DIR" 2>/dev/null
    }
    trap cleanup EXIT INT TERM

    # --- Interaction avec host-isolate.sh ---------------------------------
    # Un hôte isolé n'a plus de sortie que vers le manager (1514/1515) : le
    # stream SSH vers le serveur de preuves serait droppé. Le cas est la norme,
    # pas l'exception — on isole d'abord, on collecte ensuite. On ouvre donc
    # une exception ciblée (ce seul hôte, ce seul port) et on la retire en
    # sortant, pour rendre l'isolation exactement dans l'état trouvé.
    if [ -x "$NFT" ] && "$NFT" list table inet "$ISOLATION_TABLE" >/dev/null 2>&1; then
        if "$NFT" add rule inet "$ISOLATION_TABLE" output ip daddr "$EVIDENCE_HOST" tcp dport 22 accept 2>/dev/null; then
            NFT_RULE_ADDED=1
            log "hôte isolé : exception nftables ajoutée vers $EVIDENCE_HOST:22 le temps de la collecte"
        else
            log "ERREUR: hôte isolé et impossible d'ouvrir la route vers le serveur de preuves, collecte abandonnée"
            exit 1
        fi
    fi

    if ! ssh_evidence "mkdir -p '$REMOTE_DIR'" 2>/dev/null; then
        log "ERREUR: serveur de preuves ${EVIDENCE_USER}@${EVIDENCE_HOST} injoignable (clé $EVIDENCE_SSH_KEY / known_hosts), collecte abandonnée"
        exit 1
    fi
    log "collecte $CASE_ID démarrée (périmètre: $SCOPE) -> ${EVIDENCE_USER}@${EVIDENCE_HOST}:$REMOTE_DIR"

    # --- Manifeste (chain of custody) --------------------------------------
    # Écrit en premier : si la collecte échoue en route, on garde la trace de
    # ce qui a été tenté, sur quelle machine et dans quel état.
    MANIFEST=$(printf '{\n'
        printf '  "case_id": "%s",\n' "$CASE_ID"
        printf '  "collected_at_utc": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '  "hostname": "%s",\n' "$(hostname)"
        printf '  "kernel": "%s",\n' "$(uname -a | tr '"' "'")"
        printf '  "uptime_seconds": %s,\n' "$(cut -d. -f1 /proc/uptime)"
        printf '  "boot_id": "%s",\n' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
        printf '  "scope": "%s",\n' "$SCOPE"
        printf '  "memory_total_kb": %s,\n' "$(awk '/MemTotal/{print $2}' /proc/meminfo)"
        printf '  "collector": "forensic-collect.sh (Wazuh active response)"\n'
        printf '}\n')
    echo "$MANIFEST" | ssh_evidence "cat > '$REMOTE_DIR/manifest.json'"

    # --- Transfert d'un flux + hash source-side ----------------------------
    # tee via FIFO : le sha256 est calculé sur le flux exact qui part, en un
    # seul passage de lecture. Un second passage sur un disque live donnerait
    # un hash différent (le support bouge sous la lecture) et ne prouverait rien.
    stream_to_evidence() {
        _name="$1"       # nom du fichier distant (sans .gz)
        _fifo="/tmp/.fc-$$-$(echo "$_name" | tr -c 'a-zA-Z0-9' '_')"

        rm -f "$_fifo"
        mkfifo -m 600 "$_fifo" || return 1
        ( sha256sum < "$_fifo" | cut -d' ' -f1 > "${_fifo}.sha" ) &
        _hashpid=$!

        # gzip -1 : le goulot est le réseau/disque, pas le CPU ; -1 suffit à
        # écraser les grandes zones de zéros d'une image disque.
        tee "$_fifo" | gzip -1 | ssh_evidence "cat > '$REMOTE_DIR/${_name}.gz'"
        _rc=$?

        wait "$_hashpid"
        _hash=$(cat "${_fifo}.sha" 2>/dev/null)
        rm -f "$_fifo" "${_fifo}.sha"

        if [ "$_rc" -ne 0 ]; then
            return 1
        fi
        echo "$_hash  $_name" | ssh_evidence "cat > '$REMOTE_DIR/${_name}.sha256'"
        log "$_name transféré (sha256 du flux source: $_hash)"
        return 0
    }

    # === 1. RAM (avant le disque : ordre de volatilité) ====================
    if [ "$SCOPE" = "ram" ] || [ "$SCOPE" = "full" ]; then
        if [ -x "$AVML" ]; then
            # AVML (Microsoft) : binaire statique, aucun module noyau à compiler
            # contre le noyau courant — contrairement à LiME, qui échoue dès que
            # les headers ne correspondent pas (le cas en incident, justement).
            # Il écrit dans un fichier, pas sur stdout : FIFO pour rester en
            # streaming et ne rien poser sur le disque analysé.
            RAMFIFO="/tmp/.fc-ram-$$"
            rm -f "$RAMFIFO"
            if mkfifo -m 600 "$RAMFIFO"; then
                "$AVML" --compress false "$RAMFIFO" >/dev/null 2>&1 &
                AVMLPID=$!
                if stream_to_evidence "memory.lime" < "$RAMFIFO"; then
                    log "RAM capturée (AVML, format LiME)"
                else
                    log "ERREUR: échec du transfert de la capture RAM"
                fi
                wait "$AVMLPID" 2>/dev/null
                rm -f "$RAMFIFO"
            else
                log "ERREUR: impossible de créer le FIFO RAM"
            fi
        else
            # Pas de repli silencieux : /proc/kcore ne capture que la mémoire
            # mappée par le noyau courant et se fait mentir par un rootkit. Une
            # capture partielle passée pour complète vaut moins que pas de
            # capture — on échoue bruyamment.
            log "ERREUR: AVML absent ($AVML), capture RAM IMPOSSIBLE (déployer le binaire, cf. shuffle/README.md)"
        fi
    fi

    # === 2. Image disque ===================================================
    if [ "$SCOPE" = "disk" ] || [ "$SCOPE" = "full" ]; then
        # Disque entier et non partition : la table de partitions, le secteur
        # d'amorçage et l'espace inter-partitions sont des caches classiques.
        ROOT_SRC=$(findmnt -no SOURCE / 2>/dev/null)
        PKNAME=$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null | head -1 | tr -d ' ')
        if [ -n "$PKNAME" ]; then
            DISK="/dev/$PKNAME"
        else
            DISK="$ROOT_SRC"
        fi

        if [ -b "$DISK" ]; then
            DISK_BYTES=$(blockdev --getsize64 "$DISK" 2>/dev/null)
            log "image disque: $DISK ($DISK_BYTES octets) — durée proportionnelle à la taille"
            # conv=noerror,sync : un secteur illisible ne doit pas arrêter la
            # collecte ; il est remplacé par des zéros, l'offset reste juste.
            if dd if="$DISK" bs=4M conv=noerror,sync 2>/dev/null | stream_to_evidence "disk.raw"; then
                log "image disque terminée"
            else
                log "ERREUR: échec de l'image disque"
            fi
        else
            log "ERREUR: périphérique disque introuvable (root=$ROOT_SRC, parent=$PKNAME)"
        fi
    fi

    log "collecte $CASE_ID terminée"
    exit 0
fi

# ===========================================================================
# MODE AR : validation, verrou, détachement du worker
# ===========================================================================
read -r INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$COMMAND" in
    add) ;;
    delete)
        # Pas de rollback : une collecte de preuves ne s'annule pas. Les images
        # déjà transférées restent sur le serveur de preuves.
        exit 0
        ;;
    *)
        log "commande invalide: '$COMMAND'"
        exit 1
        ;;
esac

SCOPE=$(echo "$INPUT_JSON" | sed -n 's/.*"extra_args"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')
[ -z "$SCOPE" ] && SCOPE="full"

case "$SCOPE" in
    ram|disk|full) ;;
    *)
        log "ERREUR: périmètre invalide '$SCOPE' (attendu: ram, disk ou full)"
        exit 1
        ;;
esac

# Verrou : deux collectes simultanées se disputeraient la bande passante et
# fausseraient les deux captures (dont la RAM, qu'on cherche à figer).
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "REFUS: une collecte est déjà en cours (verrou $LOCK_DIR)"
    exit 1
fi

CASE_ID="$(hostname)-$(date -u '+%Y%m%dT%H%M%SZ')"

# setsid + redirection complète : le worker survit à la fin de l'AR et à
# wazuh-execd qui referme ses descripteurs.
setsid "$0" --worker "$SCOPE" "$CASE_ID" </dev/null >/dev/null 2>&1 &

log "collecte $CASE_ID lancée en arrière-plan (périmètre: $SCOPE), suivi dans ce fichier"
exit 0
