#!/bin/sh
# Source de collecte forensique — s'exécute SUR L'AGENT (machine suspecte).
#
# Déployé en /usr/local/sbin/forensic-source.sh et appelé UNIQUEMENT comme
# forced command SSH depuis l'hôte manager :
#
#   authorized_keys de l'agent :
#     command="sudo /usr/local/sbin/forensic-source.sh",no-port-forwarding,\
#     no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... manager-forensic
#
# ---------------------------------------------------------------------------
# POURQUOI CE SENS (agent -> manager, jamais l'inverse)
#
# La première version poussait les preuves depuis l'agent vers le serveur de
# dépôt, ce qui imposait de stocker une CLÉ PRIVÉE sur la machine suspecte. Un
# attaquant root y lisait la clé, et gagnait un accès en écriture au dépôt de
# preuves : de quoi altérer les preuves des autres incidents, ou s'en servir
# comme rebond. Le sens est donc inversé — ici l'agent ne détient qu'une clé
# PUBLIQUE dans authorized_keys, et n'a d'accès sortant vers rien.
#
# Ce script est la surface d'attaque restante côté agent : il ne prend AUCUN
# argument de l'appelant hors des trois mots-clés ci-dessous, n'interprète
# jamais SSH_ORIGINAL_COMMAND comme une commande, et n'écrit rien nulle part.
# Il ne fait que produire des octets sur stdout.
#
# Il tourne en root (lecture de /dev/mem et du disque brut) : toute évolution
# doit garder cette propriété — aucun chemin, aucun nom de fichier, aucune
# option ne vient de l'extérieur.
# ---------------------------------------------------------------------------

set -u

AVML="/usr/local/sbin/avml"

# Le mot-clé arrive dans SSH_ORIGINAL_COMMAND parce que la forced command
# écrase la commande demandée. On ne l'exécute pas : on le compare à une liste
# fermée. Toute autre valeur est refusée.
REQUEST="${SSH_ORIGINAL_COMMAND:-}"

# stderr part dans le canal SSH et remonte au manager : c'est le seul retour
# d'erreur exploitable, stdout étant réservé aux octets de preuve.
fail() {
    echo "forensic-source: $1" >&2
    exit 1
}

resolve_disk() {
    # Disque ENTIER, pas la partition racine : table de partitions, secteur
    # d'amorçage et espace inter-partitions sont des caches classiques.
    _src=$(findmnt -no SOURCE / 2>/dev/null)
    [ -n "$_src" ] || return 1
    _parent=$(lsblk -no PKNAME "$_src" 2>/dev/null | head -1 | tr -d ' ')
    if [ -n "$_parent" ]; then
        echo "/dev/$_parent"
    else
        echo "$_src"
    fi
}

case "$REQUEST" in
    ram)
        [ -x "$AVML" ] || fail "AVML absent ($AVML), capture RAM impossible"
        # AVML écrit dans un fichier, pas sur stdout : on passe par un FIFO pour
        # rester en flux. Écrire la RAM dans un fichier local est exclu — sur
        # disque ça écrase l'espace non alloué (donc les fichiers supprimés
        # récupérables), en tmpfs ça consomme la RAM qu'on essaie de capturer.
        FIFO="/tmp/.fsrc-ram-$$"
        rm -f "$FIFO"
        mkfifo -m 600 "$FIFO" || fail "création du FIFO impossible"
        "$AVML" --compress false "$FIFO" >&2 2>/dev/null &
        AVML_PID=$!
        cat "$FIFO"
        wait "$AVML_PID" 2>/dev/null
        AVML_RC=$?
        rm -f "$FIFO"
        [ "$AVML_RC" -eq 0 ] || fail "AVML a échoué (code $AVML_RC)"
        ;;
    disk)
        DISK=$(resolve_disk) || fail "périphérique disque introuvable"
        [ -b "$DISK" ] || fail "$DISK n'est pas un périphérique bloc"
        # conv=noerror,sync : un secteur illisible ne doit pas interrompre la
        # copie ; il est remplacé par des zéros et les offsets restent justes.
        dd if="$DISK" bs=4M conv=noerror,sync 2>/dev/null
        ;;
    meta)
        # État de la machine au moment de la collecte (chain of custody).
        # Uniquement des lectures, aucun paramètre extérieur.
        printf '{\n'
        printf '  "hostname": "%s",\n' "$(hostname)"
        printf '  "collected_at_utc": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '  "kernel": "%s",\n' "$(uname -a | tr '"' "'")"
        printf '  "uptime_seconds": %s,\n' "$(cut -d. -f1 /proc/uptime)"
        printf '  "boot_id": "%s",\n' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
        printf '  "memory_total_kb": %s,\n' "$(awk '/MemTotal/{print $2}' /proc/meminfo)"
        printf '  "disk_device": "%s",\n' "$(resolve_disk 2>/dev/null)"
        printf '  "disk_bytes": %s\n' "$(blockdev --getsize64 "$(resolve_disk 2>/dev/null)" 2>/dev/null || echo 0)"
        printf '}\n'
        ;;
    *)
        fail "requête refusée: '$REQUEST' (attendu: ram, disk ou meta)"
        ;;
esac
