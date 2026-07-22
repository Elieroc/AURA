#!/usr/bin/env bash
#
# Dépose (ou retire) les fichiers canaris de détection ransomware sur un agent.
#
# Principe : un ransomware qui chiffre une arborescence touche les canaris comme
# n'importe quel autre document. Aucun process légitime, lui, n'écrit dedans —
# les lectures (antivirus, updatedb, sauvegarde) ne déclenchent pas le FIM Wazuh,
# seules les écritures / renommages / suppressions le font. D'où un signal à
# quasi zéro faux positif, sans seuil ni fenêtre temporelle à régler.
#
# Détail qui compte :
#   - nom préfixé "000_" : les chiffreurs parcourent les répertoires dans l'ordre
#     retourné par readdir/scandir, souvent trié — le canari est touché tôt, ce
#     qui laisse du temps pour réagir ;
#   - extensions .xlsx / .docx / .pdf : les familles courantes chiffrent sur
#     liste blanche d'extensions bureautiques, un .txt ou un fichier caché est
#     souvent ignoré. Le canari n'est donc ni caché ni exotique ;
#   - taille non nulle et contenu compressible : certaines familles ignorent les
#     fichiers vides ou déjà à haute entropie ;
#   - propriétaire = propriétaire du répertoire, mode 0644 : le canari doit être
#     ÉCRITURABLE par le compte qu'un ransomware compromettrait, sinon il est
#     simplement sauté et ne détecte rien.
#
# Les canaris sont surveillés en temps réel via l'attribut `restrict` du bloc
# <syscheck> de wazuh/config/wazuh_cluster/agent.conf (règle locale 100670).
#
# Usage (en root sur la machine cible) :
#   ./deploy-canary.sh                 # dépose dans les emplacements par défaut
#   ./deploy-canary.sh -d /data -d /mnt/share
#   ./deploy-canary.sh --remove        # retire tous les canaris
#   ./deploy-canary.sh --dry-run
#
set -euo pipefail

CANARY_TAG="CANARY_SOC_NE_PAS_TOUCHER"
EXTENSIONS=(xlsx docx pdf)

REMOVE=0
DRY_RUN=0
TARGETS=()

usage() {
    sed -n '2,30p' "$0" | sed 's/^#//; s/^ //'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir)   TARGETS+=("$2"); shift 2 ;;
        --remove)   REMOVE=1; shift ;;
        --dry-run)  DRY_RUN=1; shift ;;
        -h|--help)  usage 0 ;;
        *)          echo "Option inconnue : $1" >&2; usage 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit être lancé en root (il écrit dans /home, /srv, /root)." >&2
    exit 1
fi

# Emplacements par défaut : la racine de chaque arborescence de données, plus le
# premier niveau de sous-répertoires (un ransomware lancé depuis un sous-dossier
# profond ne remonte pas forcément). Doit rester cohérent avec les <directories>
# et leur recursion_level dans agent.conf.
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    for base in /home/* /srv /var/www /root; do
        [[ -d "$base" ]] || continue
        TARGETS+=("$base")
        while IFS= read -r sub; do
            TARGETS+=("$sub")
        done < <(find "$base" -mindepth 1 -maxdepth 1 -type d ! -name '.*' 2>/dev/null)
    done
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "Aucun répertoire cible trouvé — rien à faire." >&2
    exit 0
fi

# Contenu : en-tête cohérent avec l'extension (certaines familles vérifient le
# magic plutôt que le suffixe) puis du texte répété, donc à faible entropie.
write_canary() {
    local path="$1" ext="$2"
    local magic
    case "$ext" in
        xlsx|docx) magic=$'PK\x03\x04' ;;   # conteneur OOXML = archive ZIP
        pdf)       magic='%PDF-1.7' ;;
    esac
    {
        printf '%s' "$magic"
        printf '\n%s\n' "Fichier canari SOC — ne pas modifier, ne pas supprimer."
        printf '%s\n' "Toute écriture sur ce fichier déclenche une alerte ransomware (100670)."
        # ~16 Ko de remplissage : au-dessus du seuil de taille minimale de la
        # plupart des chiffreurs, et compressible (faible entropie).
        for _ in $(seq 1 400); do
            printf '%s\n' "canari-soc-$CANARY_TAG-remplissage-0123456789abcdef"
        done
    } > "$path"
}

action=0
for dir in "${TARGETS[@]}"; do
    [[ -d "$dir" ]] || continue

    owner="$(stat -c '%u:%g' "$dir")"

    for ext in "${EXTENSIONS[@]}"; do
        file="${dir}/000_${CANARY_TAG}.${ext}"

        if [[ $REMOVE -eq 1 ]]; then
            [[ -e "$file" ]] || continue
            if [[ $DRY_RUN -eq 1 ]]; then
                echo "[dry-run] rm $file"
            else
                rm -f "$file"
                echo "supprimé : $file"
            fi
            action=$((action + 1))
            continue
        fi

        # Idempotent : ne pas réécrire un canari existant, sinon chaque exécution
        # du script déclenche l'alerte qu'il est censé détecter.
        if [[ -e "$file" ]]; then
            continue
        fi

        if [[ $DRY_RUN -eq 1 ]]; then
            echo "[dry-run] créer $file (owner $owner)"
        else
            write_canary "$file" "$ext"
            chown "$owner" "$file"
            chmod 0644 "$file"
            echo "déposé : $file"
        fi
        action=$((action + 1))
    done
done

if [[ $action -eq 0 ]]; then
    echo "Rien à faire (canaris déjà en place)."
else
    echo "---"
    echo "$action opération(s) sur ${#TARGETS[@]} répertoire(s)."
fi

if [[ $REMOVE -eq 0 && $DRY_RUN -eq 0 ]]; then
    cat <<'EOF'

Étape suivante : vérifier que l'agent surveille bien les canaris.
  grep -c CANARY_SOC /var/ossec/etc/shared/agent.conf   # doit être > 0
  systemctl restart wazuh-agent

Test de détection (déclenche volontairement l'alerte 100670) :
  echo test >> /home/<user>/000_CANARY_SOC_NE_PAS_TOUCHER.xlsx
EOF
fi
