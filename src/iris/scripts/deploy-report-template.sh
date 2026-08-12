#!/usr/bin/env bash
#
# Déploie (ou remplace) un template de rapport Markdown dans DFIR-IRIS.
#
# IRIS n'a pas d'endpoint de mise à jour : /manage/templates/add crée toujours
# une nouvelle entrée, avec un nom de fichier interne aléatoire. Rejouer ce
# script sans nettoyage empilerait donc des doublons dans la liste « Generate
# report » du case. On supprime d'abord toute entrée portant le même nom, puis
# on ajoute — l'id du template change à chaque déploiement, c'est le nom qui
# fait foi.
#
# La clé API doit appartenir à un compte `server_administrator` : les routes
# /manage/templates/* sont refusées aux autres.
#
# Usage :
#   IRIS_URL=https://127.0.0.1:8443 IRIS_API_KEY=… \
#     ./deploy-report-template.sh ../report-templates/incident-technique-fr.md \
#       "Aura-SOC — Rapport d'incident technique (FR)"

set -euo pipefail

FICHIER="${1:?usage: $0 <template.md> [nom]}"
# Valeurs par défaut posées à part : une apostrophe dans un ${VAR:-défaut}
# ouvre une citation pour bash et casse la substitution.
NOM_DEFAUT="Aura-SOC — Rapport d'incident technique (FR)"
DESCRIPTION_DEFAUT="Rapport d'investigation complet : synthèse, analyse IA, machines, exposition aux vulnérabilités, IOC, chronologie, remédiations, preuves."
NOM="${2:-$NOM_DEFAUT}"
DESCRIPTION="${DESCRIPTION:-$DESCRIPTION_DEFAUT}"
# %code_name% = doc_id (AAMMJJ_HHMM). On n'injecte PAS %case_name% : les titres
# de case du soc-agent contiennent des crochets et pourraient contenir un « / »,
# qui casserait le chemin d'écriture du fichier généré.
FORMAT_NOM="${FORMAT_NOM:-Aura-SOC_rapport-incident_%code_name%}"
LANGUE="${LANGUE:-1}"   # 1 = french (table languages)
TYPE="${TYPE:-1}"       # 1 = Investigation, 2 = Activities (table report_type)

: "${IRIS_URL:?IRIS_URL manquant}"
: "${IRIS_API_KEY:?IRIS_API_KEY manquant}"

[[ -f "$FICHIER" ]] || { echo "template introuvable : $FICHIER" >&2; exit 1; }

api() { curl -sk -H "Authorization: Bearer ${IRIS_API_KEY}" "$@"; }

# Suppression des versions précédentes portant le même nom. La liste renvoie
# `name`, pas `report_name` (le champ de l'ajout) — vérifié sur v2.4.27.
export NOM
ANCIENS=$(api "${IRIS_URL}/manage/templates/list" \
  | python3 -c "import json,sys,os
d=json.load(sys.stdin).get('data') or []
print(' '.join(str(t['id']) for t in d if t.get('name')==os.environ['NOM']))" 2>/dev/null || true)
for id in ${ANCIENS:-}; do
  echo "suppression de l'ancien template #${id}"
  api -X POST "${IRIS_URL}/manage/templates/delete/${id}" >/dev/null
done

REPONSE=$(api -X POST "${IRIS_URL}/manage/templates/add" \
  -F "report_name=${NOM}" \
  -F "report_description=${DESCRIPTION}" \
  -F "report_name_format=${FORMAT_NOM}" \
  -F "report_language=${LANGUE}" \
  -F "report_type=${TYPE}" \
  -F "file=@${FICHIER}")

echo "$REPONSE"
echo "$REPONSE" | grep -q '"status": "success"' || exit 1
