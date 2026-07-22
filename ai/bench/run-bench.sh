#!/usr/bin/env bash
#
# Bench llama.cpp sur l'hôte du SOC — phase 0.
#
# Objectif : savoir si un triage LLM est tenable sur CPU avant d'écrire le
# pipeline. Deux mesures, dans cet ordre d'importance :
#
#   pp (prompt processing / prefill)  — le goulot réel. C'est le temps avant le
#                                       premier token, proportionnel à la
#                                       taille du contexte.
#   tg (token generation)             — le débit de sortie. Secondaire, nos
#                                       réponses font ~100 tokens.
#
# La mesure tg à profondeur non nulle (-d) est la seule honnête : générer avec
# 2000 tokens déjà dans le cache KV est plus lent que de générer à vide, et
# c'est notre cas d'usage.
#
# Usage :  ./run-bench.sh [chemin/vers/llama.cpp/build/bin] [dossier/modeles]

set -euo pipefail

BIN_DIR="${1:-$HOME/.local/share/soc-ai/llama.cpp/build/bin}"
MODEL_DIR="${2:-$HOME/.local/share/soc-ai/models}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SMALL="${MODEL_DIR}/Qwen3-4B-Instruct-2507-Q5_K_M.gguf"
LARGE="${MODEL_DIR}/Qwen3-8B-Q4_K_M.gguf"

# 8 threads = cœurs physiques. Le SMT dégrade l'inference (les deux threads
# d'un cœur se disputent les mêmes unités vectorielles), et on laisse de la
# marge à Wazuh : le manager ne doit pas rater une alerte parce que le modèle
# réfléchit.
THREADS="${THREADS:-8}"

for f in "${SMALL}" "${LARGE}"; do
    [[ -f "$f" ]] || { echo "Modèle manquant : $f" >&2; exit 1; }
done

echo "###############################################################"
echo "# Contexte machine"
echo "###############################################################"
lscpu | grep -E "^Model name|^Thread|^Core|^Socket" || true
free -h | head -2
echo "threads utilisés : ${THREADS}"
echo

echo "###############################################################"
echo "# 1. Débit brut — prefill et génération"
echo "###############################################################"
# -p : prefill de N tokens.  -n : génération de N tokens.
# -d : profondeur du cache KV pendant la génération.
# 512 / 2048 encadrent notre budget de contexte ; 4096 montre le coût d'un
# dépassement, pour objectiver la limite qu'on s'impose.
for m in "${SMALL}" "${LARGE}"; do
    echo "--- $(basename "$m")"
    "${BIN_DIR}/llama-bench" -m "$m" -t "${THREADS}" \
        -p 512,2048,4096 -n 128 -d 0,2048 -r 3 2>/dev/null
    echo
done

echo "###############################################################"
echo "# 2. Triage réel — alerte Wazuh, sortie contrainte par grammaire"
echo "###############################################################"
#
# On passe par llama-server et pas llama-cli : c'est le chemin de production
# (le soc-agent parlera HTTP), son endpoint /completion renvoie les timings
# décomposés prefill/génération, et il porte le prefix caching qui est notre
# principal levier d'optimisation.
#
# Deux requêtes identiques par modèle : la première paye le prefill complet, la
# seconde doit le retrouver en cache. L'écart mesure ce que le prefix caching
# nous rapporte réellement.

PORT="${PORT:-18080}"
PROMPT_JSON=$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "${HERE}/prompt-triage.txt")
GRAMMAR_JSON=$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "${HERE}/triage.gbnf")

run_triage() {
    local label="$1"
    curl -s "http://127.0.0.1:${PORT}/completion" \
        -H "Content-Type: application/json" \
        -d "{\"prompt\":${PROMPT_JSON},\"grammar\":${GRAMMAR_JSON},\"n_predict\":200,\"temperature\":0.2,\"seed\":42,\"cache_prompt\":true}" \
    | python3 -c '
import json, sys
r = json.load(sys.stdin)
t = r["timings"]
print("  sortie   :", r["content"].strip()[:300])
print("  prefill  : %5d tokens en %7.2f s  (%.1f t/s)" % (
    t["prompt_n"], t["prompt_ms"] / 1000, t["prompt_per_second"]))
print("  génération: %4d tokens en %7.2f s  (%.1f t/s)" % (
    t["predicted_n"], t["predicted_ms"] / 1000, t["predicted_per_second"]))
print("  TOTAL    : %.2f s" % ((t["prompt_ms"] + t["predicted_ms"]) / 1000))
'
}

for m in "${SMALL}" "${LARGE}"; do
    echo "--- $(basename "$m")"
    "${BIN_DIR}/llama-server" -m "$m" -t "${THREADS}" -c 4096 \
        --host 127.0.0.1 --port "${PORT}" > "${HERE}/.server.log" 2>&1 &
    SRV=$!
    # shellcheck disable=SC2064
    trap "kill ${SRV} 2>/dev/null" EXIT

    until curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; do
        kill -0 "${SRV}" 2>/dev/null || { echo "serveur mort, cf. ${HERE}/.server.log"; exit 1; }
        sleep 2
    done

    echo " [1] à froid"
    run_triage froid
    echo " [2] même prompt, prefix cache chaud"
    run_triage chaud

    kill "${SRV}" 2>/dev/null; wait "${SRV}" 2>/dev/null || true
    trap - EXIT
    echo
done

rm -f "${HERE}/.server.log"
