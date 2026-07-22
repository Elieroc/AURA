#!/usr/bin/env bash
#
# Bench de QUALITÉ du triage — complément de run-bench.sh, qui ne mesure que la
# vitesse.
#
# Motivation : le premier passage a rendu "false_positive" sur une brute force
# SSH réussie depuis une IP notée 96/100 par AbuseIPDB. Avant d'en conclure que
# les modèles de cette taille sont inaptes, on écarte deux défauts de méthode :
#
#   1. /completion envoie le prompt BRUT, sans template de chat. Le modèle
#      n'est pas dans le format sur lequel il a été instruit. On compare avec
#      /v1/chat/completions, qui applique le template embarqué dans le GGUF.
#
#   2. triage.gbnf impose "verdict" en premier champ : le modèle tranche avec
#      zéro token de raisonnement derrière lui. triage-reason-first.gbnf place
#      "reason" d'abord, pour le même coût en tokens.
#
# Quatre combinaisons par modèle. La bonne réponse attendue ici est
# true_positive, avec une action d'investigation ou d'escalade.

set -euo pipefail

BIN_DIR="${1:-$HOME/.local/share/soc-ai/llama.cpp/build/bin}"
MODEL_DIR="${2:-$HOME/.local/share/soc-ai/models}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THREADS="${THREADS:-8}"
PORT="${PORT:-18081}"

for m in "${MODEL_DIR}"/Qwen3-4B-Instruct-2507-Q5_K_M.gguf \
         "${MODEL_DIR}"/Qwen3-8B-Q4_K_M.gguf; do
    echo "=============================================================="
    echo "$(basename "$m")"
    echo "=============================================================="
    "${BIN_DIR}/llama-server" -m "$m" -t "${THREADS}" -c 4096 \
        --host 127.0.0.1 --port "${PORT}" > "${HERE}/.quality-server.log" 2>&1 &
    SRV=$!
    # shellcheck disable=SC2064
    trap "kill ${SRV} 2>/dev/null" EXIT
    until curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; do
        kill -0 "${SRV}" 2>/dev/null || { tail -20 "${HERE}/.quality-server.log"; exit 1; }
        sleep 2
    done

    python3 "${HERE}/quality_probe.py" "http://127.0.0.1:${PORT}" "${HERE}"

    kill "${SRV}" 2>/dev/null; wait "${SRV}" 2>/dev/null || true
    trap - EXIT
    echo
done

rm -f "${HERE}/.quality-server.log"
