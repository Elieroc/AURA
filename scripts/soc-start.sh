#!/bin/sh
# Lancement du SOC par l'administrateur.
#
# Un seul point d'entrée : lit config/soc-ai.conf (la config de l'admin),
# exporte ce qui concerne la stack docker, démarre les conteneurs du soc-agent.
#
# Le mode training se pilote d'ici : avec TRAINING_ENABLED="true", le tout
# premier démarrage ouvre une fenêtre d'apprentissage de TRAINING_DAYS jours
# pendant laquelle le SOC n'analyse ni ne remédie rien — il apprend le bruit
# ambiant du SI et le transforme en whitelists. Cf. src/ai/soc_agent/training.py.
#
# Idempotent : relancer ce script ne rouvre PAS de fenêtre de training (une
# fenêtre déjà enregistrée en base suffit à l'inhiber).
set -eu

RACINE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONF=${SOC_AI_CONF:-$RACINE/config/soc-ai.conf}

if [ -f "$CONF" ]; then
    # shellcheck disable=SC1090  # chemin résolu à l'exécution
    . "$CONF"
else
    echo "soc-start: $CONF absent, valeurs par défaut" >&2
fi

# Valeurs par défaut alignées sur src/ai/soc_agent/config.py : le conteneur doit
# se comporter pareil, que la clé soit présente ou non dans soc-ai.conf.
export TRAINING_ENABLED="${TRAINING_ENABLED:-false}"
export TRAINING_DAYS="${TRAINING_DAYS:-7}"
export TRAINING_MIN_LEVEL="${TRAINING_MIN_LEVEL:-12}"
export TRAINING_MAX_LEVEL="${TRAINING_MAX_LEVEL:-15}"

# Compose racine unique (Wazuh/IRIS/Shuffle/soc-agent) : ne cible que les
# services soc-agent, pour garder le comportement historique de ce script
# (lancement/relance du seul soc-agent, pas de toute la stack). Pour tout
# démarrer d'un coup, faire `docker compose up -d` directement depuis la
# racine du dépôt.
cd "$RACINE"
docker compose up -d --build \
    soc-agent-db soc-agent-cycle soc-agent-reconcile \
    soc-agent-whitelist-task soc-training soc-agent-metrics \
    soc-agent-rule-tuning

if [ "$TRAINING_ENABLED" = "true" ]; then
    echo
    echo "Mode training ACTIF ($TRAINING_DAYS j) : le pipeline d'analyse"
    echo "(triage, cases IRIS, remédiation) est suspendu jusqu'à la clôture."
    echo "  état  : docker exec soc-training python -m soc_agent.training --etat"
    echo "  fin anticipée : docker exec soc-training python -m soc_agent.training --cloturer"
fi
