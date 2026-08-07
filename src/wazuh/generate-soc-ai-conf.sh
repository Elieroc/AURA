#!/usr/bin/env bash
#
# Génère soc-ai.conf (déployable sur agents + hôte manager forensique) à
# partir du .env racine — évite un second fichier maintenu à la main.
#
# Deux fichiers distincts, deux machines, deux jeux de clés :
#   - sur les AGENTS      -> /var/ossec/etc/soc-ai.conf   (WAZUH_MANAGER_IP)
#   - sur l'HÔTE MANAGER  -> /etc/soc-ai/soc-ai.conf      (bloc forensique)
# On peut déployer le MÊME fichier généré des deux côtés : chaque script ne
# lit que les clés qui le concernent. Format shell POSIX, sourcé par des
# scripts tournant EN ROOT — d'où le mode 640 à l'installation (cf. plus bas) :
# un fichier inscriptible par un autre compte serait une escalade directe.
#
# Usage :
#   ./src/wazuh/generate-soc-ai-conf.sh
#   # agents :
#   scp src/wazuh/soc-ai.conf <agent>:/tmp/soc-ai.conf
#   ssh <agent> 'sudo install -o root -g wazuh -m 640 /tmp/soc-ai.conf /var/ossec/etc/soc-ai.conf'
#   # manager :
#   sudo install -o root -g root -m 640 src/wazuh/soc-ai.conf /etc/soc-ai/soc-ai.conf

set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$RACINE/.env"
OUT="$RACINE/src/wazuh/soc-ai.conf"

[ -f "$ENV_FILE" ] || { echo "generate-soc-ai-conf: $ENV_FILE absent (cp .env.example .env d'abord)" >&2; exit 1; }

# shellcheck disable=SC1090
set -a
. "$ENV_FILE"
set +a

cat > "$OUT" <<EOF
# Généré depuis .env par generate-soc-ai-conf.sh — NE PAS ÉDITER À LA MAIN.
# Éditer .env puis relancer ce script.

WAZUH_MANAGER_IP="${WAZUH_MANAGER_IP:-}"
SOC_AI_NO_ISOLATE="${SOC_AI_NO_ISOLATE:-0}"

AGENT_SSH_USER="${AGENT_SSH_USER:-forensic}"
AGENT_SSH_KEY="${AGENT_SSH_KEY:-/etc/soc-ai/forensic_agent_ed25519}"
AGENT_KNOWN_HOSTS="${AGENT_KNOWN_HOSTS:-/etc/soc-ai/known_hosts_agents}"

EVIDENCE_HOST="${EVIDENCE_HOST:-}"
EVIDENCE_USER="${EVIDENCE_USER:-forensics}"
EVIDENCE_PATH="${EVIDENCE_PATH:-/var/lib/forensics}"
EVIDENCE_SSH_KEY="${EVIDENCE_SSH_KEY:-/etc/soc-ai/forensic_evidence_ed25519}"
EVIDENCE_KNOWN_HOSTS="${EVIDENCE_KNOWN_HOSTS:-/etc/soc-ai/known_hosts_evidence}"
EOF

chmod 600 "$OUT"
echo "généré : $OUT"
