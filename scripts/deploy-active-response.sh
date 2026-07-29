#!/usr/bin/env bash
#
# Déploie les scripts active-response SOC-AI sur des agents Wazuh déjà installés.
#
# Pourquoi ce script existe : `install-agent.sh` ne les posait pas, et un agent
# sans ces fichiers fait échouer TOUTE remédiation en SILENCE — l'ar.conf poussé
# par le manager déclare bien `firewall-drop.sh`, l'API Wazuh répond 200 (elle ne
# fait que transmettre la commande), et l'agent ne trouve pas l'exécutable. Le
# seul indice est l'absence de ligne dans son /var/ossec/logs/active-responses.log.
# C'est exactement ce qui rendait le blocage d'IP inopérant sur le lab.
#
# Les binaires natifs livrés par le paquet ne suffisent pas : ils lisent la cible
# dans l'alerte (alert.data.srcip / dstuser) et échouent sur tout appel piloté par
# extra_args (API, MCP, soc-agent).
#
# Usage (depuis une machine qui joint les agents en SSH root par clé) :
#   ./deploy-active-response.sh <hôte> [<hôte> ...]
#   ./deploy-active-response.sh --local            # pose les scripts sur CETTE machine
#
# Exemple lab (à lancer depuis admin.lab, seul hôte qui joint tous les agents) :
#   ./deploy-active-response.sh 192.168.2.11 192.168.2.18 192.168.6.4
#
# Vérification de bout en bout après coup (depuis le manager) :
#   TOK=$(curl -sk -u "$API_USER:$API_PASS" -X POST \
#     "https://127.0.0.1:55000/security/user/authenticate?raw=true")
#   curl -sk -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
#     -X PUT "https://127.0.0.1:55000/active-response?agents_list=003" \
#     -d '{"command":"!firewall-drop.sh","arguments":["198.51.100.77"]}'
#   # puis, sur l'agent : tail /var/ossec/logs/active-responses.log && iptables -S INPUT
#
# Le préfixe `!` est obligatoire : il désigne le nom de FICHIER littéral. Sans lui
# l'API résout un `<command>` d'ossec.conf et répond 1652 « command is not defined ».

set -euo pipefail

AR_SRC="$(cd "$(dirname "$0")/../wazuh/active-response" && pwd)"
AR_DST="/var/ossec/active-response/bin"

[ $# -ge 1 ] || { grep '^#' "$0" | sed 's/^# \?//'; exit 1; }

poser_local() {
  [ -d "$AR_DST" ] || { echo "ERREUR: $AR_DST absent (agent Wazuh non installé ?)" >&2; exit 1; }
  for f in "$AR_SRC"/*.sh; do
    install -m 750 -o root -g wazuh "$f" "$AR_DST/$(basename "$f")"
  done
  echo "  $(ls -1 "$AR_SRC"/*.sh | wc -l) script(s) déployé(s) sur $(hostname)"
}

if [ "$1" = "--local" ]; then
  poser_local
  exit 0
fi

# Transfert par tar sur stdin : un seul aller-retour SSH par hôte, et les droits
# (root:wazuh, 750) sont posés à l'arrivée plutôt que hérités de la source.
for h in "$@"; do
  echo "== $h"
  tar -C "$AR_SRC" -czf - ./*.sh | ssh -o BatchMode=yes -o ConnectTimeout=10 "root@$h" '
    set -e
    [ -d /var/ossec/active-response/bin ] || { echo "  agent Wazuh absent, ignoré" >&2; exit 1; }
    tar -xzf - -C /var/ossec/active-response/bin
    cd /var/ossec/active-response/bin
    chown root:wazuh ./*.sh && chmod 750 ./*.sh
    echo "  OK ($(ls -1 ./*.sh | wc -l) scripts)"
    # Sans iptables ni nft, firewall-drop.sh ne peut rien bloquer. Il le
    # journalise, mais autant le voir au déploiement.
    command -v iptables >/dev/null || command -v nft >/dev/null \
      || echo "  AVERTISSEMENT: ni iptables ni nft — le blocage d IP échouera"
  ' || echo "  ECHEC sur $h"
done
