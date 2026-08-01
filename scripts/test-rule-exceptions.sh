#!/bin/sh
# Rejeu des EXCLUSIONS de regles (niveau 0) contre wazuh-logtest.
#
# Complement de test-detection-rules.sh, qui ne peut pas les couvrir : ses logs
# de synthese perdent euid/auid/cwd au decodage, et ce sont precisement les
# champs des exclusions. Les cas sont donc construits depuis de VRAIES alertes
# par scripts/build-exception-cases.py, puis mutes pour fabriquer le
# contre-exemple attaquant.
#
# Chaque exclusion est testee dans les DEUX sens : le faux positif doit etre
# tu, et le meme evenement avec la signature d'un attaquant doit toujours tirer.
# Sans le second sens, une exclusion trop large passe le test.
#
# Piege : wazuh-logtest ecrit sur STDERR (cf. test-detection-rules.sh).
#
# Usage :  ./scripts/test-rule-exceptions.sh [fichier_cas] [nom_conteneur]
set -u
CAS="${1:-/tmp/cases.tsv}"
CT="${2:-wazuh-wazuh.manager-1}"
ok=0; ko=0

while IFS='	' read -r want desc log; do
  [ -z "$want" ] && continue
  out=$(printf '%s\n' "$log" | docker exec -i "$CT" /var/ossec/bin/wazuh-logtest 2>&1 \
        | sed -n '/Phase 3/,$p')
  got=$(echo "$out" | grep -m1 -E "^[[:space:]]+id: '"    | sed "s/.*id: '\([0-9]*\)'.*/\1/")
  lvl=$(echo "$out" | grep -m1 -E "^[[:space:]]+level: '" | sed "s/.*level: '\([0-9]*\)'.*/\1/")
  if [ "$got" = "$want" ]; then
    ok=$((ok+1)); printf 'OK   %-62s -> %s (niv %s)\n' "$desc" "${got:-aucune}" "${lvl:-0}"
  else
    ko=$((ko+1)); printf 'FAIL %-62s -> attendu %s, obtenu %s (niv %s)\n' "$desc" "$want" "${got:-aucune}" "${lvl:-0}"
  fi
done < "$CAS"

echo
echo "resultat : $ok OK, $ko FAIL"
[ "$ko" -eq 0 ]
