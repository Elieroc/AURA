#!/usr/bin/env bash
#
# Déploie le CAPTEUR auditd sur un agent Wazuh DÉJÀ ENRÔLÉ.
#
# Pourquoi ce script existe séparément de install-agent.sh : des agents peuvent
# avoir été enrôlés SANS auditd. Un déploiement l'a vécu : auditd absent sur
# toute la flotte (0 event execve/auditd, cf. `alerts`), donc les ~15 règles
# comportementales 1006xx/1007xx (reverse shell, fileless, énumération privesc,
# credential access, suid, cve, exploit) n'avaient JAMAIS de télémétrie — elles
# étaient validées au logtest mais mortes en prod.
#
# Ce script est l'extrait auditd de install-agent.sh, rendu idempotent et sans
# l'enrôlement / le user d'admin / les scripts AR (déjà en place sur un agent vivant).
#
# Usage (en root sur la machine cible, avec zz-audit-wazuh.rules dans le même dossier
# OU dans ../src/wazuh/config/agent/) :
#   ./deploy-auditd-sensor.sh
#
# REBOOT : `-e 2` (dernière ligne des règles) rend la config d'audit immuable. Au
# PREMIER chargement `augenrules --load` réussit à chaud. S'il échoue (audit déjà
# verrouillé) OU si systemd-journald tient le socket netlink audit, le script le
# signale et un REBOOT est requis pour activer le capteur. Rien d'autre ne casse.
set -euo pipefail

log() { printf '%s\n' "$*"; }

[ "$(id -u)" = "0" ] || { echo "ERREUR: exécuter en root" >&2; exit 1; }

# Localise le jeu de règles (à côté du script, ou dans l'arbo repo)
HERE="$(cd "$(dirname "$0")" && pwd)"
for c in "$HERE/zz-audit-wazuh.rules" "$HERE/../src/wazuh/config/agent/zz-audit-wazuh.rules"; do
  [ -f "$c" ] && { RULES_SRC="$c"; break; }
done
[ -n "${RULES_SRC:-}" ] || { echo "ERREUR: zz-audit-wazuh.rules introuvable" >&2; exit 1; }

log "[1/5] Paquet auditd"
if ! command -v auditctl >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq auditd audispd-plugins >/dev/null
fi

log "[2/5] Règles auditd -> /etc/audit/rules.d/zz-audit-wazuh.rules"
# Préfixe zz- OBLIGATOIRE : augenrules concatène en collation C et audit.rules Debian
# commence par -D (purge). Un nom < zz- se ferait effacer au chargement suivant.
install -m 640 -o root -g root "$RULES_SRC" /etc/audit/rules.d/zz-audit-wazuh.rules
rm -f /etc/audit/rules.d/audit-wazuh.rules   # ancien nom chargé trop tôt, si présent

# /etc/ld.so.preload doit EXISTER pour être surveillable (watch sur un inode absent
# n'arme rien ; la création par un rootkit userland passerait inaperçue).
[ -e /etc/ld.so.preload ] || { : > /etc/ld.so.preload; chmod 644 /etc/ld.so.preload; }

log "[3/5] local_internal_options : autorise les <localfile><command> de agent.conf"
LIO="/var/ossec/etc/local_internal_options.conf"
grep -q "^logcollector.remote_commands=1" "$LIO" 2>/dev/null || \
  printf '# Aura-SOC : autorise les <localfile><command> poussés par agent.conf\nlogcollector.remote_commands=1\n' >> "$LIO"

log "[4/5] ossec.conf : localfile audit.log"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
NEED_RESTART=0
if ! grep -q "log_format>audit<" "$OSSEC_CONF" 2>/dev/null; then
  python3 - "$OSSEC_CONF" <<'PYEOF'
import sys
path = sys.argv[1]
content = open(path).read()
insert = "  <localfile>\n    <log_format>audit</log_format>\n    <location>/var/log/audit/audit.log</location>\n  </localfile>\n\n"
marker = "</ossec_config>"
idx = content.rfind(marker)
open(path, "w").write(content[:idx] + insert + content[idx:])
PYEOF
  NEED_RESTART=1
fi

log "[5/5] Activation auditd + chargement des règles"
systemctl enable --now auditd >/dev/null 2>&1 || true
REBOOT_REQUIRED=0
if ! augenrules --load >/dev/null 2>&1; then
  REBOOT_REQUIRED=1
fi
# Vérifie l'état réel du noyau (le vrai juge, pas le service)
ENABLED="$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')"
HAVE_EXECVE="$(auditctl -l 2>/dev/null | grep -c execveat || true)"
[ "$NEED_RESTART" = "1" ] && systemctl restart wazuh-agent >/dev/null 2>&1 || true

echo "---------------------------------------------"
echo "auditd service : $(systemctl is-active auditd 2>/dev/null || echo inconnu)"
echo "audit noyau    : enabled=${ENABLED:-?}"
echo "règles execve  : ${HAVE_EXECVE} chargée(s)"
if [ "$ENABLED" = "1" ] && [ "${HAVE_EXECVE:-0}" -ge 1 ]; then
  echo "RESULTAT       : capteur ACTIF — les règles 1006xx/1007xx voient enfin les execve."
else
  echo "RESULTAT       : capteur PAS ENCORE ACTIF."
  echo "                 Cause probable : audit immuable (-e 2) ou journald tient le socket netlink."
  echo "                 >>> REBOOT REQUIS pour activer le capteur. Après reboot, re-vérifier :"
  echo "                     auditctl -s | grep enabled ; auditctl -l | grep -c execveat"
fi
