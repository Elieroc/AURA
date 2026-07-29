#!/bin/sh
# Enrichit l'audit.log de l'hôte Proxmox avec le CONTENEUR LXC d'origine.
#
# Problème : l'auditd de l'hôte capture l'execve de TOUS les conteneurs (noyau
# partagé), mais le record ne dit pas DE QUEL conteneur — tout remonte étiqueté
# agent « pve ». Le cgroup du process le dit : /proc/<pid>/cgroup contient
# `/lxc/<ctid>/...` pour un process de conteneur (cgroup v2, une seule ligne).
#
# Suit audit.log, résout le conteneur et réécrit chaque ligne SYSCALL avec
# ` lxc_ct=<nom>` (ou host / unknown), dans audit-soc.log que l'agent Wazuh lit.
# Un décodeur en extrait le champ `lxc_ct`.
#
# Course : à l'écriture du record, un exec court peut être terminé (/proc/<pid>
# disparu). On résout `pid` PUIS, en repli, `ppid` (shell parent, encore vivant).
# Écrit en AWK mono-process (pas de fork par ligne) pour tenir le débit — un
# enrichisseur trop lent prend du retard et rate la fenêtre où /proc/<pid> existe.
# Les exec qui comptent (reverse shell, listener, interpréteur) vivent assez.
set -u
SRC=/var/log/audit/audit.log
OUT=/var/log/audit/audit-soc.log
MAP=/run/soc-ct-map

# Rafraîchit le cache ctid->nom en tâche de fond (pct list, périodique).
( while : ; do
    pct list 2>/dev/null | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1, $NF}' > "$MAP.tmp" \
      && mv "$MAP.tmp" "$MAP"
    sleep 60
  done ) &

# -n0 : pas d'historique ; -F : suit les rotations.
exec tail -n0 -F "$SRC" 2>/dev/null | awk -v map="$MAP" '
  function load_map(   k,v) {
    delete NAME; while ((getline line < map) > 0) { split(line,a," "); NAME[a[1]]=a[2] } close(map)
  }
  function name(id) { return (id in NAME) ? NAME[id] : id }
  function resolve(p,   f,l) {
    if (p=="") return "";
    f="/proc/" p "/cgroup"
    if ((getline l < f) > 0) { close(f)
      if (match(l, /lxc\/[0-9]+/)) return name(substr(l,RSTART+4,RLENGTH-4))
      return "host"
    }
    close(f); return ""
  }
  BEGIN { load_map(); n=0 }
  {
    if ($0 ~ /type=SYSCALL/) {
      if ((++n % 2000) == 0) load_map()
      pid=""; ppid=""
      if (match($0, / pid=[0-9]+/))  pid=substr($0, RSTART+5, RLENGTH-5)
      if (match($0, / ppid=[0-9]+/)) ppid=substr($0, RSTART+6, RLENGTH-6)
      ct=resolve(pid); if (ct=="") ct=resolve(ppid); if (ct=="") ct="unknown"
      print $0 " lxc_ct=" ct
    } else print $0
    fflush()
  }
' >> "$OUT"
