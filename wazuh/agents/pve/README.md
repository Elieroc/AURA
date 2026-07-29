# Capteur SOC sur l'hôte Proxmox (`pve.lab`)

La flotte est en conteneurs **LXC** où auditd est impossible (`CAP_AUDIT_CONTROL`
refusé). Le noyau étant partagé, l'auditd de l'**hôte** capte l'execve de tous
les conteneurs. Détail et pièges : `../../AUDITD-ROLLOUT.md`.

## Fichiers

- `../../../scripts/pve-install-sensor.sh` — installe l'agent Wazuh (009 = pve) +
  auditd + règles `zz-audit-wazuh.rules`. Détection SEULE (pas de remédiation
  autonome sur l'hyperviseur).
- `soc-audit-enrich.sh` + `soc-audit-enrich.service` — **attribution conteneur**.

## Attribution pid → conteneur

L'auditd de l'hôte voit l'execve de tous les conteneurs mais tout remonterait
étiqueté agent `pve`. `/proc/<pid>/cgroup` d'un process de conteneur contient
`/lxc/<ctid>/…` : l'enrichisseur suit `audit.log`, résout le conteneur et réécrit
chaque ligne SYSCALL avec ` lxc_ct=<nom>` dans `audit-soc.log`, que l'agent Wazuh
lit à la place. Côté pipeline, `soc_agent.iris._conteneurs` l'extrait du full_log
pour que le case IRIS dise « jellyfin » et pas « pve » (valeurs réelles, note
locale — jamais envoyé au LLM : c'est un nom d'hôte).

### Installation

    scp soc-audit-enrich.sh root@pve.lab:/usr/local/sbin/
    scp soc-audit-enrich.service root@pve.lab:/etc/systemd/system/
    ssh root@pve.lab 'systemctl enable --now soc-audit-enrich'
    # puis repointer l'agent : ossec.conf <location> audit.log -> audit-soc.log

### Limite : best-effort

La résolution se fait a posteriori via `/proc`. Un exec **court** (id, whoami)
peut avoir disparu avant lecture → `lxc_ct=unknown` (repli sur `ppid`, le shell
parent, quand il vit encore). Les exec **longs** qui portent les vraies alertes
(reverse shell, listener, interpréteur, script linpeas) vivent assez et
résolvent — vérifié le 2026-07-29 : un exec persistant dans jellyfin remonte
`lxc_ct=jellyfin` jusqu'à la base soc_agent. Le bruit `unknown` est constitué
d'exec courts bénins qui ne déclenchent pas de règle.

Pas de mapping natif (`audit_containerid`/`contid` absent sur ce noyau). `-e 2`
rend les règles audit immuables : les changer exige un reboot de pve.
