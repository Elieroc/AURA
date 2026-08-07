# Capteur auditd — architecture LXC : auditd sur l'HÔTE Proxmox

## Le piège découvert le 2026-07-29

Toute la flotte est en **conteneurs LXC** sur un hôte Proxmox (`pve.lab`,
bare-metal). `systemd-detect-virt` = `lxc` sur jellyfin, bookstack, adguard,
wireguard, nginx-proxy-manager, nextcloud, admin, et le SOC-core (192.168.10.5).

**auditd ne peut PAS tourner dans un conteneur LXC** : le netlink audit est une
facilité du noyau de l'HÔTE, `CAP_AUDIT_CONTROL` est refusé au conteneur →
`auditctl`/`augenrules` renvoient `Operation not permitted`, `auditd.service`
échoue sur sa dépendance `audit-rules.service`. Aucun reboot n'y change rien.
Déployer auditd *dans* les conteneurs (ancienne approche de ce runbook) est donc
un cul-de-sac : les règles execve `1006xx`/`1007xx` n'y auront jamais de données.

**Ne JAMAIS `reboot` un conteneur depuis l'intérieur** : en LXC ça l'ARRÊTE sans
le relancer (nextcloud est resté down le 2026-07-29 → `pct start` requis sur pve).

## La bonne cible : l'hôte Proxmox

Le noyau étant partagé, **l'auditd de l'hôte capture l'execve de TOUS les
conteneurs**. Un seul agent Wazuh sur `pve.lab` couvre la flotte entière.
Vérifié le 2026-07-29 : un `cp /bin/true /tmp/x` exécuté DANS le conteneur
jellyfin apparaît bien dans `/var/log/audit/audit.log` de pve, remonte à l'agent
009 (pve) et fait tirer 100625 (exec depuis /tmp), 100634, 100658.

Installé par `scripts/pve-install-sensor.sh` (détection SEULE : agent Wazuh +
auditd + règles `zz-audit-wazuh.rules`, enrôlement manuel par clé car authd/1515
fermé). **Volontairement sans** user `wazuh-admin`/sudo ni scripts
active-response : jamais de remédiation autonome sur l'hyperviseur (isoler pve
couperait tout).

État : agent **009 = pve** (192.168.10.252), auditd `enabled=2` (immuable, `-e 2`),
2 règles execve chargées, agent Actif. Volume au repos ~0 (pas de flood).

## Limites connues (à raffiner)

- **Attribution** : un execve de conteneur remonte étiqueté agent `pve`, pas le
  conteneur d'origine. Le record audit porte le pid ; le mapping pid → CT
  (`/proc/<pid>/cgroup` contient `/lxc/<ctid>`) reste à câbler pour localiser
  l'action. En l'état on VOIT l'attaque (reverse shell, enum, exec /tmp), on ne
  la localise pas encore automatiquement.
- **Immuabilité** : `-e 2` ⇒ changer les règles audit exige un reboot de pve
  (= tous les conteneurs). Considérer le ruleset comme figé.
- **Conteneurs** : gardent la config auditd inerte posée le 2026-07-29 (règles
  dans `/etc/audit/rules.d`, `<localfile>audit.log` dans ossec.conf pointant un
  fichier absent — warning bénin). Nettoyage optionnel, sans urgence.
- **Volume** : l'auditd hôte agrège l'execve de toute la flotte. Repos ≈ 0, mais
  surveiller que le manager ne sature pas si un conteneur devient exec-intensif
  (rate-limit audit `-r` ou exclusions si besoin — au prix d'angles morts).

## Reste dans les conteneurs (marche déjà, non-auditd)

FIM/syscheck (temps réel), journald (auth/sshd/pam), et Suricata au périmètre
(pfSense). C'est ce qui a détecté le crontab du case 13 (via FIM).
