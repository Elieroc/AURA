# Capteur auditd — architecture LXC : auditd sur l'HÔTE Proxmox

## Le piège

Une flotte en **conteneurs LXC** sur un hôte Proxmox bare-metal a
`systemd-detect-virt` = `lxc` dans chaque conteneur.

**auditd ne peut PAS tourner dans un conteneur LXC** : le netlink audit est une
facilité du noyau de l'HÔTE, `CAP_AUDIT_CONTROL` est refusé au conteneur →
`auditctl`/`augenrules` renvoient `Operation not permitted`, `auditd.service`
échoue sur sa dépendance `audit-rules.service`. Aucun reboot n'y change rien.
Déployer auditd *dans* les conteneurs est donc un cul-de-sac : les règles
execve `1006xx`/`1007xx` n'y auront jamais de données.

**Ne JAMAIS `reboot` un conteneur depuis l'intérieur** : en LXC ça l'ARRÊTE sans
le relancer (`pct start` requis depuis l'hôte Proxmox).

## La bonne cible : l'hôte Proxmox

Le noyau étant partagé, **l'auditd de l'hôte capture l'execve de TOUS les
conteneurs**. Un seul agent Wazuh sur l'hôte Proxmox couvre la flotte entière.
Vérifié : un `cp /bin/true /tmp/x` exécuté DANS un conteneur apparaît bien dans
`/var/log/audit/audit.log` de l'hôte, remonte à l'agent de l'hôte et fait
tirer 100625 (exec depuis /tmp), 100634, 100658.

Installé par `scripts/pve-install-sensor.sh` (détection SEULE : agent Wazuh +
auditd + règles `zz-audit-wazuh.rules`, enrôlement manuel par clé car authd/1515
fermé). **Volontairement sans** user admin/sudo ni scripts active-response :
jamais de remédiation autonome sur l'hyperviseur (isoler l'hôte couperait tout).

État attendu : agent = hôte Proxmox, auditd `enabled=2` (immuable, `-e 2`),
règles execve chargées, agent Actif. Volume au repos ~0 (pas de flood).

## Limites connues (à raffiner)

- **Attribution** : un execve de conteneur remonte étiqueté agent = l'hôte, pas
  le conteneur d'origine. Le record audit porte le pid ; le mapping pid → CT
  (`/proc/<pid>/cgroup` contient `/lxc/<ctid>`) reste à câbler pour localiser
  l'action. En l'état on VOIT l'attaque (reverse shell, enum, exec /tmp), on ne
  la localise pas encore automatiquement.
- **Immuabilité** : `-e 2` ⇒ changer les règles audit exige un reboot de l'hôte
  (= tous les conteneurs). Considérer le ruleset comme figé.
- **Conteneurs** : peuvent garder une config auditd inerte (règles dans
  `/etc/audit/rules.d`, `<localfile>audit.log` dans ossec.conf pointant un
  fichier absent — warning bénin). Nettoyage optionnel, sans urgence.
- **Volume** : l'auditd hôte agrège l'execve de toute la flotte. Repos ≈ 0, mais
  surveiller que le manager ne sature pas si un conteneur devient exec-intensif
  (rate-limit audit `-r` ou exclusions si besoin — au prix d'angles morts).

## Reste dans les conteneurs (marche déjà, non-auditd)

FIM/syscheck (temps réel), journald (auth/sshd/pam), et une sonde réseau au
périmètre (ex. Suricata sur le pare-feu). Ce sont ces sources, pas auditd, qui
détectent par exemple un crontab suspect (via FIM).
