# Rollout du capteur auditd sur la flotte

## Pourquoi

Mesuré le 2026-07-29 : **auditd est absent sur toute la flotte** (0 event
`execve`/`audit` dans `alerts`, tous agents confondus). Les agents ont été
enrôlés sans auditd. Conséquence : les ~15 règles comportementales
`1006xx`/`1007xx` (reverse shell, fileless, énumération privesc, credential
access, suid, cve, exploit) sont validées au `wazuh-logtest` mais **n'ont jamais
eu de télémétrie live** — elles sont mortes en prod.

C'est la moitié de l'explication du case IRIS 13 incomplet (brute-force SSH →
linpeas → C2 → pivot → credential harvest → persistance : seule la persistance
crontab a été vue, via FIM). L'autre moitié : Suricata étouffé par un flood
`stream-events` (corrigé, cf. `[[soc-ai-suricata-flood-blindness]]`).

## Cibles

Agents Linux (auditd) : `admin` (001), `nginx-proxy-manager` (002),
`bookstack` (003), `nextcloud` (004), `jellyfin` (005), `wireguard` (006),
`adguard-home` (007), + l'hôte manager (`192.168.3.5`, monitoring local 000).
**Exclu** : `home-r-pf01.pfsense` (008) = FreeBSD, audit natif Suricata/BSM.

## REBOOT OBLIGATOIRE

Pilote sur jellyfin (2026-07-29) : après pose des fichiers,
`systemctl start auditd` échoue (`Error sending status request (Operation not
permitted)` ; `auditd.service` échoue sur dépendance `audit-rules`).
**systemd-journald tient le socket netlink audit** — `augenrules --load` à chaud
ne peut pas gagner. Le **reboot** est le seul moyen d'activer proprement : au
boot journald relâche le socket, `auditd` démarre en premier, charge les règles
puis `-e 2` verrouille en immuable. Prévoir une fenêtre de maintenance.

## Procédure par hôte (dans la fenêtre)

Depuis `admin.lab` (accès aux hôtes du lab), pour chaque cible :

```sh
# 1. Poser le script + les règles
scp deploy-auditd-sensor.sh zz-audit-wazuh.rules root@<host>.lab:/tmp/
# 2. Stager (idempotent, pas de coupure) — dira "REBOOT REQUIS"
ssh root@<host>.lab 'chmod +x /tmp/deploy-auditd-sensor.sh; /tmp/deploy-auditd-sensor.sh'
# 3. Rebooter (fenêtre planifiée)
ssh root@<host>.lab 'reboot'
# 4. Après reboot — vérifier que le capteur est ACTIF
ssh root@<host>.lab 'auditctl -s | grep -E "^enabled"; auditctl -l | grep -c execveat'
#    Attendu : enabled 1  (ou 2 immuable) ; execveat >= 1
```

L'hôte manager (`192.168.3.5`) : accès SSH direct root, même procédure.

`deploy-auditd-sensor.sh` et `zz-audit-wazuh.rules` sont dans `scripts/` et
`wazuh/config/agent/`.

## État actuel

- `jellyfin` (005) : **déjà staged** le 2026-07-29 (fichiers posés, `ossec.conf`
  localfile audit ajouté). Reste à **rebooter** pour activer. Agent Wazuh sain
  entre-temps (aucune dégradation du pipeline).
- Tous les autres : à faire.

## Vérification globale post-rollout

Sur `socagent-db` : `select agent_name, count(*) filter (where raw::text ilike
'%execve%') from alerts where ts > now()-interval '1h' group by 1;` — chaque
hôte rebooté doit produire des `execve`. Puis rejouer une action de test
(exécuter un binaire depuis `/tmp`, `nc -e`, lire `/etc/shadow`) et confirmer que
la règle `1006xx` correspondante fire.
