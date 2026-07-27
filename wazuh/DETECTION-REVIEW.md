# Révision des règles High/Critical — 2026-07-27

Revue déclenchée par un constat de purple teaming : beaucoup de techniques
rejouées sur `debian-vm` ne déclenchaient rien. Périmètre : les règles locales de
niveau ≥ 12, plus les trous que la revue a mis au jour.

Le ruleset **natif** est hors périmètre après vérification : 376 règles natives
de niveau ≥ 12 existent, mais la part Linux se limite à `rpc.statd`, `WU-FTPD
2.6` et `Solaris cachefsd`. Toute la détection utile de cette infra est portée
par `local_rules.xml`.

---

## Le vrai problème n'était pas les règles

Diagnostic initial, sur l'agent live :

```
$ auditctl -s
enabled 0      # audit noyau désactivé
pid 544        # auditd tourne pourtant
```

Dernier événement dans `/var/log/audit/audit.log` : **2 h plus tôt**.
`ausearch -k audit-wazuh-c` sur les 5 dernières minutes : **0**.

**19 des 24 règles locales de niveau ≥ 12 dépendent de `if_group audit`.** Elles
étaient inertes. Sur l'historique complet des alertes, 4 règles seulement avaient
déjà tiré en conditions réelles (100653, 100661, 100701). Ce n'était pas un
problème de regex trop étroite : le capteur était éteint.

### Cause racine

Ce n'était pas non plus une action hostile ni une erreur d'exploitation. Le
journal noyau donne :

```
audit: CONFIG_CHANGE op=set audit_enabled=0 old=1 auid=4294967295 res=1
```

émis par **systemd-journald à chaque redémarrage du service** — déclenché ici par
le logrotate quotidien. Le SOC devenait donc aveugle par intermittence, sans
intervention extérieure et sans la moindre alerte.

**Correction** : `-e 2` (configuration d'audit immuable) dans
`wazuh/config/agent/zz-audit-wazuh.rules`. Vérifié sur l'agent :

```
$ sudo systemctl restart systemd-journald && auditctl -s | head -1
enabled 2                                    # journald ne peut plus l'éteindre
$ sudo auditctl -e 0
Error sending enable request (Operation not permitted)   # ni un attaquant
```

Contrepartie assumée : toute modification ultérieure des règles auditd exige un
redémarrage de la machine.

---

## Phase 0 — trous de capteur

| # | Trou | Correction |
|---|------|-----------|
| C1 | `enabled 0` | `-e 2` immuable (cause racine ci-dessus) |
| C2 | `-S execve` seul, pas `execveat` | ajouté — `fexecve`, memfd et DDexec passent par `execveat` : les règles fileless 100630/100631 ne pouvaient pas se déclencher |
| C3 | `arch=b64` seul | `arch=b32` ajouté — un binaire 32 bits s'exécutait sans aucun événement |
| C4 | Aucun watch fichier | watches sur shadow, passwd, sudoers, cron, systemd, pam, ld.so.preload, /etc/audit |
| C5 | `-e 1` | → `-e 2` |
| C6 | **Ordre de chargement** : `audit-wazuh.rules` était concaténé AVANT le `audit.rules` de Debian, qui commence par `-D` | renommé `zz-audit-wazuh.rules` (collation C : `-` < `.` < `z`), donc chargé en dernier |
| C7 | FIM restreint aux motifs ransomware | FIM temps réel étendu : cron, systemd, `.ssh/authorized_keys`, passwd/shadow/sudoers, pam.d, ssh, profile.d, ld.so.preload, scripts dans `/var/www` |
| C8 | Rien ne détectait le silence du capteur | heartbeat + règles 100800-100806 (phase 1) |

Volume mesuré après extension : **38 lignes d'audit / 60 s**, `lost 0`.

---

## Phase 1 — filet anti-cécité (100800-100806)

Une règle de corrélation ne peut pas détecter une absence : elle ne raisonne que
sur des événements présents. D'où deux mécanismes complémentaires.

- **100800-100802** — heartbeat : `agent.conf` pousse toutes les 5 min
  `audit_enabled=<n> audit_rules=<n>`, et l'alerte porte sur la **valeur**.
  Nécessite `logcollector.remote_commands=1` sur l'agent, sans quoi Wazuh ignore
  silencieusement toute commande venant d'une configuration distante.
  *Piège résolu* : une règle autonome avec un simple `<match>` perd l'arbitrage
  face à la règle native 530, qui capte toute sortie de `<localfile><command>`.
  Il faut chaîner sur 530.
- **100805-100806** — détection directe via l'événement noyau `CONFIG_CHANGE`
  (`op=set audit_enabled=0`, `op=remove_rule`). Immédiat et porteur de l'`auid`.
  Ne remplace pas le heartbeat : si l'audit est coupé avant le démarrage de
  l'agent, seul un signal périodique révèle l'état courant.
- **100803/100804** — promotion des règles natives 506 (agent arrêté → 12) et
  504 (déconnecté → 10, sous le seuil de triage IA : trop ambigu pour armer une
  remédiation autonome).

Validé en conditions réelles : audit coupé → **100801 niveau 13 en ~5 min**.

---

## Phase 2 — défauts des règles existantes

### 100653 — lecture de `/etc/shadow`

L'ancienne version exigeait `audit.exe` dans une liste d'utilitaires
(`cat|less|head|cp|...`). Trois contournements triviaux, tous vérifiés :
`sh -c 'cat /etc/shadow'` (exe = dash), `python3 -c "open(...)"` (exe = python3),
et tout binaire compilé (aucun execve exploitable). La liste énumérait les
**moyens** alors que le signal est la **cible** — elle ne pouvait pas être
complétée. Réécrite sur le chemin dans l'argv, en clair **et** en hexadécimal
(tout `sh -c '...'` contient un espace, donc auditd encode l'argument entier).

Ajout de **100643** : la lecture vue par le watch auditd, seul canal qui capte un
accès **sans execve associé**.

*Piège majeur découvert en mesurant* : sans cloisonnement par
`audit.key`, 100653 captait aussi les événements du watch (dont le champ PATH
contient `/etc/shadow`). Mesure réelle : **11 alertes niveau 12 sur `sudo` et 2
sur `sshd` en quelques minutes** — la chaîne d'authentification normale
requalifiée en vol de credentials, et 100643 jamais atteinte. Résolu en
scindant sur `audit.key` (`audit-wazuh-c` = execve, `audit-wazuh-shadow` = watch).

### 100654 — altération d'un service de sécurité

Trois défauts cumulés, chacun rendant la règle contournable :

1. **Ordre imposé** : la regex exigeait le verbe *avant* le nom du service. Or
   `service auditd stop` et `rc-service auditd stop` mettent le verbe en dernier
   → aucun match. Le contournement était d'écrire `service` au lieu de
   `systemctl`. Regex rendue bidirectionnelle.
2. **Contrainte sur `audit.exe`** avec `/service$` dans la liste : or
   `/usr/sbin/service` est un **script shell**, donc `audit.exe` vaut
   `/usr/bin/dash`. La condition ne pouvait jamais être satisfaite. Même piège
   pour `ufw` (script Python).
3. **Ancrage sur `a0=`** (première correction) : insuffisant. Pour un script à
   shebang, le noyau **réécrit l'argv** en insérant l'interpréteur en tête. Trace
   réelle :
   ```
   a0="/bin/sh" a1="/usr/sbin/service" a2="auditd" a3="stop"
   ```
   Le nom de l'outil est en `a1`. Ancrage final sur `a\d+=`.

> Les règles 100673/100674/100680/100681 ancrent encore sur `a0=`. Elles ne
> visent que de vrais binaires ELF, donc pas de faux négatif aujourd'hui — mais y
> ajouter un outil livré en script rouvrirait exactement ce trou.

Nouvelles règles associées : **100645** (purge du filtrage réseau — enjeu propre
à cette infra : un `nft flush ruleset` **annule l'isolation d'hôte** appliquée
par le SOC) et **100647** (altération de la configuration auditd).

### Autres corrections

| Règle | Défaut | Correction |
|-------|--------|-----------|
| 100626 | fork bomb : ne couvrait que la forme shell/PAM | ajout des signatures cgroup v2 (`fork rejected by pids controller`), le cas le plus courant sur Debian 12 |
| 100634 | interpréteurs et tmpfs incomplets | ajout `awk/gawk/env/nohup/setsid/xargs/timeout/Rscript`, et des chemins `/run/user/<uid>` et `/dev/mqueue` |
| 100680 | outils d'effacement manquants | `hdparm --security-erase`, `nvme format`, `sgdisk --zap-all`, `cryptsetup luksErase`, `badblocks` |
| 100700 | branche « noms de paramètre » inutile (le nom est choisi par l'appli vulnérable) | ajout `%0a`, `${IFS}`, double encodage `%2527`, `${jndi:}` (Log4Shell, absent de tout le ruleset), `\|base64`, one-liners `python -c` |
| 100701 | ne voit qu'une liste de répertoires et de noms connus | répertoires CMS ajoutés + **100750** : détection du **dépôt** par FIM, seul moyen de voir un web shell à la racine du docroot sous un nom quelconque |
| 100710 | `euid=33` codé en dur | **100711** ajoutée : shell exécuté par tout compte de service (euid 1-999). Une RCE sur PostgreSQL, MySQL, Redis ou Tomcat ne déclenchait rien |

---

## Phase 3 — catégories absentes

**Persistance / intégrité (FIM, 100740-100750)** — le P1 de
`DETECTION-ROADMAP.md`, jamais implémenté : cron, `authorized_keys`, unit
systemd, base de comptes, second UID 0, sudoers, PAM, `sshd_config`,
`ld.so.preload`, `profile.d`, web shell déposé.

**Post-exploitation (auditd, 100760-100773)** — module noyau (T1014), compte
ajouté à un groupe privilégié (T1136.001), compte UID 0 (T1078.003), effacement
d'historique (T1070.003), tunneling C2 `ssh -R`/`chisel`/`ngrok` (T1572),
`curl | bash` (T1105), évasion de conteneur (T1611), **abus de binaire SUID
GTFOBins** (T1548.001), capacités Linux (T1548.001), scan sortant (T1046),
écriture sur un chemin de persistance vue par auditd (100770), écriture sur
`ld.so.preload` (100772).

Deux points valent d'être notés.

**100767 (GTFOBins) est structurel, pas signaturel.** Un processus dont l'uid
réel appartient à un utilisateur normal mais dont l'euid vaut 0 s'exécute via le
bit setuid. `sudo find` ne matche pas — sudo a déjà basculé l'uid réel à 0. Seul
le cas « binaire setuid lancé par un non-root » satisfait uid≠0 ET euid=0.
`^[1-9][0-9]*$` plutôt qu'un lookahead négatif : le moteur n'honore pas les
lookaheads dans les patterns de champ.

**Le FIM temps réel s'est révélé intermittent sur `/etc/passwd`** — trois
modifications successives, une seule alerte. Faire reposer la détection d'une
backdoor UID 0 sur ce seul canal était un pari. D'où **100770**, qui passe par le
watch auditd : déterministe, et porteur de ce que le FIM ne donne jamais — **qui**
a écrit (`exe`, `uid`, `auid`). Le FIM garde l'avantage complémentaire du contenu
(le diff). Les deux sont conservés délibérément.

### Faux positif majeur trouvé et corrigé en mesurant

Le watch `-w /etc/ld.so.preload -p rwa` a produit **33 alertes de niveau 14 en
30 secondes** : le fichier existant désormais, le chargeur dynamique l'ouvre à
chaque `exec`, donc une alerte par processus lancé. Corrigé en `-p wa` — seule
l'écriture porte du signal. Après correction : **0 alerte de niveau ≥ 10** sur
une fenêtre au repos, et l'écriture réelle reste détectée par les deux canaux.

> Prérequis non évident : `/etc/ld.so.preload` doit **exister**, même vide.
> inotify comme les watches auditd ciblent un inode — sur un chemin absent, rien
> n'est armé et la création du fichier, c'est-à-dire précisément l'action de
> l'attaquant, passe inaperçue. Créé par `scripts/install-agent.sh`.

---

## Tests

Deux niveaux, parce qu'aucun des deux ne suffit seul.

**Bout-en-bout sur `debian-vm`** — attaque réellement exécutée, alerte vérifiée
dans `alerts.json` : contournement `sh -c` de 100653, watch shadow, `service X
stop`, `auditctl -e0`, `iptables -F`, shell par compte de service, script depuis
`/run/user`, altération de `/etc/audit`, dépôt de cron / clé SSH / unit systemd /
web shell / `ld.so.preload`, chargement de module noyau, `usermod -aG`,
`history -c`, `ssh -R`, `curl | bash`, `setcap`, `useradd -o -u 0`, abus SUID
GTFOBins, coupure d'audit, et la batterie web (injection de commande, Log4Shell,
`${IFS}`, `%0a`, web shells, LFI).

**Rejeu logtest** (`scripts/test-detection-rules.sh`, **43 cas, 43 OK**) — pour
ce que le test bout-en-bout ne peut pas faire : les actions destructives (wipe de
disque, `rm -rf /home`, destruction de snapshots) et les outils absents de la VM
(nmap, Docker). Sert aussi de non-régression quand on édite une regex.

Deux pièges de ce harnais, chacun payé en heures :

1. **`wazuh-logtest` écrit sur STDERR.** Un `2>/dev/null` fait échouer 100 % des
   cas, contrôles négatifs compris — ce qui ressemble à « toutes mes règles sont
   cassées » et ne l'est pas.
2. **Il lit une ligne = un log.** En production le logcollector agrège
   SYSCALL + EXECVE + CWD + PATH + PROCTITLE. On concatène donc sur une ligne
   unique. Fidèle pour toutes les règles testées, qui ancrent leurs motifs à
   l'intérieur de la ligne EXECVE — mais une règle corrélant deux lignes ne peut
   pas être validée ainsi.

---

## Limites connues

- **Justesse non mesurée.** Cette revue élargit la couverture ; elle ne dit rien
  du taux de faux positifs en régime réel ni de la qualité des verdicts. Le
  golden set reste le prochain jalon, et il est maintenant plus nécessaire
  qu'avant : ces règles arment des remédiations autonomes.
- **FP attendus non encore observés** : `100740` (dpkg dépose des fichiers dans
  `/etc/cron.d`), `100760` (un redémarrage charge des dizaines de modules →
  rafale ponctuelle), `100711` (`archive_command` PostgreSQL, jobs cron sous
  compte de service). Choix délibéré de les laisser à la whitelist automatique
  plutôt qu'à des exclusions figées, qui aveugleraient aussi l'attaquant opérant
  au même endroit.
- **`100744`** (second UID 0 via le diff FIM) n'a pas pu être validé en direct,
  le FIM n'ayant pas produit de diff d'ajout exploitable pendant les tests. Le
  scénario est couvert par deux autres chemins vérifiés, eux : `100762`
  (`useradd -o -u 0`) et `100770` (écriture sur `/etc/passwd`).
- **`-e 2`** : toute évolution des règles auditd impose désormais un redémarrage
  de la machine.
- **`debian-vm` est isolée** (table nftables `wazuh_isolation`, policy drop),
  reliquat d'une remédiation autonome antérieure. Les tests web ont donc été
  lancés depuis la loopback de la VM. L'isolation n'a pas été levée.
