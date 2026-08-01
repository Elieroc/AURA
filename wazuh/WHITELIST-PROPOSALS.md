# Propositions de whitelist — cases IRIS ouverts au 2026-08-01

Source : prod `soc-ai` (192.168.10.5). Cases ouverts au moment de l'analyse : 73,
74, 75, 76, 77, 78, 79 (+ le case démo #1). Alertes HIGH/CRITICAL (niveau ≥ 12)
extraites de la timeline de chaque case, puis relues dans l'indexer
(`wazuh-*`, 3 derniers jours) pour récupérer les champs auditd que la timeline
ne porte pas.

## 1. Vue d'ensemble

| Case | Règle | Niv | Agent | Signature observée | Verdict |
|------|-------|-----|-------|--------------------|---------|
| 75, 76, 77, 78 | 100653 | 12 | debian, debian2, debian3, pve, home-s-pve01 | `stat /etc/shadow|/etc/shadow-|/etc/gshadow|/etc/gshadow-`, `cwd=/var/ossec`, `auid=unset` | FP — vérifs SCA/rootcheck de l'agent Wazuh |
| 75 | 100645 | 12 | debian3, pve, home-s-pve01 | `nft -j -f -` / `nft -f -`, `auid=unset` | FP — bug de regex (voir 2.a) |
| 75 | 100760 | 13 | debian3 | `modprobe` (`audit-wazuh-module`), même seconde que le `nft` ci-dessus | FP dérivé, **ne pas whitelister** (voir 3) |
| 79 | 100711 | 12 | debian, pve, home-s-pve01 | `busybox`/`bash` en `euid=911`, `cwd=/config` ou `/run/s6-rc/...` ; `apt-key`/`awk` en `euid=42`, `auid=0` | FP — s6-overlay de conteneurs LinuxServer + apt |
| 78 | 100643 | 12 | debian | `perl`, `comm=dpkg-preconfigu`, `auid=0` | FP — debconf pendant un `apt install` |
| 78 | 100643 | 12 | debian | `php-fpm8.2` (`euid=33`, `cwd=/var/www/html`) et `cat` (`cwd=/var/www/html/uploads`) | **VRAI POSITIF — ne pas whitelister** |
| 74, 75 | 100743 | 12 | wireguard, adguard-home, nginx-proxy-manager, bookstack, jellyfin, nextcloud, debian2, debian3 | `/etc/passwd` modifié, `Changed attributes: inode,mtime` (aucun hash changé) | FP — réécriture en place, contenu identique |
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

### b. 100642 — exclusion inopérante pour 100653

L'exclusion filtre `audit.exe ^/var/ossec/`, mais le SCA appelle le `stat`
système : `exe=/usr/bin/stat`. Ce qui identifie le scan, c'est le répertoire de
travail du démon et l'absence de session de login.

```xml
<rule id="100642" level="0">
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

### f. Nouvelle exclusion 100750 — FIM /etc/passwd sans changement de contenu

Le gros du bruit 100743 est `Changed attributes: inode,mtime` : le fichier a été
réécrit en place (rename d'un temporaire) avec un contenu **identique** — aucun
compte n'a bougé.

```xml
<rule id="100750" level="0">
  <if_sid>100743</if_sid>
  <field name="changed_attributes" type="pcre2">^(?!.*(?:md5|sha1|sha256|size))</field>
  <description>Exclusion 100743: account database rewritten in place, content unchanged (no hash change)</description>
</rule>
```

Les alertes de `wireguard` où le hash change réellement (taille 1331 ↔ 1292 en
va-et-vient les 2026-07-30/31) ne sont **pas** couvertes : il faut savoir ce qui
réécrit `/etc/passwd` sur cet hôte avant de les taire.

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

- **`.status.php`, 29 octets, dans `nginx-proxy-manager` (192.168.20.11)** —
  fichier caché, minuscule, matché `WEBSHELL_PHP_Generic_Eval`, dans le
  répertoire html de nginx, présent dans les couches `diff` **et** `merged` de
  deux overlay2 différents. L'image jc21 ne livre pas ce fichier et le
  conteneur n'a pas d'interpréteur PHP (donc non exploitable en l'état), mais
  c'est un artefact à expliquer avant tout classement en FP. À récupérer et
  lire sur l'hôte.
- **100643 sur `debian` : `php-fpm8.2` (`euid=33`, `cwd=/var/www/html`) et
  `cat` depuis `/var/www/html/uploads`** — c'est la chaîne d'un web shell, pas
  du bruit. Toute exclusion sur 100643 doit rester ancrée sur `perl` +
  `dpkg-preconfigu`.
- **100760 (`modprobe`, 16 alertes/3 j)** — déclenché ici en cascade du `nft`
  du point 2.a (chargement des modules `nf_tables`). Une fois 100645 corrigé,
  le volume tombe de lui-même. Exclure `kmod`/`modprobe` reviendrait à aveugler
  la détection de LKM malveillant, pour un gain de 5 alertes/jour.
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

## 6. Ordre d'application conseillé

1. 2.a (regex 100645) — supprime ~410 alertes/3 j et l'alerte du case 75.
2. 2.b (exclusion 100642) — supprime 155 alertes/3 j sur 5 hôtes.
3. 2.c + 2.d (exclusions 100711) — supprime ~958 alertes/3 j.
4. 2.e, 2.f, 2.g — volumes faibles, mais lèvent les cases 74/78/73.
5. Section 5 (code) — condition pour que la whitelist auto sache faire ça seule.
6. Investigation de `.status.php` sur 192.168.20.11.

Toute modification de règle passe par le flux habituel : `wazuh-logtest` +
`scripts/test-detection-rules.sh`, PR git, merge humain — jamais d'écriture
directe sur le manager.
