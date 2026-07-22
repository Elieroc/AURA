# Wazuh — Docker single-node

Déploiement officiel wazuh-docker single-node (manager + indexer + dashboard), adapté a minima :
secrets sortis vers `.env`, intégrations threat intel VirusTotal + AbuseIPDB.

## Setup initial

1. `sysctl -w vm.max_map_count=262144` (root, requis par l'indexer)
2. Copier les fichiers de config avec secrets :
   ```
   cp .env.example .env                                                          # remplir
   cp config/wazuh_cluster/wazuh_manager.conf.example config/wazuh_cluster/wazuh_manager.conf
   cp config/wazuh_dashboard/wazuh.yml.example config/wazuh_dashboard/wazuh.yml
   ```
   - `.env` : `INDEXER_PASSWORD`, `API_PASSWORD`, clés VT/AbuseIPDB
   - `wazuh_manager.conf` : remplacer `CHANGEME_VT_API_KEY` / `CHANGEME_ABUSEIPDB_API_KEY` (valeurs du `.env`)
   - `wazuh.yml` dashboard : remplacer `CHANGEME_API_PASSWORD` (= `API_PASSWORD`)
   - `config/wazuh_indexer/internal_users.yml` : hash bcrypt de `INDEXER_PASSWORD` pour `admin`
     (générer : `docker compose exec wazuh.indexer bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p MOT_DE_PASSE'`)
3. Générer les certificats SSL : `docker compose -f generate-indexer-certs.yml run --rm generator`
4. `docker compose up -d`
5. Dashboard : https://localhost — `admin` / `INDEXER_PASSWORD`

## Intégrations threat intel

### VirusTotal (natif)
- Déclencheur : alertes syscheck (FIM) — hash des fichiers ajoutés/modifiés envoyés à l'API VT.
- Config : bloc `<integration>` dans `wazuh_manager.conf`.
- Alertes : règles built-in 87103–87105 (87105 = fichier détecté malveillant, niveau 12).

### AbuseIPDB (custom)
- Script : `integrations/custom-abuseipdb.py` (+ wrapper `custom-abuseipdb`), monté dans
  `/var/ossec/integrations/` du manager.
- Déclencheur : alertes des groupes `sshd,attacks,authentication_failed,invalid_login` avec `data.srcip`
  publique. IP privées ignorées.
- Réinjection du résultat dans l'analyseur → règles locales (`config/wazuh_cluster/local_rules.xml`) :
  - 100621 (niv. 3) : enrichissement reçu
  - 100622 (niv. 12) : score ≥ 80 — IP malveillante
  - 100623 (niv. 7) : score 20–79 — IP suspecte
  - 100624 (niv. 5) : erreur API

### GeoIP (par défaut)
- Enrichissement fait côté indexer : le pipeline ingest `filebeat-7.10.2-wazuh-alerts-pipeline`
  applique un processor `geoip` (GeoLite2 embarquée dans OpenSearch) sur `data.srcip`
  (+ `data.win.eventdata.ipAddress`, `data.aws.sourceIPAddress`) → champ `GeoLocation`
  (pays, ville, lat/lon). Rien à installer.
- Les événements custom-abuseipdb émettent `srcip` à la racine pour bénéficier du même
  enrichissement.

### Test manuel
```
# AbuseIPDB — injecter une alerte factice avec srcip Tor puis chercher règle 100622 :
docker compose exec wazuh.manager /var/ossec/integrations/custom-abuseipdb <alert.json> <api_key>
# VirusTotal — alerte syscheck factice avec md5 EICAR (44d88612fea8a8f36de82e1278abb02f) :
docker compose exec wazuh.manager /var/ossec/integrations/virustotal <alert.json> <api_key> ""
grep -E "abuseipdb|virustotal" /var/ossec/logs/alerts/alerts.json
```

## Sévérité des alertes (`rule.severity`)

Calculée depuis `rule.level` par un processor `script` du pipeline ingest (`config/wazuh_cluster/alerts-pipeline.json`) :

| `rule.level` | `rule.severity` | `rule.severity_order` |
|---|---|---|
| < 5 | Info | 1 |
| 5-6 | Low | 2 |
| 7-10 | Medium | 3 |
| 11-14 | High | 4 |
| 15-16 | Critical | 5 |

**Escalade nocturne (20h-7h, heure Europe/Paris, DST géré)** : sévérité remontée d'un cran (ex. Low → Medium), plafonnée à Critical. Jamais appliquée à Info — les alertes bruit ne doivent pas remonter juste parce que c'est la nuit. Basée sur `ctx.timestamp` (toujours en UTC côté manager), converti en heure Paris via `ZonedDateTime`.

- Modif : éditer le script `severity` dans `alerts-pipeline.json`, puis recréer le manager
  (`docker compose up -d --force-recreate wazuh.manager`) **et** repousser le pipeline à l'indexer
  (filebeat ne le repousse pas toujours au redémarrage) :
  ```bash
  curl -sk -u admin:$INDEXER_PASSWORD -X PUT "https://localhost:9200/_ingest/pipeline/filebeat-7.10.2-wazuh-alerts-pipeline" \
    -H "Content-Type: application/json" -d @config/wazuh_cluster/alerts-pipeline.json
  ```

## Détection — exécution depuis répertoire temporaire

Règle locale `100625` (niv. 8, Medium) dans `local_rules.xml` : détecte l'exécution d'un binaire
depuis `/tmp`, `/var/tmp` ou `/dev/shm` (technique classique de drop-and-execute), via le champ
`audit.exe` du module Linux Audit (auditd).

- **Nécessite auditd configuré sur l'agent** pour surveiller `execve` — sans ça, aucun événement
  `audit.exe` n'est généré et la règle ne se déclenche jamais.
- Testé via `wazuh-logtest` : `exe="/tmp/malware"` → alerte 100625 ; `exe="/bin/bash"` → pas de
  faux positif (tombe sur la règle par défaut 80792, niv. 3). Testé bout-en-bout sur agent
  `001 debian-vm` : binaire déposé + exécuté depuis `/tmp` → alerte 100625 remontée dans l'indexer.
- Côté Windows, couverture équivalente déjà présente dans le ruleset par défaut (Sysmon event 1/7,
  `0800-sysmon_id_1.xml` / `0820-sysmon_id_7.xml`) pour l'exécution depuis `Users\...\AppData\Local\Temp`
  et `Windows\Temp` — nécessite Sysmon installé sur l'agent.
- **Exclusion `100629`** (règle enfant niveau 0) pour le module `ansible.builtin.script` : en
  temps normal, l'exécution des modules Ansible (Python) ne déclenche déjà pas 100625 —
  `audit.exe` résout vers l'interpréteur (`/usr/bin/python3.x`), jamais vers `/tmp` (vérifié). Le
  garde-fou couvre le cas où Ansible pousserait et exécuterait un binaire brut depuis
  `/tmp/ansible-tmp-*`. Piège de decoder découvert en testant : Wazuh **tronque `audit.exe` au
  premier tiret rencontré** (`/tmp/ansible-tmp-123/x` → `/tmp/ansible`, `/tmp/mal-ware` →
  `/tmp/mal`) — l'exclusion matche donc la forme tronquée `^/tmp/ansible$`, pas le chemin complet.
  Autre piège : le **lookahead négatif PCRE2 n'est pas honoré** par le moteur de règles Wazuh
  (testé, matchait quand même) — la suppression passe par une règle enfant niveau 0
  (`if_sid` + niveau 0), le mécanisme standard Wazuh pour exclure un sous-cas d'une règle plus
  large sans y toucher.

### Setup côté agent Linux (auditd)

```bash
sudo apt-get install -y auditd audispd-plugins
echo "-a always,exit -F arch=b64 -S execve -k audit-wazuh-c" | sudo tee /etc/audit/rules.d/audit-wazuh.rules
sudo augenrules --load
```

Puis ajouter dans `/var/ossec/etc/ossec.conf` de l'agent (avant `</ossec_config>`) :
```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```
`sudo systemctl restart wazuh-agent` pour appliquer.

## Détection — fork bomb

Règle locale `100626` (niv. 12, High) : détecte l'épuisement de la table de process
(`ulimit -u`/nproc) via le message d'erreur émis par le noyau/PAM/le shell au moment où la limite
est atteinte (`fork: retry: Resource temporarily unavailable`, `Too many processes`,
`clone() failed`) — capté via syslog/journald, déjà configuré par défaut sur l'agent.

- Choix volontaire de **ne pas** auditer `clone()`/`fork()` en direct via auditd : des millions
  d'appels légitimes par seconde en usage normal, bien trop bruyant pour une règle exploitable.
  Le message de refus du noyau est un signal bien plus rare et bien plus fiable.
- Testé via `wazuh-logtest` : le message déclenche 100626 ; un login SSH normal ne déclenche pas
  de faux positif.

**Zip bomb** — envisagé (règle FIM sur taille de fichier anormale dans `/tmp`), testé
bout-en-bout avec succès (alerte remontée sur fichier 220 Mo), mais **retiré** : risque de faux
positifs jugé trop élevé pour un usage général (dumps DB, cache de build/CI, téléchargements
volumineux dans `/tmp` déclenchent tous légitimement le seuil). Pas de FIM temps réel poussé sur
`/tmp`/`/var/tmp`/`/dev/shm` (config `agent.conf` retirée). À reconsidérer si un besoin précis se
présente, avec un seuil plus élevé ou des exclusions ciblées.

## Détection — ransomware (T1486 / T1490)

Règles `100670`-`100674`. Approche retenue : **déception (fichiers canaris)**, pas détection de
masse.

### Pourquoi pas la détection de burst FIM

L'approche réflexe — alerter sur *N* modifications de fichiers en *T* secondes (`frequency` sur la
règle 550) — a été écartée. Elle regarde beaucoup de fichiers en cherchant l'anormal, donc elle
produit du bruit par construction : `rsync`, `apt upgrade`, `git clone`, décompression d'archive,
job de build CI et sauvegarde nocturne génèrent tous des bursts d'écritures parfaitement
légitimes. Chaque déploiement d'appli devient une alerte, et le seuil qui les fait taire est aussi
celui qui laisse passer un chiffrement lent.

Le canari inverse le rapport signal/bruit : il ne surveille que des fichiers que **rien de
légitime n'écrit**. Un seul événement suffit, pas de seuil ni de fenêtre temporelle à régler, pas
de whitelist à maintenir. Les lectures (antivirus, `updatedb`, sauvegarde) ne déclenchent pas le
FIM — seules les écritures, renommages et suppressions le font.

### Fonctionnement

`scripts/deploy-canary.sh` dépose des leurres `000_CANARY_SOC_NE_PAS_TOUCHER.{xlsx,docx,pdf}` à la
racine et au premier niveau de `/home/*`, `/srv`, `/var/www`, `/root`. Détails qui conditionnent
la détection :

- préfixe `000_` : les chiffreurs parcourent les répertoires dans l'ordre de `scandir`, souvent
  trié — le canari est touché tôt ;
- extensions bureautiques : les familles courantes chiffrent sur liste blanche d'extensions ; un
  `.txt` ou un fichier caché est souvent ignoré, donc le canari n'est **ni caché ni exotique** ;
- ~16 Ko de contenu compressible : certaines familles sautent les fichiers vides ou déjà à haute
  entropie ;
- propriétaire = propriétaire du répertoire, mode `0644` : le canari doit être **écriturable** par
  le compte qu'un ransomware compromettrait, sinon il est sauté et ne détecte rien.

Le script est idempotent (ne réécrit pas un canari existant — sinon chaque exécution déclencherait
l'alerte qu'il surveille) et réversible (`--remove`).

### Surveillance FIM

`config/wazuh_cluster/agent.conf` (monté sur `/wazuh-config-mount/etc/shared/default/agent.conf`,
poussé automatiquement aux agents). On ne surveille **pas** `/home` en entier : l'attribut
`restrict` fait que Wazuh ne pose des watches inotify que sur les chemins matchant le motif —
quelques watches par arborescence au lieu de plusieurs milliers, et un volume d'événements nul en
fonctionnement normal.

Un seul bloc `<directories>` par chemin : Wazuh ne garde qu'une entrée par répertoire, deux blocs
sur `/home` feraient perdre le premier motif. Le `restrict` est donc un pré-filtre unique couvrant
à la fois les canaris, les noms de notes de rançon et les extensions de chiffrement connues. Sa
syntaxe est le *sregex* OSSEC (limitée) : on s'y tient à des sous-chaînes littérales, la précision
est portée par les règles, qui utilisent du PCRE2 fiable.

| Règle | Niv. | Détecte | MITRE |
|---|---|---|---|
| `100670` | 15 | canari modifié / supprimé / renommé | T1486 |
| `100671` | 14 | note de rançon déposée (`_readme.txt`, `HOW_TO_DECRYPT…`, `akira_readme`…) | T1486 |
| `100672` | 14 | fichier avec extension de chiffrement connue (`.lockbit`, `.djvu`, `.phobos`…) | T1486 |
| `100673` | 12 | destruction de sauvegardes/snapshots | T1490 |
| `100674` | 12 | arrêt/désactivation d'un service de sauvegarde | T1490 |
| `100680` | 13 | effacement bas niveau d'un support (`wipefs`, `mkfs`, `dd of=/dev/…`) | T1561.001 |
| `100681` | 12 | `rm -rf` sur une racine système/données | T1485 |
| `100682` | 15 | corrélation : 3+ canaris altérés en 2 min | T1485 / T1486 |

`100671` exclut volontairement `README` nu — bien trop courant en `/home` et `/srv`. Seuls les
motifs sans usage légitime sont retenus.

### Destruction massive de fichiers (T1485 / T1561)

La règle native `553` (« File deleted », niveau 7) est taggée T1485 mais raisonne **par fichier** :
elle ne distingue pas une suppression isolée d'un effacement complet. Et notre FIM étant filtré par
`restrict`, elle ne se déclenche de toute façon quasiment jamais. D'où trois règles dédiées.

Même doctrine que le reste du pack : on ne cherche pas le volume — compter les suppressions
impliquerait de surveiller `/home` en entier, soit exactement le bruit qu'on a refusé — on cherche
l'**intention non ambiguë**, plus une corrélation sur les canaris.

- **`100680`** — primitives de wipe (`wipefs`, `blkdiscard`, `mkfs.*`, `dd of=/dev/…`,
  `shred /dev/…`). Aucun usage courant en production : ces commandes apparaissent au provisioning
  (machine neuve, pas encore d'agent) ou lors d'un wipe malveillant. Un `dd of=/tmp/img.bin` ne
  matche pas — la cible doit être un device.
- **`100681`** — `rm -rf` sur une racine fermée (`/`, `/home`, `/srv`, `/etc`, `/boot`, `/var`,
  `/var/lib/mysql`…). Un `rm -rf` générique est l'opération la plus banale d'un script de build :
  l'alerter revient à alerter en continu. **Limite assumée** : le shell développe `rm -rf /home/*`
  *avant* `execve`, donc auditd voit les chemins un par un et la règle ne matche pas ce cas — il
  est couvert par le canari (100670), qui se trouve précisément dans ces répertoires. Les deux
  règles sont complémentaires par construction.
- **`100682`** — corrélation `if_matched_sid` sur 100670. Un canari isolé peut à la rigueur être
  une manipulation humaine maladroite ; trois canaris dans des répertoires différents en deux
  minutes, non : c'est la signature d'un parcours récursif automatisé. Pas de `<same_field>` dans
  cette règle — il casse le comptage de fréquence (même piège que sur 100658).

Angle écarté : audit des syscalls `unlink`/`unlinkat`. Techniquement précis, mais chaque fichier
temporaire supprimé génère un événement — volume ingérable, même raisonnement que pour
`clone()`/`fork()` en 100626.

Testé : matrice `wazuh-logtest` 11 cas sur 100680/100681 (les 4 primitives de wipe et les 3 formes
de `rm -rf` sur racine matchent ; `dd of=/tmp/img.bin`, `rm -rf node_modules`,
`rm -rf /var/cache/apt/x` et `rm -f` non récursif restent en 80792 niveau 3). `100682` testée
bout-en-bout sur `debian-vm` : suppression de 4 canaris → 4 alertes 100670 puis 1 alerte 100682.

### Ordre de déploiement (sinon alertes parasites)

Déposer les canaris **avant** de pousser `agent.conf`. Dans l'autre sens, la création de chaque
canari est vue par le FIM comme un fichier ajouté et génère une alerte `100670` — bruit ponctuel
et sans gravité, mais évitable :

```bash
sudo ./deploy-canary.sh              # 1. les leurres
# 2. puis recréer le manager pour pousser agent.conf, puis sur l'agent :
sudo systemctl restart wazuh-agent
```

### Pièges auditd (règles 100673 / 100674)

Les arguments arrivent découpés en `a0="zfs" a1="destroy"` — il n'y a **pas d'espace** entre le
binaire et son verbe dans `full_log`. Une regex de type `zfs\s+destroy` ne matche jamais. Les
règles matchent donc le binaire en `a0` (chemin optionnel) puis le verbe dans un argument
ultérieur quelconque. Même piège que le hex-encoding documenté plus haut.

Verbes limités à la destruction non ambiguë. Sont **exclus** `restic forget`, `borg prune`,
`duplicity remove` : ce sont les commandes de rétention, lancées par cron sur toute machine
correctement sauvegardée — faux positif quotidien garanti. `rm -rf /var/backups` nu est exclu pour
la même raison (scripts de ménage). FP résiduel possible : purge de snapshots planifiée
(`zfs-auto-snapshot`) — d'où le niveau 12 et non 15. Le signal à zéro FP, c'est le canari.

### Testé bout-en-bout

- `100673` / `100674` via `wazuh-logtest`, matrice 6 cas : `zfs destroy` et
  `btrfs subvolume delete` matchent ; `restic forget`, `zfs list` et `systemctl restart nginx` ne
  matchent pas (restent en 80792 niveau 3).
- `100670` / `100671` / `100672` sur l'agent `debian-vm` : écriture sur un canari, dépôt d'un
  `HOW_TO_DECRYPT_FILES.txt` et création d'un `.lockbit` remontent bien en niveaux 15/14/14.

Réserve connue : le canari de `/var/www/html` est téléchargeable si le vhost sert le répertoire.
Sans impact (contenu inerte), mais à retirer sur un serveur exposé publiquement.

## Routage des alertes par type (index dédiés)

Les alertes des **agents** (pas celles du manager, agent 000) sont routées vers des index dédiés
par un processor `script` ajouté en fin de pipeline ingest
(`config/wazuh_cluster/alerts-pipeline.json`, bind-mounté sur le module filebeat du manager) :

| Index | Critère |
|-------|---------|
| `wazuh-web-*` | `rule.groups` contient web/apache/nginx/iis |
| `wazuh-windows-*` | `rule.groups` contient windows, ou champ `data.win` présent |
| `wazuh-linux-*` | groupes syslog/sshd/pam/systemd/audit/auth, ou `location` = journald ou /var/log/* |
| `wazuh-alerts-*` (défaut) | tout le reste + alertes du manager |

- Template d'index `soc-ai-routing` (clone du template wazuh, mêmes mappings) appliqué aux 3 patterns.
- Index patterns dashboard : `wazuh-linux-*`, `wazuh-windows-*`, `wazuh-web-*`, plus le pattern
  combiné `soc-ai-all-alerts` (= les 4) utilisé par l'app Wazuh (`pattern:` dans
  `wazuh_dashboard/wazuh.yml`) et le dashboard custom, pour garder une vue globale.
- Modif du routage : éditer le script dans `alerts-pipeline.json` puis recréer le manager
  (`docker compose up -d --force-recreate wazuh.manager`).

## Dashboards custom

- `dashboards/soc-ai-dashboards.ndjson` (généré par `dashboards/gen_dashboard.py`), 3 dashboards :
  - **Threat Intel** : carte GeoIP des IP sources, réputation AbuseIPDB, détections VirusTotal
  - **Global** : compteur d'événements global + timeline des alertes par niveau
  - **Linux** : top règles, top alertes, échecs d'authentification, top agents (index `wazuh-linux-*`)
  - **Web** : top règles/alertes d'attaque, timeline, top URLs ciblées, top IP sources, codes HTTP (index `wazuh-web-*`)
- Import (API saved objects, idempotent) :
  ```
  curl -sk -u admin:$INDEXER_PASSWORD -X POST \
    "https://localhost/api/saved_objects/_import?overwrite=true" \
    -H 'osd-xsrf: true' --form file=@dashboards/soc-ai-dashboards.ndjson
  ```
- Accès : menu Dashboards (time range 30 jours, refresh 60s).
- Les modules built-in du dashboard Wazuh couvrent déjà Threat Hunting, MITRE ATT&CK, FIM,
  vulnérabilités — pas dupliqués ici.

## Fichiers gitignorés (secrets)

- `.env`, `config/wazuh_cluster/wazuh_manager.conf` (clés API), `config/wazuh_dashboard/wazuh.yml`
  (mdp API), `config/wazuh_indexer_ssl_certs/*` (certificats). Versions `.example` versionnées.
