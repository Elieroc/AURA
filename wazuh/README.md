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
- Réinjection du résultat dans l'analyseur → règles locales (`config/wazuh_cluster/rules/`, un fichier par règle) :
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

Règle locale `100625` (niv. 8, Medium), dans `config/wazuh_cluster/rules/100625-*.xml` : détecte l'exécution d'un binaire
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
| `wazuh-firewall-*` | `decoder.name == 'pf-nohost'` — **avant** le test `agent.id`, car pfSense arrive en syslog direct sur le manager (agent.id=000), pas via un agent ; **ou** `rule.groups` contient `suricata` (IDS du même boîtier, mais remonté par l'agent Wazuh de pfSense) |
| `wazuh-proxy-*` | `decoder.name == 'npm-access'` |
| `wazuh-jellyfin-*` | `decoder.name == 'jellyfin'` — log applicatif, pas un format web (pas de nginx devant Jellyfin) |
| `wazuh-vpn-*` | `decoder.name == 'wg-monitor'` — WireGuard n'a pas de log natif, cf. section VPN plus bas |
| `wazuh-dns-*` | `rule.groups` contient `dns` (AdGuard Home, decoder générique `json` — pas assez spécifique pour router dessus) |
| `wazuh-alerts-*` (défaut) | tout le reste + alertes du manager |

Firewall, proxy, jellyfin et vpn testent le **décodeur**, pas `rule.groups`
(contrairement aux trois premiers) : firewall/proxy héritent du ruleset natif
(`<type>web-log</type>`) pour profiter de signatures d'attaque existantes (cf.
section NPM plus bas), et une règle native sœur peut gagner à la place de la
règle locale qui porterait le tag de groupe. Jellyfin/vpn n'ont pas ce
problème d'héritage mais suivent la même convention par cohérence. Le nom du
décodeur, lui, ne dépend pas de quelle règle matche finalement, donc reste
fiable pour router.

Exception : les alertes **Suricata** partagent l'index `wazuh-firewall-*` avec le
syslog pfSense (même boîtier), mais se routent sur `rule.groups` et non sur le
décodeur — l'EVE JSON est décodé par le décodeur générique `json`, comme AdGuard,
donc `decoder.name` ne discrimine rien. Ce test est placé **avant** celui de
`dns` : sinon une alerte Suricata portant le groupe `dns` (règles 86601+ sur des
événements DNS) atterrirait dans `wazuh-dns-*`.

- **Template d'index `soc-ai-routing` — À CRÉER, sinon mappings dynamiques faux.**
  Le routage envoie les alertes vers des index qui ne matchent PAS
  `wazuh-alerts-4.x-*`, donc le template `wazuh` natif ne s'y applique pas :
  sans template dédié, OpenSearch mappe dynamiquement et se trompe —
  `GeoLocation.location` devient un objet `{lat,lon}` de floats au lieu d'un
  `geo_point`, ce qui casse la carte GeoIP (« Saved field
  "GeoLocation.location" is invalid for use with the "Geohash" aggregation »)
  et met le champ en `conflict` dans le pattern combiné. Les strings partent
  en `text` + `.keyword` au lieu de `keyword` pur, ce qui décale tous les noms
  de champs des agrégations. Création (clone du mapping natif) :
  ```bash
  source .env
  curl -sk -u admin:$INDEXER_PASSWORD "https://localhost:9200/_template/wazuh" -o /tmp/wazuh_tpl.json
  python3 -c "
  import json
  d = json.load(open('/tmp/wazuh_tpl.json'))['wazuh']
  json.dump({
      'index_patterns': ['wazuh-linux-*','wazuh-windows-*','wazuh-web-*','wazuh-firewall-*',
                         'wazuh-proxy-*','wazuh-jellyfin-*','wazuh-vpn-*','wazuh-dns-*'],
      'settings': {'index': {'number_of_shards': 1, 'number_of_replicas': 0,
                             'mapping': {'total_fields': {'limit': 10000}}}},
      'mappings': d['mappings'], 'order': 1,
  }, open('/tmp/soc-ai-routing.json','w'))"
  curl -sk -u admin:$INDEXER_PASSWORD -X PUT "https://localhost:9200/_template/soc-ai-routing" \
    -H "Content-Type: application/json" -d @/tmp/soc-ai-routing.json
  ```
  Un template ne s'applique qu'aux index **créés après** : les index déjà
  mal mappés gardent leur mapping. Les laisser expirer (un par jour) ou les
  reindexer. **Si reindex : ne jamais supprimer la copie de travail avant
  d'avoir vérifié le `count` de la destination** — un `_reindex` renvoie
  `"failures": []` même quand il n'a copié qu'une partie des documents
  (refresh non forcé), et l'original supprimé ne se récupère pas.
- **Template d'index `wazuh-ai` — À CRÉER aussi**, même piège que `soc-ai-routing`
  mais pour les métriques d'IA (`ai/soc_agent/metrics.py`). Sans lui, les
  strings partent en `text` + `.keyword` et TOUTES les agrégations du dashboard
  AI tombent à côté en silence. Le mapping est versionné :
  ```bash
  source .env
  curl -sk -u admin:$INDEXER_PASSWORD -X PUT "https://localhost:9200/_template/wazuh-ai" \
    -H "Content-Type: application/json" -d @config/wazuh_indexer/wazuh-ai-template.json
  ```
  `wazuh-ai-*` est un index pattern à part et reste **hors** du pattern combiné
  `soc-ai-all-alerts` : ces documents ne sont pas des alertes, les y compter
  fausserait tous les totaux du dashboard Global.
- **Vérifier les visualisations après chaque import** : `_import` de saved
  objects réussit même quand les champs référencés n'existent pas — la visu
  s'ouvre ensuite sur « No results found » ou une erreur d'agrégation, sans
  rien dans les logs. `dashboards/verify_visualizations.py` rejoue chaque
  agrégation de chaque visu contre son index pattern et signale les champs
  invalides.
- Index patterns dashboard : `wazuh-linux-*`, `wazuh-windows-*`, `wazuh-web-*`, `wazuh-firewall-*`,
  `wazuh-proxy-*`, `wazuh-jellyfin-*`, `wazuh-vpn-*`, `wazuh-dns-*`, plus le pattern combiné `soc-ai-all-alerts`
  (= ceux qui ont réellement des données, cf. piège plus bas) utilisé par l'app Wazuh
  (`pattern:` dans `wazuh_dashboard/wazuh.yml`) et le dashboard custom, pour garder
  une vue globale.

### pfSense (et tout équipement sans agent possible) — syslog direct

pfSense n'a pas de paquet wazuh-agent officiel (FreeBSD, appliance). Approche :
syslog UDP direct vers le manager (`<remote><connection>syslog</connection>...`
dans `wazuh_manager.conf`, `allowed-ips` restreint à l'IP du pare-feu — **celle
vue par le manager**, pas l'IP WAN/mgmt de pfSense : un routeur multi-interface
sort avec l'IP de l'interface la plus proche de la destination).

Piège rencontré en prod : le syslogd FreeBSD de pfSense (14.0-CURRENT) envoie
les messages `filterlog` **sans hostname** (`<PRI>Mmm dd hh:mm:ss filterlog[pid]:
...`), cassant le pré-décodage syslog standard de Wazuh (le token
`filterlog[pid]:` atterrit dans `hostname`, `program_name` reste vide) — le
décodeur natif `pf` (basé sur `<program_name>`) ne matche jamais, silencieusement.
Décodeur de secours basé sur `<prematch>` : `decoders/pfsense-nohostname.xml`
(commentaire en tête du fichier : détail des pièges de syntaxe `offset` Wazuh
rencontrés en le construisant). Règles miroir de la native `0540-pfsense_rules.xml`
dans `rules/100810-100812-*.xml`.

Config pfSense (activation remote syslog + catégorie "Firewall Events", sans
toucher aux autres cibles syslog déjà configurées) : `wazuh/agents/pfsense/`
(script + README détaillé).

**Pas d'active response sur pfSense** : c'est un flux read-only (visibilité),
pas une cible de remédiation automatisée pour l'instant.

### Nginx Proxy Manager — agent Wazuh standard

Contrairement à pfSense, l'hôte NPM est un Linux classique (Debian 12 testé) :
agent Wazuh normal, `<localfile>` wildcard sur `data/logs/*_access.log` /
`*_error.log` (NPM nomme ses logs par host proxy, liste qui change à chaque
host ajouté). Détail (ACL sur `/root`, install, permissions) :
`wazuh/agents/npm/`.

Décodeur `decoders/npm-proxy.xml` : format d'access log custom (pas le
combined log nginx standard), porte volontairement `<type>web-log</type>` et
des champs nommés `id`/`url` (convention native) pour **hériter tout le
ruleset natif `<category>web-log</category>`** (0245-web_rules.xml : erreurs
4xx/5xx, SQLi, XSS, LFI, CGI/PHP — 31101-31106, 31109, 31110) et les règles
locales déjà écrites dessus (100700-100702, domaine `web,attack,web_attack_soc,`
— command injection, web shell, confirmed attack) sans rien réécrire.

Deux pièges rencontrés, documentés en tête de fichier :
- Le format NPM coïncide avec le prematch du décodeur natif `zeus`
  (`0390-zeus_decoders.xml`, pensé pour un panel C2 historique) qui le capture
  en premier — désactivé via `<decoder_exclude>`/`<rule_exclude>` dans
  `wazuh_manager.conf` (les deux ensemble, sinon les rules zeus natives
  plantent le chargement).
- Hériter `<type>web-log</type>` a un effet de bord : la règle racine native
  31100 gagne toujours face à notre propre règle racine 100820 (deux règles
  sœurs sans `if_sid` sur le même décodeur, la première chargée gagne) —
  d'où le routage d'index sur `decoder.name` plutôt que `rule.groups`
  (cf. tableau plus haut), et `100823` (détection de scan par fréquence)
  chaînée sur la native `31101`, pas sur notre `100820` mort en pratique.

Règles : `rules/100820-npm-proxy-rules.xml`.

### BookStack / Nextcloud — agents Wazuh standard, décodeur natif

Deux images linuxserver.io (nginx interne, format combined log standard) :
décodeur natif Wazuh `web-accesslog` matche directement, aucun décodeur/règle
custom. Détail (ACL, install) : `wazuh/agents/bookstack/`,
`wazuh/agents/nextcloud/`.

### Jellyfin — agent Wazuh, log applicatif (pas de format web)

Pas de nginx devant (serveur Kestrel embarqué, `network_mode: host`) : pas de
log d'accès HTTP à la verbosité par défaut (vérifié : 0 requête loguée).
Log applicatif Serilog ingéré tel quel dans son propre index
`wazuh-jellyfin-*` (pas `wazuh-web-*`, le contenu n'est pas comparable à un
access log). Décodeur `decoders/jellyfin.xml` extrait `level`
(VRB/DBG/INF/WRN/ERR/FTL) et la classe émettrice ; règles
`rules/100830-jellyfin-rules.xml` (WRN=5, ERR=7, FTL=12). Détail :
`wazuh/agents/jellyfin/`.

### WireGuard — agent Wazuh + wg-monitor (via la base WGDashboard)

WireGuard (module noyau) n'a **aucun audit natif** : pas de log par pair,
seul `wg show` donne un état instantané. `dynamic_debug` noyau (journalise
chaque handshake) indisponible sur wireguard.lab — `/sys/kernel/debug`
inaccessible même en root (LXC Proxmox, même contrainte que le manager
Aura-SOC). wireguard.lab tourne avec **WGDashboard**, qui suit déjà l'état des
pairs dans une base SQLite (status running/stopped calculé par WGDashboard,
historique des IP source par pair, noms de pairs) — `wg-monitor.py` lit
cette base en lecture seule plutôt que de réinterroger `wg show` en
parallèle. Systemd timer (30s), compare à l'état précédent, loggue les
**transitions** (connect/disconnect/roaming) dans
`/var/log/wireguard-events.log`. Décodeur `decoders/wireguard.xml` ; règles
`rules/100840-wireguard-rules.xml` (connect/disconnect/endpoint changé level
3, reconnexions ou changements d'IP répétés en level 7). Index
`wazuh-vpn-*`. Détail (script, unités systemd, piège du test en direct sans
passer par systemd) : `wazuh/agents/wireguard/`.

### AdGuard Home — agent Wazuh, JSON natif (aucun décodeur custom)

Query log déjà en JSON structuré (une ligne par requête DNS) :
`log_format=json` suffit, Wazuh décode tous les champs automatiquement
(objets imbriqués aplatis, ex `Result.IsFiltered`) — premier agent de ce
repo sans le moindre décodeur custom. Règles
`rules/100850-adguard-dns-rules.xml` : grouped, requête bloquée (level 3),
nombreuses résolutions bloquées depuis la même IP en 60s (level 7, machine
potentiellement compromise). Index `wazuh-dns-*`.

**Piège rencontré** : AdGuard Home bufferise le query log en mémoire avant
d'écrire sur disque (`querylog.size_memory`, défaut 1000 requêtes) — sur un
homelab, une résolution bloquée peut mettre des dizaines de minutes à
apparaître dans Wazuh. Abaissé à 20 sur adguard-home.lab pour une visibilité
quasi temps réel. Détail : `wazuh/agents/adguard-home/`.

- Modif du routage : éditer le script dans `alerts-pipeline.json` puis recréer le manager
  (`docker compose up -d --force-recreate wazuh.manager`).

## Dashboards custom

- `dashboards/soc-ai-dashboards.ndjson` (généré par `dashboards/gen_dashboard.py`), 5 dashboards :
  - **Threat Intel** : carte GeoIP des IP sources, réputation AbuseIPDB, détections VirusTotal
  - **Global** : compteur d'événements global + timeline des alertes par niveau
  - **Linux** : top règles, top alertes, échecs d'authentification, top agents (index `wazuh-linux-*`)
  - **Web** : top règles/alertes d'attaque, timeline, top URLs ciblées, top IP sources, codes HTTP (index `wazuh-web-*`)
  - **YARA** : fichiers malveillants détectés par Loki/YARITRUST, top machines infectées, timeline par gravité, liste des matches (index `wazuh-yara-*`)
- Import (API saved objects, idempotent) — les index patterns custom **avant**, sinon l'import
  échoue silencieusement sur les visualisations qui les référencent (`soc-ai-all-alerts`,
  `wazuh-linux-*`, `wazuh-web-*` n'existent pas par défaut, contrairement à `wazuh-alerts-*`) :
  ```
  INDEXER_PASSWORD=... python3 dashboards/create_index_patterns.py
  curl -sk -u admin:$INDEXER_PASSWORD -X POST \
    "https://localhost/api/saved_objects/_import?overwrite=true" \
    -H 'osd-xsrf: true' --form file=@dashboards/soc-ai-dashboards.ndjson
  ```
- **Pièges rencontrés en prod (dashboards Global/Threat Intel en erreur alors que
  Web/Linux marchaient)** :
  - Toute agrégation `terms` sur un champ string doit cibler `<champ>.keyword`,
    jamais le champ nu — Wazuh/OpenSearch mappe dynamiquement les strings en
    `text` + sous-champ `.keyword`, et une agrégation sur `text` est rejetée
    (`illegal_argument_exception`). `gen_dashboard.py` applique `.keyword`
    partout où c'est une agrégation terms (`rule.description`, `agent.name`,
    `data.url`, `data.srcip`, etc.) — jamais sur `timestamp`, un champ numérique,
    ou `GeoLocation.location` (geo_point).
  - `soc-ai-all-alerts` (pattern combiné) : l'API `_fields_for_wildcard`
    d'OpenSearch Dashboards rejette le pattern **entier** (404
    `no_matching_indices`) dès qu'**un seul** des sous-patterns listés ne
    matche aucun index — même si les autres existent avec des données (vécu :
    `wazuh-jellyfin-*` vide, avant le premier WRN/ERR réel, a cassé Global et
    Threat Intel en entier). `create_index_patterns.py` recalcule ce pattern à
    chaque run en excluant les sous-patterns sans index actuellement — relancer
    le script après l'ajout d'une nouvelle source suffit, pas besoin d'y toucher
    à la main.
- Accès : menu Dashboards (time range 30 jours, refresh 60s).
- Les modules built-in du dashboard Wazuh couvrent déjà Threat Hunting, MITRE ATT&CK, FIM,
  vulnérabilités — pas dupliqués ici.

## Fichiers gitignorés (secrets)

- `.env`, `config/wazuh_cluster/wazuh_manager.conf` (clés API), `config/wazuh_dashboard/wazuh.yml`
  (mdp API), `config/wazuh_indexer_ssl_certs/*` (certificats). Versions `.example` versionnées.
