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

- **Nécessite auditd configuré sur l'agent** pour surveiller `execve` (ex. règle audit
  `-a always,exit -F arch=b64 -S execve -k audit-wazuh-c`) — sans ça, aucun événement `audit.exe`
  n'est généré et la règle ne se déclenche jamais.
- Testé via `wazuh-logtest` : `exe="/tmp/malware"` → alerte 100625 ; `exe="/bin/bash"` → pas de
  faux positif (tombe sur la règle par défaut 80792, niv. 3).
- Côté Windows, couverture équivalente déjà présente dans le ruleset par défaut (Sysmon event 1/7,
  `0800-sysmon_id_1.xml` / `0820-sysmon_id_7.xml`) pour l'exécution depuis `Users\...\AppData\Local\Temp`
  et `Windows\Temp` — nécessite Sysmon installé sur l'agent.

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
