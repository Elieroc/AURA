# Installation

Prérequis : Docker, Docker Compose, Python 3.12+, `vm.max_map_count=262144`.

## 1. Wazuh

```bash
cd wazuh
sysctl -w vm.max_map_count=262144
cp .env.example .env
cp config/wazuh_cluster/wazuh_manager.conf.example config/wazuh_cluster/wazuh_manager.conf
cp config/wazuh_dashboard/wazuh.yml.example config/wazuh_dashboard/wazuh.yml
$EDITOR .env
$EDITOR config/wazuh_cluster/wazuh_manager.conf
$EDITOR config/wazuh_dashboard/wazuh.yml
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Dashboard : https://localhost — `admin` / `INDEXER_PASSWORD`.

Dashboards/visualisations custom (index patterns d'abord, sinon l'import
échoue silencieusement sur les références manquantes) :

```bash
INDEXER_PASSWORD=... python3 dashboards/create_index_patterns.py
curl -sk -u admin:$INDEXER_PASSWORD -X POST \
  "https://localhost/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' --form file=@dashboards/soc-ai-dashboards.ndjson
```

## 2. DFIR-IRIS

```bash
cd iris
cp .env.example .env
$EDITOR .env
./scripts/generate-certs.sh
docker compose up -d
docker compose logs app | grep "IRIS IS READY"
```

UI : https://localhost:8443

## 3. Shuffle (SOAR)

```bash
cd shuffle
cp .env.example .env
$EDITOR .env
docker compose up -d
```

UI : http://localhost:3001 — API : http://localhost:5001

Workflows Host Isolation / Kill Process — pas d'export upstream à importer,
recréés par l'API (webhook ids fixés sur ceux attendus par `ai/.env`) :

```bash
SHUFFLE_DEFAULT_APIKEY=$(grep SHUFFLE_DEFAULT_APIKEY .env | cut -d= -f2) \
WAZUH_API_USER=wazuh-wui \
WAZUH_API_PASSWORD=$(grep API_PASSWORD ../wazuh/.env | cut -d= -f2) \
WAZUH_HOST=<IP LAN de l'hôte, pas 127.0.0.1> \
SHUFFLE_WEBHOOK_ISOLATE=webhook_00000000-0000-0000-0000-00000000a001 \
SHUFFLE_WEBHOOK_KILL=webhook_00000000-0000-0000-0000-00000000a002 \
python3 workflows/build_workflows.py
```

Forensic Collection reste manuel (infra SSH K1/K2/K3 lourde à provisionner) —
cf. `shuffle/README.md`.

## 4. Active response Wazuh (agents)

```bash
scp wazuh/active-response/*.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g wazuh -m 750 /tmp/*-*.sh /var/ossec/active-response/bin/'
```

Déployer **tous** les scripts, pas seulement `host-*` et `kill-process` : un AR
déclaré dans `ossec.conf` du manager mais absent de l'agent échoue sans que rien
ne le signale côté manager (l'API répond 200, elle ne fait que transmettre). Les
comptes en particulier — `disable-account.sh` / `enable-account.sh` — vont par
paire : sans le second, une désactivation n'est pas défaisable.

## 5. soc-agent (pipeline IA)

```bash
cd ai
cp .env.example .env
$EDITOR .env
docker compose up -d db
docker exec -i socagent-db psql -q -U socagent -d socagent < soc_agent/schema.sql
docker compose up -d --build soc-agent-cycle soc-agent-reconcile soc-agent-whitelist-task
```
