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

Importer/configurer les workflows Wazuh (Host Isolation, Kill Process,
Forensic Collection) — cf. `shuffle/README.md`.

## 4. Active response Wazuh (agents)

```bash
scp wazuh/active-response/host-*.sh wazuh/active-response/kill-process.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g wazuh -m 750 /tmp/host-*.sh /tmp/kill-process.sh /var/ossec/active-response/bin/'
```

## 5. soc-agent (pipeline IA)

```bash
cd ai
cp .env.example .env
$EDITOR .env
docker compose up -d --build db soc-agent-cycle soc-agent-reconcile soc-agent-whitelist-task
```
