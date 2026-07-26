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
docker compose up -d --build db soc-agent-cycle soc-agent-reconcile soc-agent-whitelist-task
```
