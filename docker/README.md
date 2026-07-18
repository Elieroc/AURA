# Wazuh — Docker

Stack Wazuh single-node (manager + indexer + dashboard) via Docker Compose. Config bind-mountée depuis `config/` — édition directe, pas besoin d'entrer dans les containers.

## Setup initial

1. Copier l'env :
   ```
   cp .env.example .env
   ```
   Remplir `INDEXER_PASSWORD` (mdp admin indexer), `WAZUH_VT_API_KEY`, `WAZUH_ABUSEIPDB_API_KEY`.

2. Reporter les clés VT/AbuseIPDB dans `config/wazuh_cluster/wazuh_manager.conf` (copié depuis `.example`, gitignored — jamais commit avec vraies clés) :
   ```
   cp config/wazuh_cluster/wazuh_manager.conf.example config/wazuh_cluster/wazuh_manager.conf
   ```
   Remplacer `WAZUH_VT_API_KEY_PLACEHOLDER` / `WAZUH_ABUSEIPDB_API_KEY_PLACEHOLDER`.

3. GeoIP : déposer `GeoLite2-City.mmdb` (compte MaxMind gratuit requis) dans `./geoip/`.

4. Générer les certs SSL indexer (une fois, avant premier démarrage) :
   ```
   docker compose -f generate-indexer-certs.yml run --rm generator
   ```

5. Démarrer :
   ```
   docker compose up -d
   ```

6. Dashboard : https://localhost (user `admin`, mdp = `INDEXER_PASSWORD` du `.env`).

## Sécurité

- `internal_users.yml` contient des hashs de démo (admin/kibanaserver) — à régénérer en prod via l'outil `wazuh-indexer` hash tool.
- `wazuh_manager.conf` (avec vraies clés API) et `wazuh_indexer_ssl_certs/` sont gitignored — seuls les `.example` / `.gitkeep` sont versionnés.
- `volumes/` (données runtime) gitignored.

## Arborescence

```
docker/
├── docker-compose.yml
├── generate-indexer-certs.yml
├── .env.example
├── config/
│   ├── certs.yml                          # définition nodes pour cert generator
│   ├── wazuh_cluster/wazuh_manager.conf.example
│   ├── wazuh_indexer/wazuh.yml
│   ├── wazuh_indexer/internal_users.yml
│   ├── wazuh_dashboard/opensearch_dashboards.yml
│   ├── wazuh_dashboard/wazuh.yml
│   └── wazuh_indexer_ssl_certs/           # certs générés (gitignored)
├── geoip/                                  # GeoLite2-City.mmdb (gitignored)
└── volumes/                                 # data runtime (gitignored)
```
