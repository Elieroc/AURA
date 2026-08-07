<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/aura-soc-logotype-dark.svg">
    <img src="assets/aura-soc-logotype.svg" alt="Aura-SOC" width="380">
  </picture>
</p>

<p align="center"><strong>A</strong>utonomous <strong>U</strong>eba <strong>R</strong>esponse <strong>A</strong>nalysis - <strong>SOC</strong></p>

---

XDR autonome piloté par IA. Détection moderne avec Wazuh, enrichissement threat intel, triage, whitelisting et remédiation automatique pilotés par un LLM - pas de validation humaine requise. Parce que votre SOC mérite d'être à la hauteur de l'ère de l'intelligence artificielle.

## Architecture

Le modèle tourne sur l'**API DeepSeek**, pas en local (pas de GPU dédié). Conséquence assumée : **le contexte d'alerte quitte l'hôte**, pseudonymisé au préalable (`src/ai/soc_agent/anonymize.py`, refus d'appel si une valeur réelle survit).

```
Agents Wazuh ──1514──► Wazuh Manager ──filebeat──► Wazuh Indexer ──┬──► Wazuh Dashboard
 (endpoints)         (règles, VT, AbuseIPDB)      (OpenSearch)     │    https://localhost
                                                                    │
                                                                    └──► soc-agent (IA, API DeepSeek)
                                                                            triage · whitelist · mitigation
                                                                                    │
                                                                                    ▼
                                                                          DFIR-IRIS (cases, IOC)
                                                                          https://localhost:8443
```

## Composants

| Composant | Rôle | État |
|-----------|------|------|
| [`src/wazuh/`](src/wazuh/) | SIEM/XDR — détection, VirusTotal, AbuseIPDB, GeoIP | ✅ Testé E2E |
| [`src/ai/soc_agent/`](src/ai/soc_agent/) | Pipeline IA — ingest, corrélation, triage LLM, whitelist auto, remédiation | ✅ Sur données réelles |
| [`src/shuffle/`](src/shuffle/) | SOAR — orchestration des remédiations (isolation, kill) | ✅ Testé E2E |
| [`src/iris/`](src/iris/) | DFIR-IRIS — case management, un case par incident trié | ✅ Boucle fermée |
| [`src/iris/mcp/`](src/iris/mcp/) | Serveur MCP IRIS — investigation interactive | ✅ Connecté |
| Rules creator | Génération de règles/decoders Wazuh à partir des alertes | 🔜 À venir |

## Démarrage rapide

Prérequis : Docker + Docker Compose, `vm.max_map_count=262144`. Un seul
`.env` et un seul `docker-compose.yml` à la racine pilotent toute la stack.

```bash
git clone <dépôt> AURA && cd AURA
sysctl -w vm.max_map_count=262144
cp .env.example .env    # remplir mots de passe + clés API
mkdir -p db/{socagent-postgres,iris-postgres,shuffle-opensearch,wazuh-indexer}
docker compose -f src/wazuh/generate-indexer-certs.yml run --rm generator
./src/iris/scripts/generate-certs.sh
docker compose up -d
```

Dashboard Wazuh : https://localhost — `admin` / `INDEXER_PASSWORD` du `.env`.
Détail complet (configs à copier depuis les `.example`, étapes par stack,
schéma Postgres soc-agent, active response) : [`docs/INSTALL.md`](docs/INSTALL.md).

## Documentation

| Document | Contenu |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | mise en service complète du stack (Wazuh, Shuffle, IRIS, soc-agent) |
| [`docs/TRAINING.md`](docs/TRAINING.md) | mode training : apprendre le bruit ambiant du SI avant de laisser le SOC agir |
| [`docs/REMEDIATION.md`](docs/REMEDIATION.md) | remédiation autonome de bout en bout + catalogue de toutes les active responses |

## Principes de sécurité

- **Ce qui sort de l'hôte** : le contexte des incidents part vers l'API DeepSeek **pseudonymisé** (`anonymize.py`, appel refusé si une valeur réelle survit, réhydraté à la réponse). Hash et IP partent aussi aux API VT/AbuseIPDB. Le reste ne quitte pas l'infra.
- **Pas d'humain dans la boucle, des garde-fous dans le code** : les actions à fort impact (isolation, blocage IP, désactivation de compte) s'exécutent **seules** sur verdict vrai positif — c'est le but du projet. Bornées par des garde-fous déterministes (`actions.appliquer_garde_fous`), pas par un accord humain. **Le LLM n'est pas une frontière de sécurité** : mesuré, 3 injections sur 4 dans les logs retournent son verdict.
- **Seule exception sous revue humaine** : un changement de règle Wazuh en prod passe par PR git + merge.
- **Secrets hors dépôt** : clés API, mots de passe et certificats gitignorés ; seuls des `.example` sont versionnés.

## Structure du dépôt

```
AURA/
├── docker-compose.yml   # compose racine unique — les 4 stacks
├── .env.example         # config racine unique (copier en .env)
├── soc-ai.conf.example  # topologie déployée hors dépôt (agents + forensique manager)
├── docs/                # INSTALL, TRAINING, REMEDIATION
├── scripts/             # install-agent.sh, déploiement AR...
├── db/                  # bases de données (Postgres/OpenSearch), gitignoré
└── src/                 # les 4 stacks buildables : ai/ · iris/ · shuffle/ · wazuh/
```

`mcp/` (serveur MCP Wazuh) reste hors dépôt et hors de ce compose — déploiement
séparé, voir `mcp/README.md`.
