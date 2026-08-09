<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/aura-soc-logotype-dark.svg">
    <img src="assets/aura-soc-logotype.svg" alt="Aura-SOC" width="100%">
  </picture>
</p>

<p align="center"><strong>A</strong>utonomous <strong>U</strong>eba <strong>R</strong>esponse <strong>A</strong>nalysis - <strong>SOC</strong></p>

---

XDR autonome piloté par IA. Détection moderne avec Wazuh, enrichissement threat intel, triage, whitelisting et remédiation automatique pilotés par un LLM - pas de validation humaine requise. Parce que votre SOC mérite d'être à la hauteur de l'ère de l'intelligence artificielle.

## Architecture

```
                          ┌─────────────────────────────┐
   Agents Wazuh ────────► │        Wazuh Manager        │
   (endpoints)    1514    │  analyse, règles, alertes   │
                          │                             │
                          │  Intégrations :             │
                          │   • VirusTotal (FIM/hash)   │
                          │   • AbuseIPDB (réput. IP)   │
                          └──────────────┬──────────────┘
                                         │ filebeat
                          ┌──────────────▼──────────────┐
                          │        Wazuh Indexer        │
                          │   (OpenSearch, alertes)     │
                          └──────┬───────────────┬──────┘
                                 │               │
                  ┌──────────────▼──────┐   ┌────▼─────────────────┐
                  │   Wazuh Dashboard   │   │  soc-agent (IA)      │
                  │   https://localhost │   │  API DeepSeek        │
                  └─────────────────────┘   │  • Triage HIGH/CRIT  │
                                            │  • Rules creator     │
                                            │  • Whitelist         │
                                            │  • Mitigation        │
                                            └──────┬───────────────┘
                                                   │
                                    ┌──────────────▼──────────────┐
                                    │         DFIR-IRIS           │
                                    │  cases, timeline, IOC       │
                                    │  https://localhost:8443     │
                                    └─────────────────────────────┘
```

## Components

| Composant | Rôle | État |
|-----------|------|------|
| [`src/wazuh/`](src/wazuh/) | SIEM/XDR — détection, VirusTotal, AbuseIPDB, GeoIP | ✅ Testé E2E |
| [`src/ai/soc_agent/`](src/ai/soc_agent/) | Pipeline IA — ingest, corrélation, triage LLM, whitelist auto, remédiation | ✅ Sur données réelles |
| [`src/shuffle/`](src/shuffle/) | SOAR — orchestration des remédiations (isolation, kill) | ✅ Testé E2E |
| [`src/iris/`](src/iris/) | DFIR-IRIS — case management, un case par incident trié | ✅ Boucle fermée |
| [`src/iris/mcp/`](src/iris/mcp/) | Serveur MCP IRIS — investigation interactive | ✅ Connecté |

## Quick start

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

## Ressources

Toute la stack tient sur une seule machine. Chiffres mesurés sur le serveur de
production (17 agents Wazuh, 8 vCPU / 16 Gio / 99 Gio, 13 jours d'uptime) :
~5,5 Gio de RAM réellement utilisés, load average 1,5, 32 Gio de disque
consommés. L'IA appelle l'API DeepSeek — aucune inférence locale, donc **pas de
GPU et pas de RAM de modèle** à prévoir.

| Ressource | Strict minimum | Recommandé | Pourquoi |
|---|---|---|---|
| CPU | 4 vCPU x86-64 | 8 vCPU | Load moyen 1,5 ; pics sur l'analyse Wazuh et le feed vulnerability detector. En dessous de 4, l'indexer et l'OpenSearch de Shuffle se disputent le CPU au démarrage. |
| RAM | 8 Gio | 16 Gio | Somme des RSS ≈ 5 Gio (indexer 1,7 · shuffle-opensearch 1,3 · manager 0,55 · dashboard 0,22 · pile IRIS 0,75 · Postgres 0,3 · MCP 0,1). À 8 Gio il faut baisser les deux heaps JVM à `-Xms512m -Xmx512m` et accepter du swap. |
| Disque | 60 Gio SSD | 100 Gio SSD | 32 Gio occupés : images Docker 21 Gio, volumes 9,5 Gio dont **7,7 Gio pour la seule base CVE du vulnerability detector**. Les index d'alertes restent petits (~220 Mio) avec la rétention courte par défaut. |
| Swap | 2 Gio | 2 Gio | Filet de sécurité, pas une réserve : sur 16 Gio il est déjà consommé à 90 % par des pages inactives. |
| Réseau | — | sortie Internet | API DeepSeek, VirusTotal, AbuseIPDB, feed CVE Wazuh. Sans elle le triage IA et l'enrichissement sont morts. |

Prévoir en plus, hors valeurs ci-dessus :

- **+1 Gio de RAM et +2 vCPU par tranche de ~50 agents** supplémentaires (le
  manager Wazuh est le premier à saturer).
- **Croissance disque** : ~1 Gio/mois d'index d'alertes pour ce volume, à
  multiplier si la rétention de `wazuh-*` est allongée.
- `vm.max_map_count=262144` est obligatoire, sinon l'indexer refuse de démarrer.

## Documentation

| Document | Contenu |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | mise en service complète du stack (Wazuh, Shuffle, IRIS, soc-agent) |
| [`docs/TRAINING.md`](docs/TRAINING.md) | mode training : apprendre le bruit ambiant du SI avant de laisser le SOC agir |
| [`docs/UEBA.md`](docs/UEBA.md) | moteur comportemental : faire remonter les alertes LOW/MEDIUM qui le méritent, sans noyer le LLM |
| [`docs/REMEDIATION.md`](docs/REMEDIATION.md) | remédiation autonome de bout en bout + catalogue de toutes les active responses |
| [`docs/MCP.md`](docs/MCP.md) | serveur MCP : administrer AURA depuis n'importe quel client IA (relaie Wazuh et IRIS) |

## Security principles

- **Ce qui sort de l'hôte** : le contexte des incidents part vers l'API DeepSeek **pseudonymisé** (`anonymize.py`, appel refusé si une valeur réelle survit, réhydraté à la réponse). Hash et IP partent aussi aux API VT/AbuseIPDB. Le reste ne quitte pas l'infra.
- **Pas d'humain dans la boucle, des garde-fous dans le code** : les actions à fort impact (isolation, blocage IP, désactivation de compte) s'exécutent **seules** sur verdict vrai positif — c'est le but du projet. Bornées par des garde-fous déterministes (`actions.appliquer_garde_fous`), pas par un accord humain. **Le LLM n'est pas une frontière de sécurité** : mesuré, 3 injections sur 4 dans les logs retournent son verdict.
- **Secrets hors dépôt** : clés API, mots de passe et certificats gitignorés ; seuls des `.example` sont versionnés.

## Repository structure

```
AURA/
├── docker-compose.yml   # compose racine unique — les 4 stacks
├── .env.example         # config racine unique (copier en .env)
├── docs/                # INSTALL, TRAINING, UEBA, REMEDIATION, MCP
├── scripts/             # install-agent.sh, déploiement AR...
├── db/                  # bases de données (Postgres/OpenSearch), gitignoré
└── src/                 # les 4 stacks buildables : ai/ · iris/ · shuffle/ · wazuh/
```

`mcp/` (serveur MCP Wazuh) reste hors dépôt et hors de ce compose — déploiement
séparé, voir `mcp/README.md`.
