# SOC-AI

SOC piloté par une IA locale. Détection avec Wazuh, enrichissement threat intel (VirusTotal, AbuseIPDB, GeoIP), et automatisation de la création de règles, de la gestion de whitelist et des propositions de mitigation par un LLM local — aucune donnée SOC n'est envoyée vers un LLM cloud.

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
                  │   Wazuh Dashboard   │   │      IA locale       │
                  │   https://localhost │   │  (llama.cpp, CPU)    │
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

## Composants

| Composant | Rôle | État |
|-----------|------|------|
| [`wazuh/`](wazuh/) | Stack Wazuh 4.9.2 single-node (Docker Compose) | ✅ Fonctionnel |
| VirusTotal | Hash des fichiers FIM vérifiés à l'API VT (règles 87103–87105) | ✅ Testé E2E |
| AbuseIPDB | Réputation IP source des alertes SSH/auth/attaques (règles 100621–100624) | ✅ Testé E2E |
| GeoIP | Géolocalisation des IP sources (pipeline ingest indexer, GeoLite2 embarquée) | ✅ Actif par défaut |
| Agents | Déploiement d'agents Wazuh sur les endpoints ([`scripts/install-agent.sh`](scripts/install-agent.sh)) | ✅ debian-vm actif |
| [`shuffle/`](shuffle/) | SOAR Shuffle — orchestration des remédiations | ✅ Testé E2E |
| Remédiation — isolation hôte | Active response nftables via workflow Shuffle ([`shuffle/README.md`](shuffle/README.md)) | ✅ Testé E2E |
| [`iris/`](iris/) | DFIR-IRIS — case management des incidents (https://localhost:8443) | ✅ Testé E2E |
| [`ai/bench/`](ai/bench/) | Bench llama.cpp CPU — modèle, quantification, prompts | ✅ Mesuré |
| [`ai/soc_agent/`](ai/soc_agent/) | Pipeline : ingest + corrélation (ph.1), triage LLM shadow (ph.2) | ✅ Sur données réelles |
| IA — Rules creator | Génération de règles/decoders Wazuh à partir des alertes | 🔜 À venir |
| IA — Whitelist | Exceptions auto sur FP récurrents jugés par l'IA | ✅ Boucle fermée |
| IA — Mitigation | Propositions d'actions de remédiation | 🔜 À venir |

## Démarrage rapide

Prérequis : Docker + Docker Compose, `vm.max_map_count=262144`.

```bash
cd wazuh
cp .env.example .env    # remplir mots de passe + clés API
# puis suivre wazuh/README.md (configs à copier depuis les .example, génération des certs)
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Dashboard : https://localhost — `admin` / `INDEXER_PASSWORD` du `.env`.
Détail complet (setup, intégrations, tests manuels) : [`wazuh/README.md`](wazuh/README.md).

## Principes de sécurité

- **Données locales** : logs, alertes et IOC ne quittent jamais l'infra locale (exception : hash/IP envoyés aux API VT/AbuseIPDB pour enrichissement).
- **Humain dans la boucle** : les actions à fort impact (blocage IP, isolation d'hôte, modification de règles en prod) sont proposées par l'IA, jamais exécutées sans validation explicite.
- **Secrets hors dépôt** : clés API, mots de passe et certificats gitignorés ; seuls des `.example` avec placeholders sont versionnés.

## Structure du dépôt

```
SOC-AI/
├── CLAUDE.md            # contexte projet pour Claude Code
├── README.md
├── ai/                  # couche IA : bench llama.cpp + soc_agent (ingest, corrélation)
├── iris/                # DFIR-IRIS (case management)
├── scripts/             # install-agent.sh (agent + user d'admin distante)
├── shuffle/             # SOAR Shuffle (remédiation, workflow isolation d'hôte)
└── wazuh/               # stack Wazuh dockerisée
    ├── docker-compose.yml
    ├── generate-indexer-certs.yml
    ├── active-response/ # scripts AR custom (isolation nftables)
    ├── config/          # configs bind-mountées (manager, indexer, dashboard)
    └── integrations/    # scripts d'intégration custom (AbuseIPDB)
```
