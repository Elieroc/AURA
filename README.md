<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/aura-soc-logotype-dark.svg">
    <img src="assets/aura-soc-logotype.svg" alt="Aura-SOC" width="380">
  </picture>
</p>

<p align="center"><strong>A</strong>utonomous <strong>U</strong>eba <strong>R</strong>esponse <strong>A</strong>nalysis - <strong>SOC</p>

---

XDR autonome pilolé par IA. Détection avec Wazuh, enrichissement threat intel (VirusTotal, AbuseIPDB, GeoIP), triage, whitelisting et remédiation pilotés par un LLM - pas de validation humaine requise. Parce que votre SOC mérite d'être à la hauteur de l'ère de l'intelligence artificielle. 

## Architecture

Le modèle tourne sur l'**API DeepSeek** et non en local : cet hôte n'a pas de GPU et pas les ressources pour un modèle en continu. Conséquence assumée : **le contexte d'alerte quitte l'hôte**, pseudonymisé au préalable (`ai/soc_agent/anonymize.py`, refus d'appel si une valeur réelle survit).

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
| [`iris/`](iris/) | DFIR-IRIS — case management, un case par incident trié (IOC + rapport IA) | ✅ Boucle fermée |
| [`iris/mcp/`](iris/mcp/) | Serveur MCP IRIS (srozb/iris-mcp) — investigation interactive | ✅ Connecté |
| [`ai/soc_agent/`](ai/soc_agent/) | Pipeline : ingest + corrélation (ph.1), triage LLM + remédiation (ph.2) | ✅ Sur données réelles |
| IA — Rules creator | Génération de règles/decoders Wazuh à partir des alertes | 🔜 À venir |
| IA — Whitelist | Exceptions auto sur FP récurrents jugés par l'IA | ✅ Boucle fermée |
| IA — Mitigation | Isolation d'hôte, blocage IP, désactivation de compte — **exécutées automatiquement** sur verdict vrai positif | ✅ Testé E2E |

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

## Documentation

| Document | Contenu |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | mise en service complète du stack (Wazuh, Shuffle, IRIS, soc-agent) |
| [`docs/TRAINING.md`](docs/TRAINING.md) | mode training : apprendre le bruit ambiant du SI avant de laisser le SOC agir |
| [`docs/REMEDIATION.md`](docs/REMEDIATION.md) | remédiation autonome de bout en bout + catalogue de toutes les active responses |

## Principes de sécurité

- **Ce qui sort de l'hôte** : le contexte des incidents part vers l'API DeepSeek, **pseudonymisé** (`anonymize.py` : jetons stables par incident, appel refusé si une valeur réelle a survécu, réhydratation à la réponse). Hash et IP partent aussi aux API VT/AbuseIPDB pour l'enrichissement. Le reste (logs bruts, base) ne quitte pas l'infra.
- **Pas d'humain dans la boucle, des garde-fous dans le code** : les actions à fort impact (isolation d'hôte, blocage IP, désactivation de compte) s'exécutent **seules** sur un verdict vrai positif — c'est le but du projet. Ce qui les borne est déterministe et vérifiable : comptes protégés, cibles internes exclues, clôture d'un incident grave impossible, suspension sur motif d'injection (`actions.appliquer_garde_fous`), plus des refus locaux dans les scripts d'active response. **Le LLM n'est pas une frontière de sécurité** : mesuré, 3 injections sur 4 dans les logs retournent son verdict.
- **Seule exception encore sous revue humaine** : un changement de règle Wazuh en prod passe par PR git + merge (le rules creator ne pousse jamais en direct).
- **Secrets hors dépôt** : clés API, mots de passe et certificats gitignorés ; seuls des `.example` avec placeholders sont versionnés.

## Structure du dépôt

```
Aura-SOC/
├── CLAUDE.md            # contexte projet pour Claude Code
├── README.md
├── assets/              # identité visuelle (logotype, pictogramme SVG)
├── docs/                # documentation transverse
│   ├── INSTALL.md       # mise en service du stack
│   ├── TRAINING.md      # fenêtre d'apprentissage du bruit ambiant
│   └── REMEDIATION.md   # remédiation autonome + catalogue des active responses
├── ai/                  # couche IA : soc_agent (ingest, corrélation, triage, remédiation)
├── iris/                # DFIR-IRIS (case management)
├── scripts/             # install-agent.sh (agent + user d'admin distante)
├── shuffle/             # SOAR Shuffle (remédiation, workflow isolation d'hôte)
└── wazuh/               # stack Wazuh dockerisée
    ├── docker-compose.yml
    ├── generate-indexer-certs.yml
    ├── active-response/ # scripts AR custom (isolation nftables, comptes, firewall)
    ├── config/          # configs bind-mountées (manager, indexer, dashboard)
    └── integrations/    # scripts d'intégration custom (AbuseIPDB)
```
