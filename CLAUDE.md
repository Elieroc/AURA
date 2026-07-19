# SOC-AI

SOC piloté par IA locale. Détection Wazuh + enrichissement threat intel + automatisation règles/whitelist/mitigation via IA locale (pas de cloud LLM sur données SOC).

## Stack

- **Wazuh** — SIEM/XDR core. Manager + agents endpoints.
  - **GeoIP** — enrichissement géoloc des IP sources (module Wazuh GeoIP / MaxMind GeoLite2).
  - **VirusTotal (VT)** — enrichissement réputation fichiers/hash/IP via API VT.
  - **AbuseIPDB** — enrichissement réputation IP (score abus, historique reports).
- **Shuffle** — SOAR pour l'orchestration des remédiations (`shuffle/`). Workflow "Wazuh - Host Isolation" : webhook → API Wazuh → active response `host-isolate.sh`/`host-unisolate.sh` (nftables) sur l'agent. Déclenchement manuel uniquement.
- **IA locale** (runtime pas encore choisi — candidats : Ollama, vLLM) :
  - **Rules creator** — génère/propose règles Wazuh (decoders/rules XML) à partir d'alertes ou de patterns observés.
  - **Whitelist** — propose/gère exceptions (faux positifs récurrents, IP/hosts de confiance).
  - **Mitigation** — propose actions de remédiation (blocage IP, isolation host, etc.) — décision finale reste humaine sauf si explicitement automatisée.

## Contraintes de sécurité

- Toute donnée SOC (logs, alertes, IOC) reste locale. Pas d'envoi vers API LLM cloud.
- Actions de mitigation à fort impact (blocage, isolation, changement de règle en prod) : proposer, ne jamais exécuter automatiquement sans validation explicite.
- Clés API (VT, AbuseIPDB) et secrets Wazuh : jamais en clair dans le repo — utiliser `.env` (gitignored) ou secrets manager.

## État du projet

Phase actuelle : mise en place initiale (infra Wazuh + repo). Runtime IA locale pas encore décidé.

## Conventions

- Commits en français ou anglais, clairs sur le "pourquoi".
- Config sensible (API keys, tokens) : jamais commit, toujours via variables d'env.
