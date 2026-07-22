# SOC-AI

SOC piloté par IA locale. Détection Wazuh + enrichissement threat intel + automatisation règles/whitelist/mitigation via IA locale (pas de cloud LLM sur données SOC).

## Stack

- **Wazuh** — SIEM/XDR core. Manager + agents endpoints.
  - **GeoIP** — enrichissement géoloc des IP sources (module Wazuh GeoIP / MaxMind GeoLite2).
  - **VirusTotal (VT)** — enrichissement réputation fichiers/hash/IP via API VT.
  - **AbuseIPDB** — enrichissement réputation IP (score abus, historique reports).
- **Shuffle** — SOAR pour l'orchestration des remédiations (`shuffle/`). Workflow "Wazuh - Host Isolation" : webhook → API Wazuh → active response `host-isolate.sh`/`host-unisolate.sh` (nftables) sur l'agent. Déclenchement manuel uniquement.
- **DFIR-IRIS** (`iris/`) — case management. Un case par incident : timeline, IOC, assets, trace des actions automatiques. Retenu contre TheHive 5 (partiellement sous licence commerciale, et 6–8 Go de RAM contre ~650 Mo). API « legacy » `/manage/*` — **pas de `/api/v2` en v2.4.27**.
- **IA locale** — **pas de GPU sur cet hôte** (Ryzen 8c/16t AVX-512, 30 Go RAM partagés avec toute la stack). Conséquences structurantes :
  - Runtime : **llama.cpp** (et pas vLLM, dont le backend CPU est faible). Grammaires GBNF pour garantir le JSON, prefix caching par slots.
  - **Un seul modèle : Qwen3-8B Q4_K_M**, pour sa robustesse au prompt. Mesuré (`ai/bench/RESULTS.md`) : le **Q4_K prefill plus vite que le Q5_K** malgré plus de paramètres (repacking AVX-512). Ne jamais prendre autre chose que du Q4_K_M sur cette machine ; repli éventuel sur un 4B, en Q4_K_M.
  - Toujours `/v1/chat/completions`, jamais `/completion` : le template de chat change le verdict.
  - Dans tout schéma de sortie, **`reason` avant `verdict`** : sinon le modèle tranche sans un token de raisonnement, et se trompe.
  - **Une politique de décision explicite pèse plus que la taille du modèle** (`ai/bench/policy.md`). Sans critères de choix des actions, le modèle retombe sur `escalate_human` — sûr et inutile. Le champ d'actions doit être une liste : une compromission réelle appelle plusieurs propositions.
  - Le prefill est le goulot (~50 t/s mesurés, pas les 100-150 estimés). Contexte visé **500–800 tokens, plafond dur 1500**. Préfiltrage déterministe avant tout appel LLM. Traitement asynchrone, ~15-25 s par alerte.
  - **L'IA ne traite que les alertes de niveau HIGH/CRITICAL.**
  - **Rules creator** — génère/propose règles Wazuh (decoders/rules XML). Jamais d'écriture directe : validation `wazuh-logtest` + rejeu de régression → PR git → merge humain.
  - **Whitelist** — propose/gère exceptions (faux positifs récurrents, IP/hosts de confiance), même flux PR.
  - **Mitigation** — propose actions de remédiation (blocage IP, isolation host, etc.) — décision finale reste humaine sauf si explicitement automatisée.

## Investigation sur les endpoints par l'IA

L'IA doit pouvoir aller chercher des infos sur la machine d'un agent (FP ou pas, contexte d'un événement). Le choix est arrêté : **collecteurs read-only en active response Wazuh, exposés comme outils MCP typés** — ni accès SSH piloté par le LLM, ni un workflow Shuffle par question.

- Pas de SSH : `host-isolate.sh` ne laisse joignable que le manager, donc le SSH tombe précisément quand on veut investiguer. Le canal Wazuh 1514 survit. Et une clé SSH sur le soc-agent, qui lit des logs contrôlés par l'attaquant, transformerait une prompt injection en shell root sur l'endpoint.
- Pas de workflow Shuffle par question : l'IA a besoin d'itérer. Shuffle reste réservé aux **actions d'écriture** avec gate humain.
- Le LLM choisit dans une **enum fermée** d'outils, avec des paramètres validés (Pydantic + allowlist). Jamais de shell arbitraire. Budget borné d'appels d'investigation par alerte.
- SSH reste réservé au forensique lourd (RAM, image disque), en pull manager→agent, comme déjà implémenté dans `scripts/forensic-*.sh`.

## Contraintes de sécurité

- Toute donnée SOC (logs, alertes, IOC) reste locale. Pas d'envoi vers API LLM cloud.
- Actions de mitigation à fort impact (blocage, isolation, changement de règle en prod) : proposer, ne jamais exécuter automatiquement sans validation explicite.
- Clés API (VT, AbuseIPDB) et secrets Wazuh : jamais en clair dans le repo — utiliser `.env` (gitignored) ou secrets manager.
- **Le LLM n'est pas une frontière de sécurité.** Mesuré : sur un ransomware avéré, 3 injections sur 4 dans les logs retournent le verdict du modèle en `false_positive`. La grammaire GBNF garantit la forme et l'enum d'actions, pas le verdict. Toute conséquence dangereuse (clôture d'un incident grave) est bloquée par une **barrière déterministe** dans le code (`actions.appliquer_garde_fous`), jamais par le prompt. Le texte non fiable est neutralisé avant le modèle (`sanitize.py`), mais ce n'est qu'une défense secondaire.

## Pipeline (ai/soc_agent/)

Phase 1 en place : ingestion + corrélation, **sans LLM**. Détail et justifications dans `ai/README.md`.

- On **tire** les alertes depuis l'indexer, on ne se fait pas pousser par l'integrator : le GeoIP est appliqué par un pipeline d'ingest côté indexer et n'existe que dans cette copie. Rattrapage gratuit après un arrêt.
- Pas de Redis tant que l'ingestion est en pull — le curseur en base fait tampon.
- Corrélation : proximité temporelle **et** point commun nommable, agent par agent. Fenêtre à deux vitesses (6 h pour un lien fort — même IP/fichier/compte ; 30 min pour un lien faible — tactique MITRE, groupe de règle). Plusieurs incidents ouverts en parallèle par agent.
- Noise filter à deux niveaux (`noise_filter.yaml`, idée reprise de majiinB/Wazuh-AI-Integration) : `query_level: true` → `must_not` indexer, jamais ingéré ; `false` → ingéré, marqué `suppressed`, gardé pour l'audit, exclu de la corrélation. `ingest --reappliquer-filtre` pour réévaluer l'existant après édition du YAML.
- Mesuré sur données réelles : 680 alertes → 36 retenues (niveau ≥ 12) → 4 incidents, facteur 9.
- Piège : `TRUNCATE incidents CASCADE` vide aussi `alerts`. Utiliser `correlate --recommencer`.

Phase 2 en place : triage LLM en **mode shadow** (verdict enregistré, rien de déclenché). Serveur llama.cpp en service systemd utilisateur (`ai/llm/`), loopback strict.

**Whitelist automatique** (`soc_agent.whitelist`) : les FP récurrents jugés par l'IA (même signature, ≥ `WHITELIST_MIN_FP`) deviennent des exceptions dans `whitelist_rules` (table distincte du YAML humain, lue par `noise.py`). Toujours composite + post-retrieval. Signature = champs constants parmi `rule_id`/`src_user`/`command`/`file` (`file` virtuel : whitelister `/tmp/eicar.com` sans aveugler la règle VT). Garde-fous : signature précise obligatoire (rule_id seul refusé), jamais au-dessus de niveau 14, jamais une signature vue en TP.

Déclenchement **périodique** : `soc_agent.cycle` enchaîne ingest → correlate → triage → whitelist ; timer systemd utilisateur toutes les 5 min (`ai/systemd/soc-agent-cycle.{service,timer}`). Verrou consultatif Postgres anti-chevauchement. Triage facultatif au cycle (`Wants` soc-llm, pas `Requires`). Plus lancé à la main.

- Le modèle ne rend qu'un **jugement** (verdict, confiance, remédiations). L'ouverture/clôture du dossier est déduite du verdict (`actions.py`), pas demandée au modèle — il oubliait `open_case` une fois sur deux.
- Cohérence verdict/actions vérifiée après coup (`coherence.py`) : mesurable sans jeu labellisé, signale un prompt dégradé.
- Température 0,2 + seed fixe = verdict reproductible. `triages` est à historique (on ajoute, on n'écrase pas) pour comparer deux prompts. `prompt_sha` tracé.
- Sortie du mode shadow : `evaluate.py` refuse de conclure sous 30 incidents labellisés. Golden set (~200) requis, et même alors l'automatisation reste une décision humaine par niveau d'autonomie.

## État du projet

Infra en place : Wazuh (manager, indexer, dashboard, agents, intégrations VT/AbuseIPDB/GeoIP), Shuffle, serveur MCP Wazuh, DFIR-IRIS, pipeline soc_agent (phases 1 et 2).

Reste à faire, dans l'ordre : golden set (~200 alertes labellisées) → mesure de justesse → création de cases IRIS → RAG → rules creator → remédiation (autonomie configurable).

## Conventions

- Commits en français ou anglais, clairs sur le "pourquoi".
- Config sensible (API keys, tokens) : jamais commit, toujours via variables d'env.
