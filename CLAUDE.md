# SOC-AI

XDR autonome. Détection Wazuh + enrichissement threat intel + triage/whitelist/remédiation pilotés par LLM, exécutés sans validation humaine par action.

## Stack

- **Wazuh** — SIEM/XDR core. Manager + agents endpoints.
  - **GeoIP** — enrichissement géoloc des IP sources (module Wazuh GeoIP / MaxMind GeoLite2).
  - **VirusTotal (VT)** — enrichissement réputation fichiers/hash/IP via API VT.
  - **AbuseIPDB** — enrichissement réputation IP (score abus, historique reports).
- **Shuffle** — SOAR pour l'orchestration des remédiations (`shuffle/`). Workflow "Wazuh - Host Isolation" : webhook → API Wazuh → active response `host-isolate.sh`/`host-unisolate.sh` (nftables) sur l'agent. Déclenché **automatiquement** par le soc-agent (`mitigate.py`) sur verdict vrai positif — pas de validation humaine (XDR autonome, cf. plus bas). Un déclenchement opérateur manuel reste possible (`mitigate --isoler`).
- **DFIR-IRIS** (`iris/`) — case management. Un case par incident trié (`soc_agent.iris`, en `dfir-iris-client` direct) : IOC + note d'analyse. FP → explication + exception whitelist ; TP → rapport LLM (résumé, analyse, remédiation, piste de règle si angle mort). Retenu contre TheHive 5 (partiellement sous licence commerciale, et 6–8 Go de RAM contre ~650 Mo). API « legacy » `/manage/*` — **pas de `/api/v2` en v2.4.27**. Serveur **MCP IRIS** (`iris/mcp/`, srozb/iris-mcp, stdio) pour l'investigation interactive — distinct de la création auto.
- **Modèle : API DeepSeek** (`llm.py`, compatible OpenAI). Un seul chemin, pas de repli local : l'IA locale (llama.cpp + Qwen3-8B) a été abandonnée faute de GPU et de RAM sur cet hôte, et tout a été supprimé — binaires, poids, dossier `ai/bench/`. Ne pas le réintroduire sans en reparler ; les mesures de l'époque restent dans l'historique git si besoin.
  - **Le contexte SOC quitte l'hôte**, donc pseudonymisation OBLIGATOIRE avant tout appel (`anonymize.py`) : jetons stables par incident (comparabilité entre triages), `verifier_fuite` refuse l'appel si une valeur réelle a survécu, réhydratation à la réponse pour qu'IRIS montre les vraies valeurs. Ne pas confondre avec `sanitize.py`, qui neutralise le texte hostile.
  - **Aucune contrainte de grammaire possible** : DeepSeek ne garantit qu'un JSON syntaxiquement valide (`response_format`), ni le schéma ni les enums. La contrainte est passée dans le code — `triage._valider` coerce et écarte, `actions.py` borne ensuite.
  - Toujours `/chat/completions` : le template de chat change le verdict.
  - Dans tout schéma de sortie, **`reason` avant `verdict`** : sinon le modèle tranche sans un token de raisonnement, et se trompe.
  - **Une politique de décision explicite pèse plus que la taille du modèle.** Le bloc qui la porte est dans `prompts/system.md`. Sans critères de choix des actions, le modèle retombe sur `escalate_human` — sûr et inutile. Le champ d'actions doit être une liste : une compromission réelle appelle plusieurs propositions.
  - Les modèles v4 **raisonnent**, et les tokens de raisonnement sont décomptés de `max_tokens` AVANT le contenu : un budget trop court rend `finish_reason=length` avec un content VIDE. D'où les plafonds larges de `config.py` (3000 pour le verdict, 4000 pour le rapport).
  - Contexte visé **500–800 tokens, plafond dur 5000** (`TRIAGE_PROMPT_MAX_TOKENS`) — imposé par le coût et par la précision (un contexte long noie ce qui tranche). Au-delà l'incident est ignoré ; l'ancien 1500 faisait taire les plus gros/graves (un incident à 350 alertes/niveau 14 sans triage ni case ni remédiation). Préfiltrage déterministe avant tout appel. ~15-25 s par incident.
  - **L'IA ne traite que les alertes de niveau HIGH/CRITICAL.**
  - **Rules creator** — génère/propose règles Wazuh (decoders/rules XML). Jamais d'écriture directe : validation `wazuh-logtest` + rejeu de régression → PR git → merge humain. Le rejeu de régression est `scripts/test-detection-rules.sh` (43 cas, dont les actions destructives qu'on ne peut pas exécuter sur l'agent).
  - **Règles locales : un fichier par règle, tout en anglais** (descriptions ET commentaires — les descriptions partent dans les alertes, les cases IRIS et le contexte LLM), dans `wazuh/config/wazuh_cluster/rules/<id>-<slug>.xml` (plus de `local_rules.xml`). Le répertoire est monté **directement** sur `/var/ossec/etc/rules` : le mécanisme `/wazuh-config-mount` copie sans jamais supprimer, donc un fichier renommé survivait dans le volume et la règle était chargée deux fois, en silence. Chargement par ordre alphabétique = ordre d'identifiant ; l'ordre n'arbitre qu'entre règles **sœurs indépendantes**, à rendre mutuellement exclusives par leurs conditions (`audit.key`, un champ discriminant), jamais par leur position. Avant de reformuler une description, vérifier qu'aucun code ne la matche (`grep -rn rule_desc ai/soc_agent/`) : `correlate.py` filtre les graines d'incident sur du texte anglais. Détail : `wazuh/config/wazuh_cluster/rules/README.md`.
  - **Capteur auditd** — les règles auditd de l'agent sont versionnées dans `wazuh/config/agent/zz-audit-wazuh.rules`. Le préfixe `zz-` est obligatoire (`augenrules` concatène en collation C et le `audit.rules` Debian commence par `-D`). Le fichier se termine par `-e 2` : la conf d'audit est **immuable**, donc **toute modification exige un reboot de la machine** — `augenrules --load` échoue. C'est ce qui empêche systemd-journald (et un attaquant) de reposer `audit_enabled=0`. Revue complète des règles High/Critical, pièges et mesures : `wazuh/DETECTION-REVIEW.md`.
  - **Whitelist** — propose/gère exceptions (faux positifs récurrents, IP/hosts de confiance), même flux PR.
  - **Mitigation** — exécute les actions de remédiation (blocage IP, isolation host, désactivation de compte) **de façon autonome** dès le verdict vrai positif (`MITIGATE_EXECUTE=true`), y compris les actions à fort impact. C'est le but du projet : un XDR autonome, pas un assistant qui attend un clic. La sûreté ne vient pas d'un accord humain a priori mais de **garde-fous déterministes** dans le code (`actions.appliquer_garde_fous`, comptes protégés, cibles internes exclues, suspension sur injection) ET dans les scripts d'active response eux-mêmes (refus de root/wazuh, de la loopback, du manager) — l'AR est aussi joignable par l'API et le MCP, qui ne passent pas par le code Python. Une action annulée par l'analyste (tâche IRIS `Canceled`) ne repart jamais seule : `_deja_exec` fige aussi `annulé`. **Résolution par machine** (`mitigate._cibles_par_machine`) : un case de campagne couvre plusieurs hôtes, donc chaque remédiation part sur **la machine où sa preuve a été observée** (l'`agent_id` de l'alerte), jamais sur un agent global — la table `mitigations` porte désormais l'`agent_id` visé. Garde-fou « dans le doute, on n'agit pas » : un agent **capteur d'hôte** (`AGENTS_CAPTEURS`, ex. l'hôte Proxmox 009) n'est jamais une cible — sa télémétrie décrit d'autres machines, donc un backdoor vu seulement par lui (conteneur sans auditd propre) n'est **pas** désactivé automatiquement (c'était le bug : `disable-account` tirait sur l'hôte où le compte n'existe pas).

## Investigation sur les endpoints par l'IA

L'IA doit pouvoir aller chercher des infos sur la machine d'un agent (FP ou pas, contexte d'un événement). Le choix est arrêté : **collecteurs read-only en active response Wazuh, exposés comme outils MCP typés** — ni accès SSH piloté par le LLM, ni un workflow Shuffle par question.

- Pas de SSH : `host-isolate.sh` ne laisse joignable que le manager, donc le SSH tombe précisément quand on veut investiguer. Le canal Wazuh 1514 survit. Et une clé SSH sur le soc-agent, qui lit des logs contrôlés par l'attaquant, transformerait une prompt injection en shell root sur l'endpoint.
- Pas de workflow Shuffle par question : l'IA a besoin d'itérer. Shuffle reste réservé aux **actions d'écriture** (remédiations), exécutées automatiquement — la séparation lecture/écriture est architecturale (investigation en MCP read-only), pas un gate humain.
- Le LLM choisit dans une **enum fermée** d'outils, avec des paramètres validés (Pydantic + allowlist). Jamais de shell arbitraire. Budget borné d'appels d'investigation par alerte.
- SSH reste réservé au forensique lourd (RAM, image disque), en pull manager→agent, comme déjà implémenté dans `scripts/forensic-*.sh`.

## Contraintes de sécurité

- Toute donnée SOC (logs, alertes, IOC) reste locale. Pas d'envoi vers API LLM cloud.
- Actions de mitigation à fort impact (blocage, isolation, désactivation de compte) : **exécutées automatiquement** dès le verdict vrai positif — c'est le but (XDR autonome). Ce qui les borne n'est pas un accord humain mais des garde-fous déterministes dans le code (comptes protégés, cibles internes exclues, suspension sur motif d'injection, idempotence). Exception : un **changement de règle Wazuh en prod** passe encore par PR git + merge humain (le rules creator ne pousse jamais en direct) — c'est un garde-fou de code, pas une revue d'action de réponse.
- Clés API (VT, AbuseIPDB) et secrets Wazuh : jamais en clair dans le repo — utiliser `.env` (gitignored) ou secrets manager.
- **Le LLM n'est pas une frontière de sécurité.** Mesuré : sur un ransomware avéré, 3 injections sur 4 dans les logs retournent le verdict du modèle en `false_positive`. La validation de sortie (`triage._valider`) garantit la forme et l'enum d'actions, pas le verdict. Toute conséquence dangereuse (clôture d'un incident grave) est bloquée par une **barrière déterministe** dans le code (`actions.appliquer_garde_fous`), jamais par le prompt. Le texte non fiable est neutralisé avant le modèle (`sanitize.py`), mais ce n'est qu'une défense secondaire.

## Pipeline (ai/soc_agent/)

Phase 1 en place : ingestion + corrélation, **sans LLM**. Détail et justifications dans `ai/README.md`.

- On **tire** les alertes depuis l'indexer, on ne se fait pas pousser par l'integrator : le GeoIP est appliqué par un pipeline d'ingest côté indexer et n'existe que dans cette copie. Rattrapage gratuit après un arrêt.
- Pas de Redis tant que l'ingestion est en pull — le curseur en base fait tampon.
- Corrélation : proximité temporelle **et** point commun nommable, agent par agent. Fenêtre à deux vitesses (6 h pour un lien fort — même IP/fichier/compte ; 30 min pour un lien faible — tactique MITRE, groupe de règle). Plusieurs incidents ouverts en parallèle par agent.
- **Fusion campagne (approche A)** : la corrélation reste cloisonnée par agent, mais à la création de case (`iris._fondre_campagne`) un incident est **fondu** dans le case d'une campagne déjà ouverte — **autre hôte inclus** — dès qu'ils partagent un **marqueur d'attaquant** (compte créé, IP C2 **externe**, fichier malveillant ; jamais une IP interne, sinon le rebond admin relierait tout le parc). Un case peut donc couvrir **plusieurs machines**. Fenêtre `CAMPAGNE_GAP_HOURS` (48 h ; 0 désactive). Le mapping n'est donc plus « 1 incident = 1 agent » : la remédiation résout la machine **par preuve** (ci-dessous).
- Noise filter à deux niveaux (`noise_filter.yaml`, idée reprise de majiinB/Wazuh-AI-Integration) : `query_level: true` → `must_not` indexer, jamais ingéré ; `false` → ingéré, marqué `suppressed`, gardé pour l'audit, exclu de la corrélation. `ingest --reappliquer-filtre` pour réévaluer l'existant après édition du YAML.
- Mesuré sur données réelles : 680 alertes → 36 retenues (niveau ≥ 12) → 4 incidents, facteur 9.
- Piège : `TRUNCATE incidents CASCADE` vide aussi `alerts`. Utiliser `correlate --recommencer`.

Phase 2 en place : triage LLM. Attention au vocabulaire, il a dérivé — `triages.mode`
vaut toujours `'shadow'` et les docs parlent de « mode shadow », mais **la
remédiation, elle, s'exécute réellement** (`MITIGATE_EXECUTE=true`, appelée par
`iris.creer_cases`). Ce qui reste « shadow » est le seuil de justesse : aucun
verdict n'a encore été validé contre un golden set. Le système agit sans que sa
justesse soit mesurée — c'est le POC assumé, pas un oubli.

**Whitelist automatique** (`soc_agent.whitelist`) : les FP récurrents jugés par l'IA (même signature, ≥ `WHITELIST_MIN_FP`) deviennent des exceptions dans `whitelist_rules` (table distincte du YAML humain, lue par `noise.py`). Toujours composite + post-retrieval. Signature = champs constants parmi `rule_id`/`src_user`/`command`/`file` (`file` virtuel : whitelister `/tmp/eicar.com` sans aveugler la règle VT). Garde-fous : signature précise obligatoire (rule_id seul refusé), jamais au-dessus de niveau 14, jamais une signature vue en TP.

Déclenchement **périodique** : `soc_agent.cycle` enchaîne ingest → correlate → triage → whitelist → cases IRIS ; conteneur `soc-agent-cycle` (boucle shell, `ai/docker-compose.yml`) toutes les 5 min. Verrou consultatif Postgres anti-chevauchement. Plus lancé à la main. Même schéma (conteneur + boucle + verrou) pour `soc-agent-reconcile` (1 min, annule une remédiation dont la tâche IRIS passe en `Canceled`) et `soc-agent-whitelist-task` (1 min, traite les tâches IRIS WHITELIST passées en `To do`).

- Le modèle ne rend qu'un **jugement** (verdict, confiance, remédiations). L'ouverture/clôture du dossier est déduite du verdict (`actions.py`), pas demandée au modèle — il oubliait `open_case` une fois sur deux.
- Cohérence verdict/actions vérifiée après coup (`coherence.py`) : mesurable sans jeu labellisé, signale un prompt dégradé.
- Température 0,2 + seed fixe = verdict reproductible. `triages` est à historique (on ajoute, on n'écrase pas) pour comparer deux prompts. `prompt_sha` tracé.
- Sortie du mode shadow : `evaluate.py` refuse de conclure sous 30 incidents labellisés. Golden set (~200) requis. L'automatisation s'active par **niveau d'autonomie configurable** — une fois un niveau activé, les actions correspondantes partent seules, sans validation humaine par action ; ce qui gouverne, c'est la justesse mesurée, pas un clic.

## État du projet

Infra en place : Wazuh (manager, indexer, dashboard, agents, intégrations VT/AbuseIPDB/GeoIP), Shuffle, serveur MCP Wazuh, DFIR-IRIS, pipeline soc_agent (phases 1 et 2).

`mcp/` (serveur MCP Wazuh) est **entièrement hors dépôt** — clone upstream, recette de déploiement et patch d'active response compris. Le dossier existe en local mais git l'ignore : ne pas s'étonner de son absence sur un clone neuf, et ne pas tenter de l'y remettre sans en reparler. Son contenu d'avant le 2026-07-26 reste dans l'historique git.

Reste à faire, dans l'ordre : golden set (~200 alertes labellisées) → mesure de justesse → RAG → rules creator (PR). La remédiation est faite et vérifiée de bout en bout sur l'agent (isolation nftables, blocage IP, désactivation de compte) ; ce qui manque n'est plus le mécanisme mais la mesure qui justifie de le laisser agir.

## Conventions

- Commits en français ou anglais, clairs sur le "pourquoi".
- Config sensible (API keys, tokens) : jamais commit, toujours via variables d'env.
