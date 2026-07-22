# Bench phase 0 — llama.cpp sur CPU

Mesuré le 2026-07-22 sur l'hôte du SOC, stack Wazuh + Shuffle + IRIS en marche.

- CPU AMD 8 cœurs / 16 threads, AVX-512 + VNNI + BF16, 30 Go RAM
- llama.cpp `e8e6c7a`, compilé `-DGGML_NATIVE=ON` (`-march=native`)
- 8 threads (les cœurs physiques ; le SMT dégrade l'inference et on garde de la
  marge pour le manager Wazuh)

Reproduire : `./run-bench.sh` (vitesse) puis `./run-quality.sh` (justesse).

## 1. Débit brut

| Modèle | pp512 | pp2048 | pp2048 @ d2048 | tg128 | tg128 @ d2048 |
|---|---|---|---|---|---|
| Qwen3-4B-Instruct-2507 **Q5_K_M** | 47,5 | 42,7 | 34,4 | 19,4 | 14,1 |
| Qwen3-8B **Q4_K_M** | **53,6** | **50,2** | **42,2** | 11,9 | — |

(tokens/s ; `pp` = prefill, `tg` = génération, `@ d2048` = avec 2048 tokens déjà
dans le cache KV)

### Le prefill est deux à trois fois plus lent que prévu

J'avais estimé 100–150 t/s de prefill à partir de la bande passante mémoire.
Le réel est ~50 t/s. La contrainte « contexte ≤ 2000 tokens » n'était pas
prudente, elle était optimiste : à 2048 tokens le prefill seul coûte ~40 s.

### La quantification pèse plus que la taille du modèle

**Le 8B Q4_K_M prefill plus vite que le 4B Q5_K_M**, avec deux fois plus de
paramètres. `Q4_K` bénéficie du repacking AVX-512 de ggml, `Q5_K` non : il
retombe sur un noyau générique.

Conséquence directe : **n'utiliser que du Q4_K_M sur cette machine.** Un Q5 ou
un Q6 « pour la qualité » se paye deux fois — plus gros *et* plus lent.

## 2. Justesse du triage

Alerte de test : brute force SSH aboutie sur `root`, IP notée 96/100 par
AbuseIPDB (1842 signalements), aucune connexion antérieure en 90 jours. Verdict
attendu : `true_positive`.

| Modèle | endpoint | ordre des champs | verdict | temps |
|---|---|---|---|---|
| 4B Q5_K_M | brut | verdict d'abord | ❌ false_positive | 18,5 s |
| 4B Q5_K_M | brut | reason d'abord | ❌ false_positive | 9,0 s |
| 4B Q5_K_M | chat | verdict d'abord | ❌ false_positive | 18,4 s |
| 4B Q5_K_M | chat | reason d'abord | ❌ false_positive | 7,8 s |
| 8B Q4_K_M | brut | verdict d'abord | ❌ **close_false_positive** | 20,2 s |
| 8B Q4_K_M | brut | reason d'abord | ✅ true_positive / high | 12,5 s |
| 8B Q4_K_M | chat | verdict d'abord | ✅ true_positive / high | 23,6 s |
| 8B Q4_K_M | chat | reason d'abord | ✅ **true_positive / high / escalate_human** | 14,7 s |

### Le 4B échoue ici — mais voir la section 5, la cause était mon prompt

Faux dans les quatre configurations. Sa justification est même lucide sur les
faits — elle décrit correctement la brute force — puis conclut à l'inverse.

J'en avais conclu qu'il était inapte au jugement. **C'était faux** : avec une
politique de décision explicite (section 5), il rend le bon verdict. La
conclusion correcte est que ces modèles sont beaucoup plus sensibles à la
qualité du prompt qu'à leur nombre de paramètres.

### Deux réglages font basculer le 8B

**Le template de chat.** L'endpoint `/completion` envoie le prompt brut, hors du
format sur lequel le modèle a été instruit. `/v1/chat/completions` applique le
template embarqué dans le GGUF. C'est la différence entre la ligne 5 et la
ligne 7 du tableau.

**L'ordre des champs JSON.** Avec `verdict` en premier, le modèle tranche au
premier token utile, sans un seul token de raisonnement derrière lui. En
plaçant `reason` d'abord, le JSON sert lui-même de chaîne de raisonnement et le
verdict est échantillonné avec l'analyse déjà en contexte. Coût identique —
mêmes tokens générés, simple ordre de champs. C'est le réglage le plus rentable
du bench.

La pire combinaison des deux donne `close_false_positive` sur une compromission
réelle : en autonomie L1, l'incident était clos sans qu'un humain le voie.

> **n = 1 alerte.** Ça suffit à valider ces réglages, pas à mesurer un taux
> d'erreur. Le golden set de ~200 alertes
> labellisées reste indispensable avant toute mise en shadow mode.

## 3. Effet du prefix caching

Deuxième requête identique, `cache_prompt: true` : prefill de 472 tokens → 1
token, soit **8,8 s économisées** sur le 8B. Le gain porte sur le préfixe
commun, donc tout ce qui est stable (prompt système, consignes, schéma) doit
précéder la partie variable (l'alerte). C'est une contrainte de rédaction des
prompts, pas une option de configuration.

## 4. Ce que ça change dans l'architecture

- **Un seul modèle : Qwen3-8B Q4_K_M.** Non parce que le 4B serait incapable
  (cf. section 5), mais parce qu'il est plus robuste au prompt, que le
  préfiltrage déterministe absorbe déjà le volume, et qu'un modèle unique tient
  en 4,7 Go avec un prefix cache non fragmenté. Si un jour la latence devient
  le problème, le 4B **en Q4_K_M** est le repli — jamais en Q5.
- **Toujours passer par `/v1/chat/completions`**, jamais `/completion`.
- **`reason` avant `verdict`** dans tout schéma de sortie où le modèle tranche.
- **Contexte : viser 500–800 tokens, plafond dur 1500.** À 2048 le prefill seul
  coûte 40 s.
- **Budget réel par alerte : 15 à 25 s.** À 100 alertes HIGH/CRITICAL par jour,
  ~40 min de CPU quotidien. Le périmètre HIGH/CRITICAL n'est pas un confort,
  c'est ce qui rend le système possible.
- Le gros modèle 14B/30B est hors de portée : à ~30 t/s de prefill il ferait
  passer le triage au-delà de la minute.

## 5. Politique de décision — le réglage le plus rentable du bench

Au premier passage, le 8B rendait le bon verdict mais choisissait
`escalate_human` sur une compromission qui appelait un blocage d'IP immédiat.

Cause : le prompt listait les actions possibles sans jamais dire **comment
choisir**. Le modèle voyait l'enum, n'avait aucun critère, et retombait sur la
sortie la plus sûre et la moins utile. Un défaut de prompt, pas de modèle.

Correction, dans `policy.md` (inséré dans `prompt-triage-v2.txt`) : un critère
de sélection par action, rédigé comme des règles et non comme des exemples — un
exemple détaillé se fait recopier même quand l'alerte ne lui ressemble pas.
Plus une ligne qui tranche le cas ambigu récurrent : *une authentification
réussie après une série d'échecs depuis une source hostile est une
compromission jusqu'à preuve du contraire, pas une tentative.*

Deux changements de schéma au passage (`triage-v2.gbnf`) : `actions` devient
une **liste** — une compromission réelle appelle plusieurs propositions, un
champ scalaire en sacrifiait deux — et `propose_disable_user` rejoint l'enum,
puisque ni le blocage d'IP ni l'isolation ne traitent le fait que l'attaquant
détient des identifiants valides.

| Modèle | prompt | verdict | actions |
|---|---|---|---|
| 8B Q4_K_M | v1 | true_positive | `escalate_human` |
| 8B Q4_K_M | **v2** | true_positive / high | `propose_block_ip`, `propose_disable_user`, `open_case`, `collect_endpoint_evidence` |
| 4B Q5_K_M | v1 | ❌ false_positive | `escalate_human` |
| 4B Q5_K_M | **v2** | ✅ true_positive / high | `propose_block_ip`, `propose_disable_user`, `collect_endpoint_evidence`, `open_case` |

Deux enseignements :

**La politique de décision compte plus que la taille du modèle.** Elle fait
passer le 4B de faux à juste. Ma conclusion de la section 2 — « le 4B est
inapte au jugement » — était une erreur d'attribution : je mesurais mon prompt,
pas le modèle.

**Le blocage d'IP arrive en tête, et les deux modèles ajoutent d'eux-mêmes la
désactivation du compte**, qui est le vrai problème ici. C'est le comportement
attendu d'un analyste : couper l'accès en cours, puis révoquer les
identifiants.

### Réserve

Le plafond de quatre actions a évincé `propose_isolate_host` des deux réponses,
alors que l'hôte est compromis et que l'isolation se défend au moins autant que
la collecte de preuves. À surveiller sur le golden set : soit relever le
plafond, soit hiérarchiser explicitement l'isolation dans la politique.

## Notes d'implémentation

- `llama-cli` du HEAD plante au démarrage (`cli_server::wait_ready`). Sans
  importance : la production passe par `llama-server`.
- GBNF — une règle se termine au retour à la ligne et ne peut s'étendre sur
  plusieurs lignes qu'à l'intérieur de parenthèses. Un `|` en début de ligne
  fait échouer tout le fichier sur un « failed to parse grammar » sans numéro de
  ligne. Cf. `grammars/json.gbnf` upstream pour l'idiome.
