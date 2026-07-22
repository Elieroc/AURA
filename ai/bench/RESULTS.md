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

### Le 4B est inapte au jugement

Faux dans les quatre configurations. Sa justification est même lucide sur les
faits — elle décrit correctement la brute force — puis conclut à l'inverse. Il
reste utilisable pour le mécanique (extraction d'IOC, résumé, déduplication),
jamais pour rendre un verdict.

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

> **n = 1 alerte.** Ça suffit à disqualifier le 4B et à valider les deux
> réglages, pas à mesurer un taux d'erreur. Le golden set de ~200 alertes
> labellisées reste indispensable avant toute mise en shadow mode.

## 3. Effet du prefix caching

Deuxième requête identique, `cache_prompt: true` : prefill de 472 tokens → 1
token, soit **8,8 s économisées** sur le 8B. Le gain porte sur le préfixe
commun, donc tout ce qui est stable (prompt système, consignes, schéma) doit
précéder la partie variable (l'alerte). C'est une contrainte de rédaction des
prompts, pas une option de configuration.

## 4. Ce que ça change dans l'architecture

- **Un seul modèle : Qwen3-8B Q4_K_M.** L'idée d'un 4B pour le volume et d'un 8B
  pour le jugement tombe : le 4B ne sait pas juger, il prefill plus lentement en
  Q5, et le préfiltrage déterministe absorbe déjà le volume. Un seul modèle,
  c'est aussi 4,7 Go au lieu de 7,4 Go et un prefix cache non fragmenté.
- **Toujours passer par `/v1/chat/completions`**, jamais `/completion`.
- **`reason` avant `verdict`** dans tout schéma de sortie où le modèle tranche.
- **Contexte : viser 500–800 tokens, plafond dur 1500.** À 2048 le prefill seul
  coûte 40 s.
- **Budget réel par alerte : 15 à 25 s.** À 100 alertes HIGH/CRITICAL par jour,
  ~40 min de CPU quotidien. Le périmètre HIGH/CRITICAL n'est pas un confort,
  c'est ce qui rend le système possible.
- Le gros modèle 14B/30B est hors de portée : à ~30 t/s de prefill il ferait
  passer le triage au-delà de la minute.

## Notes d'implémentation

- `llama-cli` du HEAD plante au démarrage (`cli_server::wait_ready`). Sans
  importance : la production passe par `llama-server`.
- GBNF — une règle se termine au retour à la ligne et ne peut s'étendre sur
  plusieurs lignes qu'à l'intérieur de parenthèses. Un `|` en début de ligne
  fait échouer tout le fichier sur un « failed to parse grammar » sans numéro de
  ligne. Cf. `grammars/json.gbnf` upstream pour l'idiome.
