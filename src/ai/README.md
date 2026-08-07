# Couche IA du SOC

- [`soc_agent/`](soc_agent/) — le pipeline. **Phase 1 : ingestion et
  corrélation, sans LLM. Phase 2 : triage LLM en mode shadow.**

## Phase 1 — ce qu'elle fait et pourquoi

Wazuh produit des alertes en continu, largement redondantes : une même attaque
en génère des dizaines. Envoyer chaque alerte au LLM le noierait — à ~20 s le
triage sur ce CPU, la file ne se viderait jamais.

La phase 1 réduit le flux avant qu'il n'atteigne le modèle :

```
Indexer Wazuh ──► ingest ──► alerts ──► correlate ──► incidents ──► (phase 2 : triage LLM)
                              filtre       regroupe
                            niveau >= 12   par proximité
```

Mesuré sur un déploiement réel :

| | |
|---|---|
| Alertes ingérées | 680 sur 3,7 jours (183/jour) |
| Retenues (niveau ≥ 12) | 36 — **5,3 %** |
| Incidents après corrélation | **4** — facteur 9 |
| Charge LLM résultante | 0,4 min de CPU par jour |

Le cas typique : 31 alertes réparties sur 4 règles (`100670`, `100671`,
`100672`, `100682`) sur un même agent deviennent **un** incident ransomware.

Sur ce déploiement, la marge est confortable. Le rapport reste utile en
production à plus grande échelle, où le rapport 5,3 % / facteur 9 dira si
l'architecture tient.

## Installation

Prérequis : la stack Wazuh doit tourner (l'indexer est la source).

```bash
# Depuis la racine du dépôt — un seul .env / un seul compose pour toute la stack.
cp .env.example .env
$EDITOR .env

docker compose up -d
docker exec -i socagent-db psql -q -U socagent -d socagent < src/ai/soc_agent/schema.sql

# Environnement Python hors dépôt : celui-ci est synchronisé Nextcloud.
python3 -m venv ~/.local/share/soc-ai/venv
~/.local/share/soc-ai/venv/bin/pip install -r src/ai/soc_agent/requirements.txt
```

## Utilisation

```bash
cd src/ai
set -a; source ../../.env; set +a
VENV=~/.local/share/soc-ai/venv/bin/python

$VENV -m soc_agent.ingest --depuis 30d   # tire depuis l'indexer
$VENV -m soc_agent.correlate             # regroupe en incidents
$VENV -m soc_agent.report                # l'entonnoir et la charge LLM
```

Les deux premières commandes sont faites pour tourner en boucle : l'ingestion
reprend à son curseur, la corrélation ne traite que les alertes non encore
rattachées. En pratique on ne les lance pas à la main — voir le déclenchement
périodique ci-dessous.

Rejouer la corrélation après un changement de paramètres :

```bash
$VENV -m soc_agent.correlate --recommencer
```

Tests :

```bash
~/.local/share/soc-ai/venv/bin/python -m pytest tests -q
```

## Choix d'implémentation

### Tirer depuis l'indexer, pas se faire pousser par l'integrator

Wazuh sait pousser les alertes vers un script externe (`<integration>`). On a
retenu la lecture de l'indexer, pour trois raisons :

1. **Le GeoIP n'existe que là.** Il est appliqué par un pipeline d'ingest côté
   indexer ; l'integrator se déclenche en amont et ne verrait que des alertes
   sans géolocalisation.
2. **Rien à changer sur le manager**, donc aucun risque pour la détection.
3. **Le rattrapage est gratuit.** Si le soc-agent est arrêté deux jours, il
   reprend à son curseur. Un integrator aurait perdu les alertes.

### Pas de Redis

La file avait du sens avec une ingestion poussée. En tirant, le curseur en base
joue déjà le rôle de tampon. Redis reviendra quand il y aura plusieurs workers
de triage à alimenter — pas avant.

### Curseur sur (timestamp, id)

Trier sur le seul horodatage ne donne pas un ordre total : les 25 alertes
canari partagent la même milliseconde. Sans second critère, une reprise en
saute ou en rejoue une partie. L'ingestion reste idempotente de toute façon
(`ON CONFLICT` sur l'identifiant natif Wazuh), mais un curseur juste évite de
rebalayer.

### Corrélation : proximité temporelle **et** point commun explicite

Deux alertes rejoignent le même incident si elles sont sur le même agent,
proches dans le temps, et partagent quelque chose de nommable — tactique MITRE,
IP source, fichier, compte, groupe de règle. La proximité seule fusionnerait
des événements sans rapport ; sur un hôte actif, tout est proche de tout.

Les groupes trop répandus (`syscheck`, `pci_dss`, `linux`…) sont exclus : ils
sont sur la moitié des règles Wazuh et ne signifient rien.

### Fenêtre à deux vitesses

- **Lien fort** — même IP, même fichier, même compte : fenêtre de 6 h. Ces
  liens désignent le même objet concret. Une IP hostile qui revient trois fois
  dans l'après-midi est une campagne, pas trois incidents (cas réel :
  `185.220.101.34`, trois alertes AbuseIPDB entre 16 h 15 et 17 h 44).
- **Lien faible** — tactique MITRE, groupe de règle : fenêtre de 30 min. Ce
  sont des indices de parenté, pas des identités.

Garde-fou : `MAX_INCIDENT_HOURS` (6 h par défaut) borne le chaînage. Sans lui,
une alerte toutes les 25 minutes fusionnerait une semaine en un incident
illisible.

### Plusieurs incidents ouverts en parallèle par agent

Un seul incident ouvert par agent paraît suffisant, et ne l'est pas : une
alerte sans rapport qui s'intercale referme l'incident en cours. Deux alertes
de la même IP séparées par un événement étranger repartaient dans deux
incidents. L'entrelacement est le cas normal sur un hôte actif.

### Champs extraits à plusieurs emplacements

Les intégrations rangent l'IP source sous leur propre clé —
`data.abuseipdb.srcip` et non `data.srcip`. Sans cette prise en compte, les
alertes AbuseIPDB, celles qui portent précisément la réputation, arrivaient
sans IP et restaient incorrélables.

### Noise filter à deux niveaux

`noise_filter.yaml` déclare les alertes à écarter, avec un `query_level` par
entrée (idée reprise de majiinB/Wazuh-AI-Integration, adaptée au pull) :

- **`query_level: true`** — poussé dans un `must_not` de la requête à
  l'indexer. L'alerte n'entre jamais en base. Pour le bruit certain et
  volumineux.
- **`query_level: false`** — l'alerte est ingérée et **conservée pour
  l'audit**, mais marquée `suppressed` et exclue de la corrélation. Pour ce
  qu'on veut pouvoir relire.

Les filtres composites (`match_all` : plusieurs champs à la fois, p.ex.
`root` + commande de maintenance APT) sont toujours post-retrieval.

Le fichier livré est un **point de départ** : les comptes bruyants qu'il liste
(`_apt`, `nobody`…) ne sont pas forcément sur ton parc. Les vrais faux positifs
récurrents se découvrent en exploitation. Après édition :

```bash
$VENV -m soc_agent.ingest --reappliquer-filtre   # réévalue l'existant
$VENV -m soc_agent.correlate --recommencer
```

`report.py` affiche le nombre d'alertes écartées. Prudence : `query_level: true`
seulement quand l'alerte n'a *aucune* valeur — dans le doute, `false`, on garde
la trace.

## Phase 2 — triage LLM, mode shadow

Le modèle rend un verdict sur chaque incident. **Rien ne se déclenche** : les
verdicts sont enregistrés, comparés au jugement humain, et c'est tout — tant
que la justesse n'est pas mesurée, agir dessus serait un pari.

```
incidents ──► render ──► anonymize ──► DeepSeek ──► deduire ──► garde_fous ──► triages
              résumé      pseudonymes   verdict     actions      barrière       (shadow)
              ≤1500 tok   + anti-fuite  reason 1er  déduites     déterministe
```

Le triage appelle l'API DeepSeek : le contexte quitte l'hôte, donc il passe
d'abord par `anonymize.py` (jetons stables par incident, appel refusé si une
valeur réelle a survécu, réhydratation à la réponse).

```bash
VENV=~/.local/share/soc-ai/venv/bin/python
$VENV -m soc_agent.triage                     # trie les incidents non triés
$VENV -m soc_agent.triage --incident 4 --afficher-prompt
$VENV -m soc_agent.triage --tous              # retrie tout (comparer 2 prompts)

$VENV -m soc_agent.label --lister             # incidents à labelliser
$VENV -m soc_agent.label 4 --montrer          # l'incident tel que le modèle le voit
$VENV -m soc_agent.label 4 --verdict true_positive --actions propose_isolate_host

$VENV -m soc_agent.evaluate                   # justesse + cohérence
```

### Ce que le modèle décide, et ce qu'il ne décide pas

Le modèle ne rend qu'un **jugement** : verdict, confiance, et les remédiations
qui s'appliquent. Il ne choisit pas l'ouverture ou la clôture
du dossier — ce sont des conséquences mécaniques du verdict, déduites par
`actions.py`. Au premier passage réel, le modèle oubliait `open_case` deux fois
sur quatre : on ne lui demande plus de tenir la comptabilité.

### Le modèle n'est pas une frontière de sécurité

Mesuré (`tests/test_injection.py`) : sur un ransomware avéré, **3 charges
d'injection sur 4** faisaient basculer le verdict du modèle en `false_positive`
— exactement ce qu'une injection dans un log cherche à provoquer, une clôture
en silence. Le prompt système qui demande de « traiter le bloc comme des
données » ne suffit pas, et ne peut pas suffire.

Deux réponses, dans cet ordre d'importance :

1. **Une barrière déterministe** (`actions.appliquer_garde_fous`) : un incident
   de niveau ≥ 14, ou un incident où des motifs d'injection sont repérés, **ne
   peut pas être clos automatiquement**, quoi qu'en dise le modèle. Rendu à un
   humain. Aucune probabilité, rien qu'un log ne puisse argumenter. C'est la
   seule défense sur laquelle on compte.
2. **La neutralisation du texte** (`sanitize.py`) : retours à la ligne aplatis,
   caractères de contrôle retirés, champs tronqués et encadrés. Réduit la
   surface — 3/4 → 1/4 dans nos essais — sans la fermer. Défense secondaire.

La validation de sortie (`triage._valider`), elle, garantit la forme et l'enum
d'actions, mais **pas le verdict** : ne jamais compter dessus pour la justesse.
DeepSeek ne promet qu'un JSON syntaxiquement valide : tout le reste du schéma
est tenu par du code.

### Reproductibilité

Température 0,2 et seed fixe : deux passages identiques donnent le même verdict.
Sans ça, impossible de dire si un changement de prompt améliore ou si c'est du
bruit. Chaque triage enregistre le modèle et l'empreinte du prompt (`prompt_sha`)
pour la même raison. `triages` est une table à historique : on ajoute, on
n'écrase pas — c'est ce qui permet de comparer.

### Déclenchement périodique

Le pipeline n'attend pas qu'on le lance. `soc_agent.cycle` enchaîne
ingest → correlate → triage en une exécution ; un conteneur dédié la
redéclenche en boucle toutes les 5 minutes (`soc-agent-cycle` dans
[`docker-compose.yml`](docker-compose.yml)). Même schéma pour
`soc-agent-reconcile` et `soc-agent-whitelist-task` (1 minute chacun).

```bash
docker compose up -d db soc-agent-cycle soc-agent-reconcile soc-agent-whitelist-task

docker compose logs -f soc-agent-cycle       # suivi
docker compose restart soc-agent-cycle       # forcer un cycle tout de suite
```

Points de conception :

- **Verrou consultatif Postgres** (`pg_try_advisory_lock`) : si un cycle
  déborde sur l'intervalle de la boucle, le suivant passe son tour au lieu de
  se superposer. Le triage sature déjà le CPU, deux cycles en parallèle ne
  gagneraient rien.
- **Idempotent** : chaque étape reprend où elle en est (curseur, alertes non
  corrélées, incidents non triés). Rejouer un cycle ne duplique rien.
- **Plafond par cycle** (`--limite-triage`, 50) : garde-fou contre un afflux
  qui saturerait le CPU d'un coup.

### Whitelist automatique

La boucle se referme : quand le triage juge `false_positive` de façon répétée
sur une même signature, `soc_agent.whitelist` crée une exception, et les
alertes futures qui matchent sont écartées avant corrélation et triage. L'IA
cesse de rejuger sans fin le même faux positif. Intégré au cycle, après le
triage.

```bash
$VENV -m soc_agent.whitelist --simulation   # montre sans créer
$VENV -m soc_agent.whitelist                # crée les exceptions dues
$VENV -m soc_agent.whitelist --lister
```

Une exception est une entrée `whitelist_rules` (table distincte du
`noise_filter.yaml` humain — un processus auto ne réécrit pas un fichier
versionné). `noise.py` lit les deux sources. Toujours composite et
post-retrieval : l'alerte reste en base pour l'audit, une whitelist trop large
reste rattrapable.

**Signature.** Les champs constants sur toutes les alertes de l'incident,
parmi `rule_id`, `src_user`, `command`, `file`. Le champ `file` est virtuel
(résout `syscheck.path`, le fichier VirusTotal, la cible auditd…) : il permet
de whitelister un chemin précis — `/tmp/eicar.com` — sans neutraliser toute la
règle VirusTotal.

**Trois garde-fous**, même logique que le triage :

- Signature **précise** exigée : `rule_id` seul est refusé (il neutraliserait
  une règle entière). Il faut au moins un compte, une commande ou un fichier.
- Jamais de whitelist auto au-dessus de `WHITELIST_MAX_LEVEL` (14). C'est aussi
  le mur contre un attaquant qui provoquerait des FP répétés pour se faire
  whitelister.
- Une signature vue **au moins une fois en `true_positive`** n'est jamais
  whitelistée, même si elle apparaît par ailleurs en FP.

Seuil de récurrence : `WHITELIST_MIN_FP` (3 par défaut). Un seul FP peut être
un accident ; la récurrence est le signal. `--min-fp 1` pour un POC agressif.

### Mode training — apprendre le bruit ambiant avant d'agir

Branché tel quel sur un SI déjà en production, l'XDR autonome tire sur tout ce
qui bouge : sauvegardes, scripts d'admin, scanners de conformité produisent des
alertes HIGH/CRITICAL parfaitement légitimes. Sans apprentissage préalable, le
premier jour se solde par des dizaines de cases et des **serveurs sains
isolés**.

Le mode training est une fenêtre de confiance déclarée par l'administrateur au
lancement du SOC, réglages dans le `.env` racine :

```bash
# .env
TRAINING_ENABLED=true
TRAINING_DAYS=7
```

```bash
docker compose up -d                                          # lance toute la stack
docker exec soc-training python -m soc_agent.training --etat
docker exec soc-training python -m soc_agent.training --cloturer   # fin anticipée
```

Pendant la fenêtre (7 jours par défaut) :

- **le pipeline d'analyse est suspendu** — `cycle.py` ingère, puis s'arrête
  net : pas de corrélation, pas de triage LLM, pas de case, donc **pas de
  remédiation** (elle part de `iris.creer_case`). Coût LLM nul ;
- chaque alerte de niveau ≥ `TRAINING_MIN_LEVEL` (12) devient une exception de
  whitelist, `source = 'training'`. **Déterministe, sans LLM** : groupement par
  (règle, machine), un `whitelist_rules` par groupe.

**Signature** — plus permissive que celle de la whitelist automatique, sur deux
points assumés :

- `agent_name` en fait **toujours** partie : le bruit ambiant appartient à une
  machine. Une exception apprise sur le serveur de sauvegarde n'aveugle pas le
  reste du parc ;
- l'absence de discriminant (compte/commande/fichier) **n'est pas un refus** —
  beaucoup de bruit d'infra n'en a aucun. `rule_id + agent_name` reste borné à
  un hôte, là où `rule_id` seul (refusé en exploitation) neutraliserait la
  règle partout.

Le plafond de niveau est propre au training : `TRAINING_MAX_LEVEL` (15, contre
14 pour `WHITELIST_MAX_LEVEL`). Le bruit CRITICAL est justement celui qui
déclenche les remédiations les plus coûteuses ; l'exclure viderait le mode de
son intérêt.

**Clôture.** À l'échéance, dans cet ordre : dernier apprentissage → noise filter
réappliqué à toutes les alertes déjà en base (`ingest.reappliquer_filtre`, le
bruit appris passe `suppressed`) → case IRIS **« TRAINING »** → statut figé, ce
qui débloque le pipeline. Le statut, pas la date, gouverne la suspension :
sinon un cycle passant entre l'échéance et la clôture corrélerait le backlog
brut.

**Révocation.** Le case TRAINING porte **une tâche par exception**. Passer une
tâche en `Canceled` désactive l'exception (`active = false`) et réapplique le
filtre : les alertes qu'elle masquait redeviennent visibles. C'est le contrôle
qui rattrape la limite du mode — *une intrusion déjà en cours au lancement du
SOC serait apprise comme du bruit*. Le sens est unique : repasser la tâche en
`Done` ne réactive rien, une exception retirée se recrée explicitement.

Le conteneur `soc-training` reste en vie après la clôture : c'est lui qui écoute
ces révocations (cadence 5 min).

### Cases DFIR-IRIS

Un case IRIS par incident trié (`soc_agent.iris`, en fin de cycle). Écrit en
`dfir-iris-client` direct — déterministe, pas de boucle d'outils. Le serveur
MCP IRIS (`src/iris/mcp/`) sert l'investigation *interactive*, c'est un autre
usage.

```bash
$VENV -m soc_agent.iris              # crée les cases manquants
$VENV -m soc_agent.iris --incident 15
```

Chaque case reçoit les IOC de l'incident (IP source, fichiers, hashs) et une
note d'analyse, selon le verdict :

- **Faux positif** → note expliquant pourquoi, et l'**exception de whitelist**
  si le pipeline en a créé une pour cette signature (état, `match_all`, motif).
- **Vrai positif** → **rapport généré par le LLM** (`prompts/report.md`) :
  résumé, analyse, puis les **actions de remédiation** exécutées automatiquement
  (celles à fort impact — isolation, blocage, désactivation — signalées comme
  telles dans le rapport, mais bien **exécutées** : XDR autonome, garde-fous
  déterministes et non validation humaine), et une **piste de règle Wazuh** si
  le modèle repère un angle mort de détection — la règle, elle, ne se déploie
  jamais seule : PR git + merge humain.

`incidents.iris_case_id` garde le lien et évite les doublons. Si le LLM est
injoignable, le case se crée quand même, avec la justification du triage en
guise de rapport.

> `correlate --recommencer` supprime les incidents et donc le lien
> `iris_case_id` : les cases déjà dans IRIS deviennent orphelins et un doublon
> serait recréé au cycle suivant. La commande le signale ; en fonctionnement
> normal (cycle), `--recommencer` n'est pas utilisé.

### Sortir du mode shadow

`evaluate.py` refuse de conclure sous 30 incidents labellisés : un « 100 % »
sur quatre cas n'a pas de sens. Le golden set d'environ 200 alertes reste le
prérequis. Une justesse suffisante permet d'**activer l'automatisation**, par
niveau d'autonomie configurable ; une fois un niveau actif, les actions
correspondantes partent seules — ce qui gouverne, c'est la justesse mesurée,
pas une validation humaine par action.

## UEBA — les alertes LOW/MEDIUM (`ueba.py`)

`MIN_LEVEL=12` laisse un angle mort : une intrusion qui n'émet que du niveau
3-11 (énumération, exécution d'un binaire déposé, connexion depuis un pays
jamais vu, persistance discrète) n'ouvre jamais d'incident. Baisser le seuil
noierait le SOC et la facture. UEBA est le troisième étage de réduction :

```
noise filter -> filtre VT -> UEBA (0 token) -> corrélation -> triage LLM -> IRIS
```

Il ne juge pas, il **classe**. Le verdict VP/FP reste au LLM, en bout de chaîne,
sur un incident déjà constitué et déjà scoré — jamais sur une alerte isolée.

**Aucune ingestion nouvelle** : tout se calcule sur `alerts` et `alerts.raw`,
déjà en base (`INGEST_MIN_LEVEL=0` stocke déjà tout).

### Comment le score est fait

Trois primitives déterministes, toutes explicables à un analyste — même
exigence que `correlate.py`, et pour la même raison : un score qu'on ne peut pas
contester ne peut pas justifier une action.

1. **Rareté (surprisal)** — `-log2(p)` de la valeur dans son scope, en bits.
   L'unité compte : sommer des bits d'information a un sens, sommer des
   « points » n'en a pas. Lissage de Laplace, donc jamais de score infini sur un
   profil maigre.
2. **Première vue** — la valeur n'existe pas dans un profil **mûr**. Score
   plafond (`UEBA_FIRSTSEEN_BITS`), **modulé par la rareté sur la flotte** : un
   binaire inédit ici mais présent sur dix autres hôtes est un déploiement
   d'admin, pas une intrusion. C'est le principal anti-faux-positif du module.
3. **Chaîne MITRE** — le brut « 3 tactiques distinctes » remonte surtout
   `Discovery` x3, soit un admin qui inventorie sa machine. Les tactiques sont
   donc **pondérées** (credential-access 5, discovery 1) et un bonus s'ajoute
   quand elles **progressent** dans l'ordre de la kill chain.

Deux scopes : `host` (la machine) et `user@host` (la personne sur cette
machine — c'est là que se voit la latéralisation). Traits observés : `exe`,
`parent_child`, `srcip`, `pays`, `dst_port`, `compte`, `rule_id`, `heure`.

`days_seen` (jours **distincts**) décide qu'une valeur est une habitude, pas le
nombre d'occurrences : 500 exécutions en un seul jour est un incident, 5 sur 5
jours est une routine.

### Ce qui borne le coût

Le seuil de score ne borne rien — le volume varie d'un facteur dix entre une
journée calme et une campagne. Ce qui borne, c'est **`UEBA_BUDGET_JOUR`** : un
nombre de promotions qu'on décide. Un signal non promu n'est pas perdu, il est
réévalué au cycle suivant et son score aura grossi s'il continue.

Calibrer le plancher **sans consommer un token** :

```bash
docker exec soc-agent-cycle python -m soc_agent.ueba --simulation
docker exec soc-agent-cycle python -m soc_agent.ueba --etat
```

Les signaux sont enregistrés dans `ueba_signals` **avec leur score et leurs
motifs, promus ou non** : l'histogramme se relit après coup.

### Démarrage à froid

Le tout premier passage ne score **rien** : aucun profil n'est mûr, tout y
serait inédit. Il avale l'historique et le prend pour baseline. Le scoring
démarre quand un scope atteint `UEBA_MATURITE_JOURS` jours **et**
`UEBA_MATURITE_MIN_OBS` observations. La fenêtre de training amorce la baseline
gratuitement si elle est utilisée.

### Garde-fous

- **`UEBA_MITIGATE=false`** par défaut, et c'est délibéré. Le reste du pipeline
  agit sans validation humaine parce qu'il part d'une règle Wazuh de niveau
  >= 12, qui a déjà exigé plusieurs corrélations. Un incident UEBA part d'un
  score **statistique dont la justesse n'est pas mesurée** : le laisser isoler
  un hôte reviendrait à confier la production à un seuil non calibré. Le verdict
  est rendu, le case IRIS créé avec les actions proposées, rien n'est exécuté.
  Même raisonnement que `evaluate.py` — on n'agit pas sur ce qu'on n'a pas
  mesuré — appliqué à un moteur neuf.
- **`seen_in_tp`** : un trait impliqué dans un vrai positif ne peut plus jamais
  devenir une habitude. Sans ça, un attaquant patient normalise son propre
  outillage en le lançant tous les jours jusqu'à ce qu'il cesse d'être scoré.
- Les **motifs partent pseudonymisés** au LLM (`anonymize.anonymiser` les traite
  par type). Sans cette passe, `verifier_fuite` refuserait l'incident — et tout
  ce que le moteur remonte serait silencieusement écarté du triage.
- `_graine_valide` s'applique aussi aux graines UEBA : un SCA ou un statut
  d'agent ne fonde pas de case, même statistiquement rare.

### Ce qui n'a pas été fait, et pourquoi

Pas de ML non supervisé (isolation forest, autoencodeur). Sans jeu labellisé, sa
dérive serait indétectable ; un score inexplicable ne peut ni être contesté par
un analyste ni justifier une remédiation. La surprisal donne le même résultat et
se lit en une phrase. À reconsidérer **après** le golden set, pas avant.

## Attention

`TRUNCATE incidents CASCADE` **vide aussi `alerts`** (clé étrangère). Pour
remettre la corrélation à zéro, utiliser `correlate --recommencer`, qui passe
par un `DELETE`.

## Reste à faire

- Golden set (~200 alertes labellisées) — le vrai prochain jalon.
- Le seuil `MIN_LEVEL=12` mérite d'être confronté au terrain : certaines
  attaques n'émettent que du niveau 10-11.
- Rétention : la table `alerts` grossit sans limite.
