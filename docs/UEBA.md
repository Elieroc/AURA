# UEBA — faire remonter les alertes LOW/MEDIUM qui le méritent

Code : [`src/ai/soc_agent/ueba.py`](../src/ai/soc_agent/ueba.py) · appelé par
`cycle.py` (conteneur `soc-agent-cycle`, toutes les 5 min) · réglages `UEBA_*`
dans le `.env` racine (gitignoré, cf. [`.env.example`](../.env.example)).

## Le problème

Le pipeline n'ouvre un incident qu'à partir du niveau Wazuh 12 (`MIN_LEVEL`).
C'est ce seuil qui rend le triage LLM abordable — mais il laisse un angle mort
entier : **une intrusion qui n'émet que du niveau 3-11 n'ouvre jamais rien.**

Énumération du système, exécution d'un binaire déposé, connexion depuis un pays
jamais vu, tâche planifiée créée, compte qui apparaît sur un hôte où il n'a
jamais servi : pris isolément, chacun de ces événements est un log de routine.
Wazuh les note 3, 5 ou 7. Aucun n'ouvre de case, aucun n'atteint le LLM.

Les descendre sous le seuil ne marche pas. Le parc produit ~32 000 alertes de
niveau 0-11 pour 110 alertes de niveau ≥ 12 : baisser `MIN_LEVEL` noierait le
SOC et ferait exploser la facture de tokens, pour un rapport signal/bruit pire
qu'avant.

## Le principe

UEBA est un **troisième étage de réduction**, à **zéro token** :

```
noise filter  ->  filtre VT  ->  UEBA  ->  corrélation  ->  triage LLM  ->  IRIS
   (0 tok)       (0 tok)      (0 tok)      (0 tok)         payant
```

Il **ne juge pas, il classe.** Il construit une baseline du comportement normal,
mesure à quel point ce qui arrive s'en écarte, regroupe les écarts voisins en
« signal », et promeut les mieux notés en **graine d'incident**. À partir de là
le chemin est celui de tout le monde : corrélation → triage → case.

Deux conséquences qui gouvernent tout le reste :

- **Le LLM ne voit jamais une alerte basse isolée.** Il voit un incident déjà
  constitué, déjà scoré, accompagné de l'explication du score.
- **Aucune ingestion nouvelle.** Tout se calcule sur `alerts` et `alerts.raw`,
  déjà en base — `INGEST_MIN_LEVEL=0` stocke déjà l'intégralité du flux.

## Ce qui est observé

Deux **scopes**, c'est-à-dire deux référentiels de normalité :

| scope | clé | ce qu'il capte |
|---|---|---|
| `host` | `agent_id` | le comportement de la **machine** |
| `user@host` | `compte` + `agent_id` | le comportement de la **personne sur cette machine** — c'est là que se voit la latéralisation |

`agent_id` et non `agent_name` : le nom peut changer, l'identifiant non.

Un scope `user@host` n'est créé que si l'événement porte un compte. Inventer un
`inconnu@hôte` fabriquerait un profil fourre-tout où tout finit par sembler
normal.

Neuf **traits**, chacun pondéré. Le critère d'admission est unique : *qu'est-ce
que ça change au verdict que cette valeur soit inédite ?* Un trait sans réponse
n'apporte que du bruit et du coût.

| trait | poids | source | pourquoi |
|---|---|---|---|
| `exe` | 1.0 | `audit.exe`, `win.eventdata.image` | le binaire qui s'exécute |
| `parent_child` | 1.3 | `parentImage` > `image` (Sysmon) | `sh` seul est banal ; `nginx>sh` est un webshell |
| `fichier` | 0.8 | `entity` (FIM) | un fichier qui apparaît est un indice, pas un fait |
| `srcip` | 0.9 | `data.srcip` | source de l'événement |
| `pays` | 1.0 | `GeoLocation.country_name` | connexion depuis un pays jamais vu |
| `dst_port` | 0.7 | `data.dstport` | sortie vers un port jamais vu |
| `compte` | 1.0 | `srcuser` | compte inhabituel sur cette machine |
| `rule_id` | 0.5 | la règle qui a tiré | règle jamais déclenchée ici |
| `heure` | 0.4 | horodatage | ouvré / hors ouvré |

`exe` ne lit **que** auditd et Sysmon. Il ne retombe surtout pas sur `entity`,
qui vaut `syscheck.path` : sur Windows c'est une clé de registre `HKEY_...`, sur
Proxmox une archive LVM. Ni l'un ni l'autre n'est un exécutable.

`heure` est volontairement grossier (ouvré / hors ouvré, pas 24 valeurs) : un
profil à 24 tranches demande des mois pour mûrir, alors que deux suffisent à
distinguer « 3 h du matin un dimanche » de l'activité de bureau.

## Comment le score est calculé

Trois primitives, toutes **déterministes et explicables à un analyste** — même
exigence que `correlate.py`, et pour la même raison : un score qu'on ne peut pas
contester ne peut pas justifier une action.

### 1. Rareté — surprisal, en bits

```
bits = -log2( (occurrences + 0.5) / (total_scope + 0.5 × valeurs_distinctes) )
```

L'unité n'est pas décorative : **sommer des bits d'information a un sens, sommer
des « points » n'en a pas.** C'est ce qui permet de composer les traits entre eux
sans table de poids arbitraire à négocier.

Le lissage de Laplace (α = 0,5) évite deux écueils : une probabilité nulle
donnerait des bits infinis, et un profil encore maigre verrait son score plafonné
— peu d'observations, peu de confiance.

### 2. Première vue — modulée par la flotte

Une valeur absente d'un profil **mûr** vaut le plafond `UEBA_FIRSTSEEN_BITS`
(12 bits ≈ « une chance sur 4096 »). Mais modulé par sa diffusion ailleurs :

| vue sur | multiplicateur | lecture |
|---|---|---|
| aucun autre hôte | ×1 | vraiment inédit |
| 1 à 2 autres hôtes | ×0,6 | rare |
| ≥ `UEBA_FLEET_COMMON` (3) hôtes | ×0,2 | déploiement d'admin, pas intrusion |

**C'est le principal anti-faux-positif du module.** Sans lui, chaque binaire
poussé sur le parc ouvrirait un incident par machine.

### 3. Chaîne MITRE — pondérée et ordonnée

Le critère brut « 3 techniques de 3 tactiques différentes » remonte surtout
`Discovery` ×3 : un admin qui inventorie sa machine. Deux corrections :

- **chaque tactique distincte apporte son poids** — `Credential Access` 5,
  `Persistence` 4, `Exfiltration` 5, `Impact` 5… contre `Discovery` 1 ;
- **bonus de progression** : si les tactiques observées avancent dans l'ordre
  canonique de la kill chain (plus longue sous-suite croissante ≥ 3 étapes), un
  bonus s'ajoute. C'est le signal le plus fort qu'on puisse tirer sans LLM.

### Ce qui cesse d'être scoré

- **Habitude** — `days_seen ≥ UEBA_DAYS_USUAL` (5). En jours **distincts**,
  pas en occurrences : 500 exécutions en un seul jour est un incident, 5 sur 5
  jours est une routine.
- **Valeur générique** — `/bin/bash`, `/bin/sh`… Le premier `bash` d'une machine
  ne doit pas valoir 12 bits.
- **Trait à cardinalité explosive** — voir ci-dessous.
- **Profil immature** — voir ci-dessous.

### Saturation

Deux plafonds, sans lesquels une valeur répétée mille fois écrase tout le reste
et le score cesse de décrire l'incident :

- `UEBA_CAP_TRAIT` (14) par trait,
- `UEBA_CAP_ALERT` (20) par alerte.

Au niveau du signal, seul le **meilleur score de chaque couple (trait, valeur)**
est retenu : quarante exécutions du même binaire rare ne valent pas quarante fois
le score.

## Le garde-fou de cardinalité

Un trait dont **presque chaque observation apporte une valeur neuve** est inédit
*par construction* : chemins horodatés, archives rotatives, GUID, identifiants de
session. « Jamais vu » n'y signifie rien, et la surprisal y est maximale en
permanence.

Ce n'est pas théorique. À la mise en service, les archives LVM de l'hôte Proxmox
(`/etc/lvm/archive/pve_19796-1149630808.vg`) produisaient à elles seules un
signal à **1434 points — quarante fois le plancher.**

Le garde-fou juge sur le **ratio `distincts / observations`**, pas sur une liste
de motifs : aucune liste noire n'anticipe ce qu'un parc produit, et elle
vieillit mal ; la statistique, elle, se corrige seule.

Le seuil de 0,25 est mesuré, pas choisi au jugé. Sur les 24 scopes du parc :

```
scope_key   trait     obs   distincts  ratio
010         fichier   493   237        0.481   <- pathologique (archives LVM)
015         fichier   358    20        0.056   <- le suivant
014         fichier   891    26        0.029
014         exe       765    11        0.014
```

Un ordre de grandeur d'écart. 0,25 tombe au milieu du fossé, donc loin des deux.

En dessous de `UEBA_CARDINALITY_MIN_OBS` (200), on ne conclut pas : on n'exclut
pas un trait faute de recul.

## Maturité et démarrage à froid

**Le tout premier passage ne score rien.** Aucun profil n'est mûr, tout y serait
inédit : scorer enverrait l'intégralité du parc au LLM le premier jour. Ce
passage avale l'historique et le prend pour baseline.

Un scope devient scorable quand il atteint **à la fois** :

- `UEBA_MATURITY_DAYS` (7) jours d'ancienneté,
- `UEBA_MATURITY_MIN_OBS` (200) observations.

Même philosophie que le [mode training](TRAINING.md), et les deux se cumulent
bien : la fenêtre de training amorce la baseline gratuitement.

```bash
docker exec soc-agent-cycle python -m soc_agent.ueba --etat
# profils : 584 (24 scopes, 196991 observations)
# scopes mûrs : 36/72 (>= 7 j et 200 observations)
```

## Ce qui borne le coût

**Le seuil de score ne borne rien.** Le volume d'alertes varie d'un facteur dix
entre une journée calme et une campagne : un seuil absolu donne soit zéro appel,
soit quatre cents.

Ce qui borne, c'est **`UEBA_BUDGET_PER_DAY`** — un nombre de promotions qu'on
décide. Chaque passage trie les signaux par score, garde ceux au-dessus du
plancher, et n'en promeut qu'autant que le budget des 24 dernières heures le
permet.

**Un signal non promu n'est pas perdu.** Il est enregistré en `en_attente`,
recalculé au cycle suivant, et son score aura grossi s'il continue. Rien n'est
jeté, tout est retardé.

`UEBA_BUDGET_PER_CYCLE` plafonne en plus le nombre par passage, pour qu'une
rafale ne consomme pas le budget quotidien en cinq minutes.

## Calibrer le plancher — à zéro token

La table `ueba_signals` conserve **score et motifs de tous les signaux, promus ou
non**. L'histogramme se relit donc après coup, sans avoir appelé le modèle une
seule fois.

```bash
# score et enregistre les signaux SANS rien promouvoir
docker exec soc-agent-cycle python -m soc_agent.ueba --simulation

# distribution des scores obtenus
docker exec socagent-db psql -U socagent -d socagent -c \
  "SELECT statut, count(*), round(max(score)::numeric,1) max,
          round(min(score)::numeric,1) min FROM ueba_signals GROUP BY 1;"

# les 15 derniers signaux avec leurs motifs
docker exec soc-agent-cycle python -m soc_agent.ueba --etat
```

Même effet en laissant `UEBA_BUDGET_PER_DAY=0` : le moteur observe et score, mais
ne promeut rien. **C'est la posture de mise en service recommandée** — voir plus
bas.

## Ce que voit le LLM

Un incident UEBA a un `max_level` bas par construction. Sans explication, le
modèle voit du niveau 5 et conclut mécaniquement au faux positif — ce qui est
d'ailleurs *le bon réflexe sur le niveau seul*, et l'erreur ici.

Le rendu (`render.py`) ajoute donc un bloc d'origine et les écarts mesurés :

```
origine          : moteur comportemental UEBA (aucune règle de niveau >= 12
                   n'a tiré ; l'incident est ouvert sur un écart statistique
                   au comportement habituel, score 108.81)
écarts mesurés (le niveau des règles est BAS, c'est la rareté qui porte le signal) :
  exe «C:\<FICHIER_4>.exe» sur cet hôte — rare : 3x sur 392 observations, 2 jour(s) (+6.83 bits)
  rule_id «92066» sur cet hôte — rare : 3x sur 17616 observations, 2 jour(s) (+6.15 bits)
  ...
```

Quelques dizaines de tokens qui remplacent avantageusement les alertes brutes
qu'elles résument.

Le prompt système (`prompts/system.md`) porte une section dédiée qui dit au
modèle : ne conclus pas au faux positif au seul motif que le niveau est bas ;
cherche l'explication légitime (déploiement, maintenance, nouvel utilisateur) et
si tu la trouves c'est un `false_positive` ; un écart qui compose une **histoire
cohérente** (exécution inédite *puis* persistance *puis* contact réseau) est un
`true_positive` même si chaque élément pris seul serait anodin.

## Garde-fous

### `UEBA_MITIGATE=false` — pas de remédiation autonome

**Par défaut, et délibérément.** Le reste du pipeline agit sans validation
humaine parce qu'il part d'une graine de niveau ≥ 12 : une règle Wazuh qui a déjà
exigé plusieurs corrélations. Un incident UEBA part d'un **score statistique dont
la justesse n'est pas mesurée** — le laisser isoler un hôte reviendrait à confier
la production à un seuil non calibré.

Le verdict LLM est rendu, le case IRIS créé, les actions proposées écrites dans
le rapport. Rien n'est exécuté.

Ce n'est **pas un gate humain déguisé** : c'est le raisonnement d'`evaluate.py`
(« on n'agit pas sur ce qu'on n'a pas mesuré ») appliqué à un moteur neuf. Le
drapeau se lève quand les verdicts UEBA auront été labellisés.

Vérifiable directement :

```bash
docker exec soc-agent-cycle python -c "
from soc_agent import config, iris
print(iris._remediation_autorisee({'id': 0, 'ueba': True}))    # False
print(iris._remediation_autorisee({'id': 0, 'ueba': False}))   # True
"
```

### `seen_in_tp` — l'attaquant patient

Un trait impliqué dans un **vrai positif** ne peut plus jamais devenir une
habitude, quelle que soit sa fréquence ultérieure. Sans ça, il suffit de lancer
son outillage tous les jours pour qu'il cesse d'être scoré.

Même garde-fou que la whitelist automatique, qui refuse toute signature déjà vue
en TP. Posé par `ueba.marquer_tp()`, appelé depuis `iris.creer_case` sur verdict
non-FP.

### Pseudonymisation par liste d'exclusion

Les motifs portent des **valeurs brutes de logs** : chemins, comptes, IP. Ils
sont pseudonymisés par `anonymize.anonymiser` avant tout envoi au cloud.

La liste `TRAITS_UEBA_ATTRIBUTS` (`pays`, `heure`, `dst_port`, `rule_id`,
`chaine_mitre`) énumère ce qui sort **verbatim** — des attributs qui portent le
signal sans identifier d'actif client. **Tout le reste est masqué, y compris un
trait ajouté demain.**

C'est une liste d'exclusion et non d'inclusion pour une raison précise : le trait
`fichier` a été ajouté à `ueba.py` sans être déclaré ici, les chemins sont partis
en clair, `verifier_fuite` a refusé l'incident (fail-closed) et **tout le triage
UEBA se serait tu en silence.** Avec une liste d'inclusion, l'oubli fuite ; avec
une liste d'exclusion, l'oubli masque.

### Filtre structurel

`correlate._graine_valide` s'applique aussi aux graines UEBA : une alerte SCA,
rootcheck, inventaire de vulns ou statut d'agent ne fonde pas de case, **même
statistiquement rare**.

### Vieillissement de la baseline

Un profil qui ne vieillit jamais fige le comportement d'il y a six mois : un
serveur réinstallé resterait « normal » sur ses anciens binaires. Les
observations au-delà de `UEBA_MEMORY_DAYS` (90) sont supprimées et les profils
**recalculés sur ce qui reste** — jamais de décrément à l'aveugle. `seen_in_tp`
est préservé : un trait vu dans un vrai positif ne redevient pas vierge par
péremption.

## Un signal promu reste UN incident

`ueba_signal_id` est un point commun **fort** dans `correlate.point_commun`, et
le premier examiné.

Sans lui, la corrélation redécoupe le signal sur ses critères génériques : un
signal de 239 alertes ressortait en **8 incidents, donc 8 triages LLM**, chacun
amputé du contexte des autres et portant un score sans rapport avec celui du
signal (115, puis 2,5 et 3,3 — le signal valait 161,8).

Les fenêtres se correspondent déjà : `UEBA_SIGNAL_MAX_HOURS` = `MAX_INCIDENT_HOURS`
= 6, et un lien fort porte jusqu'à `ENTITY_GAP_MINUTES` (360).

Un incident UEBA peut en revanche être **fondu** dans un case déjà ouvert
(`iris._fondre_si_doublon`, `_fondre_campagne`) si l'hôte a une intrusion en
cours. C'est correct — les alertes basses deviennent le contexte de l'incident
réel — mais ça rend une démonstration confuse : pour observer un case UEBA pur,
choisir un hôte sans incident ouvert.

## Schéma

| table | rôle |
|---|---|
| `ueba_observations` | fait brut agrégé par jour, **seule source de vérité** |
| `ueba_profiles` | résumé par valeur : `total`, `days_seen`, `seen_in_tp` |
| `ueba_scopes` | totaux par scope (dénominateur de la rareté) + maturité |
| `ueba_signals` | concentration jugée anormale — **audit autant que travail** |

`ueba_profiles` est **recalculable** depuis `ueba_observations` : c'est ce qui
permet de faire vieillir la baseline en supprimant des jours plutôt qu'en
décrémentant des compteurs.

Colonnes ajoutées :

- `alerts` — `ueba_vu` (curseur : on score **avant** d'absorber), `ueba_score`,
  `ueba_traits`, `ueba_seed` (le seul drapeau que lit `correlate`),
  `ueba_signal_id` ;
- `incidents` — `ueba`, `ueba_score`, `ueba_motifs`.

## Réglages

| variable | défaut | rôle |
|---|---|---|
| `UEBA_ENABLED` | `true` | interrupteur général |
| `UEBA_MATURITY_DAYS` | `7` | ancienneté minimale d'un scope pour être scoré |
| `UEBA_MATURITY_MIN_OBS` | `200` | observations minimales, idem |
| `UEBA_FIRSTSEEN_BITS` | `12` | score plafond d'une valeur inédite |
| `UEBA_FLEET_COMMON` | `3` | nb d'hôtes à partir duquel « inédit ici » est banal |
| `UEBA_DAYS_USUAL` | `5` | jours distincts au-delà desquels c'est une routine |
| `UEBA_BITS_MIN_RARITY` | `4` | plancher sous lequel un trait n'est pas un motif |
| `UEBA_CARDINALITY_MAX` | `0.25` | ratio distincts/obs au-delà duquel le trait est muet |
| `UEBA_CARDINALITY_MIN_OBS` | `200` | recul minimal avant de conclure sur la cardinalité |
| `UEBA_CAP_TRAIT` | `14` | saturation par trait |
| `UEBA_CAP_ALERT` | `20` | saturation par alerte |
| `UEBA_WINDOW_MINUTES` | `60` | écart max entre deux alertes d'un même signal |
| `UEBA_SIGNAL_MAX_HOURS` | `6` | durée totale max d'un signal |
| `UEBA_MIN_TACTICS` | `3` | tactiques distinctes avant tout bonus de chaîne |
| `UEBA_BONUS_ORDER` | `3` | bonus par étape de progression kill-chain |
| `UEBA_SCORE_FLOOR` | `35` | score minimal pour être promouvable |
| `UEBA_BUDGET_PER_DAY` | `20` | **le garde-fou de coût** — promotions par 24 h |
| `UEBA_BUDGET_PER_CYCLE` | `2` | promotions par passage |
| `UEBA_RETENTION_HOURS` | `24` | âge au-delà duquel une alerte n'est plus candidate |
| `UEBA_BATCH` | `20000` | taille du lot d'observation par passage |
| `UEBA_MEMORY_DAYS` | `90` | fenêtre de la baseline |
| `UEBA_MITIGATE` | `false` | remédiation autonome sur incident UEBA |

## Commandes

```bash
# maturité des profils, budget restant, 15 derniers signaux
docker exec soc-agent-cycle python -m soc_agent.ueba --etat

# passage complet : observation + scoring + promotion
docker exec soc-agent-cycle python -m soc_agent.ueba

# score et enregistre les signaux SANS rien promouvoir (0 token)
docker exec soc-agent-cycle python -m soc_agent.ueba --simulation

# vieillissement de la baseline (aussi appelé à chaque passage)
docker exec soc-agent-cycle python -m soc_agent.ueba --purger
```

Réinitialiser complètement l'état UEBA (baseline comprise) :

```bash
docker exec socagent-db psql -U socagent -d socagent -c "
TRUNCATE ueba_observations, ueba_profiles, ueba_scopes, ueba_signals;
UPDATE alerts SET ueba_vu=false, ueba_score=NULL, ueba_traits=NULL,
                  ueba_seed=false, ueba_signal_id=NULL;"
```

## Mise en service — observer avant de promouvoir

**Déployer avec `UEBA_BUDGET_PER_DAY=0`.** Le moteur observe, score et enregistre
ses signaux ; il n'en promeut aucun, donc aucun incident, aucun case, aucun
token. Laisser tourner le temps que les profils mûrissent, puis lire la
distribution réelle des scores et fixer `UEBA_SCORE_FLOOR` au-dessus du bruit
observé.

Cette phase n'est pas de la prudence rituelle : à la mise en service du
2026-08-07, elle a révélé quatre défauts **tous invisibles en test synthétique**.

| défaut | symptôme | correctif |
|---|---|---|
| haute cardinalité | archives LVM → signal à 1434 pts, 40× le plancher | `UEBA_CARDINALITY_MAX` |
| `exe` retombait sur `entity` | clés `HKEY_*` et archives comptées comme binaires | `exe` = auditd + Sysmon seuls ; trait `fichier` séparé |
| émiettement | 239 alertes → 8 incidents → 8 triages LLM | `ueba_signal_id` en point commun fort |
| fuite | trait non déclaré dans `anonymize` → incident refusé fail-closed, triage UEBA muet | pseudonymisation par liste d'exclusion |

Deux bugs préexistants ont été trouvés au passage, hors UEBA :
`anonymize.Anonymiseur.ip` laissait sortir **en clair** toute valeur non parsable
comme IP ; et DeepSeek recopie les chemins `C:\...` dans sa justification et rend
un JSON invalide (`Invalid \escape`), ce qui bloquait l'incident à chaque cycle
— le lot étant trié de façon déterministe, il repassait en tête indéfiniment
(`llm._charger_json`).

## État en production

Déployé sur `/opt/AURA` le **2026-08-07**, en testing :
`UEBA_BUDGET_PER_DAY=3`, `UEBA_SCORE_FLOOR=60`, `UEBA_MITIGATE=false`.

Deux limites connues :

- **`UEBA_MATURITY_DAYS=2` au lieu de 7.** La stack a été réinstallée le
  2026-08-05 : il n'existe que 3 jours d'historique, et l'indexer n'en a pas
  davantage. Une baseline courte fait passer pour inédit ce qui est simplement
  peu fréquent. **À remonter à 7 vers le 2026-08-19.**
- **Le plancher à 60 n'est pas calibré contre une vérité terrain**, seulement
  placé au-dessus du bruit observé (qui plafonne vers 80). Il n'y a pas
  d'intrusion connue dans la fenêtre pour vérifier qu'il laisse passer ce qui
  compte.

## Ce qui n'a pas été fait, et pourquoi

**Pas de ML non supervisé** (isolation forest, autoencodeur, clustering). Trois
raisons, dans ce contexte précisément :

- aucun jeu labellisé (`labels` est vide, `evaluate.py` refuse de conclure sous
  30 incidents) — la dérive du modèle serait indétectable ;
- un verdict inexplicable ne peut ni être contesté par un analyste, ni justifier
  une remédiation autonome ;
- la surprisal donne l'essentiel du résultat et se lit en une phrase.

À reconsidérer **après** le golden set, pas avant.

## Voir aussi

- [`../src/ai/README.md`](../src/ai/README.md) — pipeline complet, phases 1 et 2
- [`TRAINING.md`](TRAINING.md) — apprentissage du bruit ambiant ; amorce la baseline UEBA
- [`REMEDIATION.md`](REMEDIATION.md) — ce que `UEBA_MITIGATE=false` empêche de partir
- [`INSTALL.md`](INSTALL.md) — mise en service du stack
