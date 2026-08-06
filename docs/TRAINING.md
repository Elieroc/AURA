# Mode training — apprendre le bruit ambiant avant de laisser le SOC agir

Code : [`ai/soc_agent/training.py`](../ai/soc_agent/training.py) · conteneur `soc-training` ·
réglages dans `config/soc-ai.conf` (gitignoré, cf.
[`config/soc-ai.conf.example`](../config/soc-ai.conf.example)), exportés vers
docker compose par [`scripts/soc-start.sh`](../scripts/soc-start.sh).

## Le problème

Un SOC autonome branché sur un SI **déjà en production** tire sur tout ce qui
bouge. Les sauvegardes, les scripts d'admin, les scanners de conformité
produisent des alertes HIGH/CRITICAL parfaitement légitimes. Sans période
d'apprentissage, la chaîne complète part dessus : triage LLM → verdict vrai
positif → case IRIS → **remédiation exécutée**. Le premier jour, l'XDR isole des
serveurs sains.

Ce n'est pas un risque théorique. La whitelist automatique (`whitelist.py`) ne
résout pas ce cas : elle a besoin de voir un faux positif **se répéter et être
jugé par le LLM** avant de créer une exception — donc après que la remédiation
soit partie.

## Le principe

Le training est une **fenêtre de confiance déclarée par l'administrateur** au
lancement du SOC. Pendant `TRAINING_DAYS` jours :

1. **le pipeline d'analyse est suspendu** — `cycle.py` ingère puis s'arrête sur
   `training.en_cours()` : ni triage, ni case, ni remédiation ;
2. toute alerte de niveau ≥ `TRAINING_MIN_LEVEL` observée est réputée être du
   bruit ambiant et devient une exception dans `whitelist_rules`
   (`source='training'`), **sans LLM** — l'apprentissage est entièrement
   déterministe ;
3. à l'échéance, la fenêtre se clôt et produit un case IRIS « TRAINING » où
   chaque exception est une tâche révocable.

L'ingestion, elle, continue : les alertes doivent être en base pour servir
l'apprentissage, et le rattrapage post-fenêtre reste possible.

## Limite assumée

**Une intrusion déjà en cours au lancement du SOC est apprise comme du bruit.**
C'est le prix de la fenêtre de confiance, et c'est explicite. Le contrôle qui
rattrape ce cas est le case IRIS de clôture : l'analyste relit la liste des
exceptions apprises et annule celles qui n'ont rien à y faire.

## Cycle de vie

```
     TRAINING_ENABLED=true, aucune fenêtre en base
                     │
                     ▼
        ┌────────────────────────┐   tick toutes les ~5 min
        │  running               │   apprendre() : alertes ≥ MIN_LEVEL
        │  pipeline SUSPENDU     │   → whitelist_rules (source='training')
        └───────────┬────────────┘
                    │ now() >= ends_at   (ou --cloturer)
                    ▼
        ┌────────────────────────────────────────────┐
        │  cloturer(), dans CET ordre :               │
        │   1. dernier apprendre()                    │
        │   2. ingest.reappliquer_filtre()            │
        │   3. case IRIS « TRAINING » + 1 tâche/excep.│
        │   4. status = 'finished'                    │
        └───────────┬────────────────────────────────┘
                    ▼
        ┌────────────────────────┐
        │  finished              │  pipeline débloqué
        │  écoute les révocations│  tâche 'Canceled' → exception désactivée
        └────────────────────────┘
```

**L'ordre de clôture n'est pas cosmétique.** C'est le passage en `finished` qui
débloque le pipeline, jamais la date : entre l'expiration du délai et la clôture
effective, `run_en_cours()` teste le **statut**. Sinon un cycle passant dans cet
intervalle corrélerait le backlog brut, avant que le bruit appris n'ait été
marqué `suppressed`.

Même logique pour le point 2 : le filtre est réappliqué à l'existant **avant**
de rendre la main, sans quoi les alertes déjà en base continueraient de grainer
des incidents malgré leurs exceptions.

Si IRIS est indisponible au moment de la clôture, le statut **reste `running`**
et le case est retenté au tick suivant — les exceptions, elles, sont déjà
créées.

## Signature apprise

Groupement par **(règle, machine)**, une exception par groupe. La signature
diffère volontairement de celle de la whitelist automatique
(`whitelist._signature`) sur deux points :

| | whitelist auto | training |
|---|---|---|
| `agent_name` dans la signature | non | **toujours** |
| discriminant absent (`src_user` / `command` / `file`) | exception **refusée** | acceptée |
| plafond de niveau | `WHITELIST_MAX_LEVEL` = 14 | `TRAINING_MAX_LEVEL` = **15** |
| jugement | LLM (FP récurrent) | déterministe |

- `agent_name` obligatoire : le bruit ambiant appartient à une machine — c'est
  *ce serveur-là* qui lance *ce script-là*. Whitelister partout aveuglerait la
  détection sur tout le parc.
- Absence de discriminant tolérée : beaucoup de bruit d'infrastructure n'a aucun
  champ discriminant. `rule_id + agent_name` reste borné à une machine, là où
  `rule_id` seul — refusé par la whitelist automatique — neutraliserait la règle
  sur tout le SI.
- Plafond à 15 : le training doit pouvoir apprendre le bruit CRITICAL, sinon il
  ne calme pas ce qui déclenche les remédiations les plus coûteuses. Assumé,
  parce que la fenêtre est bornée dans le temps et chaque exception révocable.

Les discriminants **constants sur tout le groupe** sont ajoutés quand ils
existent : ils rétrécissent encore la signature.

## Case IRIS de clôture

Un case classé `other:other` (id 36, surchargeable par
`TRAINING_IRIS_CLASSIFICATION`) — pas un incident : le ranger en intrusion
fausserait toute statistique tirée des classifications.

- une **tâche par exception**, statut `Done`, préfixe `TRAINING — whitelist`.
  Le préfixe est volontairement différent de `WHITELIST` : `whitelist_task.py`
  ramasse toute tâche commençant par `WHITELIST` passée en `To do`, il ne doit
  pas confondre les deux ;
- la description de la tâche porte la signature en JSON et le motif ;
- **passer une tâche en `Canceled` désactive l'exception** (`active = false`),
  traité au tick suivant (~5 min), avec un commentaire posé sur la tâche et une
  réapplication du filtre — sans quoi les alertes resteraient marquées
  `suppressed` en base et la révocation n'aurait aucun effet visible ;
- **sens unique** : repasser la tâche en `Done` ne réactive pas l'exception. Une
  exception retirée par un analyste doit être recréée explicitement, pas au gré
  d'un statut cliqué.

## Réglages

`config/soc-ai.conf` (gitignoré ; modèle dans `config/soc-ai.conf.example`) :

| Variable | Défaut | Rôle |
|---|---|---|
| `TRAINING_ENABLED` | `false` | ouvre une fenêtre **au tout premier lancement seulement** (aucune fenêtre en base) |
| `TRAINING_DAYS` | `7` | durée de la fenêtre |
| `TRAINING_MIN_LEVEL` | `12` | niveau à partir duquel une alerte est apprise (aligné sur `MIN_LEVEL`, HIGH) |
| `TRAINING_MAX_LEVEL` | `15` | plafond : au-dessus, la règle n'est pas whitelistée |
| `TRAINING_IRIS_CLASSIFICATION` | `36` | classification du case de clôture |

`TRAINING_ENABLED=true` ne rouvre **jamais** une fenêtre plus tard : le training
est une phase de mise en service, pas un mode récurrent. En rouvrir une est une
décision explicite (`--demarrer`).

## Commandes

```bash
# état de toutes les fenêtres (statut, dates, exceptions actives/total)
docker exec soc-training python -m soc_agent.training --etat

# un passage manuel (identique à la boucle du conteneur)
docker exec soc-training python -m soc_agent.training --tick

# ouvrir une fenêtre après coup
docker exec soc-training python -m soc_agent.training --demarrer --jours 3

# clôture anticipée (apprend, réapplique le filtre, crée le case, débloque)
docker exec soc-training python -m soc_agent.training --cloturer
```

Vérifier que le pipeline est bien suspendu :

```bash
docker logs --tail 20 soc-agent-cycle     # doit s'arrêter après l'ingestion
docker exec socagent-db psql -U socagent -d socagent \
  -c "select id, status, started_at, ends_at, iris_case_id from training_runs"
```

Exceptions apprises :

```bash
docker exec socagent-db psql -U socagent -d socagent -c \
  "select signature, active, fp_count, iris_task_id from whitelist_rules
    where source = 'training' order by id"
```

## Détails d'implémentation

- **Verrou consultatif Postgres** `0x50CA4` (les autres boucles ont le leur :
  `0x50CA1` cycle, `0x50CA2` reconcile, `0x50CA3` whitelist_task) : deux ticks ne
  se chevauchent jamais.
- `apprendre()` est **idempotent** — contrainte d'unicité sur la signature
  canonique, `ON CONFLICT DO NOTHING`.
- Les exceptions produites vivent dans la même table que la whitelist
  automatique (`whitelist_rules`), lue par `noise.py` en post-retrieval ; elles
  s'en distinguent par `source='training'` et `training_run_id`.
- Le YAML humain (`noise_filter.yaml`) n'est pas touché : le training n'écrit
  que dans la table.

## Voir aussi

- [`REMEDIATION.md`](REMEDIATION.md) — ce que le training empêche de partir trop tôt
- [`INSTALL.md`](INSTALL.md) — mise en service du stack
- [`../ai/README.md`](../ai/README.md) — pipeline complet
