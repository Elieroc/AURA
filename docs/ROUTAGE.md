# Routage des sources de log — contrôle et création automatiques

Module [`src/ai/soc_agent/routing.py`](../src/ai/soc_agent/routing.py) ·
table `routage_sources` ([`schema.sql`](../src/ai/soc_agent/schema.sql)) ·
exécuté par le watchdog (toutes les 2 min)

## Le problème

Wazuh n'a pas de notion d'« index par agent ». Le routage se fait par **type de
log**, dans un script painless du pipeline d'ingest
([`alerts-pipeline.json`](../src/wazuh/config/wazuh_cluster/alerts-pipeline.json)).
Une source qu'aucune branche ne reconnaît atterrit dans `wazuh-alerts-4.x-*`
sans le moindre message : ni erreur côté Wazuh, ni alerte manquante. Et si la
liste `INDEXER_ALERT_INDICES` a été oubliée en même temps, l'IA est aveugle sur
ce capteur.

Ce piège s'est produit **trois fois** : `wazuh-linux-*`/`wazuh-web-*`, puis
`wazuh-yara-*` (5 alertes de niveau 12, dont un web shell) et `wazuh-firewall-*`
le 2026-07-29.

## Un index set, c'est cinq pièces

Créer `wazuh-jellyfin` ne veut pas dire créer un index :

| # | Pièce | Sans elle |
|---|-------|-----------|
| 1 | branche de routage dans le pipeline d'ingest | rien n'entre dans l'index |
| 2 | template `soc-ai-routing` | mapping par défaut, tous les champs en `text` |
| 3 | politique ISM `aura-retention` | l'index n'est jamais purgé → disque plein |
| 4 | liste d'indices lue par l'ingestion | l'IA ne voit pas ces alertes |
| 5 | index pattern du dashboard | invisible dans Discover |

Les cinq sont posées par `appliquer()`, dans cet ordre : template et ISM
d'abord (ils ne valent que pour les index créés **après**), le routage en
dernier, quand tout est prêt à recevoir.

### L'exception : `wazuh-hunting`

`wazuh-hunting-*` porte un nom d'index set et n'en est pas un. Aucune source n'y
écrit : c'est l'espace où l'on **remet** une archive froide pour chasser dedans
([HUNTING.md](HUNTING.md)). Il a les pièces 2, 3 et 5 (avec sa propre politique
ISM, plus courte) et **pas** les pièces 1 et 4 — cette absence est la
fonctionnalité, pas un oubli :

- pièce 1 absente parce que rien n'y écrit en direct ;
- pièce 4 absente, et **structurellement interdite** : `indices_lus()` ajoute
  `-wazuh-hunting-*` en négation finale. Si l'ingestion lisait cet espace, les
  alertes restaurées seraient corrélées, triées, puis **remédiées** — AURA
  agirait sur la production d'aujourd'hui en réponse à une attaque de l'an
  dernier. La négation gagne même si quelqu'un met `wazuh-*` dans
  `INDEXER_ALERT_INDICES`.

Le routage ne l'observe donc pas non plus, ce qui évite un second faux problème :
les alertes restaurées gardent leur `decoder.name`, et ressembleraient sinon à une
**dérive** — un dossier ouvert pour un geste d'analyste normal.

## Ce que fait un passage

```
observer  -> agrégation « qui écrit où » sur 24 h (decoder.name × _index)
classer   -> routée OK / non routée / dérive / muette
nommer    -> wazuh-<suffixe>, LLM + validation en code
appliquer -> les cinq pièces
réparer   -> le pipeline en service porte-t-il encore nos branches ?
```

`python -m soc_agent.routing --observer` répond à la seule question qui compte
au départ — qui écrit où — **sans toucher ni la base ni le modèle**.

## Convention de nommage

La décision tient en une question : *un autre produit du même métier
remplacerait-il cette source sans changer l'usage de ses logs ?*

- **oui** → nom de **métier**, choisi dans un vocabulaire **fermé** (`firewall`,
  `web`, `dns`, `proxy`, `vpn`, `edr`, …). pfSense et Fortinet partagent
  `wazuh-firewall` : nommer l'index `pfsense` obligerait à créer `fortinet`
  demain et à interroger deux index pour une seule question ;
- **non** → nom de l'**application** (`jellyfin`, `bookstack`). Il doit être
  **attesté** par les données de la source (décodeur, nom de machine, chemin du
  log, description de règle), sinon il est rejeté.

Le modèle choisit un nom ; il n'obtient jamais le droit d'écrire. Toute réponse
qui ne passe pas la validation retombe sur un nom déterministe marqué `repli`,
qui reste **en attente d'un humain** et n'est jamais auto-appliqué.

## Garde-fous

- **Simulation obligatoire avant tout `PUT`.** Le pipeline se termine par
  `on_failure: [{"drop": {}}]` : un painless invalide ne remonte aucune erreur,
  il fait *disparaître* toutes les alertes du SOC. Chaque source appliquée
  garde une alerte réelle comme témoin ; toutes sont rejouées dans
  `_ingest/pipeline/_simulate` et doivent ressortir dans leur index. **Un seul
  témoin en échec annule tout**, y compris pour une source sans rapport — c'est
  précisément la régression qu'on cherche.
- **Plafond de 2 créations / 24 h.** Dix index sets le même jour, ce n'est pas
  dix index sets qu'il faut, c'est un humain qui regarde ce qui a changé dans le
  SI. Le plafond ne s'applique pas au rattachement d'une source à un index de
  métier existant, qui est le cas nominal.
- **Jamais de renommage ni de suppression.** Changer l'index d'une source coupe
  l'historique en deux et casse les dashboards.
- **Refus d'insérer à l'aveugle** : si le repère `routage-statique` est
  introuvable dans le pipeline, rien n'est écrit.

## Pièges (mesurés)

- **`return` en painless ne sort que du script courant, pas du pipeline.** Une
  branche apprise insérée *avant* le routage statique écrit bien `ctx._index`,
  puis le script statique le réécrit derrière elle, sans erreur. Vérifié le
  2026-08-14 : `pam -> wazuh-endpoint` repartait dans `wazuh-linux`. Les
  branches apprises vont donc **après** le statique — et le script YARA garde
  volontairement le dernier mot.
- **`fields.index_prefix` n'existe dans aucun document indexé.** Le pipeline
  l'efface (`remove`) avant l'écriture, alors que `date_index_name` en a besoin
  et qu'il est le seul processor en `ignore_failure: false`. Un témoin rejoué
  sans ce champ part dans le `drop` du `on_failure` : *tous* les témoins
  ressortent « perdus ». Il est reposé à la simulation.
- **Filebeat repousse le pipeline à chaque démarrage du manager** et efface les
  branches apprises. C'est pour cela que le pipeline attendu est recalculé et
  comparé à chaque passage plutôt qu'écrit une fois : la panne se répare seule
  en moins de deux minutes.
- **Le manager (agent 000) est exclu de l'observation**, comme il l'est du
  routage par OS. Ses alertes `web-accesslog` (426 sur 7 j) écrasaient en nombre
  celles des vrais agents web et faisaient passer une source parfaitement routée
  pour une source orpheline.
- **Le FIM ne se décode pas sous un seul nom** (`syscheck_deleted`,
  `syscheck_integrity_changed`, `syscheck_registry_value_modified`…). Six
  décodeurs, 226 alertes/24 h, donc six propositions d'index set si on ne
  raisonne que sur des noms exacts. La liste blanche des sources transverses
  travaille par **préfixe**.
- **Un même flux se décrit par plusieurs critères** : Suricata pèse à lui seul
  les groupes `suricata`, `ids` et `command_and_control`. Les alertes « source
  muette » sont donc dédupliquées **par index** — la question de l'analyste est
  « plus rien n'arrive dans `wazuh-firewall` », pas « le groupe `ids` s'est
  tu ».

## Anomalies remontées (alertes IRIS)

Elles passent par la table d'état du watchdog (`capteur_pannes`), donc :
ouverture unique, alerte IRIS, **clôture automatique** au retour à la normale.

| Pseudo-capteur | Signification |
|---|---|
| `routage:<source>` | source non routée qu'on n'a pas su créer seul, ou routage dévié |
| `source-muette:<source>` | source établie dont l'index ne reçoit plus rien depuis 48 h |

## Réglages

| Variable | Défaut | Effet |
|---|---|---|
| `ROUTING_ACTIVE` | `true` | coupe tout le contrôle |
| `ROUTING_APPLY` | `true` | `false` = détecte et propose, n'écrit rien côté indexer |
| `ROUTING_WINDOW_HOURS` | `24` | fenêtre d'observation |
| `ROUTING_BASELINE_MIN` | `20` | volume minimum pour créer un index set |
| `ROUTING_DRIFT_MIN` | `5` | volume minimum pour signaler une dérive |
| `ROUTING_SILENCE_HOURS` | `48` | silence au-delà duquel une source est dite muette |
| `ROUTING_MAX_NEW_PER_DAY` | `2` | plafond de créations automatiques |

## Arbitrage humain

```bash
python -m soc_agent.routing --observer                      # qui écrit où
python -m soc_agent.routing                                 # état, dry-run
python -m soc_agent.routing --appliquer                     # crée ce qui manque
python -m soc_agent.routing --source decoder:x --index wazuh-web   # forcer
python -m soc_agent.routing --source decoder:x --refuser           # ne plus proposer
```
