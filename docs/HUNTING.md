# Threat hunting : `wazuh-hunting`

Module [`src/ai/soc_agent/hunting.py`](../src/ai/soc_agent/hunting.py) ·
outils MCP `aura_archives_list`, `aura_hunting_state`, `aura_hunting_restore`,
`aura_hunting_purge` ([MCP.md](MCP.md)) · politique ISM `aura-hunting`

## Le problème

Les alertes quittent l'indexer à 90 jours ([RETENTION.md](RETENTION.md)) et
survivent douze mois en archive chiffrée dans S3 ([ARCHIVAGE.md](ARCHIVAGE.md)).
Une archive, c'est bien pour répondre à une réquisition ; c'est inutilisable pour
**chasser**. Personne ne trouve un mouvement latéral en lisant du NDJSON au `jq`.

`wazuh-hunting-*` est l'espace où l'on remet un mois d'archive **en ligne**, dans
l'indexer, requêtable dans Discover : agrégations, pivots, visualisations, tout
ce qui rend une recherche possible.

## Ce que ce n'est PAS — et c'est le cœur du sujet

**`wazuh-hunting` n'est pas un index set de routage.** Aucune source de log n'y
écrit, aucune branche du pipeline d'ingest ne le désigne. Sur les cinq pièces
d'un index set ([ROUTAGE.md](ROUTAGE.md)), il en a trois, et **l'absence des deux
autres est la fonctionnalité** :

| # | Pièce | `wazuh-hunting` |
|---|---|---|
| 1 | branche de routage dans le pipeline | **non** — rien n'y écrit en direct |
| 2 | template `soc-ai-routing` | **oui** — même mapping que les alertes vivantes |
| 3 | politique ISM | **oui**, mais la sienne : `aura-hunting`, 30 jours |
| 4 | lu par l'ingestion | **NON, et structurellement interdit** |
| 5 | index pattern du dashboard | **oui** — c'est le but |

### Pourquoi l'ingestion ne doit jamais le lire

C'est le point dur de toute cette fonctionnalité.

AURA corrèle ce qu'il ingère, trie ce qu'il corrèle, et **remédie tout seul** sur
verdict vrai positif : isolation d'hôte, blocage d'IP, désactivation de compte
([REMEDIATION.md](REMEDIATION.md)). Si les alertes restaurées entraient dans
l'ingestion, restaurer mars 2026 ne produirait pas des faux positifs — ça ferait
**rejouer à AURA une attaque vieille de dix mois**, avec des actions réelles sur
la production d'aujourd'hui, contre des machines et des comptes qui n'ont peut-être
plus rien à voir.

### Pourquoi le routage ne doit pas l'observer

Les alertes restaurées gardent leur `decoder.name` d'origine. Vues par
`routage.sources_observees()`, qui agrège « qui écrit où » sur 24 h, elles
ressembleraient à une source qui n'atterrit plus dans son index attendu — donc à
une **dérive de routage**, avec l'alerte IRIS qui va avec. Un dossier ouvert pour
un geste d'analyste parfaitement normal.

### Comment l'exclusion est posée

Par une **négation**, en fin de liste, dans `routage.indices_lus()` :

```
wazuh-alerts-*,wazuh-linux-*,…,wazuh-firewall-*,-wazuh-hunting-*
```

Ce n'est pas une liste à tenir à jour, et c'est délibéré : la syntaxe multi-index
d'OpenSearch applique les exclusions après coup, donc cette ligne **gagne même si
quelqu'un met `wazuh-*` dans `INDEXER_ALERT_INDICES`**. La protection ne dépend
pas de la discipline de configuration — c'est la même logique que partout ailleurs
dans AURA : ce qui compte doit être une conséquence, pas une vigilance.

Un test dédié le vérifie, y compris dans ce pire cas
([`test_hunting.py`](../src/ai/tests/test_hunting.py)).

## Nommage

```
wazuh-hunting-<source>-<AAAA-MM>
wazuh-hunting-firewall-2026-03
wazuh-hunting-alerts-4.x-2026-01
```

Le préfixe `wazuh-` de la source est retiré : `wazuh-hunting-wazuh-firewall` ne
dirait rien de plus et ferait un nom illisible dans Discover.

**Pas de date au jour**, et c'est structurel : c'est la forme `-AAAA.MM.JJ` qui
détermine ce que l'archivage prend. Ce nommage garantit donc à lui seul qu'on
n'archive jamais une archive restaurée — ce qui, sous Object Lock, reviendrait à
payer deux fois la même donnée pendant douze mois. `ARCHIVE_INDEX_EXCLUS` porte
`wazuh-hunting-*` en seconde barrière, celle qui tient même si le nommage change.

## Provenance

Elle est écrite dans les **métadonnées de l'index** (`mappings._meta`), pas dans
les documents :

```json
{"aura_hunting": {
  "archive_cle": "v1/wazuh-firewall/2026/wazuh-firewall.2026-03.ndjson.zst.age",
  "index_origine": "wazuh-firewall",
  "indices_origine": ["wazuh-firewall-2026.03.01", "…"],
  "documents_attendus": 184203,
  "sha256_clair": "…",
  "restaure_le": "2026-08-14T15:40:12Z"
}}
```

Une alerte restaurée doit rester **octet pour octet** ce qui a été archivé. Un
champ ajouté dans `_source` rendrait le SHA-256 du manifeste inutilisable comme
preuve, et fausserait les agrégations sur les champs qu'on chasse.

L'`_id` d'origine est conservé à la réinjection : rejouer une restauration écrase
les mêmes documents au lieu d'en créer des doublons. L'opération est donc
idempotente sans repère à tenir.

## Garde-fous

Cet espace est exposé par le serveur MCP, donc accessible à un agent IA.
« Restaure-moi tout pour voir » doit être **refusé par le code**, pas déconseillé
par une consigne.

| Garde-fou | Défaut | Ce qu'il empêche |
|---|---|---|
| seuil de disque | `DISQUE_SEUIL_ALERTE` (80 %) | le hunting est du confort ; un disque plein bascule l'indexer en lecture seule et **arrête l'ingestion de tout le parc** |
| `HUNTING_MAX_DOCS` | 2 000 000 | indexer une archive énorme au lieu de la filtrer en local |
| `HUNTING_MAX_INDICES` | 10 | l'accumulation de restaurations qu'on oublie |
| `HUNTING_MAX_GO` | 10 | le dépassement, calculé sur l'occupation **projetée** et pas sur l'actuelle |
| `aura-hunting` (ISM) | 30 jours | l'espace de travail qui reste indéfiniment |

Le seuil de disque est vérifié **en premier**, avant même de regarder la taille de
l'archive : c'est la seule limite dont le franchissement casse autre chose que le
hunting.

La rétention est plus courte que celle des alertes vivantes (30 contre 90) parce
que ce sont des **copies** : les perdre ne perd rien, l'archive S3 vit douze mois
de son côté.

## Usage

### Depuis un client MCP

```
aura_archives_list                          → le catalogue de ce qui est restaurable
aura_hunting_state                          → la place disponible AVANT de tenter
aura_hunting_restore(index_set, periode)    → dry-run : le plan + le verdict
aura_hunting_restore(…, appliquer=true)     → la restauration
aura_hunting_purge(index, confirmer=true)   → rendre la place
```

Le dry-run rend le verdict des garde-fous **sans rien télécharger** : c'est le
seul moyen honnête de répondre « est-ce que ça passe ? » sans attendre trois
minutes pour l'apprendre.

`aura_hunting_purge` refuse tout nom qui ne commence pas par le préfixe de
hunting, ainsi que les jokers et les listes. Il ne peut pas toucher un index
d'alertes de production.

### En ligne de commande

```bash
docker compose -p aura exec aura-mcp python -m soc_agent.hunting --etat
docker compose -p aura exec aura-mcp \
  python -m soc_agent.hunting --restaurer wazuh-firewall/2026-03
docker compose -p aura exec aura-mcp \
  python -m soc_agent.hunting --restaurer wazuh-firewall/2026-03 --appliquer
docker compose -p aura exec aura-mcp \
  python -m soc_agent.hunting --purger wazuh-hunting-firewall-2026-03 --confirmer
```

`--preparer` pose template, ISM et index pattern. Inutile de l'appeler : chaque
restauration le fait, parce que l'échec le plus bête serait de réinjecter 200 000
documents dans un index sans mapping, où plus aucune agrégation ne fonctionne et
qu'aucune rétention ne purgera.

### Chasser

Dans Discover, index pattern `wazuh-hunting-*`. Tous les champs se comportent
comme dans les index d'alertes vivants — c'est exactement ce que garantit le
partage du template `soc-ai-routing`.

Pour comparer un mois restauré au parc actuel, interroger les deux motifs à la
fois (`wazuh-hunting-firewall-2026-03,wazuh-firewall-*`) reste possible depuis
Discover : l'exclusion ne vaut que pour ce que **l'ingestion** lit, pas pour ce
qu'un humain requête.

## Pièges

- **`zstd` et `age` doivent être dans l'image `aura-mcp`**, pas seulement dans
  `soc-agent` : la restauration déchiffre côté MCP. Ils y sont depuis le
  Dockerfile, mais un `up -d` sans `--build` donne un outil qui échoue à
  l'exécution seulement.
- **La clé d'archivage doit être montée sur `aura-mcp`**
  (`ARCHIVE_KEY_DIR_HOST` → `/run/secrets`). Sans elle, `aura_hunting_restore`
  échoue au déchiffrement alors que tout le reste fonctionne.
- **Un `_bulk` répond `200` même quand des documents sont rejetés.** Le module lit
  `items[].error` et rend `injectes` / `erreurs` séparément : compter les succès
  sans lire les erreurs ferait conclure à une restauration complète sur une copie
  partielle. `complet` dans la réponse compare au manifeste.
- **Une archive en `verif_etat` autre que `ok` est quand même restaurable**, et
  c'est voulu : une archive douteuse est justement ce qu'on veut inspecter. Le
  module le journalise en WARNING — ne pas conclure sur une copie partielle en
  croyant tenir la vérité.
- **Deux politiques ISM, deux motifs disjoints.** Un index ne porte qu'**une**
  politique : si `aura-retention` et `aura-hunting` matchaient le même index à la
  même priorité, le rattachement serait arbitraire. Un test vérifie la disjonction.
