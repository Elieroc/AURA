# Couche IA du SOC

Deux choses ici :

- [`bench/`](bench/) — mesures llama.cpp sur CPU. Résultats et conclusions dans
  [`bench/RESULTS.md`](bench/RESULTS.md).
- [`soc_agent/`](soc_agent/) — le pipeline. **Phase 1 : ingestion et
  corrélation, sans LLM.**

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

Mesuré sur les données réelles du lab :

| | |
|---|---|
| Alertes ingérées | 680 sur 3,7 jours (183/jour) |
| Retenues (niveau ≥ 12) | 36 — **5,3 %** |
| Incidents après corrélation | **4** — facteur 9 |
| Charge LLM résultante | 0,4 min de CPU par jour |

Le cas typique : 31 alertes réparties sur 4 règles (`100670`, `100671`,
`100672`, `100682`) sur `debian-vm` deviennent **un** incident ransomware.

Sur ce lab, la marge est confortable. Le rapport reste utile en production, où
le rapport 5,3 % / facteur 9 dira si l'architecture tient.

## Installation

Prérequis : la stack Wazuh doit tourner (l'indexer est la source).

```bash
cd ai
cp .env.example .env
# INDEXER_PASSWORD = celui de wazuh/.env ; PGPASSWORD = openssl rand -hex 24
$EDITOR .env

docker compose --env-file .env up -d
docker exec -i socagent-db psql -q -U socagent -d socagent < soc_agent/schema.sql

# Environnement Python hors dépôt : celui-ci est synchronisé Nextcloud.
python3 -m venv ~/.local/share/soc-ai/venv
~/.local/share/soc-ai/venv/bin/pip install -r soc_agent/requirements.txt
```

## Utilisation

```bash
cd ai
set -a; source .env; set +a
VENV=~/.local/share/soc-ai/venv/bin/python

$VENV -m soc_agent.ingest --depuis 30d   # tire depuis l'indexer
$VENV -m soc_agent.correlate             # regroupe en incidents
$VENV -m soc_agent.report                # l'entonnoir et la charge LLM
```

Les deux premières commandes sont faites pour tourner en boucle (cron ou
timer) : l'ingestion reprend à son curseur, la corrélation ne traite que les
alertes non encore rattachées.

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

## Attention

`TRUNCATE incidents CASCADE` **vide aussi `alerts`** (clé étrangère). Pour
remettre la corrélation à zéro, utiliser `--recommencer`, qui passe par un
`DELETE`.

## Reste à faire

- Réingestion périodique (timer systemd ou cron).
- Le seuil `MIN_LEVEL=12` mérite d'être confronté au terrain : certaines
  attaques n'émettent que du niveau 10-11.
- Rétention : la table `alerts` grossit sans limite.
