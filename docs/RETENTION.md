# Rétention des données

Le 2026-08-14, la prod était à **66 % de disque (92 Go sur 148)** et personne
ne l'avait vu venir. Aucune politique de rétention n'existait nulle part :
l'indexer gardait tout depuis son installation, la table `alerts` grossissait de
~150 Mo/jour, et rien ne surveillait le remplissage.

Contre-intuitif, et c'est le point à retenir : **ce n'étaient pas les logs
Wazuh**. L'indexer pesait 470 Mo pour 155 index. Les 92 Go venaient de trois
boucles qui écrivaient en rond.

## Ce qui remplissait le disque

| Source | Volume | Nature |
|---|---|---|
| `audit_logs` MISP | 12,75 Go en **2 jours** | journal d'audit de l'ingestion des feeds — 49 M de lignes, 5,8 M/h |
| Evidences IRIS | 8,3 Go | 2 987 572 lignes pour 217 542 pièces distinctes (jusqu'à **54 copies** du même fichier) |
| Résidus feed CVE | 6,7 Go | `queue/vd_updater/tmp/contents`, laissé par une mise à jour interrompue |
| Images docker | ~2 Go | 394 images dangling |

Les deux premières étaient des **boucles**, pas des volumes normaux :

- **MISP** auditait chaque attribut et chaque tag posé par ses feeds. La feed
  URLhaus rejouait son historique 2021-2022 (20,8 M d'attributs, 2,66 M
  d'objets) et chaque écriture était journalisée deux fois, dans `audit_logs` et
  dans `logs`.
- **IRIS** recevait l'intégralité des alertes de chaque incident à chaque cycle
  de 5 minutes. `iris._evidences` demandait à IRIS ce qu'il avait déjà posé
  (`list_evidences`) ; passé quelques milliers de pièces l'appel échouait, et
  l'échec était avalé en `log.debug` — la liste des « déjà posées » retombait à
  vide et tout était reposté.

La cause première des deux côtés IRIS : des incidents énormes. **126 508
alertes** sur un incident pfSense, 96 804 sur un autre, alimentés par du bruit
Suricata et des `80730 Auditd: SELinux permission check`.

## Ce qui est en place

### À la source

| Correctif | Où |
|---|---|
| Écriture des journaux MISP en base coupée (`MISP.log_skip_db_logs_completely`) | réglage MISP, prod |
| Idempotence des Evidences portée par Postgres (`iris_evidences`), plus par IRIS | `iris.py`, `schema.sql` |
| Échec IRIS journalisé en WARNING et repère retiré (retenté), plus jamais silencieux | `iris.py` |
| Plafond de pièces Evidence par case (`EVIDENCE_MAX_PAR_CASE`, 500) | `config.py` |
| Chargement d'alertes borné par incident (`INCIDENT_MAX_ALERTES`, 2000) | `iris._alertes` |
| Membres d'incident bornés aux 50 plus récents à la corrélation | `correlate.py` |

`INCIDENT_MAX_ALERTES` prend les plus **anciennes** et les plus **récentes** à
parts égales : le début porte la graine de l'incident, la fin son état courant,
et c'est le milieu d'une salve répétitive qui n'apprend rien. `alert_count`
reste le compte réel, jamais tronqué.

### Par vieillissement — `soc-agent-retention`

Un passage par jour (`retention.py`) :

| Cible | Défaut | Variable |
|---|---|---|
| `alerts` (Postgres) | 90 jours | `RETENTION_ALERTES_JOURS` |
| Index datés de l'indexer (politique ISM) | 90 jours | `RETENTION_INDEX_JOURS` |
| Résidus `vd_updater/tmp` | 12 heures | `RETENTION_VD_TMP_HEURES` |
| Repères d'Evidence orphelins | — | — |

Deux garde-fous dans la purge des alertes :

- une alerte rattachée à un incident **encore actif** est épargnée quel que soit
  son âge — une intrusion lente tient dans un incident dont les premières
  alertes sont hors fenêtre, et les supprimer viderait le dossier de son début ;
- la politique ISM **exclut `wazuh-voc-vulns`**, seul index non daté du lot :
  c'est lui qui porte le cycle de vie des vulnérabilités, donc le MTTR (cf.
  [VOC.md](VOC.md)). Les motifs sont listés un par un dans `retention.py`
  plutôt qu'un `wazuh-*` qui l'avalerait.

La politique ISM est (ré)appliquée à chaque passage : elle est déclarative, la
poser est idempotent, et un indexer réinstallé la retrouve sans geste manuel.
`ism_template` ne vaut que pour les index créés **après** sa pose, d'où le
rattachement explicite des index existants — sans quoi une politique posée
aujourd'hui ne verrait jamais les index d'hier, c'est-à-dire précisément ceux
qu'elle doit supprimer.

### Par Wazuh lui-même

`monitord.keep_log_days = 31` : les fichiers d'alertes du manager
(`/var/ossec/logs/alerts/YYYY/MMM/*.gz`) sont tournés quotidiennement et purgés
au bout de 31 jours. Rien à faire, c'est en place et cohérent.

`logall`/`logall_json` sont à `no` : **aucun log brut n'est conservé**. Seul ce
qui matche une règle de niveau ≥ 3 existe. Un événement non couvert par une
règle est perdu à la seconde — pas de replay, pas de hunting rétroactif. C'est
un choix de volumétrie assumé, pas un oubli.

## Ce qui n'est PAS automatisé, et pourquoi

- **MISP.** Sa base pèse ~15 Go, mais c'est de la donnée CTI légitime : 21 M
  d'attributs venus de l'historique URLhaus. La purger serait une décision de
  **couverture CTI**, pas de rétention. À trancher séparément : cet historique
  a-t-il une valeur de détection, ou la feed doit-elle passer en cache seul ?
- **Images docker.** Les élaguer depuis un conteneur exigerait de lui donner la
  socket docker en écriture, c'est-à-dire root sur l'hôte, pour récupérer ~2 Go.
  À faire depuis l'hôte :
  ```bash
  docker image prune -f && docker builder prune -f
  ```
  Ne **jamais** utiliser `prune -a` : Shuffle instancie ses apps depuis des
  images inactives à l'instant T, qui seraient re-pull à chaud.

## Surveillance

Le watchdog mesure le disque à chaque passage et ouvre une **alerte IRIS**
(pas un case — cf. [watchdog.py](../src/ai/soc_agent/watchdog.py)) au-delà de
`DISQUE_SEUIL_ALERTE` (80 %), en `High` au-delà de `DISQUE_SEUIL_CRITIQUE`
(90 %). Elle se referme seule au retour sous le seuil.

Le disque est traité comme un capteur : même table d'état, même canal, même
cycle de vie. Un disque plein a exactement la conséquence d'un capteur muet, à
l'échelle de tout le pipeline — l'indexer bascule en lecture seule, Postgres
refuse d'écrire, et plus une alerte n'entre. C'est aussi pour ça qu'il reste
mesuré **même quand l'ingestion est en retard**, cas où le reste du watchdog se
tait : une ingestion à l'arrêt est précisément ce que produit un disque plein.

## Vérifier

```bash
# état du disque et des gros postes
ssh root@<soc> 'df -h /; du -xhd1 /opt/AURA/db | sort -h; docker system df'

# ce que la rétention supprimerait, sans le faire
docker exec soc-agent-retention python -m soc_agent.retention --dry-run

# politique ISM en place et index rattachés
curl -sk -u admin:$INDEXER_PASSWORD \
  https://localhost:9200/_plugins/_ism/explain/wazuh-linux-* | head
```
