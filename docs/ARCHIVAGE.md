# Archivage à froid vers S3

Module [`src/ai/soc_agent/archive.py`](../src/ai/soc_agent/archive.py) ·
table `archives_s3` ([`schema.sql`](../src/ai/soc_agent/schema.sql)) ·
service `soc-agent-archive` (quotidien) · **désactivé par défaut**

## Le problème

[`RETENTION.md`](RETENTION.md) supprime les index datés à 90 jours et les alertes
Postgres à 90 jours. C'est la bonne décision pour le disque, et c'en est une
mauvaise pour tout le reste : un SOC doit pouvoir répondre plus tard que trois
mois. Une réquisition arrive six mois après les faits. Un audit demande l'année
écoulée. Une intrusion se découvre en mars et a commencé en octobre.

L'archivage est la copie qui survit à la purge. Pas une sauvegarde de l'indexer —
une copie **autonome**, lisible sans lui.

## Ce qui n'est PAS archivé, et ce n'est pas réparable ici

`logall` et `logall_json` sont à `no` sur le manager. **Aucun log brut n'a jamais
existé.** Seul ce qui a matché une règle de niveau ≥ 3 est passé par l'indexer, et
c'est donc tout ce que l'archive peut contenir.

Conséquence à connaître avant qu'un auditeur ne la découvre : à la question
« montrez-moi toutes les connexions SSH de mars », il n'y a pas de réponse, et
l'archivage n'y est pour rien. C'est un choix de volumétrie assumé en amont. Le
changer signifierait activer `logall_json`, multiplier le volume par un facteur
de deux chiffres et refaire ce calcul — pas ajuster un réglage ici.

Sont aussi hors périmètre, par la **forme du nom d'index** et sans aucune liste à
tenir à jour :

| Index | Pourquoi |
|---|---|
| `wazuh-voc-vulns` | index d'**état**, non daté : un document par vulnérabilité réécrit à chaque passage. Il porte le cycle de vie de la dette, donc le MTTR ([VOC.md](VOC.md)). L'archiver par date n'a pas de sens |
| `wazuh-monitoring-*`, `wazuh-statistics-*` | datés à la **semaine** (`2026.33w`), télémétrie interne de Wazuh |

Seuls les index datés **au jour** (`-AAAA.MM.JJ`) sont archivés. C'est le filtre
réel du module, et il est structurel : rien à oublier de mettre à jour.

## Snapshot OpenSearch ou export NDJSON — la décision

Le choix a été fait pour l'export NDJSON. Les deux options s'excluent, il faut
savoir pourquoi.

| | Snapshot (`repository-s3`) | Export NDJSON (retenu) |
|---|---|---|
| Arborescence | **imposée** : `indices/<uuid>/__xyz`, `snap-*.dat`. Opaque, non réorganisable | libre : `v1/<index-set>/<annee>/` |
| Restauration | `POST _restore` → index requêtable | ré-ingestion `_bulk`, ou lecture hors ligne |
| Incrémental | oui (dédup par segment) | **non**, chaque archive est autonome |
| Chiffrement client | **impossible** — OpenSearch doit lire ses propres métadonnées | trivial |
| Lisible dans 3 ans | avec un cluster de version compatible | avec `zstdcat` et `age` |

Les trois raisons qui ont tranché :

1. **Le chiffrement client est non négociable** (voir plus bas). Un repo de
   snapshots chiffré par nous n'est plus un repo : il aurait fallu confier la clé
   au fournisseur, ce qui revient à ne pas chiffrer.
2. **Une archive doit valoir seule.** Un snapshot OpenSearch 2.x ne se restaure
   pas nécessairement sur un OpenSearch 4.x. L'archive doit survivre à la mort du
   cluster, pas en dépendre.
3. **L'usage réel est l'enquête tardive, pas le requêtage quotidien.** Un
   `.ndjson.zst` se lit avec `zstdcat | jq` sur n'importe quelle machine.

Le prix payé, assumé : pas d'incrémental, et la restauration n'est pas un clic.

## Les trois propriétés qui tiennent le reste

### 1. La prod ne détient que la clé publique

Le chiffrement est `age` (X25519 + ChaCha20-Poly1305), **côté client, avant
l'upload**. Seule la clé **publique** est dans le `.env` de la prod.

Qui prend root sur l'hôte du SOC peut écrire de nouvelles archives ; il ne peut
**pas relire les douze mois précédents**. C'est la propriété qui compte, et elle
a un corollaire dérangeant qu'il faut assumer : **ce code est incapable de
vérifier que ses propres archives se déchiffrent.** Le drill automatique prouve
l'intégrité, le drill complet est un geste humain (voir plus bas).

Ce qui a été écarté, et pourquoi :

| Écarté | Raison |
|---|---|
| Mot de passe d'archive (`zip -e`, `7z -p`) | dérivation de clé faible, noms de fichiers en clair en ZIP standard, mot de passe partagé entre humains donc fuité, pas d'intégrité vérifiable |
| **SSE-B2** (chiffrement serveur, clé Backblaze) | Backblaze détient la clé. Face à un audit RGPD ou au CLOUD Act, ça coche une case et ne protège rien |
| **SSE-C** (clé fournie à chaque requête) | la clé transite en en-tête HTTP à chaque appel, atterrit dans les logs et l'historique shell |

Chiffrer **après** compresser, jamais l'inverse : du chiffré est incompressible.

### 2. Le repère vit en Postgres, jamais dans le système distant

`archives_s3` est la seule autorité sur « ce qui est archivé ». Interroger S3 pour
le savoir reproduirait exactement le bug des pièces Evidence d'IRIS : l'appel
échoue passé un certain volume, l'échec est avalé, la liste des « déjà faites »
retombe à vide, et tout est refait — 8,3 Go et jusqu'à 54 copies du même fichier
([RETENTION.md](RETENTION.md)).

Une ligne n'est écrite qu'**après** relecture de l'objet côté S3 (`HEAD`, taille
comparée). Un `upload_file` qui rend la main sans exception n'est pas une preuve :
c'est la promesse d'une bibliothèque cliente.

Si le processus meurt entre l'upload et l'`INSERT`, la clé étant déterministe, le
passage suivant retrouve l'objet orphelin, lit son manifeste, compare le nombre de
documents au décompte vivant et **adopte** la ligne. Il ne réécrit pas : sous
Object Lock, un second upload ne remplace pas l'objet, il crée une **version**
supplémentaire elle aussi verrouillée — on paierait deux fois douze mois pour la
même donnée.

### 3. Le mois se lit dans le nom de l'index

`wazuh-firewall-2026.08.14` appartient à `2026-08`, point. Pas de fenêtre de
requête sur `@timestamp`, donc pas de document à cheval, pas de fuseau horaire
dans l'équation, et l'archive couvre **exactement** ce que la purge ISM va
supprimer.

## Arborescence

```
aura-archives/                                  (bucket dédié, privé, région UE)
  v1/
    wazuh-firewall/
      2026/
        wazuh-firewall.2026-03.ndjson.zst.age   ← l'archive
        wazuh-firewall.2026-03.manifest.json    ← le manifeste, EN CLAIR
      2027/
    wazuh-linux/
    wazuh-web/
    wazuh-alerts-4.x/
```

**Index set avant l'année**, contrairement à l'intuition. La question posée à une
archive est presque toujours « que disait le pare-feu entre mars et juin ? », pas
« que s'est-il passé en 2026, toutes sources confondues ? » : un seul préfixe à
restaurer, et une fenêtre à cheval sur le nouvel an ne se cherche pas dans deux
endroits. C'est aussi la seule disposition qui permette d'exprimer une règle de
cycle de vie par index set, si un jour `wazuh-firewall` doit se garder plus
longtemps que le reste.

Le `v1/` en tête n'est pas décoratif : le jour où le codec, la projection ou le
schéma du manifeste changent, `v2/` cohabite sans ambiguïté et un outil de lecture
sait à quoi il a affaire sans le deviner. Ne pas l'incrémenter pour un changement
de réglage.

## Le manifeste

En clair à côté de l'objet — il ne contient aucune donnée d'alerte, seulement de
quoi savoir ce que l'objet contient et comment le relire :

```json
{
  "format_version": "v1",
  "index_set": "wazuh-firewall",
  "periode": "2026-03",
  "indices": ["wazuh-firewall-2026.03.01", "…"],
  "documents": 184203,
  "octets_clair": 1073741824,
  "octets_objet": 41943040,
  "sha256_clair": "…",
  "sha256_chiffre": "…",
  "chaine": "zstd -19 --long=27 | age -r age1… -r age1secours…",
  "destinataires_age": ["age1…", "age1secours…"],
  "champs_exclus": [],
  "schema_ligne": "{_index, _id, _source}",
  "relecture": "age -d -i <cle-privee> <objet> | zstd -d | jq -c '…'"
}
```

`sha256_clair` est ce qui fait la différence entre une sauvegarde et une preuve :
c'est lui qui permet, dans deux ans, d'affirmer que ce qu'on déchiffre est ce qui
a été archivé.

## Le garde-fou qui empêche vraiment la perte

Le seul risque qui compte n'est pas « l'archivage a-t-il échoué cette nuit ? »
mais « reste-t-il de la donnée sur le point de disparaître sans copie ? ». Un
archivage en panne depuis trois jours est sans conséquence ; le même en panne
depuis quatre-vingts jours détruit de la donnée à la prochaine rotation.

Un index qui entre dans les `ARCHIVE_MARGE_JOURS` (7) précédant sa suppression
sans archive confirmée est **détaché de la politique ISM** (`_ism/remove`).

Le point technique à ne pas manquer : **suspendre la pose de la politique ne
protégerait rien.** Elle est déjà attachée aux index existants et continuerait de
les supprimer à l'heure prévue. Il faut détacher.

Et l'ordre des opérations compte, parce que `appliquer_ism()` rattache par
**motif** :

```
1. retention.appliquer_ism()   -> _ism/add par motif (réattache tout)
2. archive.proteger(peril)     -> _ism/remove sur les index sans copie
```

Protéger d'abord puis appliquer défairait la protection dans la seconde. C'est
exactement la classe de bug qui a déjà coûté cher ici : un ordre d'opérations qui
annule silencieusement l'opération précédente.

La protection se **répare seule** : dès que l'archive existe, le passage suivant
de la rétention réattache la politique par motif et l'index redevient purgeable.
Aucun geste manuel.

Conséquence à accepter : **tant que l'archivage est en panne, le disque grossit.**
C'est le compromis voulu — perdre de la donnée est pire qu'un disque qui monte, et
le garde-fou disque du watchdog ouvrira son alerte de son côté.

## Surveillance

Quatre signaux, portés par le watchdog dans `capteur_pannes` — même table, même
canal IRIS, même clôture automatique que le disque saturé. Une archive manquante
est une perte de visibilité **future** : la donnée est là aujourd'hui, elle ne
sera plus là quand on la cherchera.

| Pseudo-capteur | Sévérité | Ce que ça dit |
|---|---|---|
| `archivage:peril` | High | de la donnée entre dans la marge de suppression sans copie. La purge a été suspendue sur ces index |
| `archivage:trou` | Medium | un mois manque **entre** deux mois archivés. Les index d'origine sont purgés depuis longtemps : cette donnée n'existe plus nulle part |
| `archivage:drill` | High | une archive relue ne correspond plus à ce qui avait été écrit |
| `archivage:drill-en-retard` | Medium | des archives n'ont pas été relues depuis `ARCHIVE_DRILL_JOURS` |

`archivage:trou` est un **constat**, pas une réparation possible : la donnée
manquante manque définitivement. L'action utile est de comprendre pourquoi
l'archivage était muet sur cette période et de vérifier que le garde-fou de péril
fonctionne aujourd'hui.

Le watchdog est ici en **lecture seule**, contrairement au routage : l'archivage
lui-même est fait par `soc-agent-archive` à sa cadence. Un export de plusieurs
centaines de mégaoctets n'a rien à faire dans un passage qui tourne toutes les
deux minutes.

## Le drill de restauration

Une archive non testée est une croyance, pas une copie.

À chaque passage, les `ARCHIVE_DRILL_LOT` (3) archives vérifiées **le moins
récemment** sont retéléchargées et leur SHA-256 recalculé. Sélection par
`verifie_a NULLS FIRST` : déterministe, et chaque archive finit par passer. Un
tirage au sort laisserait durablement des trous.

**Ce drill automatique prouve l'intégrité, pas la lisibilité.** Sans la clé privée
— qui n'a rien à faire sur cet hôte — il ne peut pas déchiffrer. C'est la limite
structurelle du chiffrement asymétrique, et c'est le prix de la propriété qui
compte.

Le **drill complet**, à faire une fois par trimestre, à la main :

```bash
# monter temporairement la clé privée, hors du .env
docker compose -p aura run --rm \
  -v /media/coffre/cle-archive-aura.txt:/tmp/cle:ro \
  soc-agent-archive \
  python -m soc_agent.archive --drill-complet --identite /tmp/cle --lot 5
```

Il déchiffre, décompresse, compare le SHA-256 du **clair** et le nombre de
documents au manifeste. C'est le seul qui prouve qu'une archive est lisible.

## Mise en service

### 1. Les clés — le geste irréversible

```bash
age-keygen -o cle-archive-aura.txt          # clé principale
age-keygen -o cle-archive-secours.txt       # clé de secours
```

**Perdre la clé privée = perdre définitivement toutes les archives.** Personne ne
les récupère, ni Backblaze ni nous. D'où deux destinataires : la seconde clé dort
hors ligne, dans un coffre ou une enveloppe scellée, et ne sert que si la première
est perdue.

Les fichiers `age-keygen` contiennent la clé **privée**. Ils ne vont ni dans le
dépôt, ni dans le `.env`, ni sur la prod. Seule la ligne
`# public key: age1...` de chacun est recopiée dans `ARCHIVE_AGE_RECIPIENTS`.

### 2. Le bucket B2

| Réglage | Valeur | Raison |
|---|---|---|
| Bucket | **privé**, dédié, région UE (Amsterdam) | dédié permet de scoper la clé applicative à lui seul |
| Clé applicative | scopée à ce bucket, `listFiles` + `readFiles` + `writeFiles` | — |
| **Pas** `deleteFiles` | — | un rançongiciel qui prend cet hôte doit être incapable d'effacer les douze mois après avoir chiffré le reste |
| Cycle de vie | `keepOnlyLastVersion` + suppression à 365 j | la purge n'appartient pas au code. B2 conserve sinon les versions masquées et vous payez du stockage fantôme sans le voir |
| Object Lock | à décider **à la création** | voir ci-dessous |

La région UE évite un transfert hors UE à documenter au registre. Elle ne met
**pas** la donnée hors de portée du CLOUD Act — Backblaze est une société
américaine. C'est le chiffrement client qui s'en charge, et c'est précisément ce
qui rend un fournisseur américain acceptable ici.

### 3. Object Lock

`ARCHIVE_OBJECT_LOCK=false` par défaut, activable par le `.env`. C'est ce qui
distingue un archivage d'une sauvegarde : permet d'affirmer devant un auditeur que
l'objet n'a pas pu être modifié.

Avant de le passer à `true` :

- le bucket doit avoir été **créé** avec Object Lock. La propriété ne se
  rétro-applique pas à un bucket existant, il faudrait en recréer un ;
- en mode `COMPLIANCE`, **aucune** suppression n'est possible avant l'échéance, y
  compris par le propriétaire du compte et y compris en cas d'erreur de votre
  part. La facture des douze mois est due quoi qu'il arrive ;
- `GOVERNANCE` laisse une porte de sortie à un compte privilégié : plus
  confortable, moins probant ;
- ne pas poser de rétention **par défaut sur le bucket** — le module pose le
  verrou objet par objet, et une rétention de bucket verrouillerait aussi le
  témoin de préflight.

### 4. Préflight, puis activation

```bash
python -m soc_agent.archive --verifier   # bucket, droits, versioning, Object Lock
python -m soc_agent.archive --plan       # ce qui serait archivé, sans rien écrire
```

`--verifier` vérifie aussi ce qui devrait être **absent** : il tente une
suppression et signale `suppression: POSSIBLE` si la clé porte `deleteFiles`. Une
clé de prod qui peut supprimer est un rançongiciel qui peut effacer les douze mois.

Puis `ARCHIVAGE_ENABLED=true` dans le `.env` et :

```bash
cd /opt/AURA && docker compose -p aura up -d --build soc-agent-archive
```

Le `--build` n'est pas optionnel : le code `soc_agent` est **baké dans l'image**,
et l'image porte désormais aussi `zstd` et `age`.

Les identifiants manquants font échouer le **démarrage** dès que
`ARCHIVAGE_ENABLED=true`, pour les douze conteneurs qui partagent `config.py`.
C'est volontaire : un archivage qui échoue en silence est pire que pas
d'archivage, il fait croire que la copie existe.

## Restaurer

```bash
docker compose -p aura run --rm \
  -v /media/coffre/cle-archive-aura.txt:/tmp/cle:ro \
  -v /srv/restore:/out \
  soc-agent-archive \
  python -m soc_agent.archive --restaurer wazuh-firewall/2026-03 \
    --identite /tmp/cle --vers /out/firewall-2026-03.ndjson
```

Vérifier l'empreinte contre le manifeste, puis exploiter selon le besoin :

```bash
# lecture directe, sans rien remettre dans l'indexer — souvent suffisant
jq -c 'select(._source.rule.level >= 12) | ._source' firewall-2026-03.ndjson

# ré-ingestion dans un index JETABLE, jamais par-dessus un index de production
jq -c '{index:{_index:"restore-firewall-2026-03"}}, ._source' \
  firewall-2026-03.ndjson \
  | curl -ku admin:"$INDEXER_PASSWORD" -H 'Content-Type: application/x-ndjson' \
      --data-binary @- "$INDEXER_URL/_bulk"
```

La réinjection est délibérément **hors du module** : décider où remettre de la
donnée vieille de dix mois est un geste d'analyste, pas d'automate. Ré-ingérer
dans `wazuh-firewall-*` ferait rentrer ces alertes dans le pipeline de triage et
fabriquerait des incidents sur des faits vieux d'un an.

## Coût réel

Sur la volumétrie actuelle, l'indexer pèse **470 Mo pour 155 index**. Douze mois
d'archives compressées ×20-30 se comptent en **centaines de mégaoctets**, soit
quelques **centimes par mois** chez B2 (6,95 $/To). L'egress gratuit jusqu'à 3× le
stockage rend les drills et les restaurations gratuits en pratique.

Autrement dit : **le coût n'est pas le sujet ici, et n'a pas orienté les
décisions.** C'est pourquoi `ARCHIVE_CHAMPS_EXCLUS` est **vide** par défaut —
élaguer `_source` économiserait quelques gigaoctets par an, et une archive amputée
ne se répare pas. À ne remplir que si la volumétrie devient un vrai problème, et
c'est alors tracé dans le manifeste (`champs_exclus`).

Les deux postes qui mordraient réellement à plus grande échelle, dans l'ordre :

1. **les transactions, pas le stockage.** B2 offre 2 500 appels de listage par
   jour. Le module ne liste **jamais** le bucket : les clés sont déterministes et
   l'existence se vérifie par `HEAD` sur la clé attendue ;
2. **l'egress**, si un jour il faut tout ressortir. Un objet par mois plutôt que
   par jour garde le nombre d'appels bas.

## Pièges

- **`zstd` et `age` sont des binaires de l'image**, pas des paquets pip. Un
  `docker compose up` sans `--build` après cette mise en place donne un conteneur
  qui échoue avec « `age` absent de l'image ».
- **Le fichier de travail est du chiffré**, jamais du clair : le NDJSON ne
  traverse que des tubes. Mais il faut de la place — un export est refusé s'il n'a
  pas de quoi s'écrire, parce qu'un disque plein arrête tout le SOC.
- **Une chaîne en échec ne laisse pas son fichier.** Un fichier tronqué qui monte
  dans S3 se fait passer pour une archive valide jusqu'au jour où on en a besoin.
- **`ARCHIVE_DELAI_JOURS` n'est pas de la prudence décorative.** Le rattrapage des
  alertes indexées en retard écrit encore dans les index de la veille. Archiver le
  1er au matin fige une copie incomplète, qui se croira complète.
- **Un mois vide produit quand même une archive** (quelques centaines d'octets).
  L'invariant « chaque mois de chaque index set a exactement un objet » est ce qui
  rend un trou détectable ; un mois simplement absent serait indistinguable d'un
  mois perdu.
- **La clôture d'une alerte `archivage:trou` ne veut pas dire réparé.** Elle se
  referme aussi si les mois qui encadraient le trou ont quitté la fenêtre de
  rétention des archives.
