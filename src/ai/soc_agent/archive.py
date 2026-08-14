"""Archivage à froid des index de l'indexer vers S3 (Backblaze B2).

La rétention (`retention.py`) supprime les index datés à 90 jours. Un SOC doit
pouvoir répondre plus tard que ça : réquisition judiciaire, audit, intrusion
découverte six mois après son début. Ce module produit la copie qui survit à la
purge.

Ce que c'est, et ce que ce n'est pas
------------------------------------
Un objet par (index set × mois), en NDJSON compressé puis CHIFFRÉ, plus un
manifeste en clair à côté. Ce n'est PAS un snapshot OpenSearch, et le choix est
délibéré :

- un snapshot ne se relit qu'avec un cluster de version compatible. Une archive
  de douze mois doit valoir seule, en 2029, avec `zstdcat` et `age` ;
- l'arborescence d'un repo de snapshots est imposée et opaque
  (`indices/<uuid>/__xyz`) : impossible d'y ranger par index set et par année ;
- un repo chiffré côté client n'est plus un repo — OpenSearch doit pouvoir lire
  ses propres métadonnées. Il aurait donc fallu confier la clé au fournisseur.

Le prix payé, assumé : pas d'incrémental (chaque archive est autonome) et la
restauration n'est pas un clic (cf. docs/ARCHIVAGE.md).

Trois propriétés qui tiennent le reste
--------------------------------------
1. **Le SOC détient la clé en entier** (`ARCHIVE_AGE_KEYFILE`) : il chiffre et
   déchiffre ses propres archives. Ce qui en découle, en bien comme en mal :

   - le drill de restauration va jusqu'au bout tout seul — il déchiffre, compte
     les documents et compare au manifeste. Il prouve la LISIBILITÉ, pas
     seulement l'intégrité du stockage ;
   - restaurer un mois ne demande aucun montage de clé à la main ;
   - mais ce fichier est la seule chose qui sépare un attaquant ayant root sur
     cet hôte de la lecture de tout l'historique. Le fournisseur, lui, ne voit
     jamais que de l'opaque — c'est le but du chiffrement client, et il est
     atteint. Le modèle de menace couvert est « B2 lit mes archives », pas
     « le SOC est compromis ».
2. **Le repère vit en Postgres**, jamais dans le système distant. Interroger S3
   pour savoir ce qui est archivé, c'est reproduire le bug des pièces Evidence
   d'IRIS : l'appel échoue, l'échec est avalé, la liste des « déjà faites »
   retombe à vide et tout est refait — 8,3 Go et 54 copies du même fichier.
3. **Le mois se lit dans le NOM de l'index**, jamais dans un `@timestamp`.
   `wazuh-firewall-2026.08.14` appartient à 2026-08, point. Pas de fenêtre de
   requête à cheval, pas de fuseau horaire, et l'archive couvre exactement ce
   que la purge ISM va supprimer.

Le clair ne touche jamais le disque : il traverse `zstd | age` par des tubes, et
seul le chiffré est écrit dans un fichier de travail.

    python -m soc_agent.archive --verifier    # préflight clé + bucket, avant tout
    python -m soc_agent.archive --plan        # ce qui serait archivé
    python -m soc_agent.archive               # un passage
    python -m soc_agent.archive --drill       # relire et déchiffrer des archives
    python -m soc_agent.archive --restaurer wazuh-firewall/2026-03 --vers f.ndjson
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)

# Même famille de verrou consultatif que les autres jobs périodiques (0x50CA*).
_LOCK_ARCHIVE = 0x50CA6

# Index DATÉ AU JOUR, seule forme archivée. Ce motif est le vrai filtre du
# module : il exclut sans aucune liste `wazuh-voc-vulns` (index d'état, il porte
# le MTTR) ainsi que `wazuh-monitoring-*` / `wazuh-statistics-*`, datés à la
# semaine par Wazuh (`2026.33w`) et qui ne sont pas des alertes.
_DATE_INDEX = re.compile(r"^(?P<base>.+)-(?P<a>\d{4})\.(?P<m>\d{2})\.(?P<j>\d{2})$")

SUFFIX_OBJECT = "ndjson.zst.age"
SUFFIX_MANIFEST = "manifest.json"

# Pseudo-capteurs posés dans `capteur_pannes` par le watchdog. Même table, même
# canal IRIS, même clôture automatique que le disque saturé : une archive
# manquante est une perte de visibilité future, exactement de la même nature.
PREFIX_SENSOR = "archivage:"


# --------------------------------------------------------------------------
# Indexer
# --------------------------------------------------------------------------

def _indexer(method: str, path: str, body: dict | None = None,
             timeout: int = 120) -> requests.Response:
    return requests.request(
        method, f"{config.INDEXER_URL}{path}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=body,
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=timeout)


def _excluded(name: str) -> bool:
    return any(fnmatch.fnmatch(name, m) for m in config.ARCHIVE_INDEX_EXCLUDED)


def dated_indices() -> list[dict]:
    """Index datés au jour, avec leur base, leur mois et leur taille.

    La liste des motifs candidats est délibérément large (`wazuh-*`) : le piège
    maison est la liste à tenir à jour qu'on oublie — trois fois pour
    `INDEXER_ALERT_INDICES` (cf. docs/ROUTAGE.md), et chaque oubli était un
    capteur invisible. Un index set créé demain par `routage.py` doit être
    archivé sans que personne y pense.
    """
    r = _indexer("GET", f"/_cat/indices/{config.ARCHIVE_INDEX_PATTERNS}"
                        "?format=json&h=index,docs.count,pri.store.size"
                        "&bytes=b&expand_wildcards=open")
    if r.status_code == 404:
        return []
    if not r.ok:
        raise RuntimeError(f"_cat/indices refusé ({r.status_code}) : {r.text}")
    output = []
    for line in r.json():
        name = line["index"]
        m = _DATE_INDEX.match(name)
        if not m or _excluded(name):
            continue
        output.append({
            "index": name,
            "base": m.group("base"),
            "day": date(int(m.group("a")), int(m.group("m")), int(m.group("j"))),
            "mois": f"{m.group('a')}-{m.group('m')}",
            "documents": int(line.get("docs.count") or 0),
            "octets": int(line.get("pri.store.size") or 0),
        })
    return output


def _first_of_next_month(month: str) -> date:
    a, m = (int(x) for x in month.split("-"))
    return date(a + 1, 1, 1) if m == 12 else date(a, m + 1, 1)


def _closed_months(month: str, today: date | None = None) -> bool:
    """Le mois est-il terminé ET assez décanté pour être figé ?

    Le délai de grâce n'est pas décoratif : le rattrapage des alertes indexées
    en retard écrit encore dans les index de la veille, et un index créé à
    cheval sur minuit peut recevoir après coup. Archiver trop tôt fige une copie
    incomplète — et une archive incomplète ne se répare pas, elle se croit
    complète.
    """
    ref = today or datetime.now(timezone.utc).date()
    return ref >= _first_of_next_month(month) + timedelta(
        days=config.ARCHIVE_DELAY_DAYS)


def batches_to_archive(conn, today: date | None = None) -> list[dict]:
    """Couples (index_base, mois) clos, non encore archivés.

    Un mois VIDE produit quand même une archive (quelques centaines d'octets).
    C'est voulu : l'invariant « chaque mois de chaque index set a exactement un
    objet » est ce qui rend un trou détectable. Un mois simplement absent serait
    indistinguable d'un mois perdu.
    """
    already = {(r["index_base"], r["period"]) for r in conn.execute(
        "SELECT index_base, period FROM archives_s3 WHERE format_version=%s",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()}
    batches: dict[tuple[str, str], dict] = {}
    for i in dated_indices():
        key = (i["base"], i["mois"])
        if key in already or not _closed_months(i["mois"], today):
            continue
        batch = batches.setdefault(key, {"index_base": i["base"], "period": i["mois"],
                                    "indices": [], "documents": 0, "octets": 0})
        batch["indices"].append(i["index"])
        batch["documents"] += i["documents"]
        batch["octets"] += i["octets"]
    for batch in batches.values():
        batch["indices"].sort()
    return sorted(batches.values(), key=lambda l: (l["period"], l["index_base"]))


# --------------------------------------------------------------------------
# Export : pagination par scroll (cf. `pages` pour le pourquoi)
# --------------------------------------------------------------------------

def _body_search(size: int) -> dict:
    body: dict = {"size": size, "query": {"match_all": {}}}
    if config.ARCHIVE_FIELDS_EXCLUDED:
        body["_source"] = {"excludes": config.ARCHIVE_FIELDS_EXCLUDED}
    # Compte EXACT et non plafonné. Sans ce réglage, OpenSearch s'arrête de
    # compter à 10 000 et rend `{"value": 10000, "relation": "gte"}` : un
    # plafond qu'on prendrait pour un total, donc une vérification de complétude
    # qui validerait n'importe quel export de plus de 10 000 documents.
    body["track_total_hits"] = True
    return body


def _check_shards(doc: dict, indices: list[str]) -> None:
    """Refuse un résultat PARTIEL. C'est la vérification qui manquait.

    OpenSearch répond `HTTP 200` avec des résultats partiels quand un shard
    tombe ou dépasse son délai : l'échec est dans `_shards.failed`, pas dans le
    code HTTP. Sans ce contrôle, un shard indisponible pendant l'export produit
    une archive tronquée qui enregistre SON PROPRE compte tronqué comme
    référence — le manifeste, le SHA-256, le drill et l'adoption sont alors tous
    d'accord entre eux, et il manque des alertes que plus rien ne réclamera.

    C'est le pire mode de défaillance possible pour un archivage : silencieux et
    auto-confirmé. D'où un échec franc du lot, quitte à le refaire demain.
    """
    shards = doc.get("_shards") or {}
    rates = shards.get("failed") or 0
    if rates or doc.get("timed_out"):
        patterns = "; ".join(
            f"{e.get('index', '?')}: {e.get('reason', {}).get('reason', e)}"
            for e in (shards.get("failures") or [])[:3]) or "aucun détail fourni"
        raise RuntimeError(
            f"export partiel refusé sur {','.join(indices[:3])}"
            f"{'…' if len(indices) > 3 else ''} : {rates} shard(s) en échec sur "
            f"{shards.get('total', '?')}"
            f"{', recherche expirée' if doc.get('timed_out') else ''} — {patterns}. "
            "Un export partiel produirait une archive tronquée qui se croirait "
            "complète. Lot abandonné, il sera repris au prochain passage.")


def pages(indices: list[str], size: int | None = None,
          control: dict | None = None):
    """Pagination de l'export par l'API scroll.

    Pourquoi le scroll et pas `point_in_time` + `search_after`, qui est la
    méthode recommandée partout : **`_shard_doc` n'existe pas dans OpenSearch.**
    Ce champ de tri a été ajouté dans Elasticsearch 7.12, après le fork
    d'OpenSearch, et n'y a jamais été porté. Un PIT s'y crée donc très bien, mais
    la recherche qui s'appuie dessus est rejetée :

        query_shard_exception: No mapping found for [_shard_doc] in order to
        sort on

    C'est exactement ce qu'a répondu l'indexer de prod (OpenSearch 2.x) au
    premier passage réel, sur les dix lots. Et sans critère de tri **total**, le
    `search_after` n'est pas utilisable : un tri sur `@timestamp` seul saute ou
    duplique les documents partagés par la même milliseconde, et `_id` n'est pas
    triable. Il ne reste que le scroll.

    Le scroll est déprécié côté Elasticsearch, pas côté OpenSearch, et son
    inconvénient (il retient un contexte de recherche) est sans portée ici :
    l'export est un tir unique sur des index qui ne reçoivent plus rien.

    `controle` reçoit `attendu`, le total EXACT du même instantané de recherche
    que les pages. Le comparer au nombre de documents réellement écrits est ce
    qui prouve la complétude, et le prendre ICI plutôt que dans `_cat/indices`
    supprime toute course : c'est le même contexte de scroll, donc le même
    ensemble de documents.
    """
    size = size or config.ARCHIVE_SIZE_BATCH
    csv = ",".join(indices)
    r = _indexer("POST", f"/{csv}/_search?scroll=10m", _body_search(size))
    if not r.ok:
        raise RuntimeError(f"scroll refusé ({r.status_code}) : {r.text}")
    doc = r.json()
    _check_shards(doc, indices)
    if control is not None:
        total = (doc.get("hits") or {}).get("total") or {}
        control["attendu"] = total.get("value")
        control["relation"] = total.get("relation")
    sid = doc.get("_scroll_id")
    try:
        while True:
            hits = doc["hits"]["hits"]
            if not hits:
                return
            yield hits
            r = _indexer("POST", "/_search/scroll",
                         {"scroll": "10m", "scroll_id": sid})
            if not r.ok:
                raise RuntimeError(f"scroll refusé ({r.status_code}) : {r.text}")
            doc = r.json()
            # Sur CHAQUE page : un shard peut tomber au milieu d'un scroll de
            # plusieurs minutes, et la page concernée revient simplement plus
            # courte, sans erreur HTTP.
            _check_shards(doc, indices)
            # L'id de scroll PEUT changer d'un appel à l'autre : réutiliser le
            # premier indéfiniment marche jusqu'au jour où il ne marche plus.
            sid = doc.get("_scroll_id") or sid
    finally:
        # Un contexte de scroll non libéré retient des segments sur disque, et le
        # disque plein est la panne qui arrête tout le SOC. Best-effort, mais
        # jamais oublié.
        if sid:
            try:
                _indexer("DELETE", "/_search/scroll", {"scroll_id": [sid]})
            except Exception as e:                                # noqa: BLE001
                log.warning("scroll non libéré : %s", e)


# --------------------------------------------------------------------------
# Chaîne compression + chiffrement
# --------------------------------------------------------------------------

def public_key() -> str:
    """Clé publique correspondant à `ARCHIVE_AGE_KEYFILE`.

    `age-keygen` écrit la publique en commentaire de l'identité ; on la lit là
    plutôt que de lancer un sous-processus à chaque archive. Repli sur
    `age-keygen -y` si le commentaire a été retiré — ne pas se contenter d'un
    échec ici, ce serait bloquer l'archivage pour une ligne de commentaire.
    """
    for line in Path(config.ARCHIVE_AGE_KEYFILE).read_text(
            encoding="utf-8", errors="replace").splitlines():
        if line.lower().startswith("# public key:"):
            return line.split(":", 1)[1].strip()
    r = subprocess.run(["age-keygen", "-y", config.ARCHIVE_AGE_KEYFILE],
                       capture_output=True)
    if r.returncode:
        raise RuntimeError(
            f"clé publique indéterminable depuis {config.ARCHIVE_AGE_KEYFILE} : "
            + r.stderr.decode(errors="replace")[:300])
    return r.stdout.decode().strip()


def recipients() -> list[str]:
    """Clé du SOC, plus les clés de secours éventuelles.

    La clé du SOC est DÉRIVÉE du fichier de clé, jamais recopiée dans le `.env`.
    C'est ce qui supprime toute une classe de pannes : un destinataire mal
    recopié produirait des archives que le SOC ne peut pas relire, et personne ne
    s'en apercevrait avant le premier drill.
    """
    return [public_key(), *config.ARCHIVE_AGE_RECIPIENTS_EXTRA]


def processing_chain() -> str:
    """Description exacte de la chaîne, telle qu'écrite dans le manifeste.

    Ce n'est pas cosmétique : c'est ce qui permet de relire une archive dans
    trois ans sans lire le code de cette version-là.
    """
    return (f"zstd -{config.ARCHIVE_ZSTD_LEVEL} --long=27 | age -r "
            + " -r ".join(recipients()))


def _check_tools() -> None:
    for tool in ("zstd", "age"):
        if not shutil.which(tool):
            raise RuntimeError(
                f"« {tool} » absent de l'image. L'archivage compresse et "
                "chiffre par des tubes, jamais en mémoire : les deux binaires "
                "sont requis (paquets Debian `zstd` et `age`).")


def _free_space(index_bytes: int) -> None:
    """Refuser d'exporter faute de place, plutôt que de remplir le disque.

    L'archive chiffrée est toujours BEAUCOUP plus petite que le store de
    l'index ; exiger l'équivalent du store est donc large, et c'est le but. Un
    disque plein arrête l'ingestion sans qu'aucune alerte ne le dise (cf.
    docs/RETENTION.md) : ce job de ménage ne doit pas en être la cause.
    """
    need = max(index_bytes, 256 * 1024 * 1024)
    free = shutil.disk_usage(config.ARCHIVE_TMP_DIR).free
    if free < need:
        raise RuntimeError(
            f"place insuffisante dans {config.ARCHIVE_TMP_DIR} : "
            f"{free / 1073741824:.1f} Go libres, {need / 1073741824:.1f} Go "
            "exigés. Export refusé — remplir le disque du SOC arrêterait "
            "l'ingestion.")


def export(batch: dict, destination: Path) -> dict:
    """Écrit l'archive CHIFFRÉE dans `destination`. Renvoie les métriques.

    Le NDJSON en clair ne touche jamais le disque : il est écrit sur l'entrée de
    `zstd`, dont la sortie alimente `age`, dont la sortie seule est un fichier.
    Le SHA-256 du clair est calculé au vol, pendant qu'on l'a sous la main.
    """
    _check_tools()
    _free_space(batch["octets"])

    recipients: list[str] = []
    for r in recipients():
        recipients += ["-r", r]

    sha_plain = hashlib.sha256()
    plain_bytes = documents = 0
    control: dict = {}

    with destination.open("wb") as output:
        zstd = subprocess.Popen(
            ["zstd", f"-{config.ARCHIVE_ZSTD_LEVEL}", "--long=27", "-T0",
             "-q", "-c"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        age = subprocess.Popen(["age", *recipients], stdin=zstd.stdout,
                               stdout=output, stderr=subprocess.PIPE)
        # Indispensable : sans ça, `zstd` ne voit jamais le EOF de son lecteur
        # et la chaîne se bloque à la fermeture.
        zstd.stdout.close()
        try:
            for page in pages(batch["indices"], control=control):
                for hit in page:
                    line = (json.dumps(
                        {"_index": hit["_index"], "_id": hit["_id"],
                         "_source": hit.get("_source") or {}},
                        ensure_ascii=False, separators=(",", ":"),
                        sort_keys=True) + "\n").encode()
                    sha_plain.update(line)
                    plain_bytes += len(line)
                    documents += 1
                    zstd.stdin.write(line)
        except BrokenPipeError as e:
            err = (zstd.stderr.read() or b"").decode(errors="replace")
            raise RuntimeError(f"zstd a rompu le tube : {err or e}") from e
        finally:
            try:
                zstd.stdin.close()
            except BrokenPipeError:
                pass
            code_zstd = zstd.wait()
            code_age = age.wait()

    if code_zstd or code_age:
        # Ne JAMAIS garder un fichier issu d'une chaîne en échec : il serait
        # tronqué, et un tronqué qui monte dans S3 se fait passer pour une
        # archive valide jusqu'au jour où on en a besoin.
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"chaîne de traitement en échec (zstd={code_zstd}, age={code_age}) : "
            + (zstd.stderr.read() or b"").decode(errors="replace")
            + (age.stderr.read() or b"").decode(errors="replace"))

    # CONTRÔLE DE COMPLÉTUDE. Le compte vient du même instantané de scroll que
    # les pages, donc un écart ne peut pas venir d'une écriture concurrente : il
    # ne peut venir que d'un export qui s'est arrêté avant la fin.
    #
    # Écrit en MOINS = archive tronquée : refus, et suppression du fichier. Ce
    # cas est celui qui rendait le trou indétectable, puisque le manifeste aurait
    # enregistré le compte tronqué comme référence et que tout le reste (SHA-256,
    # drill, adoption) se compare au manifeste.
    #
    # Écrit en PLUS n'est pas une erreur : le scroll rend ce qu'il a, et un
    # surplus signifierait au pire un doublon, pas une perte. On le journalise.
    expected = control.get("attendu")
    if expected is not None and documents < expected:
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"export INCOMPLET refusé : {documents} documents écrits pour "
            f"{expected} annoncés par l'indexer "
            f"({batch['index_base']}/{batch['period']}). Le fichier a été supprimé "
            "— l'archiver aurait produit une copie tronquée qui se croit "
            "complète. Lot repris au prochain passage.")
    if expected is not None and documents > expected:
        log.warning("export %s/%s : %d documents écrits pour %d annoncés — "
                    "surplus conservé (aucune perte), à surveiller si ça se "
                    "répète", batch["index_base"], batch["period"], documents,
                    expected)

    return {"documents": documents, "plain_bytes": plain_bytes,
            "sha256_plain": sha_plain.hexdigest(),
            "object_bytes": destination.stat().st_size,
            "sha256_encrypted": _sha256_file(destination)}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for bloc in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloc)
    return h.hexdigest()


# --------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------

def _s3():
    import boto3
    from botocore.config import Config as BotoConfig
    return boto3.client(
        "s3",
        endpoint_url=config.ARCHIVE_S3_ENDPOINT,
        region_name=config.ARCHIVE_S3_REGION,
        aws_access_key_id=config.ARCHIVE_S3_KEY_ID,
        aws_secret_access_key=config.ARCHIVE_S3_APP_KEY,
        config=BotoConfig(signature_version="s3v4",
                          retries={"max_attempts": 5, "mode": "standard"}))


def object_key(index_base: str, period: str, suffix: str) -> str:
    """`[prefixe/]<version>/<index-set>/<annee>/<index-set>.<AAAA-MM>.<suffixe>`

    Index set AVANT l'année, contrairement à l'intuition. La question posée à une
    archive est presque toujours « que disait le pare-feu entre mars et juin ? »,
    pas « que s'est-il passé en 2026, toutes sources confondues ? » : un seul
    préfixe à restaurer, et une fenêtre à cheval sur le nouvel an ne se cherche
    pas dans deux endroits. C'est aussi la seule disposition qui permette
    d'exprimer une règle de cycle de vie par index set.
    """
    parts = [p for p in (config.ARCHIVE_S3_PREFIX,
                         config.ARCHIVE_FORMAT_VERSION,
                         index_base, period[:4]) if p]
    return "/".join(parts) + f"/{index_base}.{period}.{suffix}"


def manifest(batch: dict, metrics: dict, key: str) -> dict:
    """Manifeste, écrit EN CLAIR à côté de l'objet.

    Il ne contient aucune donnée d'alerte — seulement de quoi savoir ce que
    l'objet contient, comment le relire, et à quoi comparer ce qu'on en sort.
    C'est `sha256_clair` qui fait la différence entre une sauvegarde et une
    preuve.
    """
    return {
        "format_version": config.ARCHIVE_FORMAT_VERSION,
        "index_set": batch["index_base"],
        "period": batch["period"],
        "indices": batch["indices"],
        "documents": metrics["documents"],
        "plain_bytes": metrics["plain_bytes"],
        "object_bytes": metrics["object_bytes"],
        "sha256_plain": metrics["sha256_plain"],
        "sha256_encrypted": metrics["sha256_encrypted"],
        "key": key,
        "chain": processing_chain(),
        "destinataires_age": recipients(),
        "excluded_fields": config.ARCHIVE_FIELDS_EXCLUDED,
        "schema_ligne": "{_index, _id, _source}",
        "genere_le": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "outil": "soc_agent.archive",
        "relecture": ("age -d -i <cle-age> <objet> | zstd -d | "
                      "jq -c 'select(._source.rule.level >= 10)'"),
    }


def _args_lock() -> dict:
    if not config.ARCHIVE_OBJECT_LOCK:
        return {}
    jusqu_a = datetime.now(timezone.utc) + timedelta(
        days=config.ARCHIVE_OBJECT_LOCK_DAYS)
    return {"ObjectLockMode": config.ARCHIVE_OBJECT_LOCK_MODE,
            "ObjectLockRetainUntilDate": jusqu_a}


def upload(s3, path: Path, key: str, meta: dict) -> None:
    extra = {"Metadata": {k: str(v) for k, v in meta.items()},
             "ContentType": "application/octet-stream", **_args_lock()}
    try:
        s3.upload_file(str(path), config.ARCHIVE_S3_BUCKET, key,
                       ExtraArgs=extra)
    except Exception as e:                                        # noqa: BLE001
        if config.ARCHIVE_OBJECT_LOCK and "ObjectLock" in str(e):
            raise RuntimeError(
                "Object Lock refusé par le bucket. La propriété ne se "
                "rétro-applique PAS à un bucket existant : il faut un bucket "
                "créé avec Object Lock, ou ARCHIVE_OBJECT_LOCK=false.") from e
        raise


def _reread(s3, key: str, expected_bytes: int) -> None:
    """HEAD après upload. Rien n'est déclaré archivé sans cette relecture.

    Un `upload_file` qui rend la main sans exception n'est pas une preuve que
    l'objet est là et complet — c'est la promesse d'une bibliothèque cliente.
    """
    head = s3.head_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=key)
    if head["ContentLength"] != expected_bytes:
        raise RuntimeError(
            f"objet {key} relu à {head['ContentLength']} octets, "
            f"{expected_bytes} attendus : upload incomplet.")


# --------------------------------------------------------------------------
# Archivage d'un lot
# --------------------------------------------------------------------------

def _record(conn, batch: dict, metrics: dict, key: str,
                 man_key: str) -> None:
    lock = _args_lock()
    conn.execute(
        """INSERT INTO archives_s3
               (format_version, index_base, period, key, manifest_key,
                indices, documents, plain_bytes, object_bytes, sha256_plain,
                sha256_encrypted, chain, recipients, excluded_fields,
                object_lock_until)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (format_version, index_base, period) DO NOTHING""",
        (config.ARCHIVE_FORMAT_VERSION, batch["index_base"], batch["period"],
         key, man_key, batch["indices"], metrics["documents"],
         metrics["plain_bytes"], metrics["object_bytes"],
         metrics["sha256_plain"], metrics["sha256_encrypted"],
         processing_chain(), recipients(),
         config.ARCHIVE_FIELDS_EXCLUDED, lock.get("ObjectLockRetainUntilDate")))
    conn.commit()


def _adopt(conn, s3, batch: dict, key: str, man_key: str) -> bool:
    """Objet déjà présent sans ligne en base : l'adopter au lieu de refaire.

    Ce cas arrive si le processus meurt entre l'upload et l'INSERT. La clé étant
    déterministe, on retrouve l'objet ; son manifeste (en clair, minuscule) dit
    combien de documents il contient. Si ce compte correspond au décompte vivant
    des index, l'objet est le bon et on écrit simplement la ligne manquante.

    Pourquoi ne pas simplement réécrire : sous Object Lock, un second upload ne
    remplace pas l'objet, il crée une VERSION supplémentaire elle aussi
    verrouillée — on paierait deux fois douze mois pour la même donnée.
    """
    try:
        s3.head_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=key)
    except Exception:                                             # noqa: BLE001
        return False
    try:
        body = s3.get_object(Bucket=config.ARCHIVE_S3_BUCKET,
                              Key=man_key)["Body"].read()
        man = json.loads(body)
    except Exception as e:                                        # noqa: BLE001
        log.warning("objet orphelin %s sans manifeste lisible (%s) : "
                    "réarchivage", key, e)
        return False
    if man.get("documents") != batch["documents"]:
        log.warning("objet orphelin %s : %s documents au manifeste, %s vivants "
                    "— réarchivage", key, man.get("documents"),
                    batch["documents"])
        return False
    _record(conn, batch, {
        "documents": man["documents"], "plain_bytes": man["plain_bytes"],
        "object_bytes": man["object_bytes"],
        "sha256_plain": man["sha256_plain"],
        "sha256_encrypted": man["sha256_encrypted"]}, key, man_key)
    log.warning("archive %s/%s ADOPTÉE : l'objet existait sans repère en base "
                "(interruption entre l'upload et l'enregistrement).",
                batch["index_base"], batch["period"])
    return True


def archive(conn, s3, batch: dict) -> dict:
    key = object_key(batch["index_base"], batch["period"], SUFFIX_OBJECT)
    man_key = object_key(batch["index_base"], batch["period"], SUFFIX_MANIFEST)

    if _adopt(conn, s3, batch, key, man_key):
        return {"index_base": batch["index_base"], "period": batch["period"],
                "etat": "adoptée", "key": key}

    tmp = Path(tempfile.mkdtemp(prefix="aura-archive-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        object_path = tmp / f"{batch['index_base']}.{batch['period']}.{SUFFIX_OBJECT}"
        metrics = export(batch, object_path)
        man = manifest(batch, metrics, key)

        upload(s3, object_path, key, {
            "index-set": batch["index_base"], "period": batch["period"],
            "documents": metrics["documents"],
            "sha256-clair": metrics["sha256_plain"],
            "sha256-chiffre": metrics["sha256_encrypted"],
            "format-version": config.ARCHIVE_FORMAT_VERSION})
        _reread(s3, key, metrics["object_bytes"])

        man_path = tmp / f"{batch['index_base']}.{batch['period']}.{SUFFIX_MANIFEST}"
        man_path.write_text(json.dumps(man, indent=2, ensure_ascii=False),
                              encoding="utf-8")
        upload(s3, man_path, man_key, {"index-set": batch["index_base"]})

        # Le repère n'est écrit qu'ici : après que l'objet ET son manifeste ont
        # été relus côté S3.
        _record(conn, batch, metrics, key, man_key)
        ratio = (metrics["plain_bytes"] / metrics["object_bytes"]
                 if metrics["object_bytes"] else 0)
        log.info("archivé %s/%s : %d documents, %.1f Mo -> %.1f Mo (x%.1f), %s",
                 batch["index_base"], batch["period"], metrics["documents"],
                 metrics["plain_bytes"] / 1048576,
                 metrics["object_bytes"] / 1048576, ratio, key)
        return {"index_base": batch["index_base"], "period": batch["period"],
                "etat": "archivée", "key": key, **metrics}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Ménage des résidus d'un passage tué
# --------------------------------------------------------------------------
#
# Tout le nettoyage du module vit dans des `finally`, et un `finally` ne
# s'exécute PAS sur SIGKILL (OOM killer, `docker kill`, coupure de courant).
# Chaque mort violente laisse donc deux traces, aucune des deux visible :
#
#  - un répertoire de travail dans ARCHIVE_TMP_DIR. Sur ce SOC, l'accumulation
#    silencieuse sur disque est précisément ce qui a rempli 92 Go sans que
#    personne le voie (cf. docs/RETENTION.md) ;
#  - un téléversement multipart inachevé côté S3 : ses parties sont FACTURÉES et
#    n'apparaissent dans aucun `list_objects`.
#
# Les deux sont balayés au début de chaque passage, avec un seuil d'âge : le
# verrou consultatif interdit deux passages d'archivage simultanés, mais pas un
# `--drill` lancé à la main pendant qu'un passage tourne.

PREFIXES_TMP = ("aura-archive-", "aura-drill-", "aura-clecheck-")


def sweep_temporary(age_hours: int = 2) -> dict:
    """Supprime les répertoires de travail abandonnés par un passage tué."""
    base = Path(config.ARCHIVE_TMP_DIR)
    limit = time.time() - age_hours * 3600
    n = byte_count = 0
    for path in base.glob("*"):
        if not path.is_dir() or not path.name.startswith(PREFIXES_TMP):
            continue
        try:
            if path.stat().st_mtime >= limit:
                continue          # peut appartenir à un drill en cours
            byte_count += sum(f.stat().st_size for f in path.rglob("*")
                          if f.is_file())
            shutil.rmtree(path, ignore_errors=True)
            n += 1
        except OSError as e:
            log.debug("résidu %s non supprimé : %s", path, e)
    if n:
        log.warning("%d répertoire(s) de travail d'archivage abandonné(s) "
                    "supprimé(s) (%.1f Mo) — signe qu'un passage a été tué sans "
                    "pouvoir se nettoyer", n, byte_count / 1048576)
    return {"repertoires": n, "octets": byte_count}


def abort_multiparts(s3, age_hours: int = 24) -> dict:
    """Avorte les téléversements multipart inachevés du bucket.

    Best-effort : si la clé applicative n'a pas le droit de les lister ou de les
    avorter, on le dit et on continue. Ne pas archiver du tout serait une bien
    plus mauvaise réponse à un défaut de facturation.
    """
    limit = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    aborted, ignored = [], 0
    try:
        response = s3.list_multipart_uploads(Bucket=config.ARCHIVE_S3_BUCKET)
    except Exception as e:                                        # noqa: BLE001
        log.info("multiparts inachevés non listables (%s) : contrôle sauté. "
                 "Poser une règle de cycle de vie côté B2 est de toute façon "
                 "la bonne réponse.", e)
        return {"etat": f"indéterminé : {e}"[:200]}
    for u in response.get("Uploads") or []:
        if u.get("Initiated") and u["Initiated"] > limit:
            ignored += 1          # peut être en cours
            continue
        try:
            s3.abort_multipart_upload(Bucket=config.ARCHIVE_S3_BUCKET,
                                      Key=u["Key"], UploadId=u["UploadId"])
            aborted.append(u["Key"])
        except Exception as e:                                    # noqa: BLE001
            log.warning("multipart %s non avorté : %s", u["Key"], e)
    if aborted:
        log.warning("%d téléversement(s) multipart inachevé(s) avorté(s) : %s — "
                    "leurs parties étaient facturées et invisibles d'un "
                    "list_objects", len(aborted), ", ".join(aborted[:5]))
    return {"avortes": aborted, "en_cours_ignores": ignored}


# --------------------------------------------------------------------------
# Protection contre la purge
# --------------------------------------------------------------------------

def indices_at_risk(conn, today: date | None = None) -> list[dict]:
    """Index que la purge ISM va supprimer sans qu'une archive existe.

    C'est la question qui compte : pas « l'archivage a-t-il réussi ? » mais
    « reste-t-il de la donnée sur le point de disparaître sans copie ? ». Un
    archivage en panne depuis trois jours n'est pas grave ; le même en panne
    depuis quatre-vingts jours détruit de la donnée à la prochaine rotation.
    """
    if not config.ARCHIVING_ENABLED:
        return []
    ref = today or datetime.now(timezone.utc).date()
    threshold = config.RETENTION_INDEX_DAYS - config.ARCHIVE_MARGIN_DAYS
    already = {(r["index_base"], r["period"]) for r in conn.execute(
        "SELECT index_base, period FROM archives_s3 WHERE format_version=%s",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()}
    risk = []
    for i in dated_indices():
        age = (ref - i["day"]).days
        if age < threshold or (i["base"], i["mois"]) in already:
            continue
        risk.append({**i, "age_jours": age,
                      "supprime_dans": config.RETENTION_INDEX_DAYS - age})
    return sorted(risk, key=lambda i: i["supprime_dans"])


def protect(indices: list[str]) -> int:
    """Retire ces index de la politique ISM pour empêcher leur suppression.

    Suspendre la POSE de la politique ne protégerait rien : elle est déjà
    attachée aux index existants et continuerait de les supprimer à l'heure.
    Le seul geste efficace est `_ism/remove`, qui détache la politique des index
    nommés.

    Ce détachement est TEMPORAIRE et se répare seul : au passage suivant,
    `retention.appliquer_ism()` réattache la politique par motif, donc un index
    archivé entre-temps redevient purgeable sans geste manuel. C'est aussi
    pourquoi la protection doit être posée APRÈS `appliquer_ism`, jamais avant —
    sinon le `_ism/add` par motif la défait dans la seconde.
    """
    if not indices:
        return 0
    r = _indexer("POST", "/_plugins/_ism/remove/" + ",".join(indices))
    if not r.ok:
        raise RuntimeError(f"_ism/remove refusé ({r.status_code}) : {r.text}")
    n = r.json().get("updated_indices", 0)
    log.error("PURGE SUSPENDUE sur %d index (%d détaché(s) de la politique "
              "« aura-retention ») : leur archive S3 n'existe pas et ils "
              "entraient dans la marge de suppression. Ils NE seront PAS "
              "supprimés tant que la copie n'existe pas — le disque va donc "
              "grossir jusqu'à ce que l'archivage reparte.", len(indices), n)
    return n


# --------------------------------------------------------------------------
# Drill de restauration
# --------------------------------------------------------------------------

def _drill_une(s3, line: dict, full: bool = True) -> dict:
    """Retélécharge une archive, la déchiffre et compare ce qu'elle contient.

    Trois vérifications qui ne disent pas la même chose, dans cet ordre :

    1. l'objet est **présent** — sinon quelqu'un ou quelque chose l'a supprimé ;
    2. son SHA-256 correspond — le stockage ne l'a ni altéré ni tronqué ;
    3. il se **déchiffre** et rend le compte de documents du manifeste. C'est la
       seule des trois qui prouve qu'une archive sert à quelque chose, et elle
       n'est possible que parce que le SOC détient sa clé.

    `complet=False` s'arrête après (2) : utile quand la clé est momentanément
    indisponible, pour ne pas déclarer en échec ce qu'on n'a pas su lire.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aura-drill-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        local = tmp / "objet"
        try:
            s3.download_file(config.ARCHIVE_S3_BUCKET, line["key"], str(local))
        except Exception as e:                                    # noqa: BLE001
            return {"etat": "absent", "detail": str(e)}
        if _sha256_file(local) != line["sha256_encrypted"]:
            return {"etat": "sha256-divergent",
                    "detail": "l'objet stocké diffère de ce qui a été écrit"}
        if not full:
            return {"etat": "ok", "complet": False}

        decrypted = subprocess.run(
            f"age -d -i {config.ARCHIVE_AGE_KEYFILE!r} {str(local)!r} "
            "| zstd -d -c", shell=True, capture_output=True)
        if decrypted.returncode:
            return {"etat": "erreur: déchiffrement",
                    "detail": decrypted.stderr.decode(errors="replace")[:500]}
        plain = decrypted.stdout
        if hashlib.sha256(plain).hexdigest() != line["sha256_plain"]:
            return {"etat": "sha256-divergent",
                    "detail": "le clair déchiffré diffère de l'archivé"}
        lines = plain.count(b"\n")
        if lines != line["documents"]:
            return {"etat": "documents-divergents",
                    "detail": f"{lines} lignes, {line['documents']} attendus"}
        return {"etat": "ok", "complet": True}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def drill(conn, s3, batch: drill_full | None = None,
          full: bool | None = None) -> list[dict]:
    """Vérifie les archives vérifiées le moins récemment.

    Sélection par `verifie_a NULLS FIRST` : déterministe, et chaque archive
    finit par passer. Un tirage au sort laisserait durablement des trous.
    """
    n = config.ARCHIVE_DRILL_BATCH if batch is None else batch
    drill_full = config.ARCHIVE_DRILL_FULL if full is None else full
    lines = conn.execute(
        "SELECT * FROM archives_s3 WHERE format_version=%s "
        " ORDER BY verified_at NULLS FIRST, archived_at LIMIT %s",
        (config.ARCHIVE_FORMAT_VERSION, n)).fetchall()
    summary = []
    for line in lines:
        try:
            r = _drill_une(s3, line, drill_full)
        except Exception as e:                                    # noqa: BLE001
            r = {"etat": f"erreur: {e}"[:200]}
        conn.execute(
            "UPDATE archives_s3 SET verified_at=now(), verify_state=%s, "
            " verify_full=%s WHERE id=%s",
            (r["etat"], bool(r.get("complet")), line["id"]))
        conn.commit()
        if r["etat"] == "ok":
            log.info("drill %s/%s : OK%s", line["index_base"],
                     line["period"], " (complet)" if r.get("complet") else "")
        else:
            log.error("DRILL EN ÉCHEC %s/%s : %s — %s. L'archive de ce mois "
                      "n'est pas fiable ; la donnée d'origine est probablement "
                      "déjà purgée de l'indexer.", line["index_base"],
                      line["period"], r["etat"], r.get("detail", ""))
        summary.append({"index_base": line["index_base"],
                      "period": line["period"], **r})
    return summary


# --------------------------------------------------------------------------
# Anomalies remontées au watchdog
# --------------------------------------------------------------------------

def _months_between(start: str, end: str) -> list[str]:
    a, m = (int(x) for x in start.split("-"))
    af, mf = (int(x) for x in end.split("-"))
    output = []
    while (a, m) <= (af, mf):
        output.append(f"{a:04d}-{m:02d}")
        a, m = (a + 1, 1) if m == 12 else (a, m + 1)
    return output


def anomalies(conn) -> list[dict]:
    """État de l'archivage, en lecture seule, au format des capteurs muets.

    Quatre signaux, chacun correspondant à une façon dont un archivage « qui
    tourne » peut ne rien archiver :

    - de la donnée entre dans la marge de suppression sans copie (High) ;
    - un mois manque au milieu d'une série (Medium) : les index sont déjà
      purgés, la donnée est perdue et rien ne le disait ;
    - une archive n'a pas été relue depuis trop longtemps (Medium) ;
    - un drill a échoué (High).
    """
    if not config.ARCHIVING_ENABLED:
        return []
    output = []

    try:
        risk = indices_at_risk(conn)
    except Exception as e:                                        # noqa: BLE001
        log.warning("péril d'archivage incalculable : %s", e)
        risk = []
    if risk:
        detail = "\n".join(
            f"  {i['index']:<40} {i['documents']:>9} docs  "
            f"supprimé dans {i['supprime_dans']} j"
            for i in risk[:15])
        output.append(_anomaly(
            "peril",
            f"[ARCHIVAGE] {len(risk)} index vont être purgés sans copie",
            "\n".join([
                "DONNÉE SUR LE POINT D'ÊTRE PERDUE",
                "",
                f"{len(risk)} index datés entrent dans les "
                f"{config.ARCHIVE_MARGIN_DAYS} jours qui précèdent leur "
                f"suppression par la politique ISM "
                f"(RETENTION_INDEX_JOURS={config.RETENTION_INDEX_DAYS}) et "
                "aucune archive S3 ne les couvre.",
                "", detail,
                "" if len(risk) <= 15 else f"  … et {len(risk) - 15} autres.",
                "",
                "Ce qui a été fait automatiquement : ces index ont été DÉTACHÉS "
                "de la politique « aura-retention ». Ils ne seront pas "
                "supprimés — mais ils ne seront pas non plus purgés, donc le "
                "disque va grossir jusqu'à ce que l'archivage reparte.",
                "",
                "Où regarder :",
                "",
                "1. `docker logs soc-agent-archive --tail 100` — l'échec y est.",
                "2. `python -m soc_agent.archive --verifier` — bucket, clé, "
                "droits, Object Lock.",
                "3. Cause la plus fréquente : clé applicative B2 expirée ou "
                "révoquée, ou bucket plein côté quota.",
                "",
                "Une fois l'archivage reparti, le rattachement à la politique "
                "ISM se refait tout seul au passage suivant de la rétention.",
            ]),
            "High", len(risk)))

    lines = conn.execute(
        "SELECT index_base, period, verified_at, verify_state FROM archives_s3 "
        " WHERE format_version=%s ORDER BY index_base, period",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()

    # Trous dans une série : un mois absent ENTRE deux mois présents. Borné aux
    # séries déjà commencées — un index set créé le mois dernier n'a pas de
    # trou, il a juste un passé qui n'existe pas.
    by_base: dict[str, list[str]] = {}
    for l in lines:
        by_base.setdefault(l["index_base"], []).append(l["period"])
    gaps = {b: [m for m in _months_between(min(p), max(p)) if m not in set(p)]
             for b, p in by_base.items()}
    gaps = {b: m for b, m in gaps.items() if m}
    if gaps:
        output.append(_anomaly(
            "trou",
            f"[ARCHIVAGE] {sum(len(m) for m in gaps.values())} mois manquant(s) "
            "dans les séries d'archives",
            "\n".join([
                "TROU DANS LA COUVERTURE D'ARCHIVAGE",
                "",
                "Un mois manque entre deux mois archivés. Les index d'origine "
                "sont donc purgés depuis longtemps : cette donnée n'existe plus "
                "nulle part, et rien ne l'avait signalé au moment où elle "
                "partait.",
                "",
                *(f"  {b} : {', '.join(m)}" for b, m in sorted(gaps.items())),
                "",
                "Il n'y a rien à réparer ici — c'est un constat, à consigner. "
                "L'action utile est de comprendre POURQUOI l'archivage était "
                "muet sur cette période et de vérifier que le garde-fou de "
                "péril fonctionne aujourd'hui.",
            ]),
            "Medium", sum(len(m) for m in gaps.values())))

    failures = [l for l in lines if l["verify_state"] and l["verify_state"] != "ok"]
    if failures:
        output.append(_anomaly(
            "drill",
            f"[ARCHIVAGE] {len(failures)} archive(s) en échec de vérification",
            "\n".join([
                "ARCHIVE NON FIABLE",
                "",
                "Le drill de restauration a relu ces archives et n'a pas "
                "retrouvé ce qui avait été écrit :",
                "",
                *(f"  {l['index_base']}/{l['period']} : {l['verify_state']}"
                  for l in failures[:20]),
                "",
                "Une archive qui ne se relit pas n'est pas une archive. La "
                "donnée d'origine est très probablement déjà purgée de "
                "l'indexer : il n'y a pas de seconde chance de la réécrire.",
                "",
                "`absent` : l'objet a disparu du bucket — vérifier que la clé "
                "applicative ne porte pas `deleteFiles` et regarder les "
                "versions masquées du bucket.",
                "`sha256-divergent` : l'objet stocké diffère de ce qui a été "
                "écrit. Corruption ou réécriture par un tiers.",
            ]),
            "High", len(failures)))

    limit = datetime.now(timezone.utc) - timedelta(
        days=config.ARCHIVE_DRILL_DAYS)
    old = [l for l in lines
                if l["verified_at"] is None or l["verified_at"] < limit]
    # Une archive du mois en cours n'a pas encore eu son tour : on ne compte
    # comme « en retard » que ce qui a dépassé la fenêtre de drill.
    if len(old) > config.ARCHIVE_DRILL_BATCH:
        output.append(_anomaly(
            "drill-en-retard",
            f"[ARCHIVAGE] {len(old)} archive(s) non vérifiées depuis plus "
            f"de {config.ARCHIVE_DRILL_DAYS} jours",
            "\n".join([
                "VÉRIFICATION D'ARCHIVES EN RETARD",
                "",
                f"{len(old)} archives n'ont pas été relues depuis "
                f"{config.ARCHIVE_DRILL_DAYS} jours (ou jamais). Une archive "
                "non testée est une croyance, pas une copie.",
                "",
                f"Le service `soc-agent-archive` en vérifie "
                f"{config.ARCHIVE_DRILL_BATCH} par passage. Ce retard signifie "
                "soit que le service ne tourne pas, soit que le lot est trop "
                "petit pour le nombre d'archives (augmenter "
                "ARCHIVE_DRILL_LOT).",
            ]),
            "Medium", len(old)))
    return output


def _anomaly(suffix: str, title: str, note: str, severity: str,
              volume: int) -> dict:
    """Format d'un capteur muet, pour traverser la boucle du watchdog sans cas
    particulier — même convention que `routage._anomalie`."""
    maintenant = datetime.now(timezone.utc)
    return {"agent_id": "000", "agent_name": "wazuh.manager",
            "sensor": f"{PREFIX_SENSOR}{suffix}", "titre": title,
            "note": note, "severity": severity, "volume": volume, "seuil": 0,
            "dernier": maintenant, "horizon": maintenant}


# --------------------------------------------------------------------------
# Préflight
# --------------------------------------------------------------------------

def check_key() -> dict:
    """Aller-retour RÉEL de chiffrement sur un témoin, avant de compter sur la clé.

    Chiffrer puis redéchiffrer trois octets coûte quelques millisecondes et
    répond à la seule question qui compte avant d'archiver un mois entier : cette
    clé permet-elle de RELIRE ? Une clé publique collée par erreur dans le
    fichier, une identité tronquée à la copie, un `age` absent — tout ça passe
    les contrôles de `config` et se voit ici.
    """
    _check_tools()
    summary = {"keyfile": config.ARCHIVE_AGE_KEYFILE,
             "recipients": recipients()}
    tmp = Path(tempfile.mkdtemp(prefix="aura-clecheck-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        witness, chiffre = b"aura\n", tmp / "t.age"
        recipients: list[str] = []
        for r in summary["recipients"]:
            recipients += ["-r", r]
        c = subprocess.run(["age", *recipients, "-o", str(chiffre)],
                           input=witness, capture_output=True)
        if c.returncode:
            raise RuntimeError("chiffrement du témoin en échec : "
                               + c.stderr.decode(errors="replace")[:300])
        d = subprocess.run(
            ["age", "-d", "-i", config.ARCHIVE_AGE_KEYFILE, str(chiffre)],
            capture_output=True)
        if d.returncode or d.stdout != witness:
            raise RuntimeError(
                "la clé ne redéchiffre PAS ce qu'elle a chiffré : "
                + d.stderr.decode(errors="replace")[:300]
                + " — archiver dans cet état produirait des objets illisibles.")
        summary["aller_retour"] = "ok"
        summary["secours"] = (config.ARCHIVE_AGE_RECIPIENTS_EXTRA
                            or "AUCUNE — perdre le keyfile perdrait tout")
        return summary
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_bucket() -> dict:
    """Préflight à lancer AVANT de compter sur l'archivage.

    Vérifie aussi ce qui devrait être ABSENT : le droit de suppression. Une clé
    de prod qui peut supprimer, c'est un rançongiciel qui peut effacer les douze
    mois après avoir chiffré le reste.
    """
    s3 = _s3()
    summary: dict = {"bucket": config.ARCHIVE_S3_BUCKET,
                   "endpoint": config.ARCHIVE_S3_ENDPOINT}
    s3.head_bucket(Bucket=config.ARCHIVE_S3_BUCKET)
    summary["joignable"] = True

    for name, call in (
            ("versioning", lambda: s3.get_bucket_versioning(
                Bucket=config.ARCHIVE_S3_BUCKET).get("Status", "Disabled")),
            ("object_lock", lambda: s3.get_object_lock_configuration(
                Bucket=config.ARCHIVE_S3_BUCKET)
                .get("ObjectLockConfiguration", {})
                .get("ObjectLockEnabled", "Disabled")),
            ("cycle_de_vie", lambda: [
                r.get("ID") or r.get("Prefix", "")
                for r in s3.get_bucket_lifecycle_configuration(
                    Bucket=config.ARCHIVE_S3_BUCKET).get("Rules", [])])):
        try:
            summary[name] = call()
        except Exception as e:                                    # noqa: BLE001
            summary[name] = f"indéterminé ({type(e).__name__})"

    witness = "/".join(p for p in (config.ARCHIVE_S3_PREFIX,
                                 config.ARCHIVE_FORMAT_VERSION,
                                 "_preflight.txt") if p)
    s3.put_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=witness,
                  Body=b"aura preflight\n")
    summary["ecriture"] = "ok"
    try:
        s3.delete_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=witness)
        summary["suppression"] = ("POSSIBLE — la clé porte deleteFiles, ce qui "
                                "n'est pas souhaitable pour une clé de prod")
    except Exception:                                             # noqa: BLE001
        summary["suppression"] = "refusée (attendu)"

    if config.ARCHIVE_OBJECT_LOCK and summary.get("object_lock") != "Enabled":
        summary["alerte"] = ("ARCHIVE_OBJECT_LOCK=true mais le bucket n'a pas "
                           "Object Lock. La propriété ne se rétro-applique pas "
                           "à un bucket existant : recréer le bucket avec "
                           "Object Lock, ou repasser le réglage à false.")
    if config.ARCHIVE_OBJECT_LOCK_DAYS < config.ARCHIVE_RETENTION_MONTH * 30:
        summary.setdefault("alerte", "")
        summary["alerte"] += (" Object Lock plus court que la rétention visée : "
                            "un objet redeviendra supprimable avant la fin des "
                            f"{config.ARCHIVE_RETENTION_MONTH} mois.")
    return summary


# --------------------------------------------------------------------------
# Restauration
# --------------------------------------------------------------------------

def restore(s3, index_base: str, period: str, destination: Path,
              identity: str | None = None) -> dict:
    """Télécharge et déchiffre une archive sur disque, avec la clé du SOC.

    Volontairement séparé de toute réinjection dans l'indexer : décider où
    remettre de la donnée vieille de dix mois est un geste d'analyste, pas
    d'automate. Ré-ingérer dans `wazuh-firewall-*` ferait rentrer ces alertes
    dans le pipeline de triage et fabriquerait des incidents sur des faits vieux
    d'un an. Le NDJSON obtenu s'injecte avec `_bulk` (cf. docs/ARCHIVAGE.md).

    `identite` permet de passer une clé de SECOURS, pour le cas qui justifie
    qu'elle existe : la clé du SOC est perdue ou l'hôte a été refait.
    """
    age_key = identity or config.ARCHIVE_AGE_KEYFILE
    key = object_key(index_base, period, SUFFIX_OBJECT)
    chiffre = destination.with_suffix(destination.suffix + ".age")
    s3.download_file(config.ARCHIVE_S3_BUCKET, key, str(chiffre))
    r = subprocess.run(
        f"age -d -i {age_key!r} {str(chiffre)!r} | zstd -d -o "
        f"{str(destination)!r} -f",
        shell=True, capture_output=True)
    chiffre.unlink(missing_ok=True)
    if r.returncode:
        raise RuntimeError("restauration en échec : "
                           + r.stderr.decode(errors="replace")[:800])
    # Confronter au manifeste appartient à l'appelant, mais compter les lignes
    # ici évite le contresens le plus courant : croire qu'un fichier obtenu sans
    # erreur est un fichier complet.
    return {"key": key, "fichier": str(destination),
            "lignes": sum(1 for _ in destination.open("rb")),
            "octets": destination.stat().st_size}


# --------------------------------------------------------------------------

def run(dry_run: bool = False) -> dict:
    """Un passage : archiver ce qui est clos, puis vérifier quelques archives.

    Le drill tourne même si l'archivage n'a rien eu à faire — c'est le cas
    normal la plupart des jours, et c'est justement là qu'on veut savoir si les
    archives des mois passés tiennent encore.
    """
    if not config.ARCHIVING_ENABLED:
        return {"etat": "désactivé"}
    summary: dict = {"dry_run": dry_run, "archivees": [], "echecs": []}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_LOCK_ARCHIVE,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("archivage : passage déjà en cours, on saute ce tour")
            return {"etat": "verrouillé"}
        try:
            # Ménage AVANT tout : ce qu'un passage tué a laissé derrière lui ne
            # doit pas s'accumuler d'un jour sur l'autre. Pas en `--plan`, qui
            # doit pouvoir être lancé sans rien modifier nulle part.
            if not dry_run:
                summary["menage_local"] = sweep_temporary()
            batches = batches_to_archive(conn)
            summary["a_faire"] = [f"{l['index_base']}/{l['period']}" for l in batches]
            if dry_run:
                summary["lots"] = batches
                summary["peril"] = [i["index"] for i in indices_at_risk(conn)]
                return summary

            s3 = _s3()
            summary["menage_s3"] = abort_multiparts(s3)
            for batch in batches:
                try:
                    summary["archivees"].append(archive(conn, s3, batch))
                except Exception as e:                            # noqa: BLE001
                    # Un lot qui échoue ne doit pas emporter les autres : le
                    # mois suivant appartient peut-être à un autre index set,
                    # et refuser de l'archiver ne répare rien.
                    log.error("archivage %s/%s en échec : %s",
                              batch["index_base"], batch["period"], e)
                    summary["echecs"].append(
                        {"index_base": batch["index_base"],
                         "period": batch["period"], "error": str(e)[:300]})

            summary["drill"] = drill(conn, s3)
            risk = indices_at_risk(conn)
            summary["peril"] = [i["index"] for i in risk]
            if risk:
                try:
                    summary["proteges"] = protect([i["index"] for i in risk])
                except Exception as e:                            # noqa: BLE001
                    log.error("PROTECTION IMPOSSIBLE (%s) : %d index restent "
                              "candidats à la suppression SANS copie.", e,
                              len(risk))
        finally:
            _unlock(conn)
    return summary


def _unlock(conn) -> None:
    """Rend le verrou consultatif SANS masquer l'erreur qui nous amène ici.

    Constaté en prod au premier passage : la table `archives_s3` n'existait pas
    encore, `lots_a_archiver` a levé `UndefinedTable`, et le `finally` a voulu
    exécuter l'`UNLOCK` dans une transaction déjà avortée. Postgres a répondu
    `InFailedSqlTransaction`, cette seconde exception a REMPLACÉ la première, et
    la trace ne disait plus du tout ce qui n'allait pas — le diagnostic utile
    (« il manque une table ») était devenu invisible.

    D'où le rollback d'abord, et le tout en best-effort : un verrou consultatif
    de session est de toute façon rendu à la fermeture de la connexion, donc
    échouer ici n'a aucune conséquence, alors que masquer la cause en a une.
    """
    for step in (conn.rollback,
                  lambda: conn.execute("SELECT pg_advisory_unlock(%s)",
                                       (_LOCK_ARCHIVE,))):
        try:
            step()
        except Exception as e:                                    # noqa: BLE001
            log.debug("libération du verrou d'archivage : %s", e)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", action="store_true",
                   help="ce qui serait archivé, sans rien écrire")
    p.add_argument("--verifier", action="store_true",
                   help="préflight : aller-retour de la clé, puis bucket "
                        "(joignable, droits, Object Lock)")
    p.add_argument("--drill", action="store_true",
                   help="relire, déchiffrer et recompter des archives, puis sortir")
    p.add_argument("--sans-dechiffrer", action="store_true",
                   help="drill limité au SHA-256 de l'objet")
    p.add_argument("--identite", help="clé age de SECOURS, si celle du SOC est "
                                     "perdue (drill et restauration)")
    p.add_argument("--lot", type=int, help="nombre d'archives à vérifier")
    p.add_argument("--restaurer", metavar="INDEX_SET/AAAA-MM",
                   help="télécharger et déchiffrer une archive")
    p.add_argument("--vers", default="archive.ndjson",
                   help="fichier de sortie de --restaurer")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if not config.ARCHIVING_ENABLED:
        print("ARCHIVAGE_ENABLED=false : rien à faire. Cf. docs/ARCHIVAGE.md.")
        return

    if args.check:
        # La clé d'abord : un bucket parfait ne sert à rien si ce qu'on y écrit
        # est illisible.
        print(json.dumps({"key": check_key(), "s3": check_bucket()},
                         indent=2, ensure_ascii=False, default=str))
        return

    if args.restore:
        base, _, period = args.restore.rpartition("/")
        print(json.dumps(restore(_s3(), base, period, Path(args.vers),
                                   args.identity),
                         indent=2, ensure_ascii=False))
        return

    if args.drill:
        if args.identity:
            monkey = config.ARCHIVE_AGE_KEYFILE
            config.ARCHIVE_AGE_KEYFILE = args.identity
            log.warning("drill avec la clé de secours %s (au lieu de %s)",
                        args.identity, monkey)
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            r = drill(conn, _s3(), args.batch, not args.without_decrypting)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    print(json.dumps(run(args.plan), indent=2, ensure_ascii=False,
                     default=str))


if __name__ == "__main__":
    main()
