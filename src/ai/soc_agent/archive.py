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
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)

# Même famille de verrou consultatif que les autres jobs périodiques (0x50CA*).
_VERROU_ARCHIVE = 0x50CA6

# Index DATÉ AU JOUR, seule forme archivée. Ce motif est le vrai filtre du
# module : il exclut sans aucune liste `wazuh-voc-vulns` (index d'état, il porte
# le MTTR) ainsi que `wazuh-monitoring-*` / `wazuh-statistics-*`, datés à la
# semaine par Wazuh (`2026.33w`) et qui ne sont pas des alertes.
_DATE_INDEX = re.compile(r"^(?P<base>.+)-(?P<a>\d{4})\.(?P<m>\d{2})\.(?P<j>\d{2})$")

SUFFIXE_OBJET = "ndjson.zst.age"
SUFFIXE_MANIFESTE = "manifest.json"

# Pseudo-capteurs posés dans `capteur_pannes` par le watchdog. Même table, même
# canal IRIS, même clôture automatique que le disque saturé : une archive
# manquante est une perte de visibilité future, exactement de la même nature.
PREFIXE_CAPTEUR = "archivage:"


# --------------------------------------------------------------------------
# Indexer
# --------------------------------------------------------------------------

def _indexer(methode: str, chemin: str, corps: dict | None = None,
             timeout: int = 120) -> requests.Response:
    return requests.request(
        methode, f"{config.INDEXER_URL}{chemin}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=corps,
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=timeout)


def _exclu(nom: str) -> bool:
    return any(fnmatch.fnmatch(nom, m) for m in config.ARCHIVE_INDEX_EXCLUS)


def indices_dates() -> list[dict]:
    """Index datés au jour, avec leur base, leur mois et leur taille.

    La liste des motifs candidats est délibérément large (`wazuh-*`) : le piège
    maison est la liste à tenir à jour qu'on oublie — trois fois pour
    `INDEXER_ALERT_INDICES` (cf. docs/ROUTAGE.md), et chaque oubli était un
    capteur invisible. Un index set créé demain par `routage.py` doit être
    archivé sans que personne y pense.
    """
    r = _indexer("GET", f"/_cat/indices/{config.ARCHIVE_INDEX_MOTIFS}"
                        "?format=json&h=index,docs.count,pri.store.size"
                        "&bytes=b&expand_wildcards=open")
    if r.status_code == 404:
        return []
    if not r.ok:
        raise RuntimeError(f"_cat/indices refusé ({r.status_code}) : {r.text}")
    sortie = []
    for ligne in r.json():
        nom = ligne["index"]
        m = _DATE_INDEX.match(nom)
        if not m or _exclu(nom):
            continue
        sortie.append({
            "index": nom,
            "base": m.group("base"),
            "jour": date(int(m.group("a")), int(m.group("m")), int(m.group("j"))),
            "mois": f"{m.group('a')}-{m.group('m')}",
            "documents": int(ligne.get("docs.count") or 0),
            "octets": int(ligne.get("pri.store.size") or 0),
        })
    return sortie


def _premier_du_mois_suivant(mois: str) -> date:
    a, m = (int(x) for x in mois.split("-"))
    return date(a + 1, 1, 1) if m == 12 else date(a, m + 1, 1)


def _mois_clos(mois: str, aujourdhui: date | None = None) -> bool:
    """Le mois est-il terminé ET assez décanté pour être figé ?

    Le délai de grâce n'est pas décoratif : le rattrapage des alertes indexées
    en retard écrit encore dans les index de la veille, et un index créé à
    cheval sur minuit peut recevoir après coup. Archiver trop tôt fige une copie
    incomplète — et une archive incomplète ne se répare pas, elle se croit
    complète.
    """
    ref = aujourdhui or datetime.now(timezone.utc).date()
    return ref >= _premier_du_mois_suivant(mois) + timedelta(
        days=config.ARCHIVE_DELAI_JOURS)


def lots_a_archiver(conn, aujourdhui: date | None = None) -> list[dict]:
    """Couples (index_base, mois) clos, non encore archivés.

    Un mois VIDE produit quand même une archive (quelques centaines d'octets).
    C'est voulu : l'invariant « chaque mois de chaque index set a exactement un
    objet » est ce qui rend un trou détectable. Un mois simplement absent serait
    indistinguable d'un mois perdu.
    """
    deja = {(r["index_base"], r["periode"]) for r in conn.execute(
        "SELECT index_base, periode FROM archives_s3 WHERE format_version=%s",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()}
    lots: dict[tuple[str, str], dict] = {}
    for i in indices_dates():
        cle = (i["base"], i["mois"])
        if cle in deja or not _mois_clos(i["mois"], aujourdhui):
            continue
        lot = lots.setdefault(cle, {"index_base": i["base"], "periode": i["mois"],
                                    "indices": [], "documents": 0, "octets": 0})
        lot["indices"].append(i["index"])
        lot["documents"] += i["documents"]
        lot["octets"] += i["octets"]
    for lot in lots.values():
        lot["indices"].sort()
    return sorted(lots.values(), key=lambda l: (l["periode"], l["index_base"]))


# --------------------------------------------------------------------------
# Export : PIT + search_after, avec repli sur le scroll
# --------------------------------------------------------------------------

def _corps_recherche(taille: int) -> dict:
    corps: dict = {"size": taille, "query": {"match_all": {}}}
    if config.ARCHIVE_CHAMPS_EXCLUS:
        corps["_source"] = {"excludes": config.ARCHIVE_CHAMPS_EXCLUS}
    return corps


def _pages_pit(indices: list[str], taille: int):
    """Pagination par point-in-time, triée sur `_shard_doc`.

    `_shard_doc` est le seul critère de tri à la fois total et stable : un tri
    sur `@timestamp` seul ne l'est pas (deux alertes à la même milliseconde
    peuvent être sautées ou dupliquées d'une page à l'autre), et `_id` n'est pas
    triable en OpenSearch. Sans PIT, `_shard_doc` n'existe pas — d'où le repli.
    """
    csv = ",".join(indices)
    r = _indexer("POST", f"/{csv}/_search/point_in_time?keep_alive=10m")
    if r.status_code in (400, 404, 405, 501):
        raise NotImplementedError(f"PIT indisponible ({r.status_code})")
    if not r.ok:
        raise RuntimeError(f"PIT refusé ({r.status_code}) : {r.text}")
    pit = r.json()["pit_id"]
    try:
        after = None
        while True:
            corps = _corps_recherche(taille)
            corps["pit"] = {"id": pit, "keep_alive": "10m"}
            corps["sort"] = [{"_shard_doc": "asc"}]
            corps["track_total_hits"] = False
            if after:
                corps["search_after"] = after
            r = _indexer("POST", "/_search", corps)
            if not r.ok:
                raise RuntimeError(f"recherche PIT refusée ({r.status_code}) : "
                                   f"{r.text}")
            hits = r.json()["hits"]["hits"]
            if not hits:
                return
            yield hits
            after = hits[-1]["sort"]
    finally:
        # Un PIT non libéré retient des segments sur disque, et le disque est la
        # panne qui arrête tout le SOC. Best-effort, mais jamais oublié.
        try:
            _indexer("DELETE", "/_search/point_in_time", {"pit_id": [pit]})
        except Exception as e:                                    # noqa: BLE001
            log.warning("PIT non libéré : %s", e)


def _pages_scroll(indices: list[str], taille: int):
    """Repli : API scroll. Dépréciée mais universellement disponible."""
    csv = ",".join(indices)
    r = _indexer("POST", f"/{csv}/_search?scroll=10m", _corps_recherche(taille))
    if not r.ok:
        raise RuntimeError(f"scroll refusé ({r.status_code}) : {r.text}")
    doc = r.json()
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
            sid = doc.get("_scroll_id") or sid
    finally:
        if sid:
            try:
                _indexer("DELETE", "/_search/scroll", {"scroll_id": [sid]})
            except Exception as e:                                # noqa: BLE001
                log.warning("scroll non libéré : %s", e)


def pages(indices: list[str], taille: int | None = None):
    taille = taille or config.ARCHIVE_TAILLE_LOT
    try:
        yield from _pages_pit(indices, taille)
    except NotImplementedError as e:
        log.info("%s : repli sur l'API scroll", e)
        yield from _pages_scroll(indices, taille)


# --------------------------------------------------------------------------
# Chaîne compression + chiffrement
# --------------------------------------------------------------------------

def cle_publique() -> str:
    """Clé publique correspondant à `ARCHIVE_AGE_KEYFILE`.

    `age-keygen` écrit la publique en commentaire de l'identité ; on la lit là
    plutôt que de lancer un sous-processus à chaque archive. Repli sur
    `age-keygen -y` si le commentaire a été retiré — ne pas se contenter d'un
    échec ici, ce serait bloquer l'archivage pour une ligne de commentaire.
    """
    for ligne in Path(config.ARCHIVE_AGE_KEYFILE).read_text(
            encoding="utf-8", errors="replace").splitlines():
        if ligne.lower().startswith("# public key:"):
            return ligne.split(":", 1)[1].strip()
    r = subprocess.run(["age-keygen", "-y", config.ARCHIVE_AGE_KEYFILE],
                       capture_output=True)
    if r.returncode:
        raise RuntimeError(
            f"clé publique indéterminable depuis {config.ARCHIVE_AGE_KEYFILE} : "
            + r.stderr.decode(errors="replace")[:300])
    return r.stdout.decode().strip()


def destinataires() -> list[str]:
    """Clé du SOC, plus les clés de secours éventuelles.

    La clé du SOC est DÉRIVÉE du fichier de clé, jamais recopiée dans le `.env`.
    C'est ce qui supprime toute une classe de pannes : un destinataire mal
    recopié produirait des archives que le SOC ne peut pas relire, et personne ne
    s'en apercevrait avant le premier drill.
    """
    return [cle_publique(), *config.ARCHIVE_AGE_RECIPIENTS_EXTRA]


def chaine_traitement() -> str:
    """Description exacte de la chaîne, telle qu'écrite dans le manifeste.

    Ce n'est pas cosmétique : c'est ce qui permet de relire une archive dans
    trois ans sans lire le code de cette version-là.
    """
    return (f"zstd -{config.ARCHIVE_ZSTD_NIVEAU} --long=27 | age -r "
            + " -r ".join(destinataires()))


def _verifier_outils() -> None:
    for outil in ("zstd", "age"):
        if not shutil.which(outil):
            raise RuntimeError(
                f"« {outil} » absent de l'image. L'archivage compresse et "
                "chiffre par des tubes, jamais en mémoire : les deux binaires "
                "sont requis (paquets Debian `zstd` et `age`).")


def _place_disponible(octets_index: int) -> None:
    """Refuser d'exporter faute de place, plutôt que de remplir le disque.

    L'archive chiffrée est toujours BEAUCOUP plus petite que le store de
    l'index ; exiger l'équivalent du store est donc large, et c'est le but. Un
    disque plein arrête l'ingestion sans qu'aucune alerte ne le dise (cf.
    docs/RETENTION.md) : ce job de ménage ne doit pas en être la cause.
    """
    besoin = max(octets_index, 256 * 1024 * 1024)
    libre = shutil.disk_usage(config.ARCHIVE_TMP_DIR).free
    if libre < besoin:
        raise RuntimeError(
            f"place insuffisante dans {config.ARCHIVE_TMP_DIR} : "
            f"{libre / 1073741824:.1f} Go libres, {besoin / 1073741824:.1f} Go "
            "exigés. Export refusé — remplir le disque du SOC arrêterait "
            "l'ingestion.")


def exporter(lot: dict, destination: Path) -> dict:
    """Écrit l'archive CHIFFRÉE dans `destination`. Renvoie les métriques.

    Le NDJSON en clair ne touche jamais le disque : il est écrit sur l'entrée de
    `zstd`, dont la sortie alimente `age`, dont la sortie seule est un fichier.
    Le SHA-256 du clair est calculé au vol, pendant qu'on l'a sous la main.
    """
    _verifier_outils()
    _place_disponible(lot["octets"])

    recipients: list[str] = []
    for r in destinataires():
        recipients += ["-r", r]

    sha_clair = hashlib.sha256()
    octets_clair = documents = 0

    with destination.open("wb") as sortie:
        zstd = subprocess.Popen(
            ["zstd", f"-{config.ARCHIVE_ZSTD_NIVEAU}", "--long=27", "-T0",
             "-q", "-c"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        age = subprocess.Popen(["age", *recipients], stdin=zstd.stdout,
                               stdout=sortie, stderr=subprocess.PIPE)
        # Indispensable : sans ça, `zstd` ne voit jamais le EOF de son lecteur
        # et la chaîne se bloque à la fermeture.
        zstd.stdout.close()
        try:
            for page in pages(lot["indices"]):
                for hit in page:
                    ligne = (json.dumps(
                        {"_index": hit["_index"], "_id": hit["_id"],
                         "_source": hit.get("_source") or {}},
                        ensure_ascii=False, separators=(",", ":"),
                        sort_keys=True) + "\n").encode()
                    sha_clair.update(ligne)
                    octets_clair += len(ligne)
                    documents += 1
                    zstd.stdin.write(ligne)
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

    return {"documents": documents, "octets_clair": octets_clair,
            "sha256_clair": sha_clair.hexdigest(),
            "octets_objet": destination.stat().st_size,
            "sha256_chiffre": _sha256_fichier(destination)}


def _sha256_fichier(chemin: Path) -> str:
    h = hashlib.sha256()
    with chemin.open("rb") as f:
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


def cle_objet(index_base: str, periode: str, suffixe: str) -> str:
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
                         index_base, periode[:4]) if p]
    return "/".join(parts) + f"/{index_base}.{periode}.{suffixe}"


def manifeste(lot: dict, metriques: dict, cle: str) -> dict:
    """Manifeste, écrit EN CLAIR à côté de l'objet.

    Il ne contient aucune donnée d'alerte — seulement de quoi savoir ce que
    l'objet contient, comment le relire, et à quoi comparer ce qu'on en sort.
    C'est `sha256_clair` qui fait la différence entre une sauvegarde et une
    preuve.
    """
    return {
        "format_version": config.ARCHIVE_FORMAT_VERSION,
        "index_set": lot["index_base"],
        "periode": lot["periode"],
        "indices": lot["indices"],
        "documents": metriques["documents"],
        "octets_clair": metriques["octets_clair"],
        "octets_objet": metriques["octets_objet"],
        "sha256_clair": metriques["sha256_clair"],
        "sha256_chiffre": metriques["sha256_chiffre"],
        "cle": cle,
        "chaine": chaine_traitement(),
        "destinataires_age": destinataires(),
        "champs_exclus": config.ARCHIVE_CHAMPS_EXCLUS,
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
        days=config.ARCHIVE_OBJECT_LOCK_JOURS)
    return {"ObjectLockMode": config.ARCHIVE_OBJECT_LOCK_MODE,
            "ObjectLockRetainUntilDate": jusqu_a}


def televerser(s3, chemin: Path, cle: str, meta: dict) -> None:
    extra = {"Metadata": {k: str(v) for k, v in meta.items()},
             "ContentType": "application/octet-stream", **_args_lock()}
    try:
        s3.upload_file(str(chemin), config.ARCHIVE_S3_BUCKET, cle,
                       ExtraArgs=extra)
    except Exception as e:                                        # noqa: BLE001
        if config.ARCHIVE_OBJECT_LOCK and "ObjectLock" in str(e):
            raise RuntimeError(
                "Object Lock refusé par le bucket. La propriété ne se "
                "rétro-applique PAS à un bucket existant : il faut un bucket "
                "créé avec Object Lock, ou ARCHIVE_OBJECT_LOCK=false.") from e
        raise


def _relire(s3, cle: str, octets_attendus: int) -> None:
    """HEAD après upload. Rien n'est déclaré archivé sans cette relecture.

    Un `upload_file` qui rend la main sans exception n'est pas une preuve que
    l'objet est là et complet — c'est la promesse d'une bibliothèque cliente.
    """
    tete = s3.head_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=cle)
    if tete["ContentLength"] != octets_attendus:
        raise RuntimeError(
            f"objet {cle} relu à {tete['ContentLength']} octets, "
            f"{octets_attendus} attendus : upload incomplet.")


# --------------------------------------------------------------------------
# Archivage d'un lot
# --------------------------------------------------------------------------

def _enregistrer(conn, lot: dict, metriques: dict, cle: str,
                 cle_man: str) -> None:
    lock = _args_lock()
    conn.execute(
        """INSERT INTO archives_s3
               (format_version, index_base, periode, cle, cle_manifeste,
                indices, documents, octets_clair, octets_objet, sha256_clair,
                sha256_chiffre, chaine, destinataires, champs_exclus,
                object_lock_jusqu_a)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (format_version, index_base, periode) DO NOTHING""",
        (config.ARCHIVE_FORMAT_VERSION, lot["index_base"], lot["periode"],
         cle, cle_man, lot["indices"], metriques["documents"],
         metriques["octets_clair"], metriques["octets_objet"],
         metriques["sha256_clair"], metriques["sha256_chiffre"],
         chaine_traitement(), destinataires(),
         config.ARCHIVE_CHAMPS_EXCLUS, lock.get("ObjectLockRetainUntilDate")))
    conn.commit()


def _adopter(conn, s3, lot: dict, cle: str, cle_man: str) -> bool:
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
        s3.head_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=cle)
    except Exception:                                             # noqa: BLE001
        return False
    try:
        corps = s3.get_object(Bucket=config.ARCHIVE_S3_BUCKET,
                              Key=cle_man)["Body"].read()
        man = json.loads(corps)
    except Exception as e:                                        # noqa: BLE001
        log.warning("objet orphelin %s sans manifeste lisible (%s) : "
                    "réarchivage", cle, e)
        return False
    if man.get("documents") != lot["documents"]:
        log.warning("objet orphelin %s : %s documents au manifeste, %s vivants "
                    "— réarchivage", cle, man.get("documents"),
                    lot["documents"])
        return False
    _enregistrer(conn, lot, {
        "documents": man["documents"], "octets_clair": man["octets_clair"],
        "octets_objet": man["octets_objet"],
        "sha256_clair": man["sha256_clair"],
        "sha256_chiffre": man["sha256_chiffre"]}, cle, cle_man)
    log.warning("archive %s/%s ADOPTÉE : l'objet existait sans repère en base "
                "(interruption entre l'upload et l'enregistrement).",
                lot["index_base"], lot["periode"])
    return True


def archiver(conn, s3, lot: dict) -> dict:
    cle = cle_objet(lot["index_base"], lot["periode"], SUFFIXE_OBJET)
    cle_man = cle_objet(lot["index_base"], lot["periode"], SUFFIXE_MANIFESTE)

    if _adopter(conn, s3, lot, cle, cle_man):
        return {"index_base": lot["index_base"], "periode": lot["periode"],
                "etat": "adoptée", "cle": cle}

    tmp = Path(tempfile.mkdtemp(prefix="aura-archive-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        objet = tmp / f"{lot['index_base']}.{lot['periode']}.{SUFFIXE_OBJET}"
        metriques = exporter(lot, objet)
        man = manifeste(lot, metriques, cle)

        televerser(s3, objet, cle, {
            "index-set": lot["index_base"], "periode": lot["periode"],
            "documents": metriques["documents"],
            "sha256-clair": metriques["sha256_clair"],
            "sha256-chiffre": metriques["sha256_chiffre"],
            "format-version": config.ARCHIVE_FORMAT_VERSION})
        _relire(s3, cle, metriques["octets_objet"])

        chemin_man = tmp / f"{lot['index_base']}.{lot['periode']}.{SUFFIXE_MANIFESTE}"
        chemin_man.write_text(json.dumps(man, indent=2, ensure_ascii=False),
                              encoding="utf-8")
        televerser(s3, chemin_man, cle_man, {"index-set": lot["index_base"]})

        # Le repère n'est écrit qu'ici : après que l'objet ET son manifeste ont
        # été relus côté S3.
        _enregistrer(conn, lot, metriques, cle, cle_man)
        ratio = (metriques["octets_clair"] / metriques["octets_objet"]
                 if metriques["octets_objet"] else 0)
        log.info("archivé %s/%s : %d documents, %.1f Mo -> %.1f Mo (x%.1f), %s",
                 lot["index_base"], lot["periode"], metriques["documents"],
                 metriques["octets_clair"] / 1048576,
                 metriques["octets_objet"] / 1048576, ratio, cle)
        return {"index_base": lot["index_base"], "periode": lot["periode"],
                "etat": "archivée", "cle": cle, **metriques}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Protection contre la purge
# --------------------------------------------------------------------------

def indices_en_peril(conn, aujourdhui: date | None = None) -> list[dict]:
    """Index que la purge ISM va supprimer sans qu'une archive existe.

    C'est la question qui compte : pas « l'archivage a-t-il réussi ? » mais
    « reste-t-il de la donnée sur le point de disparaître sans copie ? ». Un
    archivage en panne depuis trois jours n'est pas grave ; le même en panne
    depuis quatre-vingts jours détruit de la donnée à la prochaine rotation.
    """
    if not config.ARCHIVAGE_ENABLED:
        return []
    ref = aujourdhui or datetime.now(timezone.utc).date()
    seuil = config.RETENTION_INDEX_JOURS - config.ARCHIVE_MARGE_JOURS
    deja = {(r["index_base"], r["periode"]) for r in conn.execute(
        "SELECT index_base, periode FROM archives_s3 WHERE format_version=%s",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()}
    peril = []
    for i in indices_dates():
        age = (ref - i["jour"]).days
        if age < seuil or (i["base"], i["mois"]) in deja:
            continue
        peril.append({**i, "age_jours": age,
                      "supprime_dans": config.RETENTION_INDEX_JOURS - age})
    return sorted(peril, key=lambda i: i["supprime_dans"])


def proteger(indices: list[str]) -> int:
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

def _drill_une(s3, ligne: dict, complet: bool = True) -> dict:
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
            s3.download_file(config.ARCHIVE_S3_BUCKET, ligne["cle"], str(local))
        except Exception as e:                                    # noqa: BLE001
            return {"etat": "absent", "detail": str(e)}
        if _sha256_fichier(local) != ligne["sha256_chiffre"]:
            return {"etat": "sha256-divergent",
                    "detail": "l'objet stocké diffère de ce qui a été écrit"}
        if not complet:
            return {"etat": "ok", "complet": False}

        dechiffre = subprocess.run(
            f"age -d -i {config.ARCHIVE_AGE_KEYFILE!r} {str(local)!r} "
            "| zstd -d -c", shell=True, capture_output=True)
        if dechiffre.returncode:
            return {"etat": "erreur: déchiffrement",
                    "detail": dechiffre.stderr.decode(errors="replace")[:500]}
        clair = dechiffre.stdout
        if hashlib.sha256(clair).hexdigest() != ligne["sha256_clair"]:
            return {"etat": "sha256-divergent",
                    "detail": "le clair déchiffré diffère de l'archivé"}
        lignes = clair.count(b"\n")
        if lignes != ligne["documents"]:
            return {"etat": "documents-divergents",
                    "detail": f"{lignes} lignes, {ligne['documents']} attendus"}
        return {"etat": "ok", "complet": True}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def drill(conn, s3, lot: int | None = None,
          complet: bool | None = None) -> list[dict]:
    """Vérifie les archives vérifiées le moins récemment.

    Sélection par `verifie_a NULLS FIRST` : déterministe, et chaque archive
    finit par passer. Un tirage au sort laisserait durablement des trous.
    """
    n = config.ARCHIVE_DRILL_LOT if lot is None else lot
    entier = config.ARCHIVE_DRILL_COMPLET if complet is None else complet
    lignes = conn.execute(
        "SELECT * FROM archives_s3 WHERE format_version=%s "
        " ORDER BY verifie_a NULLS FIRST, archivee_a LIMIT %s",
        (config.ARCHIVE_FORMAT_VERSION, n)).fetchall()
    bilan = []
    for ligne in lignes:
        try:
            r = _drill_une(s3, ligne, entier)
        except Exception as e:                                    # noqa: BLE001
            r = {"etat": f"erreur: {e}"[:200]}
        conn.execute(
            "UPDATE archives_s3 SET verifie_a=now(), verif_etat=%s, "
            " verif_complet=%s WHERE id=%s",
            (r["etat"], bool(r.get("complet")), ligne["id"]))
        conn.commit()
        if r["etat"] == "ok":
            log.info("drill %s/%s : OK%s", ligne["index_base"],
                     ligne["periode"], " (complet)" if r.get("complet") else "")
        else:
            log.error("DRILL EN ÉCHEC %s/%s : %s — %s. L'archive de ce mois "
                      "n'est pas fiable ; la donnée d'origine est probablement "
                      "déjà purgée de l'indexer.", ligne["index_base"],
                      ligne["periode"], r["etat"], r.get("detail", ""))
        bilan.append({"index_base": ligne["index_base"],
                      "periode": ligne["periode"], **r})
    return bilan


# --------------------------------------------------------------------------
# Anomalies remontées au watchdog
# --------------------------------------------------------------------------

def _mois_entre(debut: str, fin: str) -> list[str]:
    a, m = (int(x) for x in debut.split("-"))
    af, mf = (int(x) for x in fin.split("-"))
    sortie = []
    while (a, m) <= (af, mf):
        sortie.append(f"{a:04d}-{m:02d}")
        a, m = (a + 1, 1) if m == 12 else (a, m + 1)
    return sortie


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
    if not config.ARCHIVAGE_ENABLED:
        return []
    sortie = []

    try:
        peril = indices_en_peril(conn)
    except Exception as e:                                        # noqa: BLE001
        log.warning("péril d'archivage incalculable : %s", e)
        peril = []
    if peril:
        detail = "\n".join(
            f"  {i['index']:<40} {i['documents']:>9} docs  "
            f"supprimé dans {i['supprime_dans']} j"
            for i in peril[:15])
        sortie.append(_anomalie(
            "peril",
            f"[ARCHIVAGE] {len(peril)} index vont être purgés sans copie",
            "\n".join([
                "DONNÉE SUR LE POINT D'ÊTRE PERDUE",
                "",
                f"{len(peril)} index datés entrent dans les "
                f"{config.ARCHIVE_MARGE_JOURS} jours qui précèdent leur "
                f"suppression par la politique ISM "
                f"(RETENTION_INDEX_JOURS={config.RETENTION_INDEX_JOURS}) et "
                "aucune archive S3 ne les couvre.",
                "", detail,
                "" if len(peril) <= 15 else f"  … et {len(peril) - 15} autres.",
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
            "High", len(peril)))

    lignes = conn.execute(
        "SELECT index_base, periode, verifie_a, verif_etat FROM archives_s3 "
        " WHERE format_version=%s ORDER BY index_base, periode",
        (config.ARCHIVE_FORMAT_VERSION,)).fetchall()

    # Trous dans une série : un mois absent ENTRE deux mois présents. Borné aux
    # séries déjà commencées — un index set créé le mois dernier n'a pas de
    # trou, il a juste un passé qui n'existe pas.
    par_base: dict[str, list[str]] = {}
    for l in lignes:
        par_base.setdefault(l["index_base"], []).append(l["periode"])
    trous = {b: [m for m in _mois_entre(min(p), max(p)) if m not in set(p)]
             for b, p in par_base.items()}
    trous = {b: m for b, m in trous.items() if m}
    if trous:
        sortie.append(_anomalie(
            "trou",
            f"[ARCHIVAGE] {sum(len(m) for m in trous.values())} mois manquant(s) "
            "dans les séries d'archives",
            "\n".join([
                "TROU DANS LA COUVERTURE D'ARCHIVAGE",
                "",
                "Un mois manque entre deux mois archivés. Les index d'origine "
                "sont donc purgés depuis longtemps : cette donnée n'existe plus "
                "nulle part, et rien ne l'avait signalé au moment où elle "
                "partait.",
                "",
                *(f"  {b} : {', '.join(m)}" for b, m in sorted(trous.items())),
                "",
                "Il n'y a rien à réparer ici — c'est un constat, à consigner. "
                "L'action utile est de comprendre POURQUOI l'archivage était "
                "muet sur cette période et de vérifier que le garde-fou de "
                "péril fonctionne aujourd'hui.",
            ]),
            "Medium", sum(len(m) for m in trous.values())))

    echecs = [l for l in lignes if l["verif_etat"] and l["verif_etat"] != "ok"]
    if echecs:
        sortie.append(_anomalie(
            "drill",
            f"[ARCHIVAGE] {len(echecs)} archive(s) en échec de vérification",
            "\n".join([
                "ARCHIVE NON FIABLE",
                "",
                "Le drill de restauration a relu ces archives et n'a pas "
                "retrouvé ce qui avait été écrit :",
                "",
                *(f"  {l['index_base']}/{l['periode']} : {l['verif_etat']}"
                  for l in echecs[:20]),
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
            "High", len(echecs)))

    limite = datetime.now(timezone.utc) - timedelta(
        days=config.ARCHIVE_DRILL_JOURS)
    vieilles = [l for l in lignes
                if l["verifie_a"] is None or l["verifie_a"] < limite]
    # Une archive du mois en cours n'a pas encore eu son tour : on ne compte
    # comme « en retard » que ce qui a dépassé la fenêtre de drill.
    if len(vieilles) > config.ARCHIVE_DRILL_LOT:
        sortie.append(_anomalie(
            "drill-en-retard",
            f"[ARCHIVAGE] {len(vieilles)} archive(s) non vérifiées depuis plus "
            f"de {config.ARCHIVE_DRILL_JOURS} jours",
            "\n".join([
                "VÉRIFICATION D'ARCHIVES EN RETARD",
                "",
                f"{len(vieilles)} archives n'ont pas été relues depuis "
                f"{config.ARCHIVE_DRILL_JOURS} jours (ou jamais). Une archive "
                "non testée est une croyance, pas une copie.",
                "",
                f"Le service `soc-agent-archive` en vérifie "
                f"{config.ARCHIVE_DRILL_LOT} par passage. Ce retard signifie "
                "soit que le service ne tourne pas, soit que le lot est trop "
                "petit pour le nombre d'archives (augmenter "
                "ARCHIVE_DRILL_LOT).",
            ]),
            "Medium", len(vieilles)))
    return sortie


def _anomalie(suffixe: str, titre: str, note: str, severite: str,
              volume: int) -> dict:
    """Format d'un capteur muet, pour traverser la boucle du watchdog sans cas
    particulier — même convention que `routage._anomalie`."""
    maintenant = datetime.now(timezone.utc)
    return {"agent_id": "000", "agent_name": "wazuh.manager",
            "capteur": f"{PREFIXE_CAPTEUR}{suffixe}", "titre": titre,
            "note": note, "severite": severite, "volume": volume, "seuil": 0,
            "dernier": maintenant, "horizon": maintenant}


# --------------------------------------------------------------------------
# Préflight
# --------------------------------------------------------------------------

def verifier_cle() -> dict:
    """Aller-retour RÉEL de chiffrement sur un témoin, avant de compter sur la clé.

    Chiffrer puis redéchiffrer trois octets coûte quelques millisecondes et
    répond à la seule question qui compte avant d'archiver un mois entier : cette
    clé permet-elle de RELIRE ? Une clé publique collée par erreur dans le
    fichier, une identité tronquée à la copie, un `age` absent — tout ça passe
    les contrôles de `config` et se voit ici.
    """
    _verifier_outils()
    bilan = {"keyfile": config.ARCHIVE_AGE_KEYFILE,
             "destinataires": destinataires()}
    tmp = Path(tempfile.mkdtemp(prefix="aura-clecheck-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        temoin, chiffre = b"aura\n", tmp / "t.age"
        recipients: list[str] = []
        for r in bilan["destinataires"]:
            recipients += ["-r", r]
        c = subprocess.run(["age", *recipients, "-o", str(chiffre)],
                           input=temoin, capture_output=True)
        if c.returncode:
            raise RuntimeError("chiffrement du témoin en échec : "
                               + c.stderr.decode(errors="replace")[:300])
        d = subprocess.run(
            ["age", "-d", "-i", config.ARCHIVE_AGE_KEYFILE, str(chiffre)],
            capture_output=True)
        if d.returncode or d.stdout != temoin:
            raise RuntimeError(
                "la clé ne redéchiffre PAS ce qu'elle a chiffré : "
                + d.stderr.decode(errors="replace")[:300]
                + " — archiver dans cet état produirait des objets illisibles.")
        bilan["aller_retour"] = "ok"
        bilan["secours"] = (config.ARCHIVE_AGE_RECIPIENTS_EXTRA
                            or "AUCUNE — perdre le keyfile perdrait tout")
        return bilan
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verifier_bucket() -> dict:
    """Préflight à lancer AVANT de compter sur l'archivage.

    Vérifie aussi ce qui devrait être ABSENT : le droit de suppression. Une clé
    de prod qui peut supprimer, c'est un rançongiciel qui peut effacer les douze
    mois après avoir chiffré le reste.
    """
    s3 = _s3()
    bilan: dict = {"bucket": config.ARCHIVE_S3_BUCKET,
                   "endpoint": config.ARCHIVE_S3_ENDPOINT}
    s3.head_bucket(Bucket=config.ARCHIVE_S3_BUCKET)
    bilan["joignable"] = True

    for nom, appel in (
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
            bilan[nom] = appel()
        except Exception as e:                                    # noqa: BLE001
            bilan[nom] = f"indéterminé ({type(e).__name__})"

    temoin = "/".join(p for p in (config.ARCHIVE_S3_PREFIX,
                                 config.ARCHIVE_FORMAT_VERSION,
                                 "_preflight.txt") if p)
    s3.put_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=temoin,
                  Body=b"aura preflight\n")
    bilan["ecriture"] = "ok"
    try:
        s3.delete_object(Bucket=config.ARCHIVE_S3_BUCKET, Key=temoin)
        bilan["suppression"] = ("POSSIBLE — la clé porte deleteFiles, ce qui "
                                "n'est pas souhaitable pour une clé de prod")
    except Exception:                                             # noqa: BLE001
        bilan["suppression"] = "refusée (attendu)"

    if config.ARCHIVE_OBJECT_LOCK and bilan.get("object_lock") != "Enabled":
        bilan["alerte"] = ("ARCHIVE_OBJECT_LOCK=true mais le bucket n'a pas "
                           "Object Lock. La propriété ne se rétro-applique pas "
                           "à un bucket existant : recréer le bucket avec "
                           "Object Lock, ou repasser le réglage à false.")
    if config.ARCHIVE_OBJECT_LOCK_JOURS < config.ARCHIVE_RETENTION_MOIS * 30:
        bilan.setdefault("alerte", "")
        bilan["alerte"] += (" Object Lock plus court que la rétention visée : "
                            "un objet redeviendra supprimable avant la fin des "
                            f"{config.ARCHIVE_RETENTION_MOIS} mois.")
    return bilan


# --------------------------------------------------------------------------
# Restauration
# --------------------------------------------------------------------------

def restaurer(s3, index_base: str, periode: str, destination: Path,
              identite: str | None = None) -> dict:
    """Télécharge et déchiffre une archive sur disque, avec la clé du SOC.

    Volontairement séparé de toute réinjection dans l'indexer : décider où
    remettre de la donnée vieille de dix mois est un geste d'analyste, pas
    d'automate. Ré-ingérer dans `wazuh-firewall-*` ferait rentrer ces alertes
    dans le pipeline de triage et fabriquerait des incidents sur des faits vieux
    d'un an. Le NDJSON obtenu s'injecte avec `_bulk` (cf. docs/ARCHIVAGE.md).

    `identite` permet de passer une clé de SECOURS, pour le cas qui justifie
    qu'elle existe : la clé du SOC est perdue ou l'hôte a été refait.
    """
    cle_age = identite or config.ARCHIVE_AGE_KEYFILE
    cle = cle_objet(index_base, periode, SUFFIXE_OBJET)
    chiffre = destination.with_suffix(destination.suffix + ".age")
    s3.download_file(config.ARCHIVE_S3_BUCKET, cle, str(chiffre))
    r = subprocess.run(
        f"age -d -i {cle_age!r} {str(chiffre)!r} | zstd -d -o "
        f"{str(destination)!r} -f",
        shell=True, capture_output=True)
    chiffre.unlink(missing_ok=True)
    if r.returncode:
        raise RuntimeError("restauration en échec : "
                           + r.stderr.decode(errors="replace")[:800])
    # Confronter au manifeste appartient à l'appelant, mais compter les lignes
    # ici évite le contresens le plus courant : croire qu'un fichier obtenu sans
    # erreur est un fichier complet.
    return {"cle": cle, "fichier": str(destination),
            "lignes": sum(1 for _ in destination.open("rb")),
            "octets": destination.stat().st_size}


# --------------------------------------------------------------------------

def tourner(dry_run: bool = False) -> dict:
    """Un passage : archiver ce qui est clos, puis vérifier quelques archives.

    Le drill tourne même si l'archivage n'a rien eu à faire — c'est le cas
    normal la plupart des jours, et c'est justement là qu'on veut savoir si les
    archives des mois passés tiennent encore.
    """
    if not config.ARCHIVAGE_ENABLED:
        return {"etat": "désactivé"}
    bilan: dict = {"dry_run": dry_run, "archivees": [], "echecs": []}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_VERROU_ARCHIVE,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("archivage : passage déjà en cours, on saute ce tour")
            return {"etat": "verrouillé"}
        try:
            lots = lots_a_archiver(conn)
            bilan["a_faire"] = [f"{l['index_base']}/{l['periode']}" for l in lots]
            if dry_run:
                bilan["lots"] = lots
                bilan["peril"] = [i["index"] for i in indices_en_peril(conn)]
                return bilan

            s3 = _s3()
            for lot in lots:
                try:
                    bilan["archivees"].append(archiver(conn, s3, lot))
                except Exception as e:                            # noqa: BLE001
                    # Un lot qui échoue ne doit pas emporter les autres : le
                    # mois suivant appartient peut-être à un autre index set,
                    # et refuser de l'archiver ne répare rien.
                    log.error("archivage %s/%s en échec : %s",
                              lot["index_base"], lot["periode"], e)
                    bilan["echecs"].append(
                        {"index_base": lot["index_base"],
                         "periode": lot["periode"], "erreur": str(e)[:300]})

            bilan["drill"] = drill(conn, s3)
            peril = indices_en_peril(conn)
            bilan["peril"] = [i["index"] for i in peril]
            if peril:
                try:
                    bilan["proteges"] = proteger([i["index"] for i in peril])
                except Exception as e:                            # noqa: BLE001
                    log.error("PROTECTION IMPOSSIBLE (%s) : %d index restent "
                              "candidats à la suppression SANS copie.", e,
                              len(peril))
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_VERROU_ARCHIVE,))
    return bilan


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

    if not config.ARCHIVAGE_ENABLED:
        print("ARCHIVAGE_ENABLED=false : rien à faire. Cf. docs/ARCHIVAGE.md.")
        return

    if args.verifier:
        # La clé d'abord : un bucket parfait ne sert à rien si ce qu'on y écrit
        # est illisible.
        print(json.dumps({"cle": verifier_cle(), "s3": verifier_bucket()},
                         indent=2, ensure_ascii=False, default=str))
        return

    if args.restaurer:
        base, _, periode = args.restaurer.rpartition("/")
        print(json.dumps(restaurer(_s3(), base, periode, Path(args.vers),
                                   args.identite),
                         indent=2, ensure_ascii=False))
        return

    if args.drill:
        if args.identite:
            monkey = config.ARCHIVE_AGE_KEYFILE
            config.ARCHIVE_AGE_KEYFILE = args.identite
            log.warning("drill avec la clé de secours %s (au lieu de %s)",
                        args.identite, monkey)
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            r = drill(conn, _s3(), args.lot, not args.sans_dechiffrer)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    print(json.dumps(tourner(args.plan), indent=2, ensure_ascii=False,
                     default=str))


if __name__ == "__main__":
    main()
