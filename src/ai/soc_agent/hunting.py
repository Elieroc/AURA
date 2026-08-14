"""Espace de threat hunting : remettre une archive en ligne pour chasser dedans.

La rétention supprime les index à 90 jours, l'archivage en garde une copie
chiffrée douze mois ([ARCHIVAGE.md](../../../docs/ARCHIVAGE.md)). Reste le geste
qui rend cette copie utile : la remettre dans l'indexer pour pouvoir la
requêter dans Discover, agréger, pivoter — chasser.

Ce que `wazuh-hunting-*` n'est PAS
---------------------------------
Ce n'est **pas un index set de routage**. Aucune source de log n'y écrit, aucune
branche du pipeline d'ingest ne le désigne. Il lui manque délibérément deux des
cinq pièces d'un index set (cf. docs/ROUTAGE.md), et cette absence *est* la
fonctionnalité :

- **pas lu par l'ingestion.** C'est le point dur. Ré-ingérer des alertes vieilles
  de dix mois les ferait entrer dans la corrélation, puis dans le triage, puis
  dans les cases IRIS — et AURA remédie tout seul sur verdict vrai positif. Une
  restauration mal cloisonnée ne produit pas un faux positif, elle produit une
  isolation d'hôte ou un blocage d'IP en réponse à une attaque de l'an dernier.
- **pas observé par le routage.** Les alertes restaurées gardent leur
  `decoder.name`. Vues par `routage.sources_observees()`, elles ressembleraient à
  une source qui n'atterrit plus dans son index attendu, donc à une dérive de
  routage, avec l'alerte IRIS qui va avec.

Les deux exclusions sont posées par une NÉGATION dans `routage.indices_lus()`
(`-wazuh-hunting-*`), pas par une liste qu'il faudrait penser à tenir. Elle gagne
même si quelqu'un met `wazuh-*` dans `INDEXER_ALERT_INDICES` : la protection ne
dépend pas de la discipline de configuration.

Ce qu'il garde : le template (même mapping que les alertes vivantes — sans lui
tous les champs seraient en `text` et aucune agrégation ne marcherait), un index
pattern pour Discover, et une rétention à lui (`aura-hunting`, 30 jours), parce
que c'est de l'espace de travail et pas de la conservation.

Le nom d'index
--------------
`wazuh-hunting-<source>-<AAAA-MM>` — `wazuh-hunting-firewall-2026-03`.

Volontairement **pas** daté au jour : c'est la forme du nom (`-AAAA.MM.JJ`) qui
détermine ce que l'archivage prend, donc ce nommage suffit à garantir qu'on
n'archive jamais une archive restaurée. `ARCHIVE_INDEX_EXCLUS` le redit en clair,
comme seconde barrière.

Garde-fous
----------
Cet espace est accessible depuis le serveur MCP, donc par un agent IA.
« Restaure-moi tout pour voir » doit être refusé par le CODE, pas déconseillé par
une consigne : plafond de documents, d'index, d'octets, et refus net si le disque
est déjà au-dessus du seuil d'alerte du watchdog. Un disque plein arrête tout le
SOC (cf. docs/RETENTION.md).

    python -m soc_agent.hunting --preparer
    python -m soc_agent.hunting --etat
    python -m soc_agent.hunting --restaurer wazuh-firewall/2026-03
    python -m soc_agent.hunting --purger wazuh-hunting-firewall-2026-03
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)


def _indexer(methode: str, chemin: str, corps: dict | None = None,
             timeout: int = 120, brut: bytes | None = None,
             content_type: str | None = None) -> requests.Response:
    entetes = {"Content-Type": content_type} if content_type else None
    return requests.request(
        methode, f"{config.INDEXER_URL}{chemin}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=corps if brut is None else None, data=brut, headers=entetes,
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=timeout)


def nom_index(index_base: str, periode: str) -> str:
    """`wazuh-firewall` + `2026-03` -> `wazuh-hunting-firewall-2026-03`.

    Le préfixe `wazuh-` de la source est retiré : `wazuh-hunting-wazuh-firewall`
    ne dirait rien de plus et ferait un nom illisible dans Discover.
    """
    source = index_base.removeprefix("wazuh-")
    return f"{config.HUNTING_INDEX_BASE}-{source}-{periode}"


# --------------------------------------------------------------------------
# Préparation de l'espace
# --------------------------------------------------------------------------

def preparer() -> dict:
    """Pose ce dont l'espace a besoin : template, ISM, index pattern.

    Idempotent, et appelé automatiquement avant chaque restauration : un espace
    de hunting qui se prépare tout seul évite le mode d'échec le plus bête —
    restaurer 200 000 documents dans un index sans mapping, où plus aucune
    agrégation ne fonctionne et qu'aucune rétention ne purgera.
    """
    from . import retention, routage
    bilan: dict = {"index_base": config.HUNTING_INDEX_BASE}

    # Template : le MÊME que les alertes vivantes. `_poser_template` lit le
    # template en place et n'y ajoute qu'un pattern — c'est ce qui garantit que
    # les champs restaurés se comportent exactement comme à l'origine, y compris
    # après une montée de version de Wazuh qui aurait changé les mappings.
    try:
        routage._poser_template(config.HUNTING_INDEX_BASE)
        bilan["template"] = routage.TEMPLATE
    except Exception as e:                                    # noqa: BLE001
        # Sans mapping, la donnée entre quand même mais devient inexploitable
        # (tout en `text`, pas d'agrégation). Autant le dire fort et refuser.
        raise RuntimeError(
            f"template {routage.TEMPLATE} non posé pour "
            f"{config.HUNTING_INDEX_BASE} ({e}) : une restauration sans mapping "
            "produirait un index inexploitable en hunting.") from e

    try:
        retention.appliquer_ism()
        bilan["ism"] = retention.ISM_HUNTING_ID
    except Exception as e:                                    # noqa: BLE001
        log.warning("politique ISM de hunting non posée (%s) : les index "
                    "restaurés ne seront pas purgés automatiquement", e)
        bilan["ism"] = f"échec : {e}"

    routage._poser_index_pattern(config.HUNTING_INDEX_BASE)
    bilan["index_pattern"] = f"{config.HUNTING_INDEX_BASE}-*"
    return bilan


# --------------------------------------------------------------------------
# État de l'espace
# --------------------------------------------------------------------------

def etat() -> dict:
    """Ce qui occupe l'espace de hunting, et ce qu'il reste avant les plafonds.

    Rendre `plafonds` avec l'état plutôt qu'à l'échec : un client (humain ou IA)
    doit pouvoir décider s'il a la place AVANT de lancer une restauration de
    trois minutes qui sera refusée à la fin.
    """
    r = _indexer("GET", f"/_cat/indices/{config.HUNTING_INDEX_BASE}-*"
                        "?format=json&h=index,docs.count,pri.store.size,"
                        "creation.date.string&bytes=b&expand_wildcards=open")
    indices = []
    if r.status_code != 404:
        if not r.ok:
            raise RuntimeError(f"_cat/indices refusé ({r.status_code}) : {r.text}")
        for ligne in r.json():
            indices.append({
                "index": ligne["index"],
                "documents": int(ligne.get("docs.count") or 0),
                "octets": int(ligne.get("pri.store.size") or 0),
                "cree_le": ligne.get("creation.date.string"),
            })
    indices.sort(key=lambda i: i["index"])
    octets = sum(i["octets"] for i in indices)
    libre = shutil.disk_usage(config.ARCHIVE_TMP_DIR)
    return {
        "index_base": config.HUNTING_INDEX_BASE,
        "indices": indices,
        "total_indices": len(indices),
        "total_documents": sum(i["documents"] for i in indices),
        "total_octets": octets,
        "plafonds": {
            "max_indices": config.HUNTING_MAX_INDICES,
            "max_octets": config.HUNTING_MAX_OCTETS,
            "max_documents_par_restauration": config.HUNTING_MAX_DOCS,
            "octets_restants": max(0, config.HUNTING_MAX_OCTETS - octets),
            "indices_restants": max(0, config.HUNTING_MAX_INDICES - len(indices)),
        },
        "disque_pct": round(100 * libre.used / libre.total),
        "retention_jours": config.HUNTING_RETENTION_JOURS,
    }


# --------------------------------------------------------------------------
# Garde-fous
# --------------------------------------------------------------------------

def verifier_place(archive: dict, courant: dict | None = None) -> None:
    """Lève si cette restauration ne doit pas avoir lieu. Aucun effet de bord.

    Séparé de `restaurer` pour être appelable en simulation : c'est ce qui permet
    au dry-run de dire « ça passerait » ou « ça serait refusé, et pourquoi » sans
    rien télécharger.
    """
    e = courant or etat()

    # Le disque d'abord. Restaurer est du confort ; un disque plein bascule
    # l'indexer en lecture seule et arrête l'ingestion de TOUT le parc.
    if e["disque_pct"] >= config.DISQUE_SEUIL_ALERTE:
        raise RuntimeError(
            f"disque à {e['disque_pct']} % (seuil d'alerte "
            f"{config.DISQUE_SEUIL_ALERTE} %) : restauration refusée. Le hunting "
            "est du confort, un disque plein arrête l'ingestion de tout le parc. "
            "Libérer de la place ou purger des index de hunting "
            "(soc_agent.hunting --etat).")

    if archive["documents"] > config.HUNTING_MAX_DOCS:
        raise RuntimeError(
            f"{archive['documents']} documents à restaurer, plafond "
            f"{config.HUNTING_MAX_DOCS} (HUNTING_MAX_DOCS). Cette archive est "
            "trop grosse pour l'espace de hunting : restaurer le fichier "
            "NDJSON en local et le filtrer avec jq "
            "(soc_agent.archive --restaurer) est le bon geste ici.")

    if e["total_indices"] >= config.HUNTING_MAX_INDICES:
        raise RuntimeError(
            f"{e['total_indices']} index de hunting déjà en place, plafond "
            f"{config.HUNTING_MAX_INDICES} (HUNTING_MAX_INDICES). Purger ce qui "
            "ne sert plus : ces index sont des copies, l'archive S3 reste.")

    # L'archive est chiffrée et compressée ; ce qui pèse dans l'indexer, c'est le
    # CLAIR. On estime à partir de `octets_clair`, qui est au manifeste, avec un
    # facteur voisin de 1 : l'indexer compresse ses segments mais ajoute ses
    # structures. Approximation assumée et annoncée comme telle.
    projete = e["total_octets"] + archive["octets_clair"]
    if projete > config.HUNTING_MAX_OCTETS:
        raise RuntimeError(
            f"{projete / 1073741824:.1f} Go projetés dans l'espace de hunting, "
            f"plafond {config.HUNTING_MAX_OCTETS / 1073741824:.1f} Go "
            "(HUNTING_MAX_GO). Purger un index de hunting d'abord.")


def archive_disponible(conn, index_base: str, periode: str) -> dict:
    """La ligne d'archive, ou une erreur qui dit quoi faire.

    On interroge Postgres et pas S3 : c'est le repère qui fait autorité
    (cf. archive.py). Un S3 qui ne répond pas ne doit pas se traduire par
    « cette archive n'existe pas ».
    """
    r = conn.execute(
        "SELECT * FROM archives_s3 WHERE format_version=%s AND index_base=%s "
        "  AND periode=%s", (config.ARCHIVE_FORMAT_VERSION, index_base,
                            periode)).fetchone()
    if r is None:
        dispo = conn.execute(
            "SELECT index_base, min(periode) d, max(periode) f, count(*) n "
            "  FROM archives_s3 WHERE format_version=%s GROUP BY index_base "
            "  ORDER BY index_base", (config.ARCHIVE_FORMAT_VERSION,)).fetchall()
        raise RuntimeError(
            f"aucune archive pour {index_base}/{periode}. Disponible : "
            + (", ".join(f"{d['index_base']} {d['d']}..{d['f']} ({d['n']} mois)"
                         for d in dispo) or "rien (l'archivage n'a rien écrit)"))
    if r["verif_etat"] and r["verif_etat"] != "ok":
        # Ne pas refuser : une archive douteuse est justement ce qu'on veut
        # inspecter. Mais le dire, pour qu'on ne conclue pas sur une copie
        # partielle en croyant tenir la vérité.
        log.warning("archive %s/%s en état « %s » : la restauration peut être "
                    "incomplète", index_base, periode, r["verif_etat"])
    return dict(r)


# --------------------------------------------------------------------------
# Restauration
# --------------------------------------------------------------------------

def _creer_index(cible: str, archive: dict) -> None:
    """Crée l'index avec sa provenance dans `_meta`.

    La provenance va dans les métadonnées de l'INDEX, jamais dans `_source` : une
    alerte restaurée doit rester octet pour octet ce qui a été archivé. Un champ
    ajouté dans le document rendrait le SHA-256 du manifeste inutilisable comme
    preuve, et fausserait les agrégations sur les champs qu'on chasse.
    """
    corps = {"mappings": {"_meta": {"aura_hunting": {
        "archive_cle": archive["cle"],
        "index_origine": archive["index_base"],
        "periode": archive["periode"],
        "indices_origine": archive["indices"],
        "documents_attendus": archive["documents"],
        "sha256_clair": archive["sha256_clair"],
        "restaure_le": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }}}}
    r = _indexer("PUT", f"/{cible}", corps)
    if r.status_code == 400 and "resource_already_exists" in r.text:
        log.info("index %s déjà présent : réinjection par-dessus (les _id sont "
                 "conservés, donc les documents sont écrasés à l'identique)",
                 cible)
        return
    if not r.ok:
        raise RuntimeError(f"création de {cible} refusée ({r.status_code}) : "
                           f"{r.text[:300]}")


def _injecter(cible: str, ndjson: Path) -> dict:
    """Réinjecte le NDJSON dans l'index cible, par lots `_bulk`.

    L'`_id` d'origine est CONSERVÉ : une restauration rejouée écrase les mêmes
    documents au lieu d'en créer des doublons. C'est ce qui rend l'opération
    idempotente sans repère à tenir.
    """
    injectes = erreurs = 0
    exemples: list[str] = []
    lot: list[bytes] = []

    def vider() -> None:
        nonlocal injectes, erreurs
        if not lot:
            return
        r = _indexer("POST", "/_bulk", brut=b"".join(lot),
                     content_type="application/x-ndjson", timeout=300)
        lot.clear()
        if not r.ok:
            raise RuntimeError(f"_bulk refusé ({r.status_code}) : {r.text[:300]}")
        reponse = r.json()
        for item in reponse.get("items", []):
            detail = item.get("index") or {}
            if detail.get("error"):
                erreurs += 1
                if len(exemples) < 3:
                    exemples.append(str(detail["error"])[:200])
            else:
                injectes += 1

    with ndjson.open("rb") as f:
        for ligne in f:
            if not ligne.strip():
                continue
            try:
                doc = json.loads(ligne)
            except json.JSONDecodeError:
                erreurs += 1
                continue
            entete = {"index": {"_index": cible}}
            if doc.get("_id"):
                entete["index"]["_id"] = doc["_id"]
            lot.append(json.dumps(entete, separators=(",", ":")).encode() + b"\n")
            lot.append(json.dumps(doc.get("_source") or {}, ensure_ascii=False,
                                  separators=(",", ":")).encode() + b"\n")
            if len(lot) >= config.HUNTING_BULK_TAILLE * 2:
                vider()
    vider()
    return {"injectes": injectes, "erreurs": erreurs,
            "exemples_erreurs": exemples}


def restaurer(index_base: str, periode: str, appliquer: bool = False,
              identite: str | None = None) -> dict:
    """Remet une archive dans l'espace de hunting.

    En dry-run (défaut), rend ce qui serait fait, y compris le verdict des
    garde-fous : c'est le seul moyen honnête de répondre « est-ce que ça passe ? »
    sans télécharger 40 Mo pour l'apprendre.
    """
    from . import archive as arch

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        ligne = archive_disponible(conn, index_base, periode)

    cible = nom_index(index_base, periode)
    courant = etat()
    apercu = {
        "index_cible": cible,
        "archive": {"cle": ligne["cle"], "documents": ligne["documents"],
                    "octets_clair": ligne["octets_clair"],
                    "indices_origine": ligne["indices"],
                    "verification": ligne["verif_etat"] or "jamais vérifiée"},
        "espace_avant": {k: courant[k] for k in
                         ("total_indices", "total_documents", "total_octets")},
        "plafonds": courant["plafonds"],
        "retention_jours": config.HUNTING_RETENTION_JOURS,
    }

    try:
        verifier_place(ligne, courant)
        apercu["garde_fous"] = "ok"
    except RuntimeError as e:
        apercu["garde_fous"] = f"REFUS : {e}"
        if not appliquer:
            return {"applique": False, **apercu}
        raise

    if not appliquer:
        return {
            "applique": False, **apercu,
            "note": "Dry-run : rien n'a été téléchargé ni indexé. Relancer avec "
                    "appliquer=true. La restauration n'entre PAS dans le "
                    "pipeline : ces alertes ne seront ni corrélées, ni triées, "
                    "ni remédiées — c'est un espace de lecture.",
        }

    preparer()
    tmp = Path(tempfile.mkdtemp(prefix="aura-hunting-",
                               dir=config.ARCHIVE_TMP_DIR))
    try:
        ndjson = tmp / f"{cible}.ndjson"
        rest = arch.restaurer(arch._s3(), index_base, periode, ndjson, identite)
        if rest["lignes"] != ligne["documents"]:
            log.warning("archive %s/%s : %d lignes déchiffrées, %d au "
                        "manifeste — restauration poursuivie, mais la copie est "
                        "incomplète", index_base, periode, rest["lignes"],
                        ligne["documents"])
        _creer_index(cible, ligne)
        bilan = _injecter(cible, ndjson)
        _indexer("POST", f"/{cible}/_refresh")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    log.info("hunting : %d document(s) restauré(s) dans %s depuis %s/%s",
             bilan["injectes"], cible, index_base, periode)
    return {
        "applique": True, **apercu,
        "lignes_dechiffrees": rest["lignes"], **bilan,
        "complet": bilan["injectes"] == ligne["documents"],
        "ou_chercher": f"Discover, index pattern {config.HUNTING_INDEX_BASE}-*, "
                       f"index {cible}",
        "note": "Ces alertes ne sont PAS dans le pipeline : ni corrélation, ni "
                "triage, ni remédiation. Elles seront supprimées "
                f"automatiquement au bout de {config.HUNTING_RETENTION_JOURS} "
                "jours — l'archive S3, elle, reste.",
    }


def purger(index: str, confirmer: bool = False) -> dict:
    """Supprime un index de hunting pour rendre de la place.

    Borné au préfixe de hunting, et pas par prudence rhétorique : la même requête
    sur `wazuh-firewall-2026.08.14` détruirait de la donnée de production que
    seule l'archive S3 pourrait rendre — si elle existe déjà.
    """
    if not index.startswith(f"{config.HUNTING_INDEX_BASE}-"):
        raise RuntimeError(
            f"« {index} » n'est pas un index de hunting (préfixe attendu : "
            f"{config.HUNTING_INDEX_BASE}-). Refus : cet outil ne supprime que "
            "des copies restaurées, jamais de la donnée de production.")
    if "*" in index or "," in index:
        raise RuntimeError(
            "un index à la fois, nommé en entier — pas de joker. Une suppression "
            "par motif est exactement le geste dont on ne mesure pas la portée.")
    if not confirmer:
        return {"supprime": False,
                "note": f"{index} serait supprimé. C'est une COPIE : l'archive "
                        "S3 reste et la restauration est rejouable. Passer "
                        "confirmer=true."}
    r = _indexer("DELETE", f"/{index}")
    if not r.ok:
        raise RuntimeError(f"suppression de {index} refusée ({r.status_code}) : "
                           f"{r.text[:200]}")
    log.info("index de hunting %s supprimé", index)
    return {"supprime": True, "index": index}


# --------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--preparer", action="store_true",
                   help="poser template, ISM et index pattern, puis sortir")
    p.add_argument("--etat", action="store_true",
                   help="ce qui occupe l'espace de hunting")
    p.add_argument("--restaurer", metavar="INDEX_SET/AAAA-MM",
                   help="remettre une archive dans l'espace de hunting")
    p.add_argument("--appliquer", action="store_true",
                   help="exécuter pour de vrai (défaut : dry-run)")
    p.add_argument("--identite", help="clé age de secours, si celle du SOC est "
                                     "perdue")
    p.add_argument("--purger", metavar="INDEX",
                   help="supprimer un index de hunting")
    p.add_argument("--confirmer", action="store_true",
                   help="confirmer la suppression")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.preparer:
        sortie = preparer()
    elif args.etat:
        sortie = etat()
    elif args.purger:
        sortie = purger(args.purger, args.confirmer)
    elif args.restaurer:
        base, _, periode = args.restaurer.rpartition("/")
        sortie = restaurer(base, periode, args.appliquer, args.identite)
    else:
        p.print_help()
        return
    print(json.dumps(sortie, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
