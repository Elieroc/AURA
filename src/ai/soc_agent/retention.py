"""Rétention des données du SOC : ce qui vieillit finit par être supprimé.

Le 2026-08-14, le disque de prod était à 66 % sans qu'aucune alerte ne l'ait
jamais signalé. Aucune de ces données n'était du log Wazuh — l'indexer pesait
470 Mo. C'étaient trois choses qui grossissaient sans borne :

- le journal d'audit MISP (12,75 Go en deux jours, 49 M de lignes écrites par
  l'ingestion des feeds) — traité à la source en coupant l'écriture ;
- les pièces Evidence IRIS reposées à chaque cycle (8,3 Go, facteur 14 de
  duplication) — traité à la source dans `iris._evidences` ;
- les résidus de mise à jour du feed CVE de Wazuh (6,7 Go de JSON décompressé
  qu'aucun ménage ne repasse jamais chercher) — traité ICI.

Ce module porte ce qui ne peut pas l'être à la source : le vieillissement de ce
qui est légitimement écrit. Trois cibles :

- `alerts` : la table qui grossit le plus vite du pipeline (~150 Mo/jour).
  Purgée au-delà de `RETENTION_ALERTES_JOURS`, en PRÉSERVANT les alertes
  rattachées à un incident non clos — une preuve ne disparaît pas sous un
  dossier ouvert.
- résidus `vd_updater/tmp` du manager Wazuh, montés en volume.
- politique ISM de l'indexer, (ré)appliquée à chaque passage : elle est
  déclarative, la poser est idempotent, et un indexer réinstallé la retrouve
  sans geste manuel.

Ce qui n'est PAS ici, et pourquoi :

- MISP. Sa base est grosse (15 Go) mais c'est de la donnée CTI légitime, pas du
  journal : les 21 M d'attributs viennent de l'historique URLhaus. La purger
  serait une décision de couverture CTI, pas de rétention.
- Les images docker. Les élaguer depuis un conteneur exigerait de lui donner la
  socket docker en écriture, c'est-à-dire root sur l'hôte, pour récupérer
  ~2 Go. Ça se fait depuis l'hôte (cf. docs/RETENTION.md).
- Les fichiers d'alertes du manager (`/var/ossec/logs/alerts`) : Wazuh les
  tourne et les purge déjà seul (`monitord.keep_log_days`, 31 jours).

    python -m soc_agent.retention            # un passage
    python -m soc_agent.retention --dry-run  # ce qui serait supprimé
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)

# Verrou consultatif : même famille que les autres jobs périodiques (0x50CA*).
_VERROU_RETENTION = 0x50CA5

# --------------------------------------------------------------------------
# Politique ISM de l'indexer
# --------------------------------------------------------------------------
#
# Les index Wazuh sont DATÉS (un par jour) : ils n'ont ni alias ni rollover, la
# rotation est déjà faite par le nom. La politique n'a donc qu'un travail —
# supprimer au-delà de l'âge de rétention.
#
# `wazuh-voc-vulns` est délibérément HORS de la politique. C'est le seul index
# non daté du lot : un document par vulnérabilité, réécrit à chaque passage,
# qui porte le cycle de vie et donc le MTTR (cf. docs/VOC.md). Une rétention par
# date y effacerait l'historique de la dette. D'où des motifs explicites plutôt
# qu'un `wazuh-*` qui l'avalerait.
ISM_POLICY_ID = "aura-retention"

ISM_PATTERNS = [
    "wazuh-alerts-*", "wazuh-archives-*", "wazuh-linux-*", "wazuh-windows-*",
    "wazuh-web-*", "wazuh-firewall-*", "wazuh-proxy-*", "wazuh-jellyfin-*",
    "wazuh-vpn-*", "wazuh-dns-*", "wazuh-yara-*", "wazuh-ai-*",
    # Séries temporelles du VOC uniquement : `wazuh-voc-20*` matche
    # `wazuh-voc-2026.08.14` et JAMAIS `wazuh-voc-vulns`.
    "wazuh-voc-20*",
]


def ism_patterns() -> list[str]:
    """Motifs statiques UNION les index sets créés par `routage.py`.

    Un index set créé sans rétention grossit indéfiniment, et le disque plein
    est la panne qui arrête TOUT le SOC (indexer en lecture seule, Postgres qui
    refuse d'écrire). Lire la table plutôt que d'ajouter une ligne ici à chaque
    création rend l'oubli impossible.

    Repli sur les seuls motifs statiques si la base ne répond pas : mieux vaut
    une politique qui couvre l'essentiel qu'un job de rétention qui ne tourne
    pas du tout.
    """
    try:
        import psycopg
        from psycopg.rows import dict_row

        from . import routage
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            appris = routage.patterns_appliques(conn)
    except Exception as e:                                    # noqa: BLE001
        log.warning("patterns de routage illisibles (%s) : politique ISM "
                    "limitée aux motifs statiques", e)
        appris = []
    return list(dict.fromkeys(ISM_PATTERNS + appris))


def politique_ism() -> dict:
    return {
        "policy": {
            "description": (
                f"AURA — suppression des index datés au-delà de "
                f"{config.RETENTION_INDEX_JOURS} jours. wazuh-voc-vulns est "
                f"exclu : index d'état, non daté."),
            "default_state": "actif",
            "states": [
                {"name": "actif",
                 "actions": [],
                 "transitions": [{
                     "state_name": "suppression",
                     "conditions": {
                         "min_index_age": f"{config.RETENTION_INDEX_JOURS}d"},
                 }]},
                {"name": "suppression",
                 "actions": [{"delete": {}}],
                 "transitions": []},
            ],
            "ism_template": [{
                "index_patterns": ism_patterns(),
                "priority": 100,
            }],
        }
    }


# Politique DISTINCTE pour l'espace de threat hunting (cf. hunting.py). Deux
# politiques plutôt qu'une durée moyenne, parce que ce ne sont pas les mêmes
# données : `wazuh-hunting-*` contient des COPIES restaurées depuis les archives
# S3, qui vivent douze mois de leur côté. Les perdre ne perd rien, et de
# l'espace de travail qui traîne est le moyen le plus simple de remplir le
# disque du SOC.
#
# Les motifs des deux politiques ne se recoupent pas : un index ne peut porter
# qu'UNE politique ISM, et deux `ism_template` concurrents à la même priorité
# donneraient un rattachement arbitraire.
ISM_HUNTING_ID = "aura-hunting"


def politique_ism_hunting() -> dict:
    return {
        "policy": {
            "description": (
                f"AURA — espace de threat hunting : suppression au-delà de "
                f"{config.HUNTING_RETENTION_JOURS} jours. Ce sont des copies "
                f"restaurées depuis les archives S3, pas des originaux."),
            "default_state": "actif",
            "states": [
                {"name": "actif",
                 "actions": [],
                 "transitions": [{
                     "state_name": "suppression",
                     "conditions": {
                         "min_index_age":
                             f"{config.HUNTING_RETENTION_JOURS}d"},
                 }]},
                {"name": "suppression",
                 "actions": [{"delete": {}}],
                 "transitions": []},
            ],
            "ism_template": [{
                "index_patterns": [f"{config.HUNTING_INDEX_BASE}-*"],
                "priority": 150,
            }],
        }
    }


def _indexer(methode: str, chemin: str, corps: dict | None = None):
    verif = config.INDEXER_CA or config.INDEXER_VERIFY_TLS
    return requests.request(
        methode, f"{config.INDEXER_URL}{chemin}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=corps, verify=verif, timeout=30)


def _poser_politique(policy_id: str, corps: dict) -> str:
    """Écrit une politique ISM, en création ou en mise à jour concurrente.

    Le couple `if_seq_no`/`if_primary_term` est ce qui rend deux passages
    simultanés inoffensifs : le second est refusé par l'indexer au lieu
    d'écraser une politique qu'il n'a pas lue.
    """
    lu = _indexer("GET", f"/_plugins/_ism/policies/{policy_id}")
    if lu.status_code == 200:
        seq = lu.json()["_seq_no"]
        prim = lu.json()["_primary_term"]
        r = _indexer("PUT", f"/_plugins/_ism/policies/{policy_id}"
                            f"?if_seq_no={seq}&if_primary_term={prim}", corps)
        etat = "mise à jour"
    else:
        r = _indexer("PUT", f"/_plugins/_ism/policies/{policy_id}", corps)
        etat = "créée"
    if not r.ok:
        raise RuntimeError(
            f"politique ISM {policy_id} refusée ({r.status_code}) : {r.text}")
    return etat


def _rattacher(policy_id: str, patterns: list[str]) -> int:
    """Attache la politique aux index DÉJÀ existants.

    `ism_template` ne vaut que pour les index créés APRÈS : sans cet appel, une
    politique posée aujourd'hui ne verrait jamais les index d'hier —
    c'est-à-dire précisément ceux qu'elle doit supprimer.

    Les index déjà gérés répondent en « failure » avec un motif explicite : ce
    n'est pas une erreur, c'est l'état normal à partir du 2e passage.
    """
    r = _indexer("POST", "/_plugins/_ism/add/" + ",".join(patterns),
                 {"policy_id": policy_id})
    return r.json().get("updated_indices", 0) if r.ok else 0


def appliquer_ism() -> str:
    """Pose les DEUX politiques : celle des alertes, celle du hunting."""
    etat = _poser_politique(ISM_POLICY_ID, politique_ism())
    ajoutes = _rattacher(ISM_POLICY_ID, ism_patterns())
    log.info("politique ISM « %s » %s (%s jours), %s index rattaché(s)",
             ISM_POLICY_ID, etat, config.RETENTION_INDEX_JOURS, ajoutes)

    # L'espace de hunting a sa propre durée et son propre motif. Best-effort
    # séparé : son échec ne doit pas emporter la rétention des alertes, qui est
    # celle qui protège le disque.
    try:
        etat_h = _poser_politique(ISM_HUNTING_ID, politique_ism_hunting())
        motifs_h = [f"{config.HUNTING_INDEX_BASE}-*"]
        log.info("politique ISM « %s » %s (%s jours), %s index rattaché(s)",
                 ISM_HUNTING_ID, etat_h, config.HUNTING_RETENTION_JOURS,
                 _rattacher(ISM_HUNTING_ID, motifs_h))
    except Exception as e:                                    # noqa: BLE001
        log.warning("politique ISM « %s » non appliquée : %s — les index de "
                    "hunting ne seront pas purgés automatiquement.",
                    ISM_HUNTING_ID, e)
    return etat


# --------------------------------------------------------------------------
# Purge des alertes
# --------------------------------------------------------------------------

# Les alertes rattachées à un incident encore OUVERT sont épargnées quel que
# soit leur âge : c'est la matière du dossier que l'analyste a sous les yeux.
# Une intrusion lente (persistance installée il y a quatre mois, réveillée
# hier) tient dans un incident dont les premières alertes sont hors fenêtre —
# les supprimer viderait le dossier de son début.
PURGE_ALERTES = """
DELETE FROM alerts a
 WHERE a.ts < now() - make_interval(days => %s)
   AND (a.incident_id IS NULL
        OR EXISTS (SELECT 1 FROM incidents i
                    WHERE i.id = a.incident_id
                      AND i.status IN ('case_ouvert', 'fp_classe')
                      AND i.last_seen < now() - make_interval(days => %s)))
"""


def purger_alertes(conn, jours: int, dry_run: bool = False) -> int:
    if dry_run:
        sql = PURGE_ALERTES.replace("DELETE FROM alerts a", "SELECT count(*) c FROM alerts a")
        return conn.execute(sql, (jours, jours)).fetchone()["c"]
    n = conn.execute(PURGE_ALERTES, (jours, jours)).rowcount
    conn.commit()
    if n:
        log.info("%d alerte(s) de plus de %d jours supprimée(s)", n, jours)
    return n


def purger_evidences_orphelines(conn, dry_run: bool = False) -> int:
    """Repères de pièces Evidence dont l'incident n'existe plus.

    La contrainte FK est en ON DELETE CASCADE, donc ce cas ne devrait pas
    exister — sauf pour les lignes écrites avant qu'elle soit posée. Peu coûteux
    à vérifier, et une table de repères qui ment reposterait des preuves.
    """
    sql = ("SELECT count(*) c FROM iris_evidences e WHERE NOT EXISTS "
           "(SELECT 1 FROM incidents i WHERE i.id = e.incident_id)")
    if dry_run:
        return conn.execute(sql).fetchone()["c"]
    n = conn.execute(
        "DELETE FROM iris_evidences e WHERE NOT EXISTS "
        "(SELECT 1 FROM incidents i WHERE i.id = e.incident_id)").rowcount
    conn.commit()
    return n


# --------------------------------------------------------------------------
# Résidus de mise à jour du feed CVE (Wazuh)
# --------------------------------------------------------------------------

def purger_residus_vd(dry_run: bool = False) -> tuple[int, int]:
    """Fichiers laissés par le vd_updater dans son répertoire de travail.

    Le module de détection de vulnérabilités décompresse le feed dans
    `queue/vd_updater/tmp/contents` et ne le vide pas si la mise à jour est
    interrompue. 6,7 Go y dormaient depuis la veille le 2026-08-14.

    L'âge minimum n'est pas cosmétique : il garantit qu'on ne supprime pas les
    fichiers d'une mise à jour EN COURS (elles durent quelques minutes, le seuil
    est en heures). Renvoie (fichiers, octets).
    """
    base = Path(config.WAZUH_QUEUE_DIR) / "vd_updater" / "tmp"
    if not base.is_dir():
        log.debug("répertoire vd_updater absent (%s) : rien à purger", base)
        return 0, 0
    limite = time.time() - config.RETENTION_VD_TMP_HEURES * 3600
    n, octets = 0, 0
    for f in base.rglob("*"):
        if not f.is_file():
            continue
        try:
            st = f.stat()
            if st.st_mtime >= limite:
                continue
            if not dry_run:
                f.unlink()
            n += 1
            octets += st.st_size
        except OSError as e:
            log.debug("résidu vd %s non supprimé : %s", f, e)
    if n:
        log.info("%d résidu(s) de feed CVE supprimé(s) (%.1f Go)",
                 n, octets / 1073741824)
    return n, octets


# --------------------------------------------------------------------------

def tourner(dry_run: bool = False) -> dict:
    """Un passage complet. Chaque cible est indépendante : une qui échoue ne
    doit pas empêcher les autres — c'est un job de ménage, pas une transaction.
    """
    bilan: dict = {"dry_run": dry_run}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_VERROU_RETENTION,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("rétention : passage déjà en cours, on saute ce tour")
            return {"etat": "verrouillé"}
        try:
            bilan["alertes"] = purger_alertes(
                conn, config.RETENTION_ALERTES_JOURS, dry_run)
            bilan["evidences_orphelines"] = purger_evidences_orphelines(
                conn, dry_run)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_VERROU_RETENTION,))

    fichiers, octets = purger_residus_vd(dry_run)
    bilan["residus_vd"] = fichiers
    bilan["residus_vd_octets"] = octets

    if config.RETENTION_ISM_ENABLED and not dry_run:
        try:
            bilan["ism"] = appliquer_ism()
        except Exception as e:  # noqa: BLE001 — l'indexer ne bloque pas le reste
            log.warning("politique ISM non appliquée : %s", e)
            bilan["ism"] = f"échec : {e}"

    # Garde-fou d'archivage, APRÈS la pose de la politique et jamais avant.
    #
    # `appliquer_ism()` rattache les index par MOTIF (`_ism/add`) : protéger
    # d'abord puis appliquer défferait la protection dans la seconde. C'est
    # exactement la classe de bug qui a déjà coûté cher ici — un ordre
    # d'opérations qui annule silencieusement l'opération précédente.
    #
    # Et il faut bien DÉTACHER : se contenter de ne pas reposer la politique ne
    # protégerait rien, elle est déjà attachée aux index existants et les
    # supprimerait à l'heure prévue.
    if config.ARCHIVAGE_ENABLED and not dry_run:
        try:
            from . import archive
            with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
                peril = archive.indices_en_peril(conn)
            bilan["archivage_peril"] = [i["index"] for i in peril]
            if peril:
                bilan["archivage_proteges"] = archive.proteger(
                    [i["index"] for i in peril])
        except Exception as e:  # noqa: BLE001
            # Le pire cas : on n'a pas su vérifier la couverture d'archivage ET
            # la politique de suppression vient d'être (ré)appliquée. Le dire
            # fort, c'est tout ce qu'on peut faire ici — le watchdog reprendra
            # le constat et ouvrira l'alerte IRIS.
            log.error("COUVERTURE D'ARCHIVAGE NON VÉRIFIÉE (%s) : la politique "
                      "de suppression est active et rien ne garantit qu'une "
                      "copie existe.", e)
            bilan["archivage_peril"] = f"indéterminé : {e}"
    return bilan


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true",
                   help="compter sans supprimer")
    p.add_argument("--ism", action="store_true",
                   help="poser la seule politique ISM et sortir")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.ism:
        print(f"politique ISM « {ISM_POLICY_ID} » : {appliquer_ism()}")
        return
    print(json.dumps(tourner(args.dry_run), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
