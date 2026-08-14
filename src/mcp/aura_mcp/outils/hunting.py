"""Outils de threat hunting : remettre une archive en ligne pour chasser dedans.

Les alertes sortent de l'indexer à 90 jours (rétention) et survivent douze mois
en archive chiffrée dans S3. Ces outils sont le pont : lister ce qui est
archivé, en remettre un mois dans `wazuh-hunting-*`, y chasser depuis Discover,
puis rendre la place.

Ce que ces outils ne font PAS, et c'est ce qui les rend utilisables par un agent
IA sans surveillance : **la donnée restaurée n'entre pas dans le pipeline.**
`wazuh-hunting-*` est exclu par négation de ce que lit l'ingestion
(`routage.indices_lus`), donc les alertes remises en ligne ne sont ni corrélées,
ni triées, ni remédiées. Sans ce cloisonnement, restaurer mars 2026 ferait
rejouer à AURA une attaque vieille de dix mois — avec l'isolation d'hôte et le
blocage d'IP au bout, puisque la remédiation est autonome.

Les plafonds (documents, index, octets, seuil de disque) sont dans
`soc_agent.hunting`, en amont : cette couche ne les rejoue pas et ne peut pas les
désactiver. « Restaure-moi tout pour voir » est refusé par le code.
"""

from soc_agent import config as soc_config
from soc_agent import hunting

from .. import auth, sortie
from ..db import lecture as base
from ..serveur import enregistrer


@auth.exige("aura:read")
def aura_archives_list(index_set: str | None = None,
                       limite: int | None = None,
                       offset: int | None = None) -> dict:
    """Les archives froides disponibles, avec leur état de vérification.

    C'est le catalogue de ce qui est restaurable : un mois d'un index set par
    ligne. La source de vérité est Postgres et non S3 — un S3 qui ne répond pas
    ne doit pas se traduire par « il n'y a pas d'archive ».

    `verif_etat` mérite un regard avant de conclure sur une restauration :

    - `ok` : l'archive a été retéléchargée, déchiffrée et recomptée ;
    - `null` : jamais vérifiée depuis son écriture ;
    - autre chose (`absent`, `sha256-divergent`, `documents-divergents`) :
      l'archive n'est pas fiable, et la donnée d'origine est très probablement
      déjà purgée de l'indexer. Restaurer reste possible et souhaitable pour
      voir ce qu'il en reste, mais ne pas conclure sur une copie partielle en
      croyant tenir la vérité.

    Args:
        index_set: filtrer sur un index set (`wazuh-firewall`).
        limite: lignes par page.
        offset: décalage de pagination.
    """
    limite, offset = sortie.bornes(limite, offset)
    where = ("WHERE format_version = %(fv)s "
             "  AND (%(base)s::text IS NULL OR index_base = %(base)s)")
    params = {"fv": soc_config.ARCHIVE_FORMAT_VERSION, "base": index_set,
              "limite": limite, "offset": offset}
    with base() as conn:
        total = conn.execute(
            f"SELECT count(*) AS n FROM archives_s3 {where}",
            params).fetchone()["n"]
        lignes = conn.execute(
            f"""SELECT index_base, periode, documents, octets_clair,
                       octets_objet, indices, archivee_a, verifie_a,
                       verif_etat, verif_complet, object_lock_jusqu_a
                  FROM archives_s3 {where}
                 ORDER BY index_base, periode DESC
                 LIMIT %(limite)s OFFSET %(offset)s""", params).fetchall()
    return sortie.page([dict(l) for l in lignes], total, limite, offset)


@auth.exige("aura:read")
def aura_hunting_state() -> dict:
    """Ce qui occupe l'espace de hunting, et ce qu'il reste avant les plafonds.

    À lire AVANT une restauration : les plafonds sont rendus ici, donc on sait si
    l'opération passera sans avoir à la tenter. `disque_pct` est le garde-fou le
    plus dur — au-delà du seuil d'alerte du watchdog, toute restauration est
    refusée, parce qu'un disque plein bascule l'indexer en lecture seule et
    arrête l'ingestion de tout le parc.

    Les index listés sont des COPIES : les supprimer ne perd rien, l'archive S3
    reste. Ils sont purgés seuls au bout de `retention_jours`.
    """
    return sortie.jsonifiable(hunting.etat())


@auth.exige("aura:write")
def aura_hunting_restore(index_set: str, periode: str,
                         appliquer: bool = False) -> dict:
    """Remet une archive froide dans `wazuh-hunting-*` pour l'analyser.

    Télécharge l'objet S3, le déchiffre avec la clé du SOC, et réinjecte les
    documents dans `wazuh-hunting-<source>-<AAAA-MM>`. L'`_id` d'origine est
    conservé : rejouer la restauration écrase les mêmes documents au lieu de les
    dupliquer.

    **La donnée restaurée n'entre pas dans le pipeline.** Ni corrélation, ni
    triage, ni case IRIS, ni remédiation : c'est un espace de LECTURE, requêtable
    dans Discover via l'index pattern `wazuh-hunting-*`. C'est un cloisonnement
    structurel, pas un réglage — sans lui, restaurer un vieux mois ferait rejouer
    à AURA une attaque passée et déclencherait des remédiations réelles.

    En dry-run (défaut), rend ce qui serait fait ET le verdict des garde-fous,
    sans rien télécharger. Les refus possibles, tous appliqués côté serveur :
    disque au-dessus du seuil d'alerte, archive plus grosse que
    `HUNTING_MAX_DOCS`, plafond d'index atteint, plafond d'octets dépassé. Pour
    une archive trop grosse, le bon geste est de la restaurer en fichier NDJSON
    et de la filtrer avec `jq` plutôt que de l'indexer entière.

    L'index restauré est supprimé automatiquement au bout de
    `HUNTING_RETENTION_JOURS` (30 par défaut) ; l'archive S3, elle, reste.

    Args:
        index_set: index set d'origine (`wazuh-firewall`), tel que rendu par
            `aura_archives_list`.
        periode: mois au format `AAAA-MM` (`2026-03`).
        appliquer: exécuter réellement. `False` rend le plan et le verdict des
            garde-fous.
    """
    return sortie.jsonifiable(hunting.restaurer(index_set, periode, appliquer))


@auth.exige("aura:write")
def aura_hunting_purge(index: str, confirmer: bool = False) -> dict:
    """Supprime un index de hunting pour rendre de la place.

    Sans danger par construction : l'outil REFUSE tout nom qui ne commence pas
    par le préfixe de hunting, et refuse les jokers et les listes. Il ne peut
    donc pas toucher un index d'alertes de production. Ce qu'il supprime est une
    copie — l'archive S3 reste et la restauration est rejouable.

    Args:
        index: nom complet de l'index (`wazuh-hunting-firewall-2026-03`).
        confirmer: exécuter. `False` rend ce qui serait supprimé.
    """
    return sortie.jsonifiable(hunting.purger(index, confirmer))


enregistrer(aura_archives_list)
enregistrer(aura_hunting_state)
enregistrer(aura_hunting_restore)
enregistrer(aura_hunting_purge)
