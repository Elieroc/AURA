"""CMDB : rôle et priorité des machines surveillées.

Le pipeline ne connaissait que `rule_level` — une propriété de la RÈGLE. Deux
incidents de niveau 12, l'un sur le contrôleur de domaine, l'autre sur un poste
de test, arrivaient dans la même file, dans le même ordre, avec les mêmes
garde-fous. Ce module apporte la seconde moitié de l'information : *sur quoi*.

Source de vérité : les **groupes Wazuh** préfixés `role-` (cf.
`config.CMDB_GROUPE_PREFIXE`). C'est le mécanisme d'inventaire natif, il survit
au redéploiement de la stack, et l'opérateur qui enrôle une machine y déclare son
rôle au même endroit que le reste de sa configuration. La table `assets` en est
un MIROIR interrogeable — jamais l'inverse : ce que dit le manager gagne, sauf
sur une ligne posée à la main par l'opérateur (`priorite_source = 'operateur'`).

    python -m soc_agent.assets --sync        # aligne la CMDB sur le manager
    python -m soc_agent.assets --couverture  # dette d'inventaire (P4 par défaut)
"""

import argparse
import logging

import psycopg
import requests
import urllib3
from psycopg.rows import dict_row

from . import config

log = logging.getLogger("assets")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sources de priorité, de la plus forte à la plus faible. `operateur` est une
# décision humaine explicite : la synchronisation ne l'écrase jamais, sinon le
# prochain passage effacerait la correction qu'un analyste vient de faire.
SOURCES = ("operateur", "groupe", "defaut")


# --------------------------------------------------------------------------
# Calcul de la priorité
# --------------------------------------------------------------------------

def role_depuis_groupes(groupes) -> str | None:
    """Rôle déclaré par les groupes Wazuh de l'agent, ou None.

    Une machine peut porter plusieurs rôles (`role-web` + `role-db` sur un LAMP
    mutualisé) : c'est le plus critique qui l'emporte. Sous-estimer un asset
    mixte serait le pire des deux mondes — on le traiterait comme sa moitié la
    moins importante.
    """
    prefixe = config.CMDB_GROUPE_PREFIXE
    roles = [str(g).lower()[len(prefixe):] for g in (groupes or [])
             if str(g).lower().startswith(prefixe)]
    connus = [r for r in roles if r in config.PRIORITE_ROLES]
    if not connus:
        return None
    return min(connus, key=lambda r: config.PRIORITE_ROLES[r])


def priorite_du_role(role: str | None) -> int:
    """Priorité d'un rôle, ou PRIORITE_DEFAUT s'il est inconnu."""
    if not role:
        return config.PRIORITE_DEFAUT
    return config.PRIORITE_ROLES.get(str(role).lower(), config.PRIORITE_DEFAUT)


def severite(max_level: int, priorite: int) -> int:
    """Sévérité EFFECTIVE d'un incident : niveau Wazuh corrigé par l'asset.

    Fonction pure, bornée à l'échelle Wazuh (1-15) pour rester lisible à côté de
    `max_level` et comparable d'un incident à l'autre. On ne modifie jamais
    `max_level` lui-même : la corrélation, UEBA et `RULES_COMPROMISSION_HOTE`
    s'appuient dessus, et un décalage silencieux changerait le sens de tous les
    seuils existants.
    """
    bonus = config.SEVERITE_BONUS_PRIORITE.get(priorite, 0)
    return max(1, min(15, int(max_level) + bonus))


# La table est-elle là ? Testé une fois par processus, et par une requête qui
# ne peut pas ÉCHOUER (`to_regclass` rend NULL au lieu de lever). Sans cela, un
# déploiement où la migration de `schema.sql` a été oubliée verrait la
# corrélation lever au premier incident — donc plus d'incidents du tout, pour
# une colonne d'agrément. Une priorisation absente doit dégrader le tri, jamais
# arrêter le SOC.
_TABLE_PRETE: bool | None = None


def _disponible(conn) -> bool:
    global _TABLE_PRETE
    if _TABLE_PRETE is None:
        _TABLE_PRETE = bool(conn.execute(
            "SELECT to_regclass('public.assets') IS NOT NULL AS ok"
        ).fetchone()["ok"])
        if not _TABLE_PRETE:
            log.warning(
                "table `assets` absente : tous les incidents naîtront en P%d. "
                "Appliquer soc_agent/schema.sql (cf. docs/CMDB.md).",
                config.PRIORITE_DEFAUT)
    return _TABLE_PRETE


def priorite_agent(conn, agent_id: str, container: str | None = None) -> dict:
    """Priorité applicable aux alertes de cet agent : {priorite, role, source}.

    Deux corrections par rapport à la lecture brute de la CMDB, dans cet ordre :

    1. **agent capteur** (`AGENTS_CAPTEURS`) : sa télémétrie décrit l'activité
       d'AUTRES machines. Le pare-feu qui porte Suricata *est* un asset P1, mais
       l'alerte qu'il remonte parle d'un poste du LAN. On rabat donc sur
       `PRIORITE_CAPTEUR`, sauf si l'alerte porte le conteneur d'origine
       (`alerts.container`) — auquel cas c'est CE dernier qui est résolu, et on
       retombe sur le cas normal.
    2. **agent absent de la CMDB** : `PRIORITE_DEFAUT`, source `defaut`. Jamais
       une erreur — un agent enrôlé hors d'AURA doit passer, pas bloquer.
    """
    if not _disponible(conn):
        return {"priorite": config.PRIORITE_DEFAUT, "role": None,
                "source": "defaut"}

    if container:
        ligne = _lire(conn, nom=container)
        if ligne:
            return {"priorite": ligne["priorite"], "role": ligne["role"],
                    "source": ligne["priorite_source"]}

    if str(agent_id) in config.AGENTS_CAPTEURS:
        return {"priorite": config.PRIORITE_CAPTEUR, "role": "capteur",
                "source": "capteur"}

    ligne = _lire(conn, agent_id=str(agent_id))
    if ligne:
        return {"priorite": ligne["priorite"], "role": ligne["role"],
                "source": ligne["priorite_source"]}
    return {"priorite": config.PRIORITE_DEFAUT, "role": None,
            "source": "defaut"}


def _lire(conn, agent_id: str | None = None, nom: str | None = None):
    if agent_id is not None:
        return conn.execute(
            "SELECT agent_id, nom, role, priorite, priorite_source "
            "  FROM assets WHERE agent_id = %s", (agent_id,)).fetchone()
    return conn.execute(
        "SELECT agent_id, nom, role, priorite, priorite_source "
        "  FROM assets WHERE nom = %s LIMIT 1", (nom,)).fetchone()


def libelle(priorite: int, role: str | None) -> str:
    """« P1 — contrôleur de domaine (dc) », pour le prompt et les cases IRIS."""
    return f"P{priorite}" + (f" ({role})" if role else " (rôle non déclaré)")


# --------------------------------------------------------------------------
# Synchronisation depuis le manager Wazuh
# --------------------------------------------------------------------------
#
# Client API minimal, volontairement local au module : `mitigate` a le sien, mais
# l'importer d'ici créerait un cycle (mitigate -> iris -> ... ) pour deux appels
# GET en lecture seule.

def _token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


def inventaire_manager() -> list[dict]:
    """Agents connus du manager, avec leurs groupes. Lecture seule."""
    tok = _token()
    r = requests.get(
        f"{config.WAZUH_API_URL}/agents",
        params={"select": "id,name,ip,os.platform,group", "limit": 2000},
        headers={"Authorization": f"Bearer {tok}"},
        verify=False, timeout=30)
    r.raise_for_status()
    return r.json().get("data", {}).get("affected_items", []) or []


UPSERT = """
INSERT INTO assets (agent_id, nom, ip, os, groupes, role, priorite,
                    priorite_source, vu_a, maj_a)
VALUES (%(agent_id)s, %(nom)s, %(ip)s, %(os)s, %(groupes)s, %(role)s,
        %(priorite)s, %(source)s, now(), now())
ON CONFLICT (agent_id) DO UPDATE SET
    nom      = EXCLUDED.nom,
    ip       = EXCLUDED.ip,
    os       = EXCLUDED.os,
    groupes  = EXCLUDED.groupes,
    vu_a     = now(),
    -- Une priorité posée à la main par l'opérateur n'est JAMAIS écrasée par la
    -- synchronisation : elle exprime une connaissance métier que les groupes
    -- Wazuh n'ont pas. Pour la reprendre, il faut la retirer explicitement
    -- (`--reprendre <agent>`).
    role     = CASE WHEN assets.priorite_source = 'operateur'
                    THEN assets.role ELSE EXCLUDED.role END,
    priorite = CASE WHEN assets.priorite_source = 'operateur'
                    THEN assets.priorite ELSE EXCLUDED.priorite END,
    priorite_source = CASE WHEN assets.priorite_source = 'operateur'
                    THEN 'operateur' ELSE EXCLUDED.priorite_source END,
    maj_a    = now()
RETURNING (xmax = 0) AS cree
"""


def synchroniser() -> dict:
    """Aligne la CMDB sur ce que le manager déclare. Retourne un récapitulatif.

    Best-effort par construction : appelée dans le cycle, une API Wazuh
    injoignable ne doit pas coûter un tour de pipeline. L'appelant décide.
    """
    agents = inventaire_manager()
    resume = {"vus": len(agents), "crees": 0, "maj": 0, "par_priorite": {}}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        for a in agents:
            groupes = [str(g).lower() for g in (a.get("group") or [])]
            role = role_depuis_groupes(groupes)
            priorite = priorite_du_role(role)
            r = conn.execute(UPSERT, {
                "agent_id": str(a.get("id")),
                "nom": a.get("name"),
                "ip": a.get("ip"),
                "os": ((a.get("os") or {}).get("platform")
                       if isinstance(a.get("os"), dict) else a.get("os")),
                "groupes": groupes,
                "role": role,
                "priorite": priorite,
                "source": "groupe" if role else "defaut",
            }).fetchone()
            resume["crees" if r["cree"] else "maj"] += 1
            resume["par_priorite"][priorite] = (
                resume["par_priorite"].get(priorite, 0) + 1)
        conn.commit()
    return resume


def definir(agent_id: str, role: str | None = None,
            priorite: int | None = None, notes: str | None = None,
            source: str = "operateur") -> dict:
    """Pose ou corrige la priorité d'un asset. `role` OU `priorite`.

    Une priorité posée ici est marquée `operateur` et survit aux
    synchronisations : c'est l'échappatoire quand les groupes Wazuh ne suffisent
    pas (machine qu'on ne peut pas regrouper, exception temporaire).
    """
    if role is not None:
        role = str(role).lower()
        if role not in config.PRIORITE_ROLES:
            raise ValueError(
                f"rôle inconnu : « {role} ». Rôles connus : "
                f"{', '.join(sorted(config.PRIORITE_ROLES))} (en ajouter un via "
                f"PRIORITE_ROLES).")
        if priorite is None:
            priorite = config.PRIORITE_ROLES[role]
    if priorite is None:
        raise ValueError("préciser au moins un rôle ou une priorité")
    if not 1 <= int(priorite) <= 4:
        raise ValueError(f"priorité hors échelle P1-P4 : {priorite}")

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        ligne = conn.execute(
            "INSERT INTO assets (agent_id, role, priorite, priorite_source, "
            "                    notes, vu_a, maj_a) "
            "VALUES (%s, %s, %s, %s, %s, now(), now()) "
            # COALESCE sur le rôle : forcer une priorité seule (échappatoire
            # hors catalogue) ne doit pas effacer le rôle déjà connu — l'asset
            # deviendrait « non déclaré » dans le rapport de couverture alors
            # qu'on vient justement de le classer.
            "ON CONFLICT (agent_id) DO UPDATE "
            "SET role = COALESCE(EXCLUDED.role, assets.role), "
            "  priorite = EXCLUDED.priorite, "
            "  priorite_source = EXCLUDED.priorite_source, "
            "  notes = COALESCE(EXCLUDED.notes, assets.notes), maj_a = now() "
            "RETURNING agent_id, nom, role, priorite, priorite_source, notes",
            (str(agent_id), role, int(priorite), source, notes)).fetchone()
        conn.commit()
    return dict(ligne)


def lister(priorite: int | None = None) -> list[dict]:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT agent_id, nom, ip, os, role, priorite, priorite_source, "
            "       groupes, notes, vu_a "
            "  FROM assets WHERE (%s::int IS NULL OR priorite = %s::int) "
            " ORDER BY priorite, nom", (priorite, priorite)).fetchall()]


def couverture() -> dict:
    """Dette d'inventaire : qui tourne sans rôle déclaré.

    Le complément indispensable du choix « P4 par défaut ». Sans cette vue, une
    machine critique jamais déclarée est traitée comme un poste jetable, et rien
    ne le dit.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        par_prio = {r["priorite"]: r["n"] for r in conn.execute(
            "SELECT priorite, count(*) AS n FROM assets GROUP BY priorite")}
        sans_role = [dict(r) for r in conn.execute(
            "SELECT agent_id, nom, ip, os FROM assets "
            " WHERE priorite_source = 'defaut' ORDER BY nom").fetchall()]
    return {"par_priorite": par_prio, "sans_role_declare": sans_role,
            "dette": len(sans_role)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sync", action="store_true",
                    help="aligne la CMDB sur les groupes du manager Wazuh")
    ap.add_argument("--couverture", action="store_true",
                    help="agents sans rôle déclaré (traités en P%d)"
                         % config.PRIORITE_DEFAUT)
    ap.add_argument("--lister", action="store_true")
    ap.add_argument("--definir", metavar="AGENT_ID",
                    help="pose une priorité d'opérateur sur un agent")
    ap.add_argument("--role")
    ap.add_argument("--priorite", type=int)
    ap.add_argument("--notes")
    args = ap.parse_args()

    if args.sync:
        r = synchroniser()
        print(f"{r['vus']} agents : {r['crees']} créés, {r['maj']} mis à jour")
        for p in sorted(r["par_priorite"]):
            print(f"  P{p} : {r['par_priorite'][p]}")
    if args.definir:
        print(definir(args.definir, args.role, args.priorite, args.notes))
    if args.lister:
        for a in lister():
            print(f"P{a['priorite']} {a['nom'] or a['agent_id']:<20} "
                  f"{a['role'] or '-':<12} {a['priorite_source']}")
    if args.couverture:
        c = couverture()
        print(f"répartition : "
              + ", ".join(f"P{p}={n}" for p, n in sorted(c["par_priorite"].items())))
        if c["dette"]:
            print(f"\n{c['dette']} agent(s) SANS rôle déclaré — traités en "
                  f"P{config.PRIORITE_DEFAUT}, donc en fin de file :")
            for a in c["sans_role_declare"]:
                print(f"  {a['agent_id']:<5} {a['nom'] or '?':<24} {a['ip'] or ''}")


if __name__ == "__main__":
    main()
