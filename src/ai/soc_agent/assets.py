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

def role_from_groups(groups) -> str | None:
    """Rôle déclaré par les groupes Wazuh de l'agent, ou None.

    Une machine peut porter plusieurs rôles (`role-web` + `role-db` sur un LAMP
    mutualisé) : c'est le plus critique qui l'emporte. Sous-estimer un asset
    mixte serait le pire des deux mondes — on le traiterait comme sa moitié la
    moins importante.
    """
    prefix = config.CMDB_GROUP_PREFIX
    roles = [str(g).lower()[len(prefix):] for g in (groups or [])
             if str(g).lower().startswith(prefix)]
    known = [r for r in roles if r in config.PRIORITY_ROLES]
    if not known:
        return None
    return min(known, key=lambda r: config.PRIORITY_ROLES[r])


def role_priority(role: str | None) -> int:
    """Priorité d'un rôle, ou PRIORITE_DEFAUT s'il est inconnu."""
    if not role:
        return config.DEFAULT_PRIORITY
    return config.PRIORITY_ROLES.get(str(role).lower(), config.DEFAULT_PRIORITY)


def severity(max_level: int, priority: int) -> int:
    """Sévérité EFFECTIVE d'un incident : niveau Wazuh corrigé par l'asset.

    Fonction pure, bornée à l'échelle Wazuh (1-15) pour rester lisible à côté de
    `max_level` et comparable d'un incident à l'autre. On ne modifie jamais
    `max_level` lui-même : la corrélation, UEBA et `RULES_COMPROMISSION_HOTE`
    s'appuient dessus, et un décalage silencieux changerait le sens de tous les
    seuils existants.
    """
    bonus = config.SEVERITY_BONUS_PRIORITY.get(priority, 0)
    return max(1, min(15, int(max_level) + bonus))


# La table est-elle là ? Testé une fois par processus, et par une requête qui
# ne peut pas ÉCHOUER (`to_regclass` rend NULL au lieu de lever). Sans cela, un
# déploiement où la migration de `schema.sql` a été oubliée verrait la
# corrélation lever au premier incident — donc plus d'incidents du tout, pour
# une colonne d'agrément. Une priorisation absente doit dégrader le tri, jamais
# arrêter le SOC.
_TABLE_READY: bool | None = None


def _available(conn) -> bool:
    global _TABLE_READY
    if _TABLE_READY is None:
        _TABLE_READY = bool(conn.execute(
            "SELECT to_regclass('public.assets') IS NOT NULL AS ok"
        ).fetchone()["ok"])
        if not _TABLE_READY:
            log.warning(
                "table `assets` absente : tous les incidents naîtront en P%d. "
                "Appliquer soc_agent/schema.sql (cf. docs/CMDB.md).",
                config.DEFAULT_PRIORITY)
    return _TABLE_READY


def agent_priority(conn, agent_id: str, container: str | None = None) -> dict:
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
    if not _available(conn):
        return {"priority": config.DEFAULT_PRIORITY, "role": None,
                "source": "defaut"}

    if container:
        line = _read(conn, name=container)
        if line:
            return {"priority": line["priority"], "role": line["role"],
                    "source": line["priority_source"]}

    if str(agent_id) in config.AGENTS_SENSORS:
        return {"priority": config.PRIORITY_SENSOR, "role": "sensor",
                "source": "sensor"}

    line = _read(conn, agent_id=str(agent_id))
    if line:
        return {"priority": line["priority"], "role": line["role"],
                "source": line["priority_source"]}
    return {"priority": config.DEFAULT_PRIORITY, "role": None,
            "source": "defaut"}


def _read(conn, agent_id: str | None = None, name: str | None = None):
    if agent_id is not None:
        return conn.execute(
            "SELECT agent_id, name, role, priority, priority_source "
            "  FROM assets WHERE agent_id = %s", (agent_id,)).fetchone()
    return conn.execute(
        "SELECT agent_id, name, role, priority, priority_source "
        "  FROM assets WHERE name = %s LIMIT 1", (name,)).fetchone()


def label(priority: int, role: str | None) -> str:
    """« P1 — contrôleur de domaine (dc) », pour le prompt et les cases IRIS."""
    return f"P{priority}" + (f" ({role})" if role else " (rôle non déclaré)")


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


def manager_inventory() -> list[dict]:
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
INSERT INTO assets (agent_id, name, ip, os, groups, role, priority,
                    priority_source, seen_at, updated_at)
VALUES (%(agent_id)s, %(name)s, %(ip)s, %(os)s, %(groups)s, %(role)s,
        %(priority)s, %(source)s, now(), now())
ON CONFLICT (agent_id) DO UPDATE SET
    name      = EXCLUDED.name,
    ip       = EXCLUDED.ip,
    os       = EXCLUDED.os,
    groups  = EXCLUDED.groups,
    seen_at     = now(),
    -- Une priorité posée à la main par l'opérateur n'est JAMAIS écrasée par la
    -- synchronisation : elle exprime une connaissance métier que les groups
    -- Wazuh n'ont pas. Pour la reprendre, il faut la retirer explicitement
    -- (`--reprendre <agent>`).
    role     = CASE WHEN assets.priority_source = 'operateur'
                    THEN assets.role ELSE EXCLUDED.role END,
    priority = CASE WHEN assets.priority_source = 'operateur'
                    THEN assets.priority ELSE EXCLUDED.priority END,
    priority_source = CASE WHEN assets.priority_source = 'operateur'
                    THEN 'operateur' ELSE EXCLUDED.priority_source END,
    updated_at    = now()
RETURNING (xmax = 0) AS cree
"""


def sync() -> dict:
    """Aligne la CMDB sur ce que le manager déclare. Retourne un récapitulatif.

    Best-effort par construction : appelée dans le cycle, une API Wazuh
    injoignable ne doit pas coûter un tour de pipeline. L'appelant décide.
    """
    agents = manager_inventory()
    resume = {"vus": len(agents), "crees": 0, "maj": 0, "par_priorite": {}}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        for a in agents:
            groups = [str(g).lower() for g in (a.get("group") or [])]
            role = role_from_groups(groups)
            priority = role_priority(role)
            r = conn.execute(UPSERT, {
                "agent_id": str(a.get("id")),
                "name": a.get("name"),
                "ip": a.get("ip"),
                "os": ((a.get("os") or {}).get("platform")
                       if isinstance(a.get("os"), dict) else a.get("os")),
                "groups": groups,
                "role": role,
                "priority": priority,
                "source": "groupe" if role else "defaut",
            }).fetchone()
            resume["crees" if r["cree"] else "maj"] += 1
            resume["par_priorite"][priority] = (
                resume["par_priorite"].get(priority, 0) + 1)
        conn.commit()
    return resume


def definir(agent_id: str, role: str | None = None,
            priority: int | None = None, notes: str | None = None,
            source: str = "operateur") -> dict:
    """Pose ou corrige la priorité d'un asset. `role` OU `priorite`.

    Une priorité posée ici est marquée `operateur` et survit aux
    synchronisations : c'est l'échappatoire quand les groupes Wazuh ne suffisent
    pas (machine qu'on ne peut pas regrouper, exception temporaire).
    """
    if role is not None:
        role = str(role).lower()
        if role not in config.PRIORITY_ROLES:
            raise ValueError(
                f"rôle inconnu : « {role} ». Rôles connus : "
                f"{', '.join(sorted(config.PRIORITY_ROLES))} (en ajouter un via "
                f"PRIORITE_ROLES).")
        if priority is None:
            priority = config.PRIORITY_ROLES[role]
    if priority is None:
        raise ValueError("préciser au moins un rôle ou une priorité")
    if not 1 <= int(priority) <= 4:
        raise ValueError(f"priorité hors échelle P1-P4 : {priority}")

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        line = conn.execute(
            "INSERT INTO assets (agent_id, role, priority, priority_source, "
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
            "RETURNING agent_id, name, role, priority, priority_source, notes",
            (str(agent_id), role, int(priority), source, notes)).fetchone()
        conn.commit()
    return dict(line)


def list(priority: int | None = None) -> list[dict]:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT agent_id, name, ip, os, role, priority, priority_source, "
            "       groupes, notes, vu_a "
            "  FROM assets WHERE (%s::int IS NULL OR priority = %s::int) "
            " ORDER BY priority, name", (priority, priority)).fetchall()]


def coverage() -> dict:
    """Dette d'inventaire : qui tourne sans rôle déclaré.

    Le complément indispensable du choix « P4 par défaut ». Sans cette vue, une
    machine critique jamais déclarée est traitée comme un poste jetable, et rien
    ne le dit.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        by_prio = {r["priority"]: r["n"] for r in conn.execute(
            "SELECT priority, count(*) AS n FROM assets GROUP BY priority")}
        sans_role = [dict(r) for r in conn.execute(
            "SELECT agent_id, name, ip, os FROM assets "
            " WHERE priority_source = 'defaut' ORDER BY name").fetchall()]
    return {"par_priorite": by_prio, "sans_role_declare": sans_role,
            "dette": len(sans_role)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sync", action="store_true",
                    help="aligne la CMDB sur les groupes du manager Wazuh")
    ap.add_argument("--couverture", action="store_true",
                    help="agents sans rôle déclaré (traités en P%d)"
                         % config.DEFAULT_PRIORITY)
    ap.add_argument("--lister", action="store_true")
    ap.add_argument("--definir", metavar="AGENT_ID",
                    help="pose une priorité d'opérateur sur un agent")
    ap.add_argument("--role")
    ap.add_argument("--priorite", type=int)
    ap.add_argument("--notes")
    args = ap.parse_args()

    if args.sync:
        r = sync()
        print(f"{r['vus']} agents : {r['crees']} créés, {r['maj']} mis à jour")
        for p in sorted(r["par_priorite"]):
            print(f"  P{p} : {r['par_priorite'][p]}")
    if args.definir:
        print(definir(args.definir, args.role, args.priority, args.notes))
    if args.list:
        for a in list():
            print(f"P{a['priority']} {a['name'] or a['agent_id']:<20} "
                  f"{a['role'] or '-':<12} {a['priority_source']}")
    if args.coverage:
        c = coverage()
        print(f"répartition : "
              + ", ".join(f"P{p}={n}" for p, n in sorted(c["par_priorite"].items())))
        if c["dette"]:
            print(f"\n{c['dette']} agent(s) SANS rôle déclaré — traités en "
                  f"P{config.DEFAULT_PRIORITY}, donc en fin de file :")
            for a in c["sans_role_declare"]:
                print(f"  {a['agent_id']:<5} {a['name'] or '?':<24} {a['ip'] or ''}")


if __name__ == "__main__":
    main()
