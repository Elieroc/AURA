"""Ingestion des alertes Wazuh depuis l'indexer vers Postgres.

Tire par lots à partir d'un curseur persisté, sans rien modifier côté manager.
Idempotent : rejouer une fenêtre ne crée pas de doublons (ON CONFLICT sur
l'identifiant natif Wazuh).

    python -m soc_agent.ingest [--depuis 30d] [--taille-lot 500]
"""

import argparse
import json
import sys
from datetime import datetime, timezone

import psycopg
import requests
import urllib3

from . import config, noise

# L'indexer utilise les certificats auto-signés de la stack Wazuh, sur la
# loopback. L'avertissement urllib3 noierait la sortie à chaque lot ; la
# vérification TLS reste pilotée par INDEXER_VERIFY_TLS.
if not config.INDEXER_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _liste(valeur) -> list[str]:
    """Wazuh rend tantôt une chaîne, tantôt une liste, tantôt rien."""
    if valeur is None:
        return []
    if isinstance(valeur, list):
        return [str(v) for v in valeur]
    return [str(valeur)]


def _premier(src: dict, chemins: list[tuple]) -> str | None:
    """Première valeur non vide parmi plusieurs emplacements possibles.

    Wazuh et ses intégrations rangent la même information à des endroits
    différents selon le décodeur qui a traité l'événement.
    """
    for chemin in chemins:
        noeud = src
        for cle in chemin:
            noeud = noeud.get(cle) if isinstance(noeud, dict) else None
            if noeud is None:
                break
        if isinstance(noeud, str) and noeud:
            return noeud
    return None


def _entite(src: dict) -> str | None:
    """Objet concerné par l'alerte, pour rapprocher des règles différentes.

    Une même intrusion déclenche des règles distinctes qui pointent le même
    fichier ou le même processus ; c'est ce point commun qui permet de les
    recoller en un incident.
    """
    return _premier(src, [
        ("syscheck", "path"),
        ("data", "virustotal", "source", "file"),
        ("data", "audit", "exe"),
        ("data", "audit", "file", "name"),
        ("data", "win", "eventdata", "image"),
    ])


def _aplatir(src: dict, filtre: noise.NoiseFilter) -> dict:
    """Document indexer -> ligne de la table alerts."""
    regle = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})
    mitre = regle.get("mitre", {})
    raison = filtre.raison_suppression(src)

    return {
        "id": src["id"],
        "ts": src["@timestamp"],
        "agent_id": agent.get("id", "?"),
        "agent_name": agent.get("name"),
        "rule_id": str(regle.get("id", "?")),
        "rule_level": int(regle.get("level", 0)),
        "rule_desc": regle.get("description"),
        "rule_groups": _liste(regle.get("groups")),
        "mitre_ids": _liste(mitre.get("id")),
        "mitre_tactics": _liste(mitre.get("tactic")),
        "srcip": _premier(src, [
            ("data", "srcip"),
            # Les intégrations rangent l'IP sous leur propre clé. Sans cette
            # entrée, les alertes AbuseIPDB — celles qui portent justement la
            # réputation — arrivaient sans IP source, donc incorrélables.
            ("data", "abuseipdb", "srcip"),
            ("data", "virustotal", "source", "srcip"),
            ("GeoLocation", "ip"),
        ]),
        "srcuser": _premier(src, [
            ("data", "srcuser"),
            ("data", "dstuser"),
            ("data", "win", "eventdata", "targetUserName"),
        ]),
        "entity": _entite(src),
        # Suppression post-retrieval du noise filter : l'alerte est ingérée
        # mais marquée, pour rester relisible tout en sortant de la corrélation.
        "suppress_reason": raison,
        # Booléen dérivé calculé en Python : le passer en SQL via
        # `%(...)s IS NOT NULL` rendait le type du paramètre indéterminable
        # pour Postgres quand la raison est NULL (AmbiguousParameter).
        "suppressed": raison is not None,
        "raw": json.dumps(src),
    }


INSERT = """
INSERT INTO alerts (id, ts, agent_id, agent_name, rule_id, rule_level,
                    rule_desc, rule_groups, mitre_ids, mitre_tactics,
                    srcip, srcuser, entity, suppressed, suppress_reason, raw)
VALUES (%(id)s, %(ts)s, %(agent_id)s, %(agent_name)s, %(rule_id)s,
        %(rule_level)s, %(rule_desc)s, %(rule_groups)s, %(mitre_ids)s,
        %(mitre_tactics)s, %(srcip)s, %(srcuser)s, %(entity)s,
        %(suppressed)s, %(suppress_reason)s, %(raw)s)
ON CONFLICT (id) DO NOTHING
"""


def _lot(depuis: str | None, apres: tuple | None, taille: int,
         filtre: noise.NoiseFilter) -> list[dict]:
    """Un lot d'alertes, trié par (timestamp, id) pour une reprise fiable."""
    requete: dict = {"bool": {"filter": [], "must_not": []}}
    if config.INGEST_MIN_LEVEL > 0:
        requete["bool"]["filter"].append(
            {"range": {"rule.level": {"gte": config.INGEST_MIN_LEVEL}}})
    if depuis:
        requete["bool"]["filter"].append(
            {"range": {"@timestamp": {"gte": f"now-{depuis}"}}})
    # Bouclier d'ingestion : le bruit certain (query_level: true) est écarté
    # côté indexer, il n'entre jamais en base.
    requete["bool"]["must_not"] = filtre.clauses_must_not()
    if not requete["bool"]["filter"] and not requete["bool"]["must_not"]:
        requete = {"match_all": {}}

    corps = {
        "size": taille,
        "query": requete,
        # search_after impose un tri total ; le tri sur le seul @timestamp ne
        # l'est pas, plusieurs alertes partageant la même milliseconde.
        "sort": [{"@timestamp": "asc"}, {"id": "asc"}],
    }
    if apres:
        corps["search_after"] = list(apres)

    rep = requests.post(
        f"{config.INDEXER_URL}/{config.INDEXER_ALERT_INDICES}/_search",
        json=corps,
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=60,
    )
    rep.raise_for_status()
    return rep.json()["hits"]["hits"]


def ingerer(depuis: str | None, taille_lot: int) -> int:
    total = 0
    with psycopg.connect(config.PG_DSN) as conn:
        # Filtre construit une fois par run, whitelist auto (DB) comprise.
        filtre = noise.charger_avec_db(conn)

        with conn.cursor() as cur:
            cur.execute("SELECT last_ts, last_alert_id FROM ingest_cursor")
            ligne = cur.fetchone()

        # Le curseur prime sur --depuis : une reprise ne doit pas re-balayer
        # une fenêtre déjà traitée.
        apres = None
        if ligne and ligne[0]:
            apres = (int(ligne[0].timestamp() * 1000), ligne[1])
            depuis = None

        while True:
            hits = _lot(depuis, apres, taille_lot, filtre)
            if not hits:
                break

            lignes = [_aplatir(h["_source"], filtre) for h in hits]
            with conn.cursor() as cur:
                cur.executemany(INSERT, lignes)
                dernier = hits[-1]
                cur.execute(
                    """INSERT INTO ingest_cursor (id, last_ts, last_alert_id, updated_at)
                       VALUES (true, %s, %s, now())
                       ON CONFLICT (id) DO UPDATE
                         SET last_ts = EXCLUDED.last_ts,
                             last_alert_id = EXCLUDED.last_alert_id,
                             updated_at = now()""",
                    (dernier["_source"]["@timestamp"], dernier["_source"]["id"]),
                )
            conn.commit()

            total += len(hits)
            apres = tuple(dernier["sort"])
            depuis = None
            print(f"  {total} alertes ingérées…", file=sys.stderr)

            if len(hits) < taille_lot:
                break
    return total


def reappliquer_filtre() -> tuple[int, int]:
    """Réévalue la suppression du noise filter sur les alertes déjà en base.

    L'ingestion étant idempotente, un filtre modifié ne s'applique pas tout
    seul à l'existant — c'est pourtant le cas d'usage normal, le filtre
    s'enrichit en exploitation. On rejoue donc la décision à partir du document
    brut conservé. Ne touche pas au rattachement : une alerte nouvellement
    supprimée sortira de la corrélation au prochain `correlate --recommencer`.
    """
    vus = supprimees = 0
    with psycopg.connect(config.PG_DSN, row_factory=psycopg.rows.dict_row) as conn:
        filtre = noise.charger_avec_db(conn)
        lignes = conn.execute("SELECT id, raw FROM alerts").fetchall()
        for ligne in lignes:
            vus += 1
            raison = filtre.raison_suppression(ligne["raw"])
            if raison:
                supprimees += 1
            conn.execute(
                "UPDATE alerts SET suppressed = %s, suppress_reason = %s "
                "WHERE id = %s",
                (raison is not None, raison, ligne["id"]))
        conn.commit()
    return supprimees, vus


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--depuis", default="30d",
                    help="fenêtre au premier passage (ignorée si un curseur existe)")
    ap.add_argument("--taille-lot", type=int, default=500)
    ap.add_argument("--reinitialiser-curseur", action="store_true",
                    help="repart du début ; l'ingestion étant idempotente, "
                         "cela ne duplique rien")
    ap.add_argument("--reappliquer-filtre", action="store_true",
                    help="réévalue le noise filter sur les alertes déjà en "
                         "base, sans réingérer")
    args = ap.parse_args()

    if args.reappliquer_filtre:
        supp, vus = reappliquer_filtre()
        print(f"Noise filter réappliqué : {supp}/{vus} alertes supprimées.")
        print("Lancer `correlate --recommencer` pour recorréler.")
        return

    if args.reinitialiser_curseur:
        with psycopg.connect(config.PG_DSN) as conn:
            conn.execute("DELETE FROM ingest_cursor")
            conn.commit()
        print("Curseur réinitialisé.")

    debut = datetime.now(timezone.utc)
    n = ingerer(args.depuis, args.taille_lot)
    duree = (datetime.now(timezone.utc) - debut).total_seconds()
    print(f"{n} alertes traitées en {duree:.1f} s")


if __name__ == "__main__":
    main()
