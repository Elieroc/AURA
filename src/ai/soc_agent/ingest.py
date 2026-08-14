"""Ingestion des alertes Wazuh depuis l'indexer vers Postgres.

Tire par lots à partir d'un curseur persisté, sans rien modifier côté manager.
Idempotent : rejouer une fenêtre ne crée pas de doublons (ON CONFLICT sur
l'identifiant natif Wazuh).

    python -m soc_agent.ingest [--depuis 30d] [--taille-lot 500]
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone

import psycopg
import requests
import urllib3

from . import config, noise, routing

# --- Attribution conteneur LXC (auditd de l'hôte Proxmox) --------------------
# L'agent pve (009) capte l'execve de TOUS les conteneurs LXC (noyau partagé) ;
# `data.lxc_ct` (extrait par le pipeline indexer) — ou le tag dans full_log en
# repli — dit lequel. On réattribue alors l'alerte à l'agent Wazuh PROPRE du
# conteneur quand il en a un (jellyfin -> 005) : la corrélation se fait par
# conteneur (agent_id est la clé) et la remédiation vise le bon hôte. Sinon on
# garde pve et on note le conteneur dans la colonne `container` pour la lisibilité.
_HOST_AUDITD = {"pve", "009"}
_CT_IGNORE = {"", "host", "unknown"}
_LXC_CT = re.compile(r"lxc_ct=([A-Za-z0-9_.-]+)")
_AGENTS: dict[str, str] = {}   # nom de conteneur -> agent_id Wazuh propre


def _load_agents(conn) -> None:
    """Carte nom d'agent -> id, pour réattribuer un conteneur à son propre agent.
    Rechargée à chaque run d'ingestion (agents stables, requête triviale)."""
    _AGENTS.clear()
    for name, aid in conn.execute(
            "SELECT DISTINCT agent_name, agent_id FROM alerts "
            "WHERE agent_name IS NOT NULL"):
        if name and name not in _HOST_AUDITD:
            _AGENTS.setdefault(name, aid)

# L'indexer utilise les certificats auto-signés de la stack Wazuh, sur la
# loopback. L'avertissement urllib3 noierait la sortie à chaque lot ; la
# vérification TLS reste pilotée par INDEXER_VERIFY_TLS.
if not config.INDEXER_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _list(value) -> list[str]:
    """Wazuh rend tantôt une chaîne, tantôt une liste, tantôt rien."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _first(src: dict, paths: list[tuple]) -> str | None:
    """Première valeur non vide parmi plusieurs emplacements possibles.

    Wazuh et ses intégrations rangent la même information à des endroits
    différents selon le décodeur qui a traité l'événement.
    """
    for path in paths:
        node = src
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, str) and node:
            return node
    return None


def _entity(src: dict) -> str | None:
    """Objet concerné par l'alerte, pour rapprocher des règles différentes.

    Une même intrusion déclenche des règles distinctes qui pointent le même
    fichier ou le même processus ; c'est ce point commun qui permet de les
    recoller en un incident.
    """
    return _first(src, [
        ("syscheck", "path"),
        ("data", "virustotal", "source", "file"),
        ("data", "audit", "exe"),
        ("data", "audit", "file", "name"),
        ("data", "win", "eventdata", "image"),
    ])


def _flatten(src: dict, noise_filter: noise.NoiseFilter) -> dict:
    """Document indexer -> ligne de la table alerts."""
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})
    mitre = rule.get("mitre", {})
    reason = noise_filter.deletion_reason(src)

    # Attribution conteneur : si l'émetteur est l'hôte auditd (pve) et que le
    # conteneur d'origine est résolu, on réattribue à son agent propre quand il
    # existe, et on trace le conteneur dans tous les cas.
    agent_id = agent.get("id", "?")
    agent_name = agent.get("name")
    container = None
    lxc = data.get("lxc_ct") or ""
    if not lxc:
        m = _LXC_CT.search(src.get("full_log") or "")
        lxc = m.group(1) if m else ""
    if lxc not in _CT_IGNORE and (agent_name in _HOST_AUDITD
                                  or agent_id in _HOST_AUDITD):
        container = lxc
        own = _AGENTS.get(lxc)
        if own:
            agent_id, agent_name = own, lxc

    return {
        "id": src["id"],
        "ts": src["@timestamp"],
        "agent_id": agent_id,
        "agent_name": agent_name,
        "container": container,
        "rule_id": str(rule.get("id", "?")),
        "rule_level": int(rule.get("level", 0)),
        "rule_desc": rule.get("description"),
        "rule_groups": _list(rule.get("groups")),
        "mitre_ids": _list(mitre.get("id")),
        "mitre_tactics": _list(mitre.get("tactic")),
        "srcip": _first(src, [
            ("data", "srcip"),
            # Les intégrations rangent l'IP sous leur propre clé. Sans cette
            # entrée, les alertes AbuseIPDB — celles qui portent justement la
            # réputation — arrivaient sans IP source, donc incorrélables.
            ("data", "abuseipdb", "srcip"),
            ("data", "virustotal", "source", "srcip"),
            ("GeoLocation", "ip"),
        ]),
        "srcuser": _first(src, [
            ("data", "srcuser"),
            ("data", "dstuser"),
            ("data", "win", "eventdata", "targetUserName"),
        ]),
        "entity": _entity(src),
        # UID auditd de l'événement. Sert à la corrélation : les actions de
        # l'attaquant (et de ses descendants privesc par SUID, qui gardent
        # l'uid réel) partagent cet uid, ce qui distingue son activité du bruit
        # de fond légitime de la même machine (démons, sessions de login).
        "audit_uid": (data.get("audit", {}) or {}).get("uid"),
        # Suppression post-retrieval du noise filter : l'alerte est ingérée
        # mais marquée, pour rester relisible tout en sortant de la corrélation.
        "suppress_reason": reason,
        # Booléen dérivé calculé en Python : le passer en SQL via
        # `%(...)s IS NOT NULL` rendait le type du paramètre indéterminable
        # pour Postgres quand la raison est NULL (AmbiguousParameter).
        "suppressed": reason is not None,
        "raw": json.dumps(src),
    }


INSERT = """
INSERT INTO alerts (id, ts, agent_id, agent_name, container, rule_id, rule_level,
                    rule_desc, rule_groups, mitre_ids, mitre_tactics,
                    srcip, srcuser, entity, audit_uid, suppressed,
                    suppress_reason, raw)
VALUES (%(id)s, %(ts)s, %(agent_id)s, %(agent_name)s, %(container)s, %(rule_id)s,
        %(rule_level)s, %(rule_desc)s, %(rule_groups)s, %(mitre_ids)s,
        %(mitre_tactics)s, %(srcip)s, %(srcuser)s, %(entity)s, %(audit_uid)s,
        %(suppressed)s, %(suppress_reason)s, %(raw)s)
ON CONFLICT (id) DO NOTHING
"""


def _batch(since: str | None, after: tuple | None, size: int,
         noise_filter: noise.NoiseFilter) -> list[dict]:
    """Un lot d'alertes, trié par (timestamp, id) pour une reprise fiable."""
    query: dict = {"bool": {"filter": [], "must_not": []}}
    if config.INGEST_MIN_LEVEL > 0:
        query["bool"]["filter"].append(
            {"range": {"rule.level": {"gte": config.INGEST_MIN_LEVEL}}})
    if since:
        query["bool"]["filter"].append(
            {"range": {"@timestamp": {"gte": f"now-{since}"}}})
    # Bouclier d'ingestion : le bruit certain (query_level: true) est écarté
    # côté indexer, il n'entre jamais en base.
    query["bool"]["must_not"] = noise_filter.clauses_must_not()
    if not query["bool"]["filter"] and not query["bool"]["must_not"]:
        query = {"match_all": {}}

    body = {
        "size": size,
        "query": query,
        # search_after impose un tri total ; le tri sur le seul @timestamp ne
        # l'est pas, plusieurs alertes partageant la même milliseconde.
        "sort": [{"@timestamp": "asc"}, {"id": "asc"}],
    }
    if after:
        body["search_after"] = list(after)

    rep = requests.post(
        # Liste statique UNION les index sets créés depuis par routage.py :
        # un index créé sans être ajouté ici est un capteur que l'IA ne voit
        # pas, en silence (cf. routage.indices_lus).
        f"{config.INDEXER_URL}/{routing.read_indices()}/_search",
        json=body,
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=60,
    )
    rep.raise_for_status()
    return rep.json()["hits"]["hits"]


UPDATE_CURSOR = """
INSERT INTO ingest_cursor (id, last_ts, last_alert_id, updated_at)
VALUES (true, %s, %s, now())
ON CONFLICT (id) DO UPDATE
  SET last_ts = EXCLUDED.last_ts,
      last_alert_id = EXCLUDED.last_alert_id,
      updated_at = now()
"""

UPDATE_SWEEP = """
INSERT INTO ingest_cursor (id, last_sweep_at) VALUES (true, now())
ON CONFLICT (id) DO UPDATE SET last_sweep_at = now()
"""


def _iterate(conn, noise_filter: noise.NoiseFilter, since: str | None,
               after: tuple | None, batch_size: int, *,
               advance_cursor: bool, label: str) -> tuple[int, int]:
    """Pagine une fenêtre et insère. Retourne (vues, nouvelles).

    `avancer_curseur=False` pour le sweep de rattrapage : il balaye en arrière
    et ne doit surtout pas repositionner le curseur du flux normal.
    """
    seen = new = 0
    while True:
        hits = _batch(since, after, batch_size, noise_filter)
        if not hits:
            break

        lines = [_flatten(h["_source"], noise_filter) for h in hits]
        with conn.cursor() as cur:
            cur.executemany(INSERT, lines)
            # ON CONFLICT DO NOTHING : rowcount ne compte que les vraies
            # insertions, ce qui donne le nombre d'alertes réellement récupérées
            # (utile pour le sweep, où la quasi-totalité du lot est déjà connue).
            new += max(cur.rowcount, 0)
            last = hits[-1]
            if advance_cursor:
                cur.execute(UPDATE_CURSOR, (last["_source"]["@timestamp"],
                                          last["_source"]["id"]))
        conn.commit()

        seen += len(hits)
        after = tuple(last["sort"])
        print(f"  {label} : {seen} alertes vues, {new} nouvelles…",
              file=sys.stderr)

        if len(hits) < batch_size:
            break
    return seen, new


def _sweep_du(conn, batch_size: int, noise_filter: noise.NoiseFilter) -> int:
    """Rebalaye une longue fenêtre pour récupérer les alertes indexées en retard.

    Le curseur avance sur `@timestamp`, la date de l'ÉVÉNEMENT, pas celle de son
    indexation. Un agent Wazuh coupé du manager bufferise ses logs et les rejoue
    à la reconnexion avec leur horodatage d'origine : si le curseur est déjà
    passé, `search_after` ne les renverra JAMAIS et ces alertes sont perdues
    pour de bon — jamais ingérées, donc jamais corrélées ni triées. Le lookback
    de `ingerer()` ne couvre qu'un décalage de quelques minutes ; une coupure
    d'agent se compte en heures ou en jours.

    D'où ce balayage complet et périodique de `INGEST_SWEEP_HOURS`, indépendant
    du curseur. L'ingestion étant idempotente, il ne coûte que la lecture — et
    au niveau de volume observé (quelques centaines d'alertes/jour), c'est
    négligeable devant un triage LLM.
    """
    _, new = _iterate(
        conn, noise_filter, f"{config.INGEST_SWEEP_HOURS}h", None, batch_size,
        advance_cursor=False, label="rattrapage")
    conn.execute(UPDATE_SWEEP)
    conn.commit()
    return new


def ingerer(since: str | None, batch_size: int,
            forcer_sweep: bool = False) -> int:
    total = 0
    with psycopg.connect(config.PG_DSN) as conn:
        # Filtre construit une fois par run, whitelist auto (DB) comprise.
        noise_filter = noise.load_with_db(conn)
        # Carte conteneur -> agent propre, pour la réattribution des alertes pve.
        _load_agents(conn)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT last_ts, last_alert_id, last_sweep_at FROM ingest_cursor")
            line = cur.fetchone()

        # Le curseur prime sur --depuis : une reprise ne doit pas re-balayer
        # une fenêtre déjà traitée.
        after = None
        if line and line[0]:
            # Recul de sécurité : on repart un peu AVANT la position enregistrée.
            # Entre le moment où une alerte est datée et celui où elle devient
            # visible à la recherche, il s'écoule le temps de transit
            # agent -> manager -> indexer, plus le refresh de l'index. Reprendre
            # exactement au curseur saute ce qui a atterri derrière lui. Le
            # recouvrement ne coûte rien : l'insertion est idempotente.
            #
            # Ne couvre que le skew normal. Un agent déconnecté qui rejoue des
            # heures de logs est rattrapé par le sweep, cf. `_sweep_du`.
            start = line[0] - timedelta(minutes=config.INGEST_LOOKBACK_MINUTES)
            # L'id ("" ci-dessous) est le second critère de tri : la chaîne vide
            # précède toutes les autres, donc on n'exclut aucune alerte de la
            # milliseconde de départ.
            after = (int(start.timestamp() * 1000), "")
            since = None

        seen, _ = _iterate(conn, noise_filter, since, after, batch_size,
                             advance_cursor=True, label="ingest")
        total += seen

        # Sweep de rattrapage, cadencé indépendamment du cycle (qui tourne
        # toutes les 5 min : sweeper à chaque tour serait du gâchis).
        first_pass = not (line and line[0])
        last_sweep = line[2] if line else None
        du = forcer_sweep or (
            not first_pass
            and (last_sweep is None
                 or (datetime.now(timezone.utc) - last_sweep
                     >= timedelta(minutes=config.INGEST_SWEEP_INTERVAL_MINUTES))))
        if first_pass and not forcer_sweep:
            # Le tout premier run vient de balayer --depuis (30 j par défaut) :
            # rien à rattraper, on pose juste le jalon.
            conn.execute(UPDATE_SWEEP)
            conn.commit()
        elif du:
            n = _sweep_du(conn, batch_size, noise_filter)
            if n:
                print(f"  rattrapage : {n} alerte(s) indexée(s) en retard "
                      f"récupérée(s)", file=sys.stderr)
            total += n
    return total


def reapply_filter() -> tuple[int, int]:
    """Réévalue la suppression du noise filter sur les alertes déjà en base.

    L'ingestion étant idempotente, un filtre modifié ne s'applique pas tout
    seul à l'existant — c'est pourtant le cas d'usage normal, le filtre
    s'enrichit en exploitation. On rejoue donc la décision à partir du document
    brut conservé. Ne touche pas au rattachement : une alerte nouvellement
    supprimée sortira de la corrélation au prochain `correlate --recommencer`.
    """
    seen = deleted = 0
    with psycopg.connect(config.PG_DSN, row_factory=psycopg.rows.dict_row) as conn:
        noise_filter = noise.load_with_db(conn)
        # Par LOTS, jamais la table entière : `raw` est le JSON complet de
        # chaque alerte, et cette requête ne porte aucun filtre — sur la base de
        # prod (plusieurs centaines de milliers d'alertes, cf. alertes.py) elle
        # tenait la base entière en mémoire avant la première ligne traitée.
        # Les ids seuls sont légers ; le `raw` ne vient qu'au lot courant.
        ids = [r["id"] for r in conn.execute("SELECT id FROM alerts").fetchall()]
        for depart in range(0, len(ids), 2000):
            batch = ids[depart:depart + 2000]
            lines = conn.execute(
                "SELECT id, raw FROM alerts WHERE id = ANY(%s)", (batch,)).fetchall()
            for line in lines:
                seen += 1
                reason = noise_filter.deletion_reason(line["raw"])
                if reason:
                    deleted += 1
                conn.execute(
                    "UPDATE alerts SET suppressed = %s, suppress_reason = %s "
                    "WHERE id = %s",
                    (reason is not None, reason, line["id"]))
            conn.commit()
    return deleted, seen


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
    ap.add_argument("--rattrapage", action="store_true",
                    help=f"force le balayage des {config.INGEST_SWEEP_HOURS} "
                         "dernières heures sans attendre sa cadence : récupère "
                         "les alertes indexées en retard (agent reconnecté)")
    args = ap.parse_args()

    if args.reapply_filter:
        supp, seen = reapply_filter()
        print(f"Noise filter réappliqué : {supp}/{seen} alertes supprimées.")
        print("Lancer `correlate --recommencer` pour recorréler.")
        return

    if args.reset_cursor:
        with psycopg.connect(config.PG_DSN) as conn:
            conn.execute("DELETE FROM ingest_cursor")
            conn.commit()
        print("Curseur réinitialisé.")

    start = datetime.now(timezone.utc)
    n = ingerer(args.since, args.batch_size, args.catchup)
    duration = (datetime.now(timezone.utc) - start).total_seconds()
    print(f"{n} alertes traitées en {duration:.1f} s")


if __name__ == "__main__":
    main()
