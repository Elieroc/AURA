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

from . import config, noise, routage

# --- Attribution conteneur LXC (auditd de l'hôte Proxmox) --------------------
# L'agent pve (009) capte l'execve de TOUS les conteneurs LXC (noyau partagé) ;
# `data.lxc_ct` (extrait par le pipeline indexer) — ou le tag dans full_log en
# repli — dit lequel. On réattribue alors l'alerte à l'agent Wazuh PROPRE du
# conteneur quand il en a un (jellyfin -> 005) : la corrélation se fait par
# conteneur (agent_id est la clé) et la remédiation vise le bon hôte. Sinon on
# garde pve et on note le conteneur dans la colonne `container` pour la lisibilité.
_HOTE_AUDITD = {"pve", "009"}
_CT_IGNORE = {"", "host", "unknown"}
_LXC_CT = re.compile(r"lxc_ct=([A-Za-z0-9_.-]+)")
_AGENTS: dict[str, str] = {}   # nom de conteneur -> agent_id Wazuh propre


def _charger_agents(conn) -> None:
    """Carte nom d'agent -> id, pour réattribuer un conteneur à son propre agent.
    Rechargée à chaque run d'ingestion (agents stables, requête triviale)."""
    _AGENTS.clear()
    for nom, aid in conn.execute(
            "SELECT DISTINCT agent_name, agent_id FROM alerts "
            "WHERE agent_name IS NOT NULL"):
        if nom and nom not in _HOTE_AUDITD:
            _AGENTS.setdefault(nom, aid)

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
    if lxc not in _CT_IGNORE and (agent_name in _HOTE_AUDITD
                                  or agent_id in _HOTE_AUDITD):
        container = lxc
        propre = _AGENTS.get(lxc)
        if propre:
            agent_id, agent_name = propre, lxc

    return {
        "id": src["id"],
        "ts": src["@timestamp"],
        "agent_id": agent_id,
        "agent_name": agent_name,
        "container": container,
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
        # UID auditd de l'événement. Sert à la corrélation : les actions de
        # l'attaquant (et de ses descendants privesc par SUID, qui gardent
        # l'uid réel) partagent cet uid, ce qui distingue son activité du bruit
        # de fond légitime de la même machine (démons, sessions de login).
        "audit_uid": (data.get("audit", {}) or {}).get("uid"),
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
        # Liste statique UNION les index sets créés depuis par routage.py :
        # un index créé sans être ajouté ici est un capteur que l'IA ne voit
        # pas, en silence (cf. routage.indices_lus).
        f"{config.INDEXER_URL}/{routage.indices_lus()}/_search",
        json=corps,
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=60,
    )
    rep.raise_for_status()
    return rep.json()["hits"]["hits"]


MAJ_CURSEUR = """
INSERT INTO ingest_cursor (id, last_ts, last_alert_id, updated_at)
VALUES (true, %s, %s, now())
ON CONFLICT (id) DO UPDATE
  SET last_ts = EXCLUDED.last_ts,
      last_alert_id = EXCLUDED.last_alert_id,
      updated_at = now()
"""

MAJ_SWEEP = """
INSERT INTO ingest_cursor (id, last_sweep_at) VALUES (true, now())
ON CONFLICT (id) DO UPDATE SET last_sweep_at = now()
"""


def _parcourir(conn, filtre: noise.NoiseFilter, depuis: str | None,
               apres: tuple | None, taille_lot: int, *,
               avancer_curseur: bool, etiquette: str) -> tuple[int, int]:
    """Pagine une fenêtre et insère. Retourne (vues, nouvelles).

    `avancer_curseur=False` pour le sweep de rattrapage : il balaye en arrière
    et ne doit surtout pas repositionner le curseur du flux normal.
    """
    vues = nouvelles = 0
    while True:
        hits = _lot(depuis, apres, taille_lot, filtre)
        if not hits:
            break

        lignes = [_aplatir(h["_source"], filtre) for h in hits]
        with conn.cursor() as cur:
            cur.executemany(INSERT, lignes)
            # ON CONFLICT DO NOTHING : rowcount ne compte que les vraies
            # insertions, ce qui donne le nombre d'alertes réellement récupérées
            # (utile pour le sweep, où la quasi-totalité du lot est déjà connue).
            nouvelles += max(cur.rowcount, 0)
            dernier = hits[-1]
            if avancer_curseur:
                cur.execute(MAJ_CURSEUR, (dernier["_source"]["@timestamp"],
                                          dernier["_source"]["id"]))
        conn.commit()

        vues += len(hits)
        apres = tuple(dernier["sort"])
        print(f"  {etiquette} : {vues} alertes vues, {nouvelles} nouvelles…",
              file=sys.stderr)

        if len(hits) < taille_lot:
            break
    return vues, nouvelles


def _sweep_du(conn, taille_lot: int, filtre: noise.NoiseFilter) -> int:
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
    _, nouvelles = _parcourir(
        conn, filtre, f"{config.INGEST_SWEEP_HOURS}h", None, taille_lot,
        avancer_curseur=False, etiquette="rattrapage")
    conn.execute(MAJ_SWEEP)
    conn.commit()
    return nouvelles


def ingerer(depuis: str | None, taille_lot: int,
            forcer_sweep: bool = False) -> int:
    total = 0
    with psycopg.connect(config.PG_DSN) as conn:
        # Filtre construit une fois par run, whitelist auto (DB) comprise.
        filtre = noise.charger_avec_db(conn)
        # Carte conteneur -> agent propre, pour la réattribution des alertes pve.
        _charger_agents(conn)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT last_ts, last_alert_id, last_sweep_at FROM ingest_cursor")
            ligne = cur.fetchone()

        # Le curseur prime sur --depuis : une reprise ne doit pas re-balayer
        # une fenêtre déjà traitée.
        apres = None
        if ligne and ligne[0]:
            # Recul de sécurité : on repart un peu AVANT la position enregistrée.
            # Entre le moment où une alerte est datée et celui où elle devient
            # visible à la recherche, il s'écoule le temps de transit
            # agent -> manager -> indexer, plus le refresh de l'index. Reprendre
            # exactement au curseur saute ce qui a atterri derrière lui. Le
            # recouvrement ne coûte rien : l'insertion est idempotente.
            #
            # Ne couvre que le skew normal. Un agent déconnecté qui rejoue des
            # heures de logs est rattrapé par le sweep, cf. `_sweep_du`.
            debut = ligne[0] - timedelta(minutes=config.INGEST_LOOKBACK_MINUTES)
            # L'id ("" ci-dessous) est le second critère de tri : la chaîne vide
            # précède toutes les autres, donc on n'exclut aucune alerte de la
            # milliseconde de départ.
            apres = (int(debut.timestamp() * 1000), "")
            depuis = None

        vues, _ = _parcourir(conn, filtre, depuis, apres, taille_lot,
                             avancer_curseur=True, etiquette="ingest")
        total += vues

        # Sweep de rattrapage, cadencé indépendamment du cycle (qui tourne
        # toutes les 5 min : sweeper à chaque tour serait du gâchis).
        premier_passage = not (ligne and ligne[0])
        dernier_sweep = ligne[2] if ligne else None
        du = forcer_sweep or (
            not premier_passage
            and (dernier_sweep is None
                 or (datetime.now(timezone.utc) - dernier_sweep
                     >= timedelta(minutes=config.INGEST_SWEEP_INTERVAL_MINUTES))))
        if premier_passage and not forcer_sweep:
            # Le tout premier run vient de balayer --depuis (30 j par défaut) :
            # rien à rattraper, on pose juste le jalon.
            conn.execute(MAJ_SWEEP)
            conn.commit()
        elif du:
            n = _sweep_du(conn, taille_lot, filtre)
            if n:
                print(f"  rattrapage : {n} alerte(s) indexée(s) en retard "
                      f"récupérée(s)", file=sys.stderr)
            total += n
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
    ap.add_argument("--rattrapage", action="store_true",
                    help=f"force le balayage des {config.INGEST_SWEEP_HOURS} "
                         "dernières heures sans attendre sa cadence : récupère "
                         "les alertes indexées en retard (agent reconnecté)")
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
    n = ingerer(args.depuis, args.taille_lot, args.rattrapage)
    duree = (datetime.now(timezone.utc) - debut).total_seconds()
    print(f"{n} alertes traitées en {duree:.1f} s")


if __name__ == "__main__":
    main()
