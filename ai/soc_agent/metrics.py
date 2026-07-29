"""Export des métriques d'IA vers l'indexer Wazuh (index `wazuh-ai-*`).

Pourquoi passer par l'indexer plutôt que d'ajouter un Grafana : le SOC a déjà
un endroit où l'on regarde les courbes. Poser les métriques dans le même
indexer, sous les mêmes conventions de champs, permet de les lire dans le même
dashboard Wazuh que les alertes — et de croiser un pic de tokens avec un pic
d'alertes sur le même axe de temps.

Trois types de documents, distingués par `event_type` :

- `llm_call`  : un appel au modèle (table `llm_calls`). Porte les tokens, la
  durée, l'appelant, le coût estimé. C'est la source des métriques de
  consommation.
- `triage`    : un verdict rendu (table `triages`). Porte verdict, confiance,
  actions, incohérences, garde-fous déclenchés, motifs d'injection. C'est la
  source des métriques de QUALITÉ.
- `snapshot`  : compteurs de l'état du pipeline à l'instant du run (incidents,
  cases, whitelists, remédiations). Ce qui ne se déduit pas des deux autres.

Idempotence par `_id` déterministe (`llm-<id>`, `triage-<id>`) : on réexporte
une fenêtre glissante à chaque passage plutôt que de tenir un curseur. Un
document déjà présent est simplement réécrit à l'identique. Le curseur en base
aurait été une table de plus, et un rattrapage impossible après une purge
d'index.

    python -m soc_agent.metrics                # exporte la fenêtre par défaut
    python -m soc_agent.metrics --depuis 30d   # rattrapage large
    python -m soc_agent.metrics --simulation   # montre, n'écrit pas
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

requests.packages.urllib3.disable_warnings()


def _index_du_jour(ts: datetime) -> str:
    """`wazuh-ai-YYYY.MM.DD` — même convention de découpage que Wazuh.

    Un index par jour : la rétention se gère en supprimant des index entiers,
    sans requête de suppression coûteuse.
    """
    return f"{config.METRICS_INDEX_PREFIX}-{ts.astimezone(timezone.utc):%Y.%m.%d}"


def _cout(prompt_tokens, completion_tokens, cache_hit, cache_miss) -> float:
    """Coût ESTIMÉ en USD, à partir des tarifs publics (cf. config).

    Approximation assumée : les tarifs viennent de la grille publiée, pas d'une
    facture. Recoupée sur la consommation réelle du compte (671 593 tokens pour
    0,09 USD), elle donne le bon ordre de grandeur — pas de quoi refacturer.

    Le cache hit est 50x moins cher que le cache miss. Quand l'API ventile
    l'entrée, on l'utilise ; sinon on compte tout en cache miss, ce qui MAJORE
    le coût. Une estimation haute est la seule erreur acceptable ici.
    """
    if cache_hit is not None or cache_miss is not None:
        hit, miss = cache_hit or 0, cache_miss or 0
    else:
        hit, miss = 0, prompt_tokens or 0
    entree = (miss / 1_000_000 * config.LLM_COUT_USD_PAR_MTOKEN_IN
              + hit / 1_000_000 * config.LLM_COUT_USD_PAR_MTOKEN_IN_CACHE)
    sortie = (completion_tokens or 0) / 1_000_000 * config.LLM_COUT_USD_PAR_MTOKEN_OUT
    return round(entree + sortie, 8)


def _doc_llm(l: dict) -> dict:
    pt, ct = l["prompt_tokens"], l["completion_tokens"]
    return {
        "@timestamp": l["ts"].astimezone(timezone.utc).isoformat(),
        "timestamp": l["ts"].astimezone(timezone.utc).isoformat(),
        "event_type": "llm_call",
        "ai": {
            "usage": l["usage"],
            "model": l["modele"],
            "prompt_tokens": pt,
            "completion_tokens": ct,
            # Total précalculé : une somme d'agrégation sur deux champs
            # séparés n'est pas exprimable dans une visualisation OSD simple.
            "total_tokens": (pt or 0) + (ct or 0),
            "cache_hit_tokens": l["cache_hit_tokens"],
            "cache_miss_tokens": l["cache_miss_tokens"],
            "max_tokens": l["max_tokens"],
            "duration_ms": l["duree_ms"],
            "cost_usd": _cout(pt, ct, l["cache_hit_tokens"],
                              l["cache_miss_tokens"]),
            "ok": l["ok"],
            "error": l["erreur"],
        },
        "incident": {"id": l["incident_id"]},
    }


def _doc_triage(t: dict) -> dict:
    return {
        "@timestamp": t["created_at"].astimezone(timezone.utc).isoformat(),
        "timestamp": t["created_at"].astimezone(timezone.utc).isoformat(),
        "event_type": "triage",
        "ai": {
            "usage": "triage",
            "model": t["modele"],
            "prompt_tokens": t["prompt_tokens"],
            "duration_ms": t["duree_ms"],
            "prompt_sha": t["prompt_sha"],
            "mode": t["mode"],
        },
        "triage": {
            "verdict": t["verdict"],
            "confidence": t["confidence"],
            "mitre": t["mitre"],
            "actions": t["actions"] or [],
            "action_count": len(t["actions"] or []),
            # Trois indicateurs de qualité mesurables SANS jeu labellisé : un
            # taux qui monte signale un prompt dégradé ou une attaque.
            "incoherences": t["incoherences"] or [],
            "incoherence_count": len(t["incoherences"] or []),
            "garde_fous": t["garde_fous"] or [],
            "garde_fou_count": len(t["garde_fous"] or []),
            "injection_motifs": t["injection_motifs"] or [],
            "injection_detected": bool(t["injection_motifs"]),
        },
        "incident": {
            "id": t["incident_id"],
            "agent_name": t["agent_name"],
            "max_level": t["max_level"],
            "alert_count": t["alert_count"],
        },
    }


def _doc_snapshot(conn, maintenant: datetime) -> dict:
    """Compteurs d'état. Un document par run — c'est une jauge, pas un flux."""
    def un(sql, *args):
        return conn.execute(sql, args).fetchone()["n"]

    return {
        "@timestamp": maintenant.isoformat(),
        "timestamp": maintenant.isoformat(),
        "event_type": "snapshot",
        "pipeline": {
            "alerts_total": un("SELECT count(*) AS n FROM alerts"),
            "alerts_suppressed": un(
                "SELECT count(*) AS n FROM alerts WHERE suppressed"),
            "incidents_total": un("SELECT count(*) AS n FROM incidents"),
            "incidents_open": un(
                "SELECT count(*) AS n FROM incidents WHERE status = 'case_ouvert'"),
            "triages_total": un("SELECT count(*) AS n FROM triages"),
            "whitelist_rules_active": un(
                "SELECT count(*) AS n FROM whitelist_rules WHERE active"),
            "mitigations_executed": un(
                "SELECT count(*) AS n FROM mitigations WHERE statut = 'exécuté'"),
            "labels_total": un("SELECT count(*) AS n FROM labels"),
        },
    }


def _bulk(lignes: list[str]) -> tuple[int, list[str]]:
    """Envoi bulk à l'indexer. Retourne (nombre écrit, erreurs)."""
    if not lignes:
        return 0, []
    r = requests.post(
        f"{config.INDEXER_URL}/_bulk",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data="".join(lignes).encode("utf-8"),
        verify=config.INDEXER_CA or config.INDEXER_VERIFY_TLS,
        timeout=60)
    r.raise_for_status()
    corps = r.json()
    erreurs = []
    if corps.get("errors"):
        for item in corps.get("items", []):
            info = next(iter(item.values()))
            if info.get("error"):
                erreurs.append(json.dumps(info["error"])[:300])
    return len(corps.get("items", [])) - len(erreurs), erreurs


def _ligne(index: str, doc_id: str, doc: dict) -> list[str]:
    return [json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n",
            json.dumps(doc, default=str) + "\n"]


def exporter(depuis: str, simulation: bool) -> dict:
    """Exporte la fenêtre demandée. Retourne un résumé."""
    unite = {"m": "minutes", "h": "hours", "d": "days"}[depuis[-1]]
    delta = timedelta(**{unite: int(depuis[:-1])})
    debut = datetime.now(timezone.utc) - delta
    maintenant = datetime.now(timezone.utc)

    lignes: list[str] = []
    resume = {"llm_call": 0, "triage": 0, "snapshot": 0}

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        for l in conn.execute(
                "SELECT * FROM llm_calls WHERE ts >= %s ORDER BY ts", (debut,)):
            lignes += _ligne(_index_du_jour(l["ts"]), f"llm-{l['id']}", _doc_llm(l))
            resume["llm_call"] += 1

        # Jointure sur incidents : un verdict sans le contexte de son incident
        # (agent, niveau, volume) n'est pas exploitable dans un dashboard.
        for t in conn.execute("""
                SELECT t.*, i.agent_name, i.max_level, i.alert_count
                  FROM triages t JOIN incidents i ON i.id = t.incident_id
                 WHERE t.created_at >= %s ORDER BY t.created_at""", (debut,)):
            lignes += _ligne(_index_du_jour(t["created_at"]),
                             f"triage-{t['id']}", _doc_triage(t))
            resume["triage"] += 1

        snap = _doc_snapshot(conn, maintenant)

    # _id horodaté à la minute : un run par 5 min ne réécrit pas le précédent,
    # et deux runs rapprochés (relance manuelle) n'en créent pas deux.
    lignes += _ligne(_index_du_jour(maintenant),
                     f"snapshot-{maintenant:%Y%m%d%H%M}", snap)
    resume["snapshot"] = 1

    if simulation:
        for l in lignes:
            print(l, end="")
        return resume

    ecrits, erreurs = _bulk(lignes)
    resume["ecrits"] = ecrits
    resume["erreurs"] = erreurs
    return resume


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--depuis", default=config.METRICS_FENETRE,
                    help="fenêtre réexportée (ex. 2h, 30d). Idempotent : "
                         "réexporter ne duplique rien.")
    ap.add_argument("--simulation", action="store_true")
    args = ap.parse_args()

    r = exporter(args.depuis, args.simulation)
    if args.simulation:
        return
    print(f"  {r['ecrits']} document(s) indexés "
          f"({r['llm_call']} appels LLM, {r['triage']} triages, 1 snapshot)")
    for e in r["erreurs"]:
        print(f"  ERREUR {e}")


if __name__ == "__main__":
    main()
