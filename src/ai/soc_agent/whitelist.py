"""Whitelist automatique à partir des faux positifs récurrents.

Boucle fermée du POC autonome : quand le triage LLM juge false_positive, de
façon répétée, sur une même signature d'événement, on crée une exception. Les
alertes qui matcheront cette signature seront écartées avant même la
corrélation et le triage — l'IA cesse de rejuger sans fin le même faux positif.

    python -m soc_agent.whitelist                 # crée les exceptions dues
    python -m soc_agent.whitelist --simulation    # montre sans rien créer
    python -m soc_agent.whitelist --lister        # exceptions actives
    python -m soc_agent.whitelist --min-fp 1       # seuil abaissé (POC/démo)

Trois garde-fous, hérités de la même logique que le triage :

- Signature PRÉCISE exigée : rule_id seul ne suffit pas (il neutraliserait
  toute une règle). Il faut au moins un compte, une commande ou un fichier.
- Jamais de whitelist auto au-dessus de WHITELIST_MAX_LEVEL : une règle qui
  tire en critique mérite un humain. C'est aussi le mur contre un attaquant qui
  provoquerait des FP répétés pour se faire whitelister.
- Une signature vue AU MOINS une fois en true_positive n'est jamais
  whitelistée, même si elle apparaît par ailleurs en FP : signal contradictoire.
"""

import argparse
import json
from collections.abc import Iterable

import psycopg
from psycopg.rows import dict_row, tuple_row

from . import config
from .noise import _value_field

# Champs candidats d'une signature de whitelist. Volontairement restreint :
# - rule_id situe la détection ;
# - src_user / command / file discriminent l'activité précise.
# dst_user et agent_name sont exclus : trop larges (dst root, ou tout un hôte).
DISCRIMINANT_FIELDS = ("src_user", "command", "file")
FIELDS_SIGNATURE = ("rule_id",) + DISCRIMINANT_FIELDS


def _signature(raw_alerts: Iterable[dict],
               discriminant: tuple[str, ...] = DISCRIMINANT_FIELDS) -> dict | None:
    """Signature d'un incident : champs constants sur toutes ses alertes.

    Un champ n'entre dans la signature que s'il a une seule valeur non nulle,
    identique sur toutes les alertes de l'incident. Retourne None si la
    signature n'est pas assez précise pour une whitelist sûre.

    `discriminants` est paramétrable pour `rule_tuning.py`, qui en accepte un de
    plus (`url`) : une exception écrite dans le moteur de règles peut discriminer
    sur l'URL, ce que le filtre post-retrieval ne sait pas faire.

    Prend un ITÉRABLE et ne le parcourt qu'une fois : l'appelant peut donc lui
    passer un curseur serveur au lieu d'une liste. Chaque champ ne retient que
    DEUX valeurs distinctes, parce que c'est tout ce que la décision demande —
    « une seule valeur » ou « plusieurs ». Sans ce plafond, la matérialisation
    des alertes d'un incident de flood (126 508 `raw`) coûtait 1 Go et a fait
    OOM-killer le cycle le 2026-08-14, arrêtant l'ingestion.

    Ne PAS remplacer ce parcours par un échantillon borné : un champ jugé
    constant sur les 2 000 premières alertes alors qu'il varie sur la 2 001e
    produirait une exception de whitelist plus large que l'incident observé.
    La borne est sur la mémoire retenue, jamais sur ce qui est examiné.
    """
    fields = ("rule_id",) + tuple(discriminant)
    values: dict[str, set] = {c: set() for c in fields}
    seen = False
    for a in raw_alerts:
        seen = True
        for field in fields:
            if len(values[field]) > 1:
                continue  # déjà multivalué : la suite ne peut plus rien changer
            if (v := _value_field(a, field)) is not None:
                values[field].add(v)
    if not seen:
        return None

    signature = {c: str(next(iter(s))) for c, s in values.items() if len(s) == 1}

    # Précision : au moins un discriminant, sinon on neutraliserait trop large
    # (rule_id seul = toute la règle).
    if not any(c in signature for c in discriminant):
        return None
    return signature


def _canonical(signature: dict) -> str:
    return "|".join(f"{k}={signature[k]}" for k in sorted(signature))


def _incidents_by_verdict(
        conn,
        discriminant: tuple[str, ...] = DISCRIMINANT_FIELDS) -> tuple[dict, set]:
    """(FP par signature, ensemble des signatures vues en TP).

    On ne considère que le DERNIER triage de chaque incident : les passages
    précédents reflètent des prompts abandonnés.
    """
    lines = conn.execute("""
        SELECT DISTINCT ON (t.incident_id)
               t.incident_id, t.verdict, i.max_level, i.status
          FROM triages t
          JOIN incidents i ON i.id = t.incident_id
         ORDER BY t.incident_id, t.created_at DESC
    """).fetchall()

    fp_by_sig: dict[str, dict] = {}
    sig_tp: set[str] = set()

    for l in lines:
        # Curseur SERVEUR (`name=`) : les lignes arrivent par paquets et ne sont
        # jamais toutes en mémoire. Un incident de flood en compte 126 508, dont
        # le `raw` complet — 1 Go matérialisé d'un coup, au-delà de la limite du
        # conteneur (cf. _signature).
        # `row_factory` explicite : la connexion est en `dict_row`, dont le
        # curseur hériterait — on ne veut qu'une colonne, autant la lire par
        # position sans construire un dict par ligne.
        with conn.cursor(name=f"sig_{l['incident_id']}",
                         row_factory=tuple_row) as cur:
            cur.itersize = 2000
            cur.execute("SELECT raw FROM alerts WHERE incident_id = %s",
                        (l["incident_id"],))
            signature = _signature((r[0] for r in cur), discriminant)
        if signature is None:
            continue
        canon = _canonical(signature)

        if l["verdict"] == "true_positive":
            sig_tp.add(canon)
        elif l["verdict"] == "false_positive":
            e = fp_by_sig.setdefault(canon, {
                "signature": signature, "incidents": [], "max_level": 0})
            e["incidents"].append(l["incident_id"])
            e["max_level"] = max(e["max_level"], l["max_level"])

    return fp_by_sig, sig_tp


def analyze(min_fp: int, simulation: bool) -> list[dict]:
    """Crée (ou simule) les exceptions dues. Retourne les décisions."""
    decisions: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        fp_by_sig, sig_tp = _incidents_by_verdict(conn)
        existing = {r["signature"] for r in conn.execute(
            "SELECT signature FROM whitelist_rules WHERE active").fetchall()}

        for canon, e in sorted(fp_by_sig.items()):
            n = len(e["incidents"])
            if canon in existing:
                continue
            if canon in sig_tp:
                decisions.append({"signature": canon, "action": "refusé",
                                  "raison": "vue aussi en true_positive"})
                continue
            if e["max_level"] >= config.WHITELIST_MAX_LEVEL:
                decisions.append({"signature": canon, "action": "refusé",
                                  "raison": f"niveau {e['max_level']} >= "
                                            f"{config.WHITELIST_MAX_LEVEL}"})
                continue
            if n < min_fp:
                decisions.append({"signature": canon, "action": "en attente",
                                  "raison": f"{n}/{min_fp} FP"})
                continue

            reason = (f"FP récurrent ({n} incidents) jugé par l'IA — "
                      f"{canon}")
            if not simulation:
                conn.execute("""
                    INSERT INTO whitelist_rules
                        (signature, match_all, reason, source, origin_incidents,
                         fp_count)
                    VALUES (%s, %s, %s, 'auto', %s, %s)
                    ON CONFLICT (signature) DO NOTHING
                """, (canon, json.dumps(e["signature"]), reason,
                      e["incidents"], n))
                # Les incidents à l'origine passent en 'whitelisted' : ils ne
                # seront plus recomptés, et le statut trace le pourquoi.
                conn.execute(
                    "UPDATE incidents SET status = 'whitelisted' "
                    "WHERE id = ANY(%s)", (e["incidents"],))
                conn.commit()
            decisions.append({"signature": canon, "action": "créé",
                              "match_all": e["signature"], "fp": n})

    return decisions


def signatures_seen_tp(conn) -> set[str]:
    """Signatures (forme canonique) vues au moins une fois en true_positive.

    Réutilisé par whitelist_task.py : une whitelist demandée manuellement par
    l'analyste obéit au même garde-fou qu'une whitelist automatique — jamais
    sur une signature contredite par un vrai positif.
    """
    return _incidents_by_verdict(conn)[1]


def validate_signature(signature: dict, level: int, sig_tp: set[str]) -> str | None:
    """Garde-fous déterministes avant toute création de whitelist_rules.

    Retourne la raison de refus, ou None si la signature est acceptable. Le
    LLM (auto ou tâche manuelle) PROPOSE ; ce garde-fou DÉCIDE — mêmes trois
    règles que `analyser()` : signature précise, niveau borné, jamais vue en
    true_positive.
    """
    if not any(c in signature for c in DISCRIMINANT_FIELDS):
        return "signature trop large : rule_id seul ne suffit pas"
    if level >= config.WHITELIST_MAX_LEVEL:
        return f"niveau {level} >= {config.WHITELIST_MAX_LEVEL} (whitelist auto interdite)"
    if _canonical(signature) in sig_tp:
        return "signature déjà vue en true_positive"
    return None


def exceptions() -> list[dict]:
    """Les exceptions de whitelist, actives ou révoquées, plus récentes d'abord."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lines = conn.execute("""
            SELECT id, signature, match_all, reason, source, fp_count, active,
                   origin_incidents, iris_task_id, created_at
              FROM whitelist_rules ORDER BY created_at DESC
        """).fetchall()
    return [dict(r, created_at=r["created_at"].isoformat()) for r in lines]


def list() -> None:
    lines = exceptions()
    if not lines:
        print("Aucune exception de whitelist.")
        return
    for r in lines:
        state = "actif " if r["active"] else "inactif"
        print(f"  #{r['id']:<3} [{state}] {r['source']:<6} "
              f"{r['fp_count']} FP  {json.dumps(r['match_all'], ensure_ascii=False)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-fp", type=int, default=config.WHITELIST_MIN_FP)
    ap.add_argument("--simulation", action="store_true",
                    help="montre les décisions sans rien créer")
    ap.add_argument("--lister", action="store_true")
    args = ap.parse_args()

    if args.list:
        list()
        return

    decisions = analyze(args.min_fp, args.simulation)
    if not decisions:
        print("Aucun faux positif à examiner.")
        return

    prefix = "[simulation] " if args.simulation else ""
    for d in decisions:
        if d["action"] == "créé":
            print(f"{prefix}CRÉÉ   {d['signature']}  ({d['fp']} FP)")
        elif d["action"] == "en attente":
            print(f"       attente {d['signature']}  ({d['raison']})")
        else:
            print(f"       refusé  {d['signature']}  ({d['raison']})")


if __name__ == "__main__":
    main()
