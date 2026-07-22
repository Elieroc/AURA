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

import psycopg
from psycopg.rows import dict_row

from . import config
from .noise import _valeur_champ

# Champs candidats d'une signature de whitelist. Volontairement restreint :
# - rule_id situe la détection ;
# - src_user / command / file discriminent l'activité précise.
# dst_user et agent_name sont exclus : trop larges (dst root, ou tout un hôte).
CHAMPS_DISCRIMINANTS = ("src_user", "command", "file")
CHAMPS_SIGNATURE = ("rule_id",) + CHAMPS_DISCRIMINANTS


def _signature(alertes_raw: list[dict]) -> dict | None:
    """Signature d'un incident : champs constants sur toutes ses alertes.

    Un champ n'entre dans la signature que s'il a une seule valeur non nulle,
    identique sur toutes les alertes de l'incident. Retourne None si la
    signature n'est pas assez précise pour une whitelist sûre.
    """
    signature: dict = {}
    for champ in CHAMPS_SIGNATURE:
        valeurs = {v for a in alertes_raw
                   if (v := _valeur_champ(a, champ)) is not None}
        if len(valeurs) == 1:
            signature[champ] = str(next(iter(valeurs)))

    # Précision : au moins un discriminant, sinon on neutraliserait trop large
    # (rule_id seul = toute la règle).
    if not any(c in signature for c in CHAMPS_DISCRIMINANTS):
        return None
    return signature


def _canonique(signature: dict) -> str:
    return "|".join(f"{k}={signature[k]}" for k in sorted(signature))


def _incidents_par_verdict(conn) -> tuple[dict, set]:
    """(FP par signature, ensemble des signatures vues en TP).

    On ne considère que le DERNIER triage de chaque incident : les passages
    précédents reflètent des prompts abandonnés.
    """
    lignes = conn.execute("""
        SELECT DISTINCT ON (t.incident_id)
               t.incident_id, t.verdict, i.max_level, i.status
          FROM triages t
          JOIN incidents i ON i.id = t.incident_id
         ORDER BY t.incident_id, t.created_at DESC
    """).fetchall()

    fp_par_sig: dict[str, dict] = {}
    sig_tp: set[str] = set()

    for l in lignes:
        raws = [r["raw"] for r in conn.execute(
            "SELECT raw FROM alerts WHERE incident_id = %s",
            (l["incident_id"],)).fetchall()]
        if not raws:
            continue
        signature = _signature(raws)
        if signature is None:
            continue
        canon = _canonique(signature)

        if l["verdict"] == "true_positive":
            sig_tp.add(canon)
        elif l["verdict"] == "false_positive":
            e = fp_par_sig.setdefault(canon, {
                "signature": signature, "incidents": [], "max_level": 0})
            e["incidents"].append(l["incident_id"])
            e["max_level"] = max(e["max_level"], l["max_level"])

    return fp_par_sig, sig_tp


def analyser(min_fp: int, simulation: bool) -> list[dict]:
    """Crée (ou simule) les exceptions dues. Retourne les décisions."""
    decisions: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        fp_par_sig, sig_tp = _incidents_par_verdict(conn)
        existantes = {r["signature"] for r in conn.execute(
            "SELECT signature FROM whitelist_rules WHERE active").fetchall()}

        for canon, e in sorted(fp_par_sig.items()):
            n = len(e["incidents"])
            if canon in existantes:
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


def lister() -> None:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lignes = conn.execute("""
            SELECT id, match_all, source, fp_count, active, created_at
              FROM whitelist_rules ORDER BY created_at DESC
        """).fetchall()
    if not lignes:
        print("Aucune exception de whitelist.")
        return
    for r in lignes:
        etat = "actif " if r["active"] else "inactif"
        print(f"  #{r['id']:<3} [{etat}] {r['source']:<6} "
              f"{r['fp_count']} FP  {json.dumps(r['match_all'], ensure_ascii=False)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-fp", type=int, default=config.WHITELIST_MIN_FP)
    ap.add_argument("--simulation", action="store_true",
                    help="montre les décisions sans rien créer")
    ap.add_argument("--lister", action="store_true")
    args = ap.parse_args()

    if args.lister:
        lister()
        return

    decisions = analyser(args.min_fp, args.simulation)
    if not decisions:
        print("Aucun faux positif à examiner.")
        return

    prefixe = "[simulation] " if args.simulation else ""
    for d in decisions:
        if d["action"] == "créé":
            print(f"{prefixe}CRÉÉ   {d['signature']}  ({d['fp']} FP)")
        elif d["action"] == "en attente":
            print(f"       attente {d['signature']}  ({d['raison']})")
        else:
            print(f"       refusé  {d['signature']}  ({d['raison']})")


if __name__ == "__main__":
    main()
