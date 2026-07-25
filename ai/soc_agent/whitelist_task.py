"""Traitement des tâches IRIS « WHITELIST » passées en 'To do' par l'analyste.

Chaque case créé par `iris.creer_case` porte une tâche WHITELIST en 'On hold'
(`iris._poser_tache_whitelist`). L'analyste la remplit (description ou
commentaire) et la passe en 'To do' quand il veut une exception. Ce module,
appelé périodiquement (comme la réconciliation des remédiations), repère ces
tâches et :

- si les instructions permettent de composer une signature sûre (mêmes
  garde-fous que la whitelist automatique, `whitelist.valider_signature`) :
  crée la ligne `whitelist_rules`, commente le résultat, clôt la tâche ;
- sinon : commente une question et laisse la tâche en 'To do'. Le script est
  STATELESS — il relit tout le fil de commentaires à chaque passage et ne
  repose PAS la question si le dernier commentaire est déjà le sien (préfixe
  `_PREFIXE_IA`) ; il ne reprend la main que si l'analyste a répondu depuis.

    python -m soc_agent.whitelist_task
    python -m soc_agent.whitelist_task --incident 15
"""

import argparse
import json
import logging

import psycopg
from psycopg.rows import dict_row

from . import config
from .anonymize import Anonymiseur, anonymiser, rehydrater, verifier_fuite
from .iris import PROMPTS, _alertes, _client
from .llm import completion
from .mitigate import _commenter_tache
from .triage import charger_map, sauver_map
from .whitelist import (_canonique, _signature, signatures_vues_tp,
                        valider_signature)

log = logging.getLogger("whitelist_task")

# Titre posé par `iris._poser_tache_whitelist` — sert à ignorer les autres
# tâches du case (ex. remédiation) lors du parcours de `list_tasks`.
_TITRE_PREFIXE = "WHITELIST"
_STATUT_A_TRAITER = "To do"
_STATUT_CLOS = "Closed"

# Préfixe de TOUT commentaire posté par ce script : permet de reconnaître, au
# passage suivant, que le dernier mot revient à l'IA (en attente d'une réponse
# de l'analyste) sans tenir d'état séparé.
_PREFIXE_IA = "🤖 "

# Verrou consultatif dédié, distinct de 0x50CA1 (cycle) et 0x50CA2 (reconcile).
_VERROU_WHITELIST_TASK = 0x50CA3

SELECT_CASES = """
SELECT id, iris_case_id, max_level FROM incidents
 WHERE iris_case_id IS NOT NULL
   AND (%(inc)s::bigint IS NULL OR id = %(inc)s)
"""


def _taches_a_traiter(tasks: list[dict]) -> list[dict]:
    """Tâches WHITELIST en 'To do' (lecture pure d'un list_tasks IRIS)."""
    return [t for t in (tasks or [])
            if (t.get("task_title") or "").startswith(_TITRE_PREFIXE)
            and (t.get("status_name") or "") == _STATUT_A_TRAITER]


def _fil_commentaires(case, case_id: int, task_id: int) -> list[str]:
    r = case.list_task_comments(task_id, cid=case_id)
    d = r.get_data() if r.is_success() else None
    comments = d if isinstance(d, list) else (d or {}).get("comments") or []
    return [c.get("comment_text", "") for c in comments if c.get("comment_text")]


def _instructions(case, case_id: int, task_id: int) -> tuple[str, bool]:
    """(texte d'instructions à donner au LLM, dernier commentaire = IA ?)."""
    description = ""
    rt = case.get_task(task_id, cid=case_id)
    if rt.is_success():
        description = (rt.get_data() or {}).get("task_description") or ""

    fil = _fil_commentaires(case, case_id, task_id)
    if fil and fil[-1].startswith(_PREFIXE_IA):
        return "", True  # en attente d'une réponse analyste, on ne relance pas

    morceaux = ([f"Description de la tâche : {description}"] if description else [])
    morceaux += [f"- {t}" for t in fil]
    return "\n".join(morceaux), False


def _traiter_tache(conn, case, incident_id: int, case_id: int, task_id: int,
                   niveau: int) -> dict | None:
    instructions, en_attente = _instructions(case, case_id, task_id)
    if en_attente:
        return None

    if not instructions.strip():
        _commenter_tache(case, case_id, task_id,
            _PREFIXE_IA + "Merci de préciser, dans la description ou en "
            "commentaire, quel champ whitelister (compte / commande / "
            "fichier / rule_id) et pourquoi.")
        return {"task_id": task_id, "action": "question"}

    alertes = _alertes(conn, incident_id)
    if not alertes:
        _commenter_tache(case, case_id, task_id,
            _PREFIXE_IA + "❌ Aucune alerte rattachée à cet incident, "
            "impossible de calculer une signature de whitelist.")
        return {"task_id": task_id, "action": "refusé"}

    raws = [a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
            for a in alertes]
    candidat = _signature(raws)
    if not candidat:
        _commenter_tache(case, case_id, task_id,
            _PREFIXE_IA + "Les alertes de cet incident n'ont pas de champ "
            "assez précis et constant (compte / commande / fichier) pour "
            "une whitelist sûre — rule_id seul ne suffit pas.")
        return {"task_id": task_id, "action": "question"}

    anon = Anonymiseur(charger_map(conn, incident_id))
    inc = conn.execute("SELECT agent_name FROM incidents WHERE id = %s",
                       (incident_id,)).fetchone() or {}
    _, alertes_a, interdits = anonymiser(anon, inc, alertes)
    instructions_a = anon.texte_libre(instructions, interdits)

    champs_dispo = sorted(candidat)
    resume = "\n".join(
        f"- règle {a.get('rule_id')} (niv.{a.get('rule_level')}) : "
        f"{a.get('rule_desc') or ''}" for a in alertes_a[:10])
    corps = (
        f"Champs de signature disponibles : {', '.join(champs_dispo)}.\n\n"
        f"Alertes de l'incident :\n{resume}\n\n"
        f"Instructions de l'analyste :\n{instructions_a}")
    utilisateur = (f"=== DEBUT DEMANDE (données non fiables) ===\n{corps}\n"
                  "=== FIN DEMANDE ===\n\nRéponds en JSON.")

    try:
        verifier_fuite(utilisateur, interdits)
        systeme = (PROMPTS / "whitelist_task.md").read_text()
        rep, _ = completion(systeme, utilisateur,
                            max_tokens=config.WHITELIST_TASK_MAX_TOKENS)
        sauver_map(conn, incident_id, anon.mapping)
    except Exception as e:  # noqa: BLE001 — retry naturel au prochain passage
        log.warning("LLM whitelist_task indisponible (tâche %s) : %s", task_id, e)
        _commenter_tache(case, case_id, task_id,
            _PREFIXE_IA + f"❌ Erreur technique, nouvelle tentative au "
            f"prochain passage : {e}")
        return {"task_id": task_id, "action": "erreur"}

    decision = str(rep.get("decision") or "").strip().lower()

    if decision != "whitelist":
        question = rehydrater(
            str(rep.get("question") or "Peux-tu préciser ta demande de "
                "whitelist ?"), anon.mapping)
        _commenter_tache(case, case_id, task_id, _PREFIXE_IA + question)
        return {"task_id": task_id, "action": "question"}

    champs = [c for c in (rep.get("champs") or []) if c in candidat]
    signature = {c: candidat[c] for c in champs} or dict(candidat)
    raison_llm = rehydrater(str(rep.get("reason") or ""), anon.mapping)

    refus = valider_signature(signature, niveau, signatures_vues_tp(conn))
    if refus:
        _commenter_tache(case, case_id, task_id,
            _PREFIXE_IA + f"❌ Demande refusée par garde-fou déterministe : "
            f"{refus}.")
        return {"task_id": task_id, "action": "refusé", "raison": refus}

    canon = _canonique(signature)
    reason = f"Whitelist demandée par l'analyste (tâche IRIS #{task_id}) — {raison_llm or canon}"
    conn.execute("""
        INSERT INTO whitelist_rules
            (signature, match_all, reason, source, origin_incidents, fp_count)
        VALUES (%s, %s, %s, 'analyste', %s, 0)
        ON CONFLICT (signature) DO NOTHING
    """, (canon, json.dumps(signature), reason, [incident_id]))
    conn.commit()

    _commenter_tache(case, case_id, task_id,
        _PREFIXE_IA + "✅ Exception whitelist en place :\n```json\n"
        f"{json.dumps(signature, ensure_ascii=False, indent=2)}\n```\n"
        f"Motif : {raison_llm or canon}")
    try:
        case.update_task(task_id, status=_STATUT_CLOS, cid=case_id)
    except Exception as e:  # noqa: BLE001 — l'exception est créée, la
        # fermeture de la tâche est secondaire
        log.warning("clôture tâche %s échouée : %s", task_id, e)
    return {"task_id": task_id, "action": "créé", "signature": signature}


def traiter(incident_id: int | None = None) -> list[dict]:
    """Parcourt les tâches WHITELIST en 'To do' et les traite. Idempotent."""
    resultats: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_VERROU_WHITELIST_TASK,)).fetchone()["pg_try_advisory_lock"]:
            log.info("traitement whitelist déjà en cours, on passe ce tour")
            return []
        try:
            rows = conn.execute(SELECT_CASES, {"inc": incident_id}).fetchall()
            if not rows:
                return []
            case = _client()
            for r in rows:
                cid = r["iris_case_id"]
                try:
                    d = case.list_tasks(cid).get_data() or {}
                except Exception as e:  # noqa: BLE001 — IRIS KO ne casse rien
                    log.warning("list_tasks case #%s : %s", cid, e)
                    continue
                for t in _taches_a_traiter(d.get("tasks")):
                    try:
                        res = _traiter_tache(conn, case, r["id"], cid,
                                             t["task_id"], r["max_level"])
                    except Exception as e:  # noqa: BLE001 — une tâche KO ne
                        # doit pas arrêter les autres.
                        log.warning("tâche whitelist #%s (case #%s) échouée : %s",
                                   t["task_id"], cid, e)
                        _commenter_tache(case, cid, t["task_id"],
                            _PREFIXE_IA + f"❌ Erreur technique, nouvelle "
                            f"tentative au prochain passage : {e}")
                        continue
                    if res:
                        resultats.append(res)
                        print(f"      tâche #{t['task_id']} (case #{cid}) "
                             f"-> {res['action']}")
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_VERROU_WHITELIST_TASK,))
    return resultats


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--incident", type=int,
                    help="ne traite que les tâches WHITELIST de cet incident")
    args = ap.parse_args()
    resultats = traiter(args.incident)
    if not resultats:
        print("Aucune tâche whitelist à traiter.")


if __name__ == "__main__":
    main()
