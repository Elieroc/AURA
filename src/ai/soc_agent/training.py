"""Mode « training » : apprendre le bruit ambiant d'un SI avant d'y lâcher le SOC.

Un SOC branché sur un SI déjà en production tire d'abord sur tout ce qui bouge :
les sauvegardes, les scripts d'admin, les scanners de conformité déclenchent des
alertes HIGH/CRITICAL parfaitement légitimes. Sans période d'apprentissage,
l'XDR autonome ouvre des dizaines de cases et REMÉDIE ce bruit — il isole des
serveurs sains le premier jour.

Le mode training est une **fenêtre de confiance déclarée par l'administrateur**
au lancement du SOC : pendant N jours (`TRAINING_DAYS`, défaut 7), toute alerte
HIGH/CRITICAL observée est réputée être du bruit ambiant et devient une exception
de whitelist. C'est un choix assumé — une intrusion en cours au moment du
lancement serait apprise comme du bruit. D'où la clôture par un case IRIS
« TRAINING » : chaque exception y est une tâche, et l'analyste défait celles qui
n'ont rien à y faire en passant la tâche en 'Canceled'.

Pendant la fenêtre, le reste du pipeline est SUSPENDU (`cycle.py` teste
`en_cours()`) : pas de triage LLM, pas de case, pas de remédiation. Seule
l'ingestion continue, pour que les alertes soient en base et servent
l'apprentissage. À la clôture, le noise filter est réappliqué à tout l'existant
(`ingest.reappliquer_filtre`) : le bruit appris est marqué supprimé et ne
graine plus aucun incident quand la corrélation reprend.

    python -m soc_agent.training --tick        # boucle du conteneur soc-training
    python -m soc_agent.training --demarrer    # ouvre une fenêtre (ou --jours N)
    python -m soc_agent.training --cloturer    # fin anticipée
    python -m soc_agent.training --etat
"""

import argparse
import json
import logging
import os
import sys

import psycopg
from psycopg.rows import dict_row

from . import config, ingest
from .noise import _value_field
from .whitelist import DISCRIMINANT_FIELDS, _canonical

log = logging.getLogger("training")

# Verrou consultatif dédié : 0x50CA1 cycle, 0x50CA2 reconcile,
# 0x50CA3 whitelist_task.
_LOCK_TRAINING = 0x50CA4

# Préfixe des tâches IRIS du case TRAINING. Volontairement DIFFÉRENT de
# « WHITELIST » : `whitelist_task.py` ramasse toute tâche dont le titre commence
# par WHITELIST et passe en 'To do', il ne doit pas confondre les nôtres avec
# une demande d'exception d'analyste.
_TITLE_PREFIX = "TRAINING — whitelist"
_STATUS_PLACED = "Done"
_STATUS_CANCELED = "Canceled"

# Classification IRIS du case TRAINING : « other:other » (id 36). Ce case n'est
# pas un incident — le ranger en intrusion fausserait toute statistique tirée
# des classifications.
CLASSIF_TRAINING = int(os.environ.get("TRAINING_IRIS_CLASSIFICATION", "36"))


# --- fenêtre -----------------------------------------------------------------

def current_run(conn) -> dict | None:
    """Fenêtre de training ouverte, ou None.

    Le critère est le STATUT, pas `ends_at` : entre l'expiration du délai et la
    clôture effective (réapplication du filtre + case IRIS), le pipeline doit
    rester suspendu. Sinon le premier cycle passant dans cet intervalle
    corrélerait le backlog brut, avant que le bruit appris ne soit marqué.
    """
    return conn.execute(
        "SELECT id, started_at, ends_at, days, status, iris_case_id "
        "  FROM training_runs WHERE status = 'running' "
        " ORDER BY id DESC LIMIT 1").fetchone()


def in_progress(conn) -> bool:
    """Le pipeline doit-il rester suspendu ? (appelé par `cycle.py`)"""
    return conn.execute(
        "SELECT 1 FROM training_runs WHERE status = 'running' LIMIT 1"
    ).fetchone() is not None


def start(conn, days: int) -> dict | None:
    """Ouvre une fenêtre de training. None si une fenêtre est déjà ouverte."""
    if current_run(conn):
        return None
    run = conn.execute("""
        INSERT INTO training_runs (ends_at, days)
        VALUES (now() + make_interval(days => %s), %s)
        RETURNING id, started_at, ends_at, days, status, iris_case_id
    """, (days, days)).fetchone()
    conn.commit()
    log.info("training : fenêtre #%s ouverte pour %d jour(s), fin %s",
             run["id"], days, run["ends_at"])
    return run


# --- apprentissage -----------------------------------------------------------

SELECT_ALERTS = """
SELECT id, rule_id, rule_level, rule_desc, agent_name, agent_id, raw
  FROM alerts
 WHERE ts >= %(depuis)s
   AND rule_level >= %(niveau)s
   AND NOT suppressed
"""


def _training_signature(raw_alerts: list[dict], rule_id: str,
                        agent_name: str | None) -> dict:
    """Signature d'un groupe d'alertes (même règle, même machine).

    Diffère de `whitelist._signature` sur deux points, assumés :

    - `agent_name` fait TOUJOURS partie de la signature. Le bruit ambiant est
      propre à une machine (c'est ce serveur-là qui lance ce script-là) ; le
      whitelister partout aveuglerait la détection sur tout le parc.
    - l'absence de discriminant (compte / commande / fichier) n'est PAS un
      refus. Beaucoup de bruit d'infrastructure n'a aucun champ discriminant, et
      `rule_id + agent_name` reste borné à une machine — là où `rule_id` seul,
      refusé par la whitelist automatique, neutraliserait la règle sur tout le SI.

    Les discriminants constants sur tout le groupe sont ajoutés : ils
    rétrécissent encore la signature quand ils existent.
    """
    signature = {"rule_id": str(rule_id)}
    if agent_name:
        signature["agent_name"] = agent_name
    for field in DISCRIMINANT_FIELDS:
        values = {v for a in raw_alerts
                   if (v := _value_field(a, field)) is not None}
        if len(values) == 1:
            signature[field] = str(next(iter(values)))
    return signature


def learn(conn, run: dict) -> list[dict]:
    """Transforme le bruit HIGH/CRITICAL observé en exceptions de whitelist.

    Entièrement DÉTERMINISTE : aucun appel au LLM. Groupement par (règle,
    machine), une exception par groupe. Idempotent — les signatures déjà
    connues sont ignorées (contrainte d'unicité).
    """
    lines = conn.execute(SELECT_ALERTS, {
        "depuis": run["started_at"], "niveau": config.TRAINING_MIN_LEVEL,
    }).fetchall()
    if not lines:
        return []

    groups: dict[tuple, list[dict]] = {}
    for l in lines:
        groups.setdefault((l["rule_id"], l["agent_name"]), []).append(l)

    existing = {r["signature"] for r in conn.execute(
        "SELECT signature FROM whitelist_rules").fetchall()}

    created: list[dict] = []
    for (rule_id, agent_name), group in sorted(
            groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        level = max(l["rule_level"] for l in group)
        if level > config.TRAINING_MAX_LEVEL:
            log.info("training : niveau %d > %d, règle %s@%s non whitelistée",
                     level, config.TRAINING_MAX_LEVEL, rule_id, agent_name)
            continue
        raws = [l["raw"] if isinstance(l["raw"], dict) else json.loads(l["raw"])
                for l in group]
        signature = _training_signature(raws, rule_id, agent_name)
        canon = _canonical(signature)
        if canon in existing:
            continue

        desc = next((l["rule_desc"] for l in group if l["rule_desc"]), "")
        reason = (f"Bruit ambiant appris en training (fenêtre #{run['id']}, "
                  f"{len(group)} alerte(s) niveau max {level}) — "
                  f"{desc or canon}")
        conn.execute("""
            INSERT INTO whitelist_rules
                (signature, match_all, reason, source, fp_count, training_run_id)
            VALUES (%s, %s, %s, 'training', %s, %s)
            ON CONFLICT (signature) DO NOTHING
        """, (canon, json.dumps(signature), reason, len(group), run["id"]))
        conn.commit()
        existing.add(canon)
        created.append({"signature": canon, "match_all": signature,
                       "alertes": len(group), "niveau": level,
                       "rule_desc": desc})
        log.info("training : exception apprise %s (%d alertes)",
                 canon, len(group))
    return created


# --- clôture -----------------------------------------------------------------

def _case_description(run: dict, rules: list[dict]) -> str:
    start = run["started_at"].strftime("%Y-%m-%d %H:%M")
    end = run["ends_at"].strftime("%Y-%m-%d %H:%M")
    return (
        f"Fenêtre d'apprentissage du bruit ambiant #{run['id']} : "
        f"{start} → {end} (UTC).\n\n"
        f"Pendant cette fenêtre, le triage LLM, la création de cases et la "
        f"remédiation autonome étaient SUSPENDUS. Toute alerte de niveau "
        f"≥ {config.TRAINING_MIN_LEVEL} observée a été considérée comme du "
        f"bruit légitime du SI et transformée en exception de whitelist : "
        f"{len(rules)} exception(s).\n\n"
        f"Chaque exception est une tâche de ce case. **Passer une tâche en "
        f"'Canceled' désactive l'exception correspondante** (traitement "
        f"cyclique par soc_agent.training, ~5 min) : les alertes qu'elle "
        f"masquait redeviennent visibles pour le pipeline.\n\n"
        f"Une intrusion déjà en cours au lancement du SOC aurait été apprise "
        f"comme du bruit — c'est la limite assumée du mode training. Revoir "
        f"cette liste est le contrôle qui la rattrape.")


def _task_description(rule: dict) -> str:
    """Description de la tâche IRIS, depuis la ligne `whitelist_rules` telle quelle."""
    return (
        f"Exception créée automatiquement pendant le training.\n\n"
        f"```json\n"
        f"{json.dumps(rule['match_all'], ensure_ascii=False, indent=2)}\n"
        f"```\n\n"
        f"{rule['reason']}\n\n"
        f"Passer cette tâche en 'Canceled' pour DÉSACTIVER l'exception : les "
        f"alertes qu'elle masque redeviendront visibles pour le pipeline.")


def close(conn, run: dict) -> dict:
    """Ferme la fenêtre : filtre réappliqué, case IRIS « TRAINING », statut figé.

    Ordre imposé : le filtre est réappliqué AVANT de basculer le statut, car
    c'est le statut qui débloque le pipeline. L'inverse laisserait un cycle
    corréler le backlog non filtré.
    """
    # Dernier passage d'apprentissage : les alertes des toutes dernières minutes.
    learn(conn, run)

    rules = conn.execute("""
        SELECT id, signature, match_all, reason, fp_count
          FROM whitelist_rules
         WHERE training_run_id = %s AND active
         ORDER BY id
    """, (run["id"],)).fetchall()

    deleted, seen = ingest.reapply_filter()
    log.info("training : filtre réappliqué, %d/%d alertes supprimées",
             deleted, seen)

    case_id = None
    try:
        case_id = _create_iris_case(conn, run, rules)
    except Exception as e:  # noqa: BLE001 — un IRIS indisponible ne doit pas
        # laisser la fenêtre ouverte indéfiniment : les exceptions sont créées,
        # le pipeline doit reprendre. Le case sera retenté au tick suivant.
        log.error("training : case IRIS non créé (%s) — nouvelle tentative "
                  "au prochain passage", e)

    if case_id is None:
        return {"case_id": None, "regles": len(rules),
                "supprimees": deleted}

    conn.execute("UPDATE training_runs SET status = 'finished', "
                 "finished_at = now(), iris_case_id = %s WHERE id = %s",
                 (case_id, run["id"]))
    conn.commit()
    log.info("training : fenêtre #%s clôturée -> case IRIS #%s (%d exceptions)",
             run["id"], case_id, len(rules))
    return {"case_id": case_id, "regles": len(rules),
            "supprimees": deleted}


def _create_iris_case(conn, run: dict, rules: list[dict]) -> int:
    # Import différé : `iris` importe tout le pipeline, inutile de le charger
    # pour un tick qui ne fait qu'apprendre.
    from .iris import _client

    case = _client()
    start = run["started_at"].strftime("%Y-%m-%d")
    r = case.add_case(
        case_name=f"TRAINING — bruit ambiant du SI ({start}, "
                  f"{run['days']} j)",
        case_description=_case_description(run, rules),
        case_customer=config.IRIS_CUSTOMER,
        case_classification=CLASSIF_TRAINING,
        soc_id=f"Aura-SOC-TRAINING-{run['id']}",
    )
    if not r.is_success():
        raise RuntimeError(f"création case TRAINING échouée : {r.get_msg()}")
    case_id = r.get_data()["case_id"]

    for rule in rules:
        title = f"{_TITLE_PREFIX} : {rule['signature']}"
        try:
            rt = case.add_task(
                title=title[:250],
                status=_STATUS_PLACED,
                assignees=[],
                description=_task_description(rule),
                tags=["training", "whitelist", "auto"],
                cid=case_id)
            task_id = rt.get_data().get("id") if rt.is_success() else None
        except Exception as e:  # noqa: BLE001 — une tâche KO n'empêche pas
            # les autres ; l'exception existe déjà en base.
            log.warning("training : tâche pour %s non créée : %s",
                        rule["signature"], e)
            continue
        if task_id:
            conn.execute("UPDATE whitelist_rules SET iris_task_id = %s "
                         "WHERE id = %s", (task_id, rule["id"]))
            conn.commit()
    return case_id


# --- révocation : tâche passée en 'Canceled' ---------------------------------

def reconcile(conn) -> list[dict]:
    """Désactive les exceptions dont la tâche IRIS est passée en 'Canceled'.

    Symétrique de `mitigate.reconcilier` pour les remédiations. Sens unique :
    remettre la tâche en 'Done' ne réactive PAS l'exception — une exception
    retirée par un analyste doit se recréer explicitement, pas au gré d'un
    clic dans un statut.
    """
    runs = conn.execute(
        "SELECT id, iris_case_id FROM training_runs "
        "WHERE iris_case_id IS NOT NULL").fetchall()
    if not runs:
        return []

    active = conn.execute("""
        SELECT id, signature, iris_task_id, training_run_id
          FROM whitelist_rules
         WHERE active AND iris_task_id IS NOT NULL
           AND training_run_id IS NOT NULL
    """).fetchall()
    if not active:
        return []
    by_task = {r["iris_task_id"]: r for r in active}

    from .iris import _client
    from .mitigate import _comment_task
    case = _client()

    removed: list[dict] = []
    for run in runs:
        cid = run["iris_case_id"]
        try:
            tasks = (case.list_tasks(cid).get_data() or {}).get("tasks") or []
        except Exception as e:  # noqa: BLE001 — IRIS KO ne casse pas le tick
            log.warning("training : list_tasks case #%s : %s", cid, e)
            continue
        for t in tasks:
            if (t.get("status_name") or "") != _STATUS_CANCELED:
                continue
            rule = by_task.get(t.get("task_id"))
            if not rule:
                continue
            conn.execute("UPDATE whitelist_rules SET active = false "
                         "WHERE id = %s", (rule["id"],))
            conn.commit()
            removed.append({"signature": rule["signature"],
                             "task_id": t["task_id"], "case_id": cid})
            log.info("training : exception %s désactivée (tâche IRIS #%s "
                     "Canceled)", rule["signature"], t["task_id"])
            _comment_task(case, cid, t["task_id"],
                "🤖 Exception de training DÉSACTIVÉE : les alertes "
                f"`{rule['signature']}` redeviennent visibles pour le "
                "pipeline (triage, case, remédiation).")

    if removed:
        # Les alertes que ces exceptions masquaient doivent redevenir
        # corrélables : sans cette réévaluation, elles resteraient marquées
        # `suppressed` en base et la révocation n'aurait aucun effet visible.
        deleted, seen = ingest.reapply_filter()
        log.info("training : filtre réappliqué après révocation "
                 "(%d/%d supprimées)", deleted, seen)
    return removed


# --- boucle ------------------------------------------------------------------

def tick() -> dict:
    """Un passage du conteneur soc-training. Idempotent.

    Démarrage automatique : seulement si `TRAINING_ENABLED` et qu'AUCUNE
    fenêtre n'a jamais été ouverte. Le training est une phase de mise en
    service, pas un mode récurrent — relancer une fenêtre plus tard est une
    décision explicite (`--demarrer`).
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)", (_LOCK_TRAINING,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("training : passage déjà en cours, on saute ce tour")
            return {"etat": "verrouillé"}
        try:
            run = current_run(conn)
            if run is None:
                already = conn.execute(
                    "SELECT 1 FROM training_runs LIMIT 1").fetchone()
                if config.TRAINING_ENABLED and not already:
                    run = start(conn, config.TRAINING_DAYS)
                else:
                    # Fenêtre close (ou jamais ouverte) : il reste à écouter les
                    # révocations de l'analyste sur le case TRAINING.
                    return {"etat": "inactif",
                            "retirees": reconcile(conn)}

            expire = conn.execute(
                "SELECT now() >= %s AS fini", (run["ends_at"],)).fetchone()["fini"]
            if expire:
                return {"etat": "clôture", **close(conn, dict(run))}

            created = learn(conn, run)
            return {"etat": "apprentissage", "run": run["id"],
                    "creees": len(created), "end_ts": run["ends_at"]}
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_TRAINING,))


def state_report() -> list[dict]:
    """Les fenêtres de training, plus récente d'abord, avec leurs exceptions."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        runs = conn.execute(
            "SELECT * FROM training_runs ORDER BY id DESC").fetchall()
        output = []
        for r in runs:
            n = conn.execute(
                "SELECT count(*) FILTER (WHERE active) AS a, count(*) AS t "
                "FROM whitelist_rules WHERE training_run_id = %s",
                (r["id"],)).fetchone()
            output.append({
                "id": r["id"], "status": r["status"], "days": r["days"],
                "started_at": r["started_at"].isoformat(),
                "ends_at": r["ends_at"].isoformat(),
                "finished_at": (r["finished_at"].isoformat()
                                if r["finished_at"] else None),
                "iris_case_id": r["iris_case_id"],
                "exceptions_actives": n["a"], "exceptions_total": n["t"],
            })
    return output


def state() -> None:
    runs = state_report()
    if not runs:
        print("Aucune fenêtre de training.")
        return
    for r in runs:
        print(f"  #{r['id']} [{r['status']}] {r['started_at'][:16]}"
              f" → {r['ends_at'][:16]} ({r['days']} j)"
              f"  case IRIS {r['iris_case_id'] or '—'}"
              f"  exceptions {r['exceptions_actives']}/{r['exceptions_total']} "
              f"actives")


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stderr)
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tick", action="store_true",
                    help="un passage complet (boucle du conteneur)")
    ap.add_argument("--demarrer", action="store_true",
                    help="ouvre une fenêtre de training")
    ap.add_argument("--jours", type=int, default=config.TRAINING_DAYS)
    ap.add_argument("--cloturer", action="store_true",
                    help="clôture la fenêtre en cours sans attendre son terme")
    ap.add_argument("--etat", action="store_true")
    args = ap.parse_args()

    if args.state:
        state()
        return

    if args.start:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            run = start(conn, args.days)
        if run is None:
            print("Une fenêtre de training est déjà ouverte.")
        else:
            print(f"Fenêtre #{run['id']} ouverte jusqu'au {run['ends_at']}.")
        return

    if args.close:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            run = current_run(conn)
            if run is None:
                print("Aucune fenêtre de training ouverte.")
                return
            res = close(conn, dict(run))
        print(f"Fenêtre clôturée : {res['regles']} exception(s), "
              f"case IRIS #{res['case_id']}.")
        return

    res = tick()
    print(res)


if __name__ == "__main__":
    main()
