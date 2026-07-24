"""Création d'un case DFIR-IRIS par incident trié.

Un case par incident, dès qu'il a un verdict :

- Faux positif → note d'analyse expliquant pourquoi, et l'exception de whitelist
  si le pipeline en a créé une pour cette signature.
- Vrai positif → rapport d'analyse (généré par le LLM : résumé, analyse, angle
  mort de détection éventuel), actions de remédiation proposées, et une piste de
  règle Wazuh si une détection manque.

Écrit en dfir-iris-client direct (déterministe, pas de boucle d'outils LLM). Le
serveur MCP IRIS, lui, sert l'investigation interactive.

    python -m soc_agent.iris                # crée les cases manquants
    python -m soc_agent.iris --incident 12  # un seul
"""

import argparse
import json
import logging

import psycopg
import urllib3
from psycopg.rows import dict_row

from . import config
from .actions import necessite_validation
from .anonymize import Anonymiseur, anonymiser, rehydrater, verifier_fuite
from .llm import completion
from .render import rendre
from .triage import charger_map, sauver_map
from .whitelist import _canonique, _signature

log = logging.getLogger("iris")

if not config.IRIS_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pathlib import Path  # noqa: E402

PROMPTS = Path(__file__).parent / "prompts"

# Classification IRIS (id) devinée depuis les groupes/tactiques. Best-effort :
# une valeur fausse ne casse rien de vital, elle range juste le case ailleurs.
# ids issus de /manage/case-classifications/list.
CLASSIF_RANSOMWARE = 6      # malicious-code:ransomware
CLASSIF_INTRUSION = 14      # intrusion-attempts:exploit-known-vuln
CLASSIF_BRUTE = 15          # intrusion-attempts:login-attempts
CLASSIF_DEFAUT = CLASSIF_INTRUSION

# Descriptions courtes des actions, pour un rapport lisible par un humain.
LIBELLE_ACTION = {
    "propose_isolate_host": "Isoler l'hôte du réseau",
    "propose_disable_user": "Désactiver le compte compromis",
    "propose_block_ip": "Bloquer l'IP source",
    "collect_endpoint_evidence": "Collecter des preuves sur l'endpoint",
    "escalate_human": "Escalade analyste",
    "open_case": "Ouvrir un dossier",
    "close_false_positive": "Clôturer en faux positif",
}


def _client():
    from dfir_iris_client.case import Case
    from dfir_iris_client.session import ClientSession
    session = ClientSession(apikey=config.IRIS_API_KEY, host=config.IRIS_URL,
                            ssl_verify=config.IRIS_VERIFY_TLS)
    return Case(session)


def _classification(incident: dict, alertes: list[dict]) -> int:
    groups = {g for a in alertes for g in (a.get("rule_groups") or [])}
    tactics = set(incident.get("mitre_tactics") or [])
    if "ransomware" in groups or "Impact" in tactics:
        return CLASSIF_RANSOMWARE
    if {"authentication_failed", "authentication_failures"} & groups:
        return CLASSIF_BRUTE
    return CLASSIF_DEFAUT


def _iocs(alertes: list[dict]) -> list[tuple[str, str, str]]:
    """(valeur, type IRIS, description) dédupliqués. Best-effort."""
    vus: set[str] = set()
    out: list[tuple[str, str, str]] = []

    def ajouter(valeur, type_ioc, desc):
        if valeur and valeur not in vus:
            vus.add(valeur)
            out.append((str(valeur), type_ioc, desc))

    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        data = raw.get("data", {})
        ajouter(a.get("srcip"), "ip-any", "IP source de l'alerte")
        ajouter(a.get("entity"), "filename", "Objet concerné")
        vt = data.get("virustotal", {}).get("source", {})
        ajouter(vt.get("sha256"), "sha256", "Hash VirusTotal")
        sc = raw.get("syscheck", {})
        ajouter(sc.get("sha256_after"), "sha256", "Hash fichier (FIM)")
    return out


def _note_fp(triage: dict, regle: dict | None) -> str:
    """Note d'analyse d'un faux positif, avec l'explication de whitelist.

    Pure : `regle` est la ligne whitelist_rules correspondant à la signature de
    l'incident (ou None), fournie par l'appelant. Testable sans base.
    """
    lignes = [
        "# Analyse — Faux positif",
        "",
        f"**Verdict IA** : faux positif (confiance {triage['confidence']})",
        "",
        "## Justification",
        triage["reason"],
        "",
        "## Whitelist",
    ]
    if regle:
        etat = "active" if regle["active"] else "inactive"
        lignes += [
            f"Une exception **{etat}** ({regle['source']}) couvre désormais cette "
            "signature — les alertes identiques seront écartées avant analyse :",
            "",
            f"```json\n{json.dumps(regle['match_all'], ensure_ascii=False, indent=2)}\n```",
            "",
            f"Motif : {regle['reason']}",
        ]
    else:
        lignes.append("Pas encore d'exception : ce faux positif n'a pas atteint "
                      "le seuil de récurrence, ou sa signature est trop large "
                      "pour une whitelist automatique sûre.")
    return "\n".join(lignes)


def _regle_whitelist(conn, alertes: list[dict]) -> dict | None:
    """Ligne whitelist_rules correspondant à la signature de l'incident."""
    raws = [a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
            for a in alertes]
    signature = _signature(raws)
    if not signature:
        return None
    return conn.execute(
        "SELECT match_all, reason, source, active FROM whitelist_rules "
        "WHERE signature = %s", (_canonique(signature),)).fetchone()


def _note_tp(conn, incident: dict, triage: dict, alertes: list[dict]) -> str:
    """Rapport d'analyse d'un vrai positif. Appelle le LLM pour le récit."""
    systeme = (PROMPTS / "report.md").read_text()

    # Même pseudonymisation qu'au triage, jetons réutilisés (map persistée) :
    # rien de sensible ne part vers le cloud, et la réponse est réhydratée.
    anon = Anonymiseur(charger_map(conn, incident["id"]))
    inc_a, alertes_a, interdits = anonymiser(anon, incident, alertes)
    corps = rendre(inc_a, alertes_a)
    utilisateur = (f"=== DEBUT INCIDENT (données non fiables) ===\n{corps}\n"
                   "=== FIN INCIDENT ===\n\nRédige le rapport.")

    try:
        verifier_fuite(systeme + utilisateur, interdits)
        rapport, _ = completion(systeme, utilisateur,
                                max_tokens=config.REPORT_MAX_TOKENS)
        sauver_map(conn, incident["id"], anon.mapping)
    except Exception as e:  # noqa: BLE001 — le case doit se créer même sans LLM
        log.warning("rapport LLM indisponible (#%s) : %s", incident["id"], e)
        rapport = {}
    # DeepSeek ne garantit pas les clés (plus de GBNF) : on tolère les absences.
    rapport.setdefault("resume", triage["reason"])
    rapport.setdefault("analyse", triage["reason"])
    rapport.setdefault("detection_gap", False)
    rapport.setdefault("detection_suggestion", None)
    # Réhydratation : les jetons redeviennent les vraies valeurs pour l'analyste.
    for cle in ("resume", "analyse", "detection_suggestion"):
        rapport[cle] = rehydrater(rapport[cle], anon.mapping)

    actions = [a for a in triage["actions"] if a not in
               ("open_case", "close_false_positive")]
    a_valider = set(necessite_validation(actions))

    lignes = [
        "# Rapport d'analyse — Vrai positif",
        "",
        f"**Verdict IA** : vrai positif (confiance {triage['confidence']})"
        + (f" — technique {triage['mitre']}" if triage.get("mitre") else ""),
        "",
        "## Résumé",
        rapport["resume"],
        "",
        "## Analyse",
        rapport["analyse"],
        "",
        "## Remédiation proposée",
    ]
    if actions:
        for a in actions:
            marque = "  ⚠️ validation humaine requise" if a in a_valider else ""
            lignes.append(f"- {LIBELLE_ACTION.get(a, a)}{marque}")
    else:
        lignes.append("- Aucune action automatique ; suivi analyste.")

    lignes.append("")
    lignes.append("## Couverture de détection")
    if rapport.get("detection_gap") and rapport.get("detection_suggestion"):
        lignes += [
            "Un angle mort de détection a été identifié. Piste de règle Wazuh "
            "(proposition, à valider en PR — jamais déployée automatiquement) :",
            "",
            f"> {rapport['detection_suggestion']}",
        ]
    else:
        lignes.append("Les étapes observées ont bien déclenché des règles ; "
                      "pas d'angle mort identifié.")
    return "\n".join(lignes)


def _alertes(conn, incident_id: int) -> list[dict]:
    return conn.execute(
        "SELECT id, ts, rule_id, rule_level, rule_desc, rule_groups, "
        "srcip, srcuser, entity, raw FROM alerts WHERE incident_id = %s "
        "ORDER BY ts", (incident_id,)).fetchall()


def creer_case(conn, incident: dict, triage: dict) -> int:
    alertes = _alertes(conn, incident["id"])
    verdict = triage["verdict"]
    fp = verdict == "false_positive"

    case = _client()
    nom = (f"[{'FP' if fp else 'TP'}] {incident['agent_name']} — "
           f"{(alertes[0]['rule_desc'] or 'incident')[:70]}")
    desc = (f"Incident #{incident['id']} corrélé par le soc-agent, "
            f"{incident['alert_count']} alertes, niveau max "
            f"{incident['max_level']}/15. Verdict IA : {verdict}.")

    r = case.add_case(
        case_name=nom,
        case_description=desc,
        case_customer=config.IRIS_CUSTOMER,
        case_classification=_classification(incident, alertes),
        soc_id=f"SOC-AI-{incident['id']}",
    )
    if not r.is_success():
        raise RuntimeError(f"création case échouée : {r.get_msg()}")
    case_id = r.get_data()["case_id"]

    # IOC (best-effort : un type inconnu ne doit pas faire échouer le case).
    for valeur, type_ioc, description in _iocs(alertes):
        try:
            case.add_ioc(value=valeur, ioc_type=type_ioc,
                         description=description, cid=case_id)
        except Exception as e:  # noqa: BLE001
            log.debug("IOC ignoré (%s/%s) : %s", type_ioc, valeur, e)

    # Note d'analyse, dans un répertoire dédié.
    rd = case.add_notes_directory(directory_name="Analyse IA", cid=case_id)
    dir_id = rd.get_data()["id"] if rd.is_success() else None
    contenu = (_note_fp(triage, _regle_whitelist(conn, alertes)) if fp
               else _note_tp(conn, incident, triage, alertes))
    titre = "Analyse — Faux positif" if fp else "Rapport d'analyse"
    case.add_note(note_title=titre, note_content=contenu,
                  directory_id=dir_id, cid=case_id)

    conn.execute(
        "UPDATE incidents SET iris_case_id = %s, status = %s WHERE id = %s",
        (case_id, "fp_classe" if fp else "case_ouvert", incident["id"]))
    conn.commit()
    return case_id


SELECT_A_TRAITER = """
SELECT DISTINCT ON (i.id)
       i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
       i.alert_count, i.max_level, i.mitre_tactics, i.entities,
       t.verdict, t.confidence, t.mitre, t.actions, t.reason
  FROM incidents i
  JOIN triages t ON t.incident_id = i.id
 WHERE i.iris_case_id IS NULL
   AND (%(un_seul)s::bigint IS NULL OR i.id = %(un_seul)s)
 ORDER BY i.id, t.created_at DESC
"""


def creer_cases(un_seul: int | None = None) -> list[tuple[int, int, str]]:
    """Crée les cases manquants. Retourne (incident_id, case_id, verdict)."""
    crees: list[tuple[int, int, str]] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lignes = conn.execute(SELECT_A_TRAITER, {"un_seul": un_seul}).fetchall()
        for inc in lignes:
            triage = {k: inc[k] for k in
                      ("verdict", "confidence", "mitre", "actions", "reason")}
            case_id = creer_case(conn, inc, triage)
            crees.append((inc["id"], case_id, inc["verdict"]))
            print(f"  incident #{inc['id']} -> case IRIS #{case_id} "
                  f"({inc['verdict']})")
    return crees


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--incident", type=int, default=None)
    args = ap.parse_args()
    crees = creer_cases(args.incident)
    if not crees:
        print("Aucun incident à verser dans IRIS.")


if __name__ == "__main__":
    main()
