"""Exécution des remédiations décidées au triage, avec trace IRIS par action.

Passage de « proposer » à « exécuter ». Pour chaque action de remédiation d'un
incident vrai positif, on :

1. l'exécute par son canal (Shuffle SOAR pour l'isolation ; API Wazuh pour le
   blocage d'IP et la désactivation de compte) ;
2. écrit une note dans le case IRIS : ce qui a été fait, pourquoi, et COMMENT
   l'annuler — toute mitigation doit être défaisable ;
3. la trace en base (`mitigations`) : audit + idempotence.

Sécurité — ceci exécute des actions à fort impact sur la prod à partir d'un
verdict de modèle. Trois barrières AVANT toute exécution :

- `MITIGATE_EXECUTE=false` par défaut : dry-run, rien n'est déclenché.
- Un incident dont le triage a relevé des motifs d'injection est SUSPENDU :
  un verdict rendu sur un contexte manipulé ne commande pas d'action réelle.
- Seules les actions de remédiation de l'énumération fermée sont exécutables ;
  open_case / close / escalate ne passent pas par ici.

    python -m soc_agent.mitigate --incident 15
    MITIGATE_EXECUTE=true python -m soc_agent.mitigate --incident 15
"""

import argparse
import json
import logging

import psycopg
import requests
import urllib3
from psycopg.rows import dict_row

from . import config
from .anonymize import _est_interne
from .anonymize import COMPTES_GENERIQUES
from .iris import LIBELLE_ACTION, _client

log = logging.getLogger("mitigate")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Actions réellement exécutables (remédiations). Le reste (open_case,
# close_false_positive, escalate_human) n'est pas une action machine.
REMEDIATIONS = {"propose_isolate_host", "propose_block_ip",
                "propose_disable_user", "collect_endpoint_evidence"}

# Ordre d'exécution : collecter les preuves AVANT de couper quoi que ce soit,
# isoler EN DERNIER (l'isolation coupe les canaux dont dépendent les autres).
ORDRE_EXEC = ["collect_endpoint_evidence", "propose_block_ip",
              "propose_disable_user", "propose_isolate_host"]


# --- canaux d'exécution -----------------------------------------------------

def _shuffle(webhook: str, payload: dict) -> str:
    r = requests.post(f"{config.SHUFFLE_URL}/api/v1/hooks/{webhook}",
                      json=payload, timeout=15)
    r.raise_for_status()
    return r.text


def fire_isolation(agent_id: str, isoler: bool, reason: str) -> str:
    """Isole (ou désisole) un agent via le webhook Shuffle. Retourne la réponse.

    Même workflow dans les deux sens, seule l'active-response change :
    host-isolate.sh pose les règles nftables, host-unisolate.sh les retire.
    """
    cmd = "!host-isolate.sh" if isoler else "!host-unisolate.sh"
    return _shuffle(config.SHUFFLE_WEBHOOK_ISOLATE,
                    {"agent_id": agent_id, "ar_command": cmd, "reason": reason})


def _tracer_isolation(agent_id: str, isoler: bool, reason: str) -> None:
    """Trace une (dé)isolation manuelle sur les incidents ouverts de l'agent.

    Pas d'incident rattaché -> pas de trace en base (la table `mitigations` est
    indexée par incident) ; Shuffle et Wazuh gardent de toute façon le journal.
    """
    statut = "exécuté" if isoler else "annulé"
    action, cible = "propose_isolate_host", agent_id
    details = (f"Isolation réseau manuelle de l'agent {agent_id}." if isoler
               else f"Levée manuelle de l'isolation de l'agent {agent_id}.")
    undo = (f"Désisoler : python -m soc_agent.mitigate --desisoler {agent_id}"
            if isoler else "—")
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        incs = conn.execute(
            "SELECT id FROM incidents WHERE agent_id = %s AND iris_case_id IS NOT NULL "
            "ORDER BY id DESC LIMIT 1", (agent_id,)).fetchall()
        for r in incs:
            conn.execute(INSERT_MITIG, {
                "incident_id": r["id"], "action": action, "cible": cible,
                "statut": statut, "details": f"{details} Motif : {reason}",
                "undo": undo, "iris_note_id": None})
        conn.commit()


def isoler(agent_id: str, reason: str = "isolation manuelle") -> None:
    fire_isolation(agent_id, True, reason)
    _tracer_isolation(agent_id, True, reason)
    print(f"  agent {agent_id} : isolation demandée ({reason})")


def desisoler(agent_id: str, reason: str = "désisolation manuelle") -> None:
    fire_isolation(agent_id, False, reason)
    _tracer_isolation(agent_id, False, reason)
    print(f"  agent {agent_id} : levée d'isolation demandée ({reason})")


def _wazuh_token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


def _wazuh_ar(agent_id: str, command: str, arguments: list[str]) -> dict:
    """Déclenche une active-response Wazuh sur un agent (API directe)."""
    tok = _wazuh_token()
    r = requests.put(
        f"{config.WAZUH_API_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {tok}"},
        json={"command": command, "arguments": arguments},
        verify=False, timeout=20)
    r.raise_for_status()
    return r.json()


# --- exécuteurs par action --------------------------------------------------
#
# Chacun retourne (statut, canal, details, undo). En dry-run, il DÉCRIT l'action
# sans la déclencher (statut 'dry_run'). Toute exception -> statut 'échec'.

def _isolate(cible: str, ctx: dict):
    canal = "Shuffle → active-response host-isolate.sh (nftables)"
    details = ("Isolation réseau de l'hôte : nftables ne laisse joignable que le "
               "manager Wazuh (canal 1514). SSH et tout autre flux sont coupés, "
               "arrêtant une attaque en cours sur la machine.")
    undo = (f"curl -X POST {config.SHUFFLE_URL}/api/v1/hooks/"
            f"{config.SHUFFLE_WEBHOOK_ISOLATE} -H 'Content-Type: application/json' "
            f"-d '{{\"agent_id\": \"{cible}\", \"ar_command\": "
            f"\"!host-unisolate.sh\", \"reason\": \"incident clos\"}}'")
    if config.MITIGATE_EXECUTE:
        fire_isolation(cible, True, ctx["reason_court"])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


def _block_ip(cible: str, ctx: dict):
    canal = "API Wazuh → active-response firewall-drop"
    details = (f"Blocage du flux réseau de l'IP {cible} sur l'agent "
               f"{ctx['agent_id']} (firewall-drop). Requiert l'AR firewall-drop "
               "configurée sur l'agent ; sinon l'API renvoie une erreur.")
    undo = (f"L'entrée firewall-drop expire au bout du timeout de l'AR. Pour un "
            f"retrait immédiat : supprimer la règle visant {cible} dans le "
            f"pare-feu de l'agent {ctx['agent_id']}.")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], "!firewall-drop0", [cible])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


def _disable_user(cible: str, ctx: dict):
    canal = "API Wazuh → active-response disable-account"
    details = (f"Désactivation du compte {cible} sur l'agent {ctx['agent_id']} "
               "(disable-account). Requiert l'AR disable-account configurée.")
    undo = (f"Réactiver le compte {cible} sur l'agent {ctx['agent_id']} "
            f"(passwd -u {cible} sous Linux, ou enable-account).")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], "!disable-account", [cible])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


def _collect(cible: str, ctx: dict):
    canal = "Forensique — scripts/forensic-pull.sh (manuel)"
    details = ("Collecte RAM + image disque de l'agent. NON automatisée ici : "
               "lourde, et tirée par SSH (manager→agent) que l'isolation coupe. "
               "À lancer AVANT toute isolation si des preuves sont nécessaires.")
    undo = "Sans objet — collecte en lecture seule, rien à annuler."
    return "sans_canal", canal, details, undo


EXECUTEURS = {
    "propose_isolate_host": _isolate,
    "propose_block_ip": _block_ip,
    "propose_disable_user": _disable_user,
    "collect_endpoint_evidence": _collect,
}


def _cibles(action: str, incident: dict, alertes: list[dict]) -> list[str]:
    """Cibles d'une action : agent pour l'isolation/collecte, IP externes pour
    le blocage, comptes nommés pour la désactivation."""
    if action in ("propose_isolate_host", "collect_endpoint_evidence"):
        return [str(incident["agent_id"])]
    if action == "propose_block_ip":
        return sorted({a["srcip"] for a in alertes
                       if a["srcip"] and not _est_interne(str(a["srcip"]))})
    if action == "propose_disable_user":
        return sorted({a["srcuser"] for a in alertes if a["srcuser"]
                       and str(a["srcuser"]).strip().lower()
                       not in COMPTES_GENERIQUES})
    return []


# --- note IRIS + persistance ------------------------------------------------

def _note(triage: dict, action: str, cible: str, statut: str,
          canal: str, details: str, undo: str) -> str:
    libelle = LIBELLE_ACTION.get(action, action)
    sim = "[SIMULATION] " if statut == "dry_run" else ""
    return "\n".join([
        f"# {sim}Remédiation — {libelle}",
        "",
        f"**Cible** : {cible}",
        f"**Statut** : {statut}",
        f"**Canal** : {canal}",
        "",
        "## Ce qui a été fait",
        details,
        "",
        "## Pourquoi",
        f"Verdict IA : {triage['verdict']} (confiance {triage['confidence']}). "
        + triage["reason"],
        "",
        "## Comment annuler",
        undo,
    ])


INSERT_MITIG = """
INSERT INTO mitigations (incident_id, action, cible, statut, details, undo,
                         iris_note_id)
VALUES (%(incident_id)s, %(action)s, %(cible)s, %(statut)s, %(details)s,
        %(undo)s, %(iris_note_id)s)
ON CONFLICT (incident_id, action, cible) DO UPDATE
SET statut = EXCLUDED.statut, details = EXCLUDED.details, undo = EXCLUDED.undo,
    iris_note_id = EXCLUDED.iris_note_id, executed_at = now()
RETURNING id
"""


def _deja_exec(conn, incident_id: int, action: str, cible: str) -> bool:
    r = conn.execute(
        "SELECT statut FROM mitigations WHERE incident_id=%s AND action=%s "
        "AND cible=%s", (incident_id, action, cible)).fetchone()
    return bool(r and r["statut"] == "exécuté")


SELECT_TRIAGE = """
SELECT verdict, confidence, reason, actions, injection_motifs, garde_fous
  FROM triages WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1
"""


def executer(incident_id: int) -> list[dict]:
    resultats: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        inc = conn.execute(
            "SELECT id, agent_id, agent_name, max_level, iris_case_id "
            "FROM incidents WHERE id = %s", (incident_id,)).fetchone()
        if not inc:
            print(f"Incident #{incident_id} introuvable.")
            return []
        triage = conn.execute(SELECT_TRIAGE, (incident_id,)).fetchone()
        if not triage:
            print(f"Incident #{incident_id} pas encore trié.")
            return []

        # Barrière : un verdict rendu sur un contexte manipulé ne commande rien.
        if triage["injection_motifs"]:
            print(f"  #{incident_id} SUSPENDU — motifs d'injection au triage : "
                  f"{', '.join(triage['injection_motifs'])}. Aucune exécution.")
            return []

        remed = [a for a in triage["actions"] if a in REMEDIATIONS]
        if not remed:
            print(f"  #{incident_id} aucune remédiation à exécuter "
                  f"(verdict {triage['verdict']}).")
            return []

        alertes = conn.execute(
            "SELECT srcip, srcuser FROM alerts WHERE incident_id = %s",
            (incident_id,)).fetchall()

        case = _client() if inc["iris_case_id"] else None
        dir_id = None
        if case:
            rd = case.add_notes_directory(directory_name="Remédiations",
                                          cid=inc["iris_case_id"])
            dir_id = rd.get_data()["id"] if rd.is_success() else None

        mode = "EXÉCUTION" if config.MITIGATE_EXECUTE else "DRY-RUN"
        print(f"  #{incident_id} {inc['agent_name']} — {mode} — "
              f"{len(remed)} action(s)")

        ctx = {"agent_id": str(inc["agent_id"]),
               "reason_court": (triage["reason"] or "")[:120]}

        for action in sorted(remed, key=lambda a: ORDRE_EXEC.index(a)
                             if a in ORDRE_EXEC else 99):
            for cible in _cibles(action, inc, alertes):
                if config.MITIGATE_EXECUTE and _deja_exec(
                        conn, incident_id, action, cible):
                    print(f"      {action} [{cible}] déjà exécuté, ignoré.")
                    continue
                try:
                    statut, canal, details, undo = EXECUTEURS[action](cible, ctx)
                except Exception as e:  # noqa: BLE001 — un échec de canal ne doit
                    # pas arrêter les autres remédiations ; on le trace.
                    statut, canal = "échec", "—"
                    details, undo = f"Échec du canal : {e}", "—"
                    log.warning("échec %s [%s] : %s", action, cible, e)

                note_id = None
                if case and dir_id is not None:
                    contenu = _note(triage, action, cible, statut, canal,
                                    details, undo)
                    titre = ("[SIMULATION] " if statut == "dry_run" else "") + \
                        f"Remédiation — {LIBELLE_ACTION.get(action, action)} ({cible})"
                    rn = case.add_note(note_title=titre, note_content=contenu,
                                       directory_id=dir_id,
                                       cid=inc["iris_case_id"])
                    if rn.is_success():
                        note_id = rn.get_data().get("note_id")

                conn.execute(INSERT_MITIG, {
                    "incident_id": incident_id, "action": action, "cible": cible,
                    "statut": statut, "details": details, "undo": undo,
                    "iris_note_id": note_id})
                conn.commit()

                resultats.append({"action": action, "cible": cible,
                                  "statut": statut})
                print(f"      {action} [{cible}] -> {statut}  ({canal})")
    return resultats


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--incident", type=int,
                   help="exécute les remédiations décidées au triage de cet incident")
    g.add_argument("--isoler", metavar="AGENT_ID",
                   help="isole un agent du réseau (action opérateur, exécutée)")
    g.add_argument("--desisoler", metavar="AGENT_ID",
                   help="lève l'isolation d'un agent (action opérateur, exécutée)")
    ap.add_argument("--motif", default="action opérateur",
                    help="motif consigné avec l'(dé)isolation manuelle")
    args = ap.parse_args()

    # --isoler / --desisoler sont des commandes opérateur explicites : elles
    # s'exécutent réellement, indépendamment de MITIGATE_EXECUTE (qui ne borne
    # que l'exécution AUTOMATIQUE depuis un verdict).
    if args.isoler:
        isoler(args.isoler, args.motif)
    elif args.desisoler:
        desisoler(args.desisoler, args.motif)
    else:
        executer(args.incident)


if __name__ == "__main__":
    main()
