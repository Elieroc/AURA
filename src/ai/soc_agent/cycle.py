"""Un cycle complet du pipeline : ingest -> correlate -> triage.

Point d'entrée du déclenchement périodique (conteneur soc-agent-cycle, cf.
ai/docker-compose.yml — boucle shell toutes les 5 min). Enchaîne les trois
étapes déjà écrites, dans une seule exécution, avec un verrou pour qu'un cycle
lent ne se superpose pas au suivant.

    python -m soc_agent.cycle

Conçu pour être lancé en boucle : chaque étape reprend là où elle en est
(curseur d'ingestion, alertes non corrélées, incidents non triés), donc rejouer
le cycle ne duplique rien.
"""

import argparse
import logging
import sys

import psycopg

from . import (assets, config, correlate, ingest, iris, training, triage, ueba,
               vt, watchdog, whitelist)

# Journalisé sur stderr -> capté par `docker compose logs` du conteneur.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("cycle")

# Clé arbitraire du verrou consultatif Postgres. Un seul cycle à la fois :
# l'ingestion et le triage écrivent les mêmes tables, et le triage sature déjà
# le CPU. Deux cycles en parallèle se marcheraient dessus sans rien gagner.
VERROU = 0x50CA1


def executer(depuis: str, taille_lot: int, limite_triage: int) -> int:
    """Enchaîne les trois étapes. Retourne un code de sortie."""
    # Connexion dédiée au verrou, maintenue ouverte toute la durée du cycle :
    # le verrou consultatif de session est libéré à la fermeture.
    with psycopg.connect(config.PG_DSN) as garde:
        pris = garde.execute(
            "SELECT pg_try_advisory_lock(%s)", (VERROU,)).fetchone()[0]
        if not pris:
            # Cas normal si le cycle précédent déborde sur l'intervalle du
            # timer. On sort proprement, le prochain déclenchement reprendra.
            log.info("cycle déjà en cours, on passe ce tour")
            return 0

        try:
            # CMDB d'abord : la corrélation fige la priorité de l'asset dans
            # l'incident qu'elle ouvre. Une machine enrôlée entre deux cycles
            # doit donc être connue AVANT, sinon son premier incident — souvent
            # le plus intéressant — naît en P4 par défaut et le reste.
            # Best-effort : une API Wazuh injoignable ne coûte pas un cycle.
            try:
                r = assets.synchroniser()
                log.info("cmdb : %d assets (%d créés)", r["vus"], r["crees"])
            except Exception as e:  # noqa: BLE001
                log.warning("synchronisation CMDB sautée : %s", e)

            n = ingest.ingerer(depuis, taille_lot)
            log.info("ingest : %d alertes traitées", n)

            # Fenêtre de training ouverte : on INGÈRE et rien de plus. Pas de
            # corrélation, pas de triage, pas de case, donc pas de remédiation
            # (elle part de iris.creer_case). Le SI n'a pas encore été appris ;
            # juger et agir maintenant reviendrait à isoler des serveurs sains
            # sur du bruit métier. Le conteneur soc-training apprend de ces
            # alertes ; à la clôture il réapplique le noise filter à tout
            # l'existant, et la corrélation reprend sur ce qui reste.
            if training.en_cours(garde):
                log.info("training en cours : corrélation, triage, cases et "
                         "remédiation suspendus (cf. soc_agent.training --etat)")
                return 0

            # Filtre VT AVANT corrélation : un exécutable jugé légitime est
            # suppressé, donc il ne graine ni ne rejoint un case (correlate lit
            # NOT suppressed). Best-effort : une panne VT ne casse pas le cycle.
            try:
                n_vt = vt.filtrer()
                if n_vt:
                    log.info("vt : %d alerte(s) écartée(s) (exe légitime)", n_vt)
            except Exception as e:  # noqa: BLE001
                log.warning("filtre VT sauté : %s", e)

            # UEBA entre le filtre VT et la corrélation : il observe les alertes
            # fraîches, met à jour la baseline comportementale, et PROMEUT en
            # graine les concentrations LOW/MEDIUM les mieux notées — dans la
            # limite d'un budget quotidien. Zéro token : le moteur ne juge pas,
            # il classe. Ce qu'il promeut suit ensuite le chemin de tout le
            # monde (corrélation -> triage LLM -> case IRIS).
            #
            # Best-effort, comme VT : un moteur comportemental en panne ne doit
            # pas empêcher le pipeline de niveau >= 12 de tourner.
            try:
                vues, scorees, promus = ueba.tourner()
                if vues:
                    log.info("ueba : %d alertes observées, %d scorées, "
                             "%d signal/signaux promus", vues, scorees,
                             len(promus))
                for s in promus:
                    log.info("ueba : signal #%s %s score %.1f -> %d alertes "
                             "graine", s["id"], s["agent_name"], s["score"],
                             len(s["alert_ids"]))
            except Exception as e:  # noqa: BLE001
                log.warning("ueba sauté : %s", e)

            n_inc, n_alertes = correlate.correler(config.MIN_LEVEL)
            log.info("correlate : %d alertes -> %d incidents", n_alertes, n_inc)

            # Capteur muet : un flux établi qui se tait (Suricata étouffé, lecteur
            # journald figé, audit coupé) rend des pans du ruleset inertes sans la
            # moindre alerte. Détecté côté base, donc pas soumis au backlog de
            # l'agent. Log-only pour l'instant (escalade IRIS = revue à part).
            try:
                watchdog.verifier()  # journalise chaque capteur muet en WARNING
            except Exception as e:  # noqa: BLE001 — un watchdog ne casse pas le cycle
                log.warning("watchdog capteur muet sauté : %s", e)

            # Le triage dépend du serveur LLM. S'il est indisponible, on ne fait
            # pas échouer tout le cycle : l'ingestion et la corrélation ont déjà
            # de la valeur, et les incidents non triés seront repris au prochain
            # tour.
            try:
                triage.trier(limite_triage, None, False, False)
            except Exception as e:  # noqa: BLE001 — on veut tout rattraper ici
                # Un échec du triage NE DOIT PAS couper la création de cases : les
                # incidents déjà triés lors des cycles précédents attendent leur
                # case (iris_case_id IS NULL) et n'ont plus besoin du LLM de
                # triage. L'ancien `return 0` ici a gelé la création de cases
                # pendant des heures dès que le LLM rendait un content vide. On
                # journalise et on poursuit vers whitelist + cases IRIS.
                log.warning("triage sauté (serveur LLM injoignable ?) : %s", e)

            # Boucle fermée : les FP récurrents deviennent des exceptions. Ne
            # tourne qu'après le triage, il lui faut des verdicts frais.
            crees = [d for d in whitelist.analyser(config.WHITELIST_MIN_FP, False)
                     if d["action"] == "créé"]
            if crees:
                log.info("whitelist : %d exception(s) créée(s) : %s",
                         len(crees), ", ".join(d["signature"] for d in crees))

            # Un case IRIS par incident trié. Après la whitelist : un incident
            # qui vient de passer en 'whitelisted' n'a pas de verdict à verser
            # (déjà écarté), les autres oui.
            try:
                cases = iris.creer_cases()
                if cases:
                    log.info("IRIS : %d case(s) créé(s)", len(cases))
            except Exception as e:  # noqa: BLE001 — IRIS down ne casse pas le cycle
                log.warning("création de cases IRIS sautée : %s", e)

            # La réconciliation des remédiations annulées (tâche IRIS passée en
            # 'Canceled') est DÉCOUPLÉE de ce cycle : elle a son propre timer plus
            # court (soc-agent-reconcile, 1 min) car elle est légère (list_tasks +
            # reverse) et ne doit pas attendre le triage qui sature le CPU.
            return 0
        finally:
            garde.execute("SELECT pg_advisory_unlock(%s)", (VERROU,))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--depuis", default="30d",
                    help="fenêtre d'ingestion au tout premier passage "
                         "(ignorée dès qu'un curseur existe)")
    ap.add_argument("--taille-lot", type=int, default=500)
    ap.add_argument("--limite-triage", type=int, default=50,
                    help="plafond d'incidents triés par cycle, garde-fou "
                         "contre un afflux qui saturerait le CPU")
    args = ap.parse_args()
    sys.exit(executer(args.depuis, args.taille_lot, args.limite_triage))


if __name__ == "__main__":
    main()
