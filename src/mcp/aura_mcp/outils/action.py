"""Outils d'action : ceux qui changent quelque chose.

Trois principes, tenus par le code et non par la consigne :

1. **Le dry-run est le défaut.** Tout outil qui touche la production a un
   paramètre `appliquer` à `False`. Sans lui, on obtient ce qui serait fait.
2. **Les actions irréversibles exigent une confirmation explicite.** Le
   paramètre `confirmer` n'a pas de valeur par défaut vraie et le refus dit
   exactement ce qui se produirait — un client IA ne le passe pas par accident.
3. **Les garde-fous ne sont pas ici.** Ils sont dans `soc_agent`, en amont, et
   s'appliquent quel que soit l'appelant. Cette couche ne les rejoue pas et ne
   peut pas les désactiver.

Ce qui n'est **jamais** exposé, à aucun scope :

- `correlate.recommencer` — efface tous les incidents ;
- `ueba.purger` — supprime définitivement l'historique de baseline ;
- `label.enregistrer` — la vérité terrain sert à noter l'IA, l'IA ne l'écrit pas ;
- `iris.nettoyer_iocs(simulation=False)` — suppression irréversible dans IRIS ;
- `llm.completion` — court-circuiterait la pseudonymisation ;
- la table `anonymization_map` — correspondances jetons ↔ valeurs réelles.
"""

from soc_agent import config as soc_config
from soc_agent import cycle, iris, mitigate, rule_tuning, triage, whitelist

from .. import auth, sortie
from ..serveur import enregistrer


@auth.exige("aura:write")
def aura_run_cycle(taille_lot: int = 500, limite_triage: int = 20,
                   depuis: str = "30d") -> dict:
    """Déclenche un cycle AURA complet, sans attendre la boucle de 5 minutes.

    Enchaîne ingestion, filtre VirusTotal, UEBA, corrélation, watchdog des
    capteurs, triage LLM, whitelist et création des cases IRIS. Un verrou
    consultatif empêche deux cycles simultanés : si la boucle périodique est en
    train de tourner, cet appel rend `verrouille` et ne fait rien — ce n'est
    pas une erreur.

    Peut durer plusieurs minutes et consomme des tokens DeepSeek (un appel par
    incident trié).

    Args:
        taille_lot: alertes ingérées par page.
        limite_triage: nombre maximal d'incidents triés dans ce cycle. C'est
            le paramètre qui borne la facture LLM de l'appel.
        depuis: fenêtre d'ingestion initiale (`30d`, `6h`) — ignorée dès qu'un
            curseur d'ingestion existe, ce qui est le cas en régime établi.
    """
    code = cycle.executer(depuis, taille_lot, limite_triage)
    return {
        "code_sortie": code,
        # `cycle.executer` ne distingue pas « rien à faire » de « verrou déjà
        # pris » : les deux rendent 0. Le dire plutôt que laisser le client
        # conclure que le cycle a forcément tourné.
        "note": "Un code 0 signifie « cycle terminé » OU « un autre cycle "
                "tournait déjà » — les deux sont normaux. Le résultat se lit "
                "dans aura_incidents_list ; le détail par incident est dans "
                "les journaux du conteneur aura-mcp.",
    }


@auth.exige("aura:write")
def aura_triage_incident(incident_id: int, forcer: bool = False) -> dict:
    """Fait (re)passer un incident au triage LLM.

    Par défaut, un incident déjà trié et hors fenêtre de rafraîchissement n'est
    pas repris — le résultat est alors une liste vide, ce n'est pas un échec.
    `forcer` retrie quand même : c'est ce qu'on fait après un changement de
    prompt pour comparer, l'ancien verdict étant conservé (`aura_triage_history`).

    Consomme un appel DeepSeek. Les données partent pseudonymisées ; si un
    identifiant interne échappe à la pseudonymisation, l'envoi est refusé et
    le statut vaut `fuite`.

    Args:
        incident_id: incident à trier.
        forcer: retrier même s'il l'a déjà été.
    """
    resultats = triage.trier(1, incident_id, forcer, False)
    return {"incident_id": incident_id,
            "resultats": sortie.jsonifiable(resultats),
            "note": None if resultats else
                    "Incident déjà trié et hors fenêtre de rafraîchissement — "
                    "utiliser forcer=true pour le reprendre."}


@auth.exige("aura:write")
def aura_iris_case_sync(incident_id: int | None = None) -> dict:
    """Crée ou met à jour les cases DFIR-IRIS des incidents triés.

    Pour un vrai positif, le rapport d'analyse est rédigé par le LLM (donc
    coûte des tokens) ; pour un faux positif, la note est déterministe. Un
    incident dont le case existe déjà et qui porte `needs_refresh` voit son
    case complété, pas dupliqué.

    Effet de bord à connaître : la détection d'un doublon peut FUSIONNER deux
    incidents, ce qui en supprime un de la base AURA (le case IRIS, lui, est
    conservé).

    Args:
        incident_id: se limiter à un incident. Sans lui, traite tous ceux qui
            attendent un case.
    """
    faits = iris.creer_cases(incident_id)
    return {"cases": [{"incident_id": i, "case_id": c, "verdict": v}
                      for i, c, v in faits],
            "total": len(faits)}


@auth.exige("aura:write")
def aura_ar_reconcile() -> dict:
    """Fige le résultat réel des remédiations envoyées aux agents.

    Une remédiation part en `émis` : l'ordre est parti, on ne sait pas encore
    ce qu'il a donné. Cet outil lit les retours d'active response remontés par
    les agents et bascule le statut en `confirmé`, `sans_effet`, `refusé_agent`
    ou `échec`. Sans lui, un tableau de bord annonce des remédiations
    « réussies » qui ont pu être refusées sur la machine.

    Idempotent, sans effet destructif.
    """
    figes = mitigate.reconcilier_resultats_ar()
    return {"reconciliees": sortie.jsonifiable(figes), "total": len(figes)}


@auth.exige("aura:admin")
def aura_mitigate_execute(incident_id: int, confirmer: bool = False) -> dict:
    """Exécute les remédiations décidées pour un incident. ACTION RÉELLE.

    Peut couper une machine du réseau, tuer un processus, bloquer une adresse,
    désactiver un compte ou mettre un fichier en quarantaine, sur la
    production. Le kill de processus n'a **aucune annulation** possible.

    Trois barrières en amont, non contournables depuis ici : la remédiation est
    entièrement suspendue si des motifs d'injection ont été relevés sur
    l'incident ; les agents protégés, comptes système et adresses internes sont
    exclus ; et si `MITIGATE_EXECUTE` vaut `false` dans la configuration du
    stack, tout reste en `dry_run` quoi qu'on demande ici.

    Args:
        incident_id: incident dont on applique les remédiations.
        confirmer: doit valoir `true` pour agir. À `false` (défaut), l'outil
            rend ce qui serait tenté sans rien envoyer.
    """
    if not confirmer:
        with_dry = "déjà globalement en dry-run" if not soc_config.MITIGATE_EXECUTE \
            else "ARMÉ : les actions partiraient réellement"
        return {
            "execute": False,
            "raison": "confirmer=false — aucune action envoyée.",
            "etat_du_stack": with_dry,
            "conseil": "Lire d'abord aura_incident_get puis "
                       "aura_simulate_decision pour voir ce que les garde-fous "
                       "laissent passer.",
        }
    faits = mitigate.executer(incident_id)
    return {"execute": True, "mitigate_execute_global": soc_config.MITIGATE_EXECUTE,
            "actions": sortie.jsonifiable(faits), "total": len(faits)}


@auth.exige("aura:admin")
def aura_isolate(agent_id: str, motif: str, confirmer: bool = False,
                 forcer: bool = False) -> dict:
    """Isole un hôte du réseau. ACTION RÉELLE, coupante.

    L'hôte perd toute connectivité sauf le canal de l'agent Wazuh. Vérifier
    d'abord avec `aura_isolation_check` : isoler un pare-feu, un proxy, un
    résolveur DNS ou une passerelle VPN coupe tout le monde, SOC compris.

    Args:
        agent_id: agent Wazuh à isoler.
        motif: pourquoi — repris dans la trace et dans IRIS. Obligatoire :
            une isolation sans motif est ingérable au moment de la lever.
        confirmer: doit valoir `true` pour agir.
        forcer: passer outre un refus de politique. À n'utiliser que sur une
            compromission établie d'une machine d'infrastructure, en sachant
            ce qu'on coupe.
    """
    refus = mitigate.raison_non_isolable(agent_id)
    if not confirmer:
        return {"execute": False,
                "raison": "confirmer=false — aucune action envoyée.",
                "serait_refuse_par_la_politique": refus,
                "forcer_necessaire": bool(refus)}
    if refus and not forcer:
        return {"execute": False, "raison": refus,
                "conseil": "forcer=true passe outre — mesurer ce que l'hôte "
                           "porte avant."}
    mitigate.isoler(agent_id, motif, forcer)
    return {"execute": True, "agent_id": agent_id, "motif": motif,
            "politique_forcee": bool(refus and forcer),
            "etat": sortie.jsonifiable(mitigate.etat_isolation(agent_id))}


@auth.exige("aura:admin")
def aura_unisolate(agent_id: str, motif: str, confirmer: bool = False) -> dict:
    """Lève l'isolation d'un hôte. ACTION RÉELLE.

    Rend sa connectivité à une machine qui avait été confinée. À ne faire
    qu'après avoir vérifié que la cause a disparu : la remédiation autonome ne
    retire PAS la persistance posée par un attaquant (cron, web shell, compte
    UID 0). Une machine désisolée trop tôt rappelle son C2.

    Args:
        agent_id: agent Wazuh à désisoler.
        motif: pourquoi — tracé.
        confirmer: doit valoir `true` pour agir.
    """
    if not confirmer:
        return {"execute": False,
                "raison": "confirmer=false — aucune action envoyée.",
                "rappel": "Vérifier l'absence de persistance (cron, web shell, "
                          "compte UID 0) avant de rendre le réseau."}
    mitigate.desisoler(agent_id, motif)
    return {"execute": True, "agent_id": agent_id, "motif": motif,
            "etat": sortie.jsonifiable(mitigate.etat_isolation(agent_id))}


@auth.exige("aura:admin")
def aura_whitelist_apply(min_fp: int | None = None,
                         appliquer: bool = False) -> dict:
    """Crée les exceptions de whitelist pour les faux positifs récurrents.

    Chaque exception créée est un angle mort assumé : ces alertes ne
    remonteront plus. Les garde-fous refusent une signature sans discriminant,
    au-dessus du niveau plafond, ou déjà vue sur un vrai positif.

    Args:
        min_fp: nombre de faux positifs requis avant d'exonérer une signature.
        appliquer: à `false` (défaut), rend les décisions sans rien créer.
    """
    decisions = whitelist.analyser(
        min_fp if min_fp is not None else soc_config.WHITELIST_MIN_FP,
        simulation=not appliquer)
    return {"applique": appliquer,
            "decisions": sortie.jsonifiable(decisions),
            "total": len(decisions)}


@auth.exige("aura:admin")
def aura_rule_tuning_apply(min_fp: int | None = None,
                           appliquer: bool = False) -> dict:
    """Génère et déploie des règles Wazuh d'exception. REDÉMARRE LE MANAGER.

    Deuxième étage de la whitelist : le bruit est calmé dans le moteur de
    règles au lieu d'être écarté après coup. Chaque règle générée est PROUVÉE
    par rejeu `/logtest` — l'évènement faux positif doit tomber dessus, et un
    contre-exemple réel doit rester sur la règle parente. Une règle non prouvée
    est retirée du disque.

    Appliquer redémarre le manager Wazuh : la détection est interrompue le
    temps du redémarrage, deux fois si une règle échoue à sa preuve.

    Args:
        min_fp: faux positifs requis avant de générer une règle.
        appliquer: à `false` (défaut), rend le XML sans rien écrire ni
            redémarrer.
    """
    decisions = rule_tuning.analyser(
        min_fp if min_fp is not None else soc_config.WHITELIST_MIN_FP,
        simulation=not appliquer)
    return {"applique": appliquer,
            "manager_redemarre": appliquer and bool(decisions),
            "decisions": sortie.jsonifiable(decisions),
            "total": len(decisions)}


enregistrer(aura_run_cycle)
enregistrer(aura_triage_incident)
enregistrer(aura_iris_case_sync)
enregistrer(aura_ar_reconcile)
enregistrer(aura_mitigate_execute)
enregistrer(aura_isolate)
enregistrer(aura_unisolate)
enregistrer(aura_whitelist_apply)
enregistrer(aura_rule_tuning_apply)
