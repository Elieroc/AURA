"""Outils de simulation : répondre à « que se passerait-il si… » sans le faire.

Tous en `aura:read`, tous sans effet de bord. Ils existent parce que la
question qui précède une action est toujours la même : qu'est-ce qui partirait
réellement, et qu'est-ce que les garde-fous retiendraient ? Y répondre en
lançant l'action pour voir n'est pas une option sur un parc de production.

Ils appellent les fonctions pures du pipeline — mêmes garde-fous, même code.
Une simulation qui divergerait de l'exécution ne servirait à rien.
"""

from soc_agent import actions as soc_actions
from soc_agent import config as soc_config
from soc_agent import mitigate, rule_tuning, ueba, whitelist

from .. import auth, output
from ..db import read as base
from ..server import register


@auth.require("aura:read")
def aura_simulate_decision(
    verdict: str,
    proposed_actions: list[str],
    max_level: int,
    suspected_injection: bool = False,
    active_compromise: bool = False,
    priority: int | None = None,
) -> dict:
    """Que deviendrait ce verdict après les garde-fous déterministes ?

    Le modèle ne fait que proposer des remédiations ; AURA en déduit
    l'ouverture ou la clôture du dossier, puis applique trois invariants que
    rien ne contourne :

    1. pas de clôture automatique si le niveau atteint 14 — seuil abaissé sur
       un asset prioritaire (12 sur un P1) ;
    2. pas de clôture si un motif d'injection a été repéré dans les logs —
       le modèle se laisse retourner par une injection 3 fois sur 4 ;
    3. l'isolation d'hôte est rétrogradée s'il existe un confinement moins
       invasif, SAUF si la compromission de l'hôte est établie.

    Args:
        verdict: `true_positive`, `false_positive` ou `needs_investigation`.
        actions_proposees: actions du modèle (`propose_block_ip`,
            `propose_isolate_host`, `propose_kill_process`,
            `propose_disable_user`, `propose_quarantine_file`,
            `propose_remove_privileged_group`, `escalate_human`).
        max_level: niveau Wazuh le plus élevé de l'incident.
        injection_suspectee: un motif d'injection a été repéré dans les logs.
        compromission_active: une règle de post-exploitation a matché
            (webshell qui exécute, reverse shell, rootkit, persistance root).
        priorite: priorité de l'asset touché (1 à 4). Elle décide du seuil de
            clôture : sur un P1, le modèle ne peut plus refermer dès le niveau
            12. Absente = seuil historique (14).
    """
    inferred = soc_actions.infer(verdict, proposed_actions)
    final, guardrails = soc_actions.apply_guardrails(
        verdict, inferred, max_level, suspected_injection,
        active_compromise, priority)
    return {
        "actions_proposees": proposed_actions,
        "apres_deduction": inferred,
        "actions_finales": final,
        "garde_fous_declenches": guardrails,
        "actions_fort_impact": soc_actions.high_impact_actions(final),
        "priority": priority,
        "niveau_cloture_interdite": soc_actions.closure_threshold(priority),
    }


@auth.require("aura:read")
def aura_validate_whitelist_signature(signature: dict, level: int) -> dict:
    """Cette signature pourrait-elle être mise en whitelist ?

    Trois refus possibles, tous déterministes et non contournables : absence
    de discriminant (compte, commande ou fichier — sans quoi l'exception
    aveuglerait bien plus que le bruit visé), niveau trop élevé, ou signature
    déjà observée sur un vrai positif. Ce dernier point est le garde-fou
    anti-normalisation : ce qui a servi une fois à une intrusion ne devient
    jamais « normal ».

    Args:
        signature: champs constants de la signature, p. ex.
            `{"rule_id": "100657", "agent_name": "web01", "command": "uname -a"}`.
        niveau: niveau Wazuh des alertes concernées.
    """
    with base() as conn:
        sig_tp = whitelist.signatures_seen_tp(conn)
    refusal = whitelist.validate_signature(signature, level, sig_tp)
    return {
        "signature": signature,
        "acceptable": refusal is None,
        "motif_de_refus": refusal,
        "niveau_maximum": soc_config.WHITELIST_MAX_LEVEL,
        "min_fp_requis": soc_config.WHITELIST_MIN_FP,
    }


@auth.require("aura:read")
def aura_ueba_score_group(alert_ids: list[str]) -> dict:
    """Quel score UEBA obtiendrait ce groupe d'alertes ?

    Sert à calibrer : comprendre pourquoi un comportement est passé sous le
    plancher, ou au contraire ce qui l'a fait remonter. Le score additionne la
    rareté de chaque trait (surprisal en bits), plafonnée par trait et par
    alerte, avec un bonus de progression dans la kill chain.

    Args:
        alert_ids: identifiants natifs Wazuh des alertes du groupe
            (`aura_alerts_search` les rend).
    """
    if not alert_ids:
        return {"error": "Aucune alerte fournie."}
    with base() as conn:
        lines = conn.execute(
            "SELECT * FROM alerts WHERE id = ANY(%s) ORDER BY ts",
            (list(alert_ids),)).fetchall()
    if not lines:
        return {"error": "Aucune de ces alertes n'est en base."}

    score, patterns = ueba.score_group([dict(r) for r in lines])
    return output.jsonifiable({
        "alertes": len(lines),
        "score": score,
        "plancher": soc_config.UEBA_SCORE_FLOOR,
        "franchirait_le_plancher": score >= soc_config.UEBA_SCORE_FLOOR,
        "patterns": patterns,
    })


@auth.require("aura:read")
def aura_rule_preview(rule_id: int, parent: str, level: int,
                      signature: dict, n_fp: int = 0,
                      incidents: list[int] | None = None) -> dict:
    """Le XML de la règle d'exception qui serait déployée, sans rien écrire.

    Deuxième étage de la whitelist : plutôt qu'écarter le bruit après coup, on
    calme la règle DANS le moteur Wazuh. Cet outil rend le XML pour relecture ;
    il ne l'écrit pas et ne redémarre pas le manager — c'est `aura:admin` et
    c'est `aura_rule_tuning_apply`.

    Piège à connaître : une règle fille doit avoir un identifiant SUPÉRIEUR à
    celui de sa parente, sinon Wazuh la charge et ne l'évalue jamais, sans le
    moindre message d'erreur.

    Args:
        rule_id: identifiant de la règle à créer (plage réservée
            101000-101999).
        parent: identifiant de la règle parente (`if_sid`).
        niveau: niveau de la règle fille (0 = suppression totale, verrouillé
            par configuration).
        signature: champs discriminants à matcher.
        n_fp: nombre de faux positifs qui motivent la règle (commentaire).
        incidents: incidents à l'origine (commentaire de traçabilité).
    """
    if not (soc_config.RULE_TUNING_ID_MIN <= rule_id
            <= soc_config.RULE_TUNING_ID_MAX):
        return {"error": f"rule_id hors plage réservée "
                          f"{soc_config.RULE_TUNING_ID_MIN}-"
                          f"{soc_config.RULE_TUNING_ID_MAX}."}
    if int(parent) >= rule_id:
        return {"error": f"La règle {rule_id} ne peut pas être fille de "
                          f"{parent} : une fille doit avoir un identifiant "
                          f"SUPÉRIEUR à sa parente, sinon Wazuh ne l'évalue "
                          f"jamais (sans erreur)."}

    xml = rule_tuning.build_xml(rule_id, parent, level, signature, {},
                                     n_fp, incidents or [])
    return {
        "rule_id": rule_id, "parent": parent, "niveau": level,
        "traduisible": xml is not None,
        "xml": xml,
        "niveau_0_autorise": soc_config.RULE_TUNING_ALLOW_LEVEL_0,
    }


@auth.require("aura:read")
def aura_isolation_check(agent_id: str) -> dict:
    """Cet agent peut-il être isolé, et l'est-il déjà ?

    Deux questions distinctes, souvent confondues : ce que la politique AURA
    autorise (`motif_de_refus`), et ce que la machine dit d'elle-même
    (`etat`, lu en SSH sur l'hôte). Une machine peut être marquée isolée dans
    IRIS sans l'être réellement — c'est l'état de l'hôte qui tranche.

    Les refus sont volontairement fermés : agent protégé (le manager, 000),
    appartenance à un groupe d'infrastructure (pare-feu, proxy, DNS, VPN), ou
    rôle inconnu. Isoler un pare-feu coupe tout le monde, y compris le SOC.

    Args:
        agent_id: identifiant d'agent Wazuh (`003`, `001`…).
    """
    refusal = mitigate.not_isolatable_reason(agent_id)
    response = {
        "agent_id": agent_id,
        "isolable": refusal is None,
        "motif_de_refus": refusal,
        "agents_proteges": sorted(soc_config.AGENTS_PROTECTED),
        "refus_si_role_inconnu": soc_config.ISOLATION_REFUSE_IF_ROLE_UNKNOWN,
    }
    try:
        response["etat"] = mitigate.isolation_state(agent_id)
    except Exception as e:  # noqa: BLE001
        # Un hôte injoignable est une information, pas une panne de l'outil :
        # il peut être éteint, ou déjà coupé du réseau par une isolation.
        response["etat"] = None
        response["etat_indisponible"] = str(e)
    return response


register(aura_simulate_decision)
register(aura_validate_whitelist_signature)
register(aura_ueba_score_group)
register(aura_rule_preview)
register(aura_isolation_check)
