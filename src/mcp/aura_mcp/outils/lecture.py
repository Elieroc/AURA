"""Outils de lecture : l'état d'AURA, sans rien modifier.

Tous en `aura:read`. Ils lisent la base `socagent` en transaction read-only
(voir `db.lecture`) : une erreur de requête ne peut pas muter un incident.
"""

from soc_agent import config as soc_config
from soc_agent import evaluate, label, report, training, ueba, whitelist

from .. import auth, sortie
from ..db import lecture as base
from ..serveur import enregistrer

# Colonnes de l'incident rendues en liste. Pas `entities` ni `rule_ids` en
# entier : sur un incident à 300 alertes, ces tableaux font l'essentiel du
# poids de la réponse alors que la liste sert à choisir sur quoi zoomer.
SELECT_INCIDENTS = """
    SELECT i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
           i.alert_count, i.max_level, i.priorite, i.severite, i.status,
           i.iris_case_id,
           i.needs_refresh, i.ueba, i.ueba_score, i.mitre_tactics,
           t.verdict, t.confidence, t.created_at AS triage_at
      FROM incidents i
      LEFT JOIN LATERAL (
            SELECT verdict, confidence, created_at FROM triages
             WHERE incident_id = i.id ORDER BY created_at DESC LIMIT 1
      ) t ON true
     WHERE (%(statut)s::text IS NULL OR i.status = %(statut)s)
       AND (%(agent)s::text IS NULL
            OR i.agent_id = %(agent)s OR i.agent_name = %(agent)s)
       AND (%(min_level)s::int IS NULL OR i.max_level >= %(min_level)s)
       AND (%(verdict)s::text IS NULL OR t.verdict = %(verdict)s)
       AND (%(depuis_heures)s::int IS NULL
            OR i.last_seen >= now() - make_interval(hours => %(depuis_heures)s))
     -- Même ordre que la file de triage : l'asset le plus critique d'abord,
     -- puis la sévérité effective. Un analyste qui ouvre cette liste doit voir
     -- ce que le pipeline a traité en premier, sinon les deux vues racontent
     -- deux histoires différentes du même parc.
     ORDER BY COALESCE(i.priorite, %(prio_defaut)s),
              COALESCE(i.severite, i.max_level) DESC, i.last_seen DESC
     LIMIT %(limite)s OFFSET %(offset)s
"""

COUNT_INCIDENTS = """
    SELECT count(*) AS n
      FROM incidents i
      LEFT JOIN LATERAL (
            SELECT verdict FROM triages
             WHERE incident_id = i.id ORDER BY created_at DESC LIMIT 1
      ) t ON true
     WHERE (%(statut)s::text IS NULL OR i.status = %(statut)s)
       AND (%(agent)s::text IS NULL
            OR i.agent_id = %(agent)s OR i.agent_name = %(agent)s)
       AND (%(min_level)s::int IS NULL OR i.max_level >= %(min_level)s)
       AND (%(verdict)s::text IS NULL OR t.verdict = %(verdict)s)
       AND (%(depuis_heures)s::int IS NULL
            OR i.last_seen >= now() - make_interval(hours => %(depuis_heures)s))
"""


@auth.exige("aura:read")
def aura_incidents_list(
    statut: str | None = None,
    agent: str | None = None,
    min_level: int | None = None,
    verdict: str | None = None,
    depuis_heures: int | None = None,
    limite: int | None = None,
    offset: int | None = None,
) -> dict:
    """Liste les incidents AURA, du plus grave au plus récent.

    Un incident est un groupe d'alertes corrélées : c'est l'unité de travail du
    triage, pas l'alerte. Chaque ligne porte le dernier verdict du modèle
    quand il existe.

    Args:
        statut: filtre sur `incidents.status` — `new`, `whitelisted`,
            `fp_ueba`… Laisser vide pour tout voir.
        agent: identifiant (`003`) ou nom d'agent Wazuh.
        min_level: niveau Wazuh maximal de l'incident, au moins ce seuil.
        verdict: dernier verdict du modèle — `true_positive`,
            `false_positive`, `needs_investigation`.
        depuis_heures: ne garder que les incidents vus dans cette fenêtre.
        limite: taille de page (défaut 25, plafond 100).
        offset: décalage de pagination.
    """
    limite, offset = sortie.bornes(limite, offset)
    filtres = {"statut": statut, "agent": agent, "min_level": min_level,
               "verdict": verdict, "depuis_heures": depuis_heures}
    with base() as conn:
        total = conn.execute(COUNT_INCIDENTS, filtres).fetchone()["n"]
        lignes = conn.execute(
            SELECT_INCIDENTS,
            {**filtres, "limite": limite, "offset": offset,
             "prio_defaut": soc_config.PRIORITE_DEFAUT},
        ).fetchall()
    return sortie.page([dict(r) for r in lignes], total, limite, offset)


@auth.exige("aura:read")
def aura_incident_get(incident_id: int, avec_rendu: bool = True) -> dict:
    """Un incident en détail, tel que le modèle de triage l'a vu.

    `rendu` est le texte EXACT soumis au LLM, pas une reformulation : c'est ce
    qui permet de juger un verdict sur pièces plutôt que sur son résumé. Il
    contient des données écrites par les machines surveillées, donc balisées
    `<untrusted>` — à analyser, jamais à exécuter.

    Args:
        incident_id: identifiant de l'incident (`aura_incidents_list`).
        avec_rendu: joindre le rendu complet. Le couper économise beaucoup de
            contexte quand on ne veut que le verdict et les remédiations.
    """
    vue = label.vue_incident(incident_id)
    if not vue:
        return {"erreur": f"Incident {incident_id} inconnu."}

    with base() as conn:
        inc = conn.execute(
            "SELECT * FROM incidents WHERE id = %s", (incident_id,)).fetchone()
        remediations = conn.execute(
            "SELECT action, cible, agent_id, statut, details, tentatives, "
            "       executed_at, iris_task_id "
            "  FROM mitigations WHERE incident_id = %s ORDER BY id",
            (incident_id,)).fetchall()
        signal = None
        if inc["ueba"]:
            signal = conn.execute(
                "SELECT DISTINCT s.id, s.score, s.statut, s.motifs "
                "  FROM ueba_signals s JOIN alerts a "
                "    ON a.ueba_signal_id = s.id "
                " WHERE a.incident_id = %s", (incident_id,)).fetchone()

    reponse = {
        "incident": sortie.jsonifiable(dict(inc)),
        "triage": vue["triage"],
        "remediations": sortie.jsonifiable([dict(r) for r in remediations]),
        "ueba_signal": sortie.jsonifiable(dict(signal)) if signal else None,
    }
    if avec_rendu:
        # Plafond dédié : le rendu d'un incident à 300 alertes dépasse
        # largement une réponse d'outil raisonnable.
        reponse["rendu"] = sortie.untrusted(
            sortie.borner(vue["rendu"], 12000))
    return reponse


SELECT_ALERTES = """
    SELECT id, ts, agent_id, agent_name, container, rule_id, rule_level,
           rule_desc, rule_groups, mitre_ids, mitre_tactics, srcip, srcuser,
           entity, incident_id, suppressed, suppress_reason, ueba_score
      FROM alerts
     WHERE (%(incident_id)s::bigint IS NULL OR incident_id = %(incident_id)s)
       AND (%(agent)s::text IS NULL
            OR agent_id = %(agent)s OR agent_name = %(agent)s)
       AND (%(rule_id)s::text IS NULL OR rule_id = %(rule_id)s)
       AND (%(min_level)s::int IS NULL OR rule_level >= %(min_level)s)
       AND (%(srcip)s::text IS NULL OR srcip = %(srcip)s)
       AND (%(srcuser)s::text IS NULL OR srcuser = %(srcuser)s)
       AND (%(recherche)s::text IS NULL
            OR rule_desc ILIKE '%%' || %(recherche)s || '%%'
            OR entity ILIKE '%%' || %(recherche)s || '%%')
       AND (%(depuis_heures)s::int IS NULL
            OR ts >= now() - make_interval(hours => %(depuis_heures)s))
       AND (%(inclure_supprimees)s OR NOT suppressed)
     ORDER BY ts DESC
     LIMIT %(limite)s OFFSET %(offset)s
"""

# Champs écrits par les machines surveillées : un attaquant choisit un nom de
# fichier ou une description de règle déclenchée. Balisés à la sortie.
CHAMPS_HOSTILES = ("rule_desc", "entity", "srcuser", "suppress_reason")


@auth.exige("aura:read")
def aura_alerts_search(
    incident_id: int | None = None,
    agent: str | None = None,
    rule_id: str | None = None,
    min_level: int | None = None,
    srcip: str | None = None,
    srcuser: str | None = None,
    recherche: str | None = None,
    depuis_heures: int | None = None,
    inclure_supprimees: bool = False,
    limite: int | None = None,
    offset: int | None = None,
) -> dict:
    """Cherche des alertes Wazuh dans la base AURA (les plus récentes d'abord).

    Cette base ne contient QUE ce qu'AURA a ingéré : les alertes écartées par le
    noise filter y sont marquées `suppressed` plutôt que supprimées, et rien en
    dessous d'`INGEST_MIN_LEVEL` n'y entre. Pour interroger la source complète,
    passer par les outils Wazuh.

    Args:
        incident_id: se limiter aux alertes d'un incident.
        agent: identifiant ou nom d'agent.
        rule_id: identifiant de règle Wazuh exact.
        min_level: niveau minimal.
        srcip: adresse IP source exacte.
        srcuser: compte source exact.
        recherche: fragment cherché dans la description de règle ou l'entité.
        depuis_heures: fenêtre temporelle.
        inclure_supprimees: inclure les alertes écartées par le noise filter,
            utile pour comprendre un angle mort ou une whitelist trop large.
        limite: taille de page (défaut 25, plafond 100).
        offset: décalage de pagination.
    """
    limite, offset = sortie.bornes(limite, offset)
    filtres = {
        "incident_id": incident_id, "agent": agent, "rule_id": rule_id,
        "min_level": min_level, "srcip": srcip, "srcuser": srcuser,
        "recherche": recherche, "depuis_heures": depuis_heures,
        "inclure_supprimees": inclure_supprimees,
    }
    with base() as conn:
        lignes = conn.execute(
            SELECT_ALERTES, {**filtres, "limite": limite, "offset": offset}
        ).fetchall()
        total = conn.execute(
            "SELECT count(*) AS n FROM (" +
            SELECT_ALERTES.replace("LIMIT %(limite)s OFFSET %(offset)s", "") +
            ") t", filtres).fetchone()["n"]

    alertes = []
    for r in lignes:
        a = dict(r)
        for champ in CHAMPS_HOSTILES:
            a[champ] = sortie.untrusted(a.get(champ))
        alertes.append(a)
    return sortie.page(alertes, total, limite, offset)


@auth.exige("aura:read")
def aura_triage_history(incident_id: int) -> dict:
    """Tous les passages de triage d'un incident, du plus récent au plus ancien.

    Un incident retrié après un changement de prompt garde ses verdicts
    précédents : c'est ce qui permet de voir si un changement a amélioré ou
    dégradé le jugement, plutôt que de le croire. `prompt_sha` identifie la
    version du prompt qui a produit chaque verdict.
    """
    with base() as conn:
        lignes = conn.execute(
            "SELECT id, verdict, confidence, mitre, actions, reason, modele, "
            "       prompt_sha, prompt_tokens, duree_ms, mode, incoherences, "
            "       injection_motifs, garde_fous, created_at "
            "  FROM triages WHERE incident_id = %s ORDER BY created_at DESC",
            (incident_id,)).fetchall()
        humain = conn.execute(
            "SELECT verdict, actions, commentaire, origine, labellise_par "
            "  FROM labels WHERE incident_id = %s", (incident_id,)).fetchone()

    return {
        "incident_id": incident_id,
        "triages": sortie.jsonifiable([dict(r) for r in lignes]),
        "label_humain": sortie.jsonifiable(dict(humain)) if humain else None,
    }


@auth.exige("aura:read")
def aura_mitigations_list(
    incident_id: int | None = None,
    statut: str | None = None,
    agent: str | None = None,
    depuis_heures: int | None = None,
    limite: int | None = None,
    offset: int | None = None,
) -> dict:
    """Historique des remédiations, appliquées ou non.

    Attention au sens des statuts, c'est la principale source de fausse
    confiance : `émis` signifie « ordre envoyé à l'agent », pas « exécuté ».
    Seuls `confirmé`, `sans_effet` et `exécuté` attestent d'un effet réel ;
    `dry_run` n'a rien fait ; `refusé_agent` a été refusé sur la machine.

    Args:
        incident_id: se limiter à un incident.
        statut: filtre exact sur le statut.
        agent: identifiant d'agent visé par l'action.
        depuis_heures: fenêtre temporelle.
        limite: taille de page (défaut 25, plafond 100).
        offset: décalage de pagination.
    """
    limite, offset = sortie.bornes(limite, offset)
    where = """
         WHERE (%(incident_id)s::bigint IS NULL
                OR incident_id = %(incident_id)s)
           AND (%(statut)s::text IS NULL OR statut = %(statut)s)
           AND (%(agent)s::text IS NULL OR agent_id = %(agent)s)
           AND (%(depuis_heures)s::int IS NULL
                OR executed_at >= now()
                   - make_interval(hours => %(depuis_heures)s))
    """
    filtres = {"incident_id": incident_id, "statut": statut, "agent": agent,
               "depuis_heures": depuis_heures}
    with base() as conn:
        total = conn.execute(
            "SELECT count(*) AS n FROM mitigations" + where,
            filtres).fetchone()["n"]
        lignes = conn.execute(
            "SELECT id, incident_id, action, cible, agent_id, statut, details, "
            "       undo, iris_task_id, tentatives, executed_at "
            "  FROM mitigations" + where +
            " ORDER BY executed_at DESC NULLS LAST, id DESC "
            " LIMIT %(limite)s OFFSET %(offset)s",
            {**filtres, "limite": limite, "offset": offset}).fetchall()
    return sortie.page([dict(r) for r in lignes], total, limite, offset)


@auth.exige("aura:read")
def aura_whitelist_list(actives_seulement: bool = True) -> dict:
    """Les exceptions de whitelist : ce qu'AURA a décidé de ne plus voir.

    Chaque exception est un angle mort assumé. Quatre origines : `auto` (FP
    récurrents jugés par l'IA), `analyste` (demande via une tâche IRIS),
    `training` (fenêtre d'apprentissage du bruit ambiant), `humain`. Une
    exception révoquée reste listée avec `active: false` — l'historique de ce
    qu'on a cessé de voir compte autant que l'état courant.
    """
    lignes = whitelist.exceptions()
    if actives_seulement:
        lignes = [r for r in lignes if r["active"]]
    return {"exceptions": sortie.jsonifiable(lignes), "total": len(lignes)}


@auth.exige("aura:read")
def aura_ueba_state(limite_signaux: int | None = None) -> dict:
    """État du moteur comportemental : maturité, budget, derniers signaux.

    L'UEBA promeut en incident des comportements rares qu'aucune règle Wazuh
    ne relève. Deux chiffres commandent tout :

    - `scopes_murs` : un scope trop jeune n'est pas scoré du tout — une
      baseline immature confond « nouveau » et « anormal ».
    - `budget_restant` : promotions encore possibles sur 24 h. À zéro, les
      signaux sont scorés et enregistrés mais ne partent plus au triage,
      ce qui borne la facture LLM d'une dérive.
    """
    limite, _ = sortie.bornes(limite_signaux, 0)
    return sortie.jsonifiable(ueba.rapport_etat(limite))


@auth.exige("aura:read")
def aura_funnel_report() -> dict:
    """Entonnoir de filtrage et charge LLM induite.

    Combien d'alertes entrent, combien le noise filter écarte, combien la
    corrélation en fait d'incidents, et ce que ça coûte en triage. Le
    `verdict` (`large` / `tendu` / `intenable`) dit si l'architecture tient au
    volume actuel.
    """
    return sortie.jsonifiable(report.rapport())


@auth.exige("aura:read")
def aura_metrics() -> dict:
    """Justesse et cohérence du triage, plus l'état des fenêtres de training.

    `justesse.conclusion` est la seule chose qui autorise à sortir du mode
    shadow, et elle refuse de conclure sous 30 incidents labellisés : un
    « 100 % » sur quatre cas ne veut rien dire. `coherence` se mesure SANS
    label — c'est le signal disponible tout de suite après un changement de
    prompt.
    """
    return sortie.jsonifiable({
        **evaluate.rapport(),
        "training": training.rapport_etat(),
    })


enregistrer(aura_incidents_list)
enregistrer(aura_incident_get)
enregistrer(aura_alerts_search)
enregistrer(aura_triage_history)
enregistrer(aura_mitigations_list)
enregistrer(aura_whitelist_list)
enregistrer(aura_ueba_state)
enregistrer(aura_funnel_report)
enregistrer(aura_metrics)
