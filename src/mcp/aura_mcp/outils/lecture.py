"""Outils de lecture : l'état d'AURA, sans rien modifier.

Tous en `aura:read`. Ils lisent la base `socagent` en transaction read-only
(voir `db.lecture`) : une erreur de requête ne peut pas muter un incident.
"""

from .. import auth, sortie
from ..db import lecture as base
from ..serveur import enregistrer

# Colonnes de l'incident rendues en liste. Pas `entities` ni `rule_ids` en
# entier : sur un incident à 300 alertes, ces tableaux font l'essentiel du
# poids de la réponse alors que la liste sert à choisir sur quoi zoomer.
SELECT_INCIDENTS = """
    SELECT i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
           i.alert_count, i.max_level, i.status, i.iris_case_id,
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
     ORDER BY i.max_level DESC, i.last_seen DESC
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
            SELECT_INCIDENTS, {**filtres, "limite": limite, "offset": offset}
        ).fetchall()
    return sortie.page([dict(r) for r in lignes], total, limite, offset)


enregistrer(aura_incidents_list)
