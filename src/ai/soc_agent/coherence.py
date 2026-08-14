"""Contrôle de cohérence entre le verdict et les actions du modèle.

La validation de sortie (`triage._valider`) garantit la *forme* — champs
présents, valeurs dans l'enum. Elle ne peut rien garantir *entre* les champs :
rien n'empêche le modèle de rendre `false_positive` tout en proposant de bloquer
une IP. C'est arrivé sur deux incidents sur quatre au premier passage réel.

Ce contrôle est déterministe et tourne après chaque triage. Il ne corrige rien
— réécrire le verdict du modèle masquerait le problème au lieu de le mesurer —
mais il l'enregistre. Un taux d'incohérence qui monte signale un prompt qu'on
vient de dégrader, et se mesure **sans jeu labellisé**.

Il ne porte que sur les actions du MODÈLE. Celles déduites du verdict
(`open_case`, `close_false_positive`, cf. actions.py) sont cohérentes par
construction.
"""

from .actions import HIGH_IMPACT_ACTIONS


def check(verdict: str, actions_modele: list[str]) -> list[str]:
    """Liste des incohérences constatées. Vide = sortie cohérente."""
    issues: list[str] = []
    proposed = set(actions_modele)

    if verdict == "false_positive":
        # Si l'activité est légitime, il n'y a rien à couper. Proposer une
        # remédiation contredit le verdict.
        high = proposed & HIGH_IMPACT_ACTIONS
        if high:
            issues.append(
                "false_positive propose " + ", ".join(sorted(high)))

    if verdict == "needs_investigation":
        # Sur un simple doute, on ne coupe rien de façon irréversible : couper
        # (isolation, kill, désactivation, blocage) sans certitude est incohérent.
        high = proposed & HIGH_IMPACT_ACTIONS
        if high:
            issues.append(
                "needs_investigation coupe sans certitude : "
                + ", ".join(sorted(high)))

    if verdict == "true_positive" and not proposed:
        # Légitime pour un vrai positif sans suite possible, mais assez rare
        # pour mériter d'être compté.
        issues.append("true_positive sans aucune action")

    return issues
