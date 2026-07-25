"""Actions déduites du verdict, et classement par impact.

L'ouverture d'un case et la clôture en faux positif ne sont pas des décisions :
elles découlent mécaniquement du verdict. Les demander au modèle, c'était lui
faire tenir une comptabilité — et il l'oubliait deux fois sur quatre. On les
dérive ici, où la règle est explicite et ne peut pas varier.

Le modèle ne juge donc que ce qui demande un jugement : le verdict, la
confiance, et les remédiations qui s'appliquent.
"""

# Actions qui touchent la production. Elles sont exécutées de façon AUTONOME
# (XDR autonome, cf. mitigate.py) ; la liste ne sert pas à réclamer un accord
# humain, mais à les SIGNALER comme telles dans le rapport et à les ordonner
# par urgence. Leur sûreté tient à des garde-fous déterministes, pas à un clic.
ACTIONS_A_FORT_IMPACT = {
    "propose_kill_process",     # tue un process en cours
    "propose_isolate_host",     # coupe l'hôte du réseau
    "propose_disable_user",     # verrouille un compte
    "propose_block_ip",         # coupe un flux réseau
}

# Ordre d'urgence pour la présentation à l'analyste. Tuer le process malveillant
# prime (le plus chirurgical : stoppe l'exécution sans couper la machine) ;
# isoler vient juste après (arrête tout mais coupe aussi l'investigation).
# La collecte forensique n'est PAS une action de l'IA (trop lourde, tirée en
# SSH par le manager, hors périmètre du triage automatique).
ORDRE = [
    "propose_kill_process",
    "propose_isolate_host",
    "propose_disable_user",
    "propose_block_ip",
    "escalate_human",
    "open_case",
    "close_false_positive",
]


def deduire(verdict: str, actions_modele: list[str]) -> list[str]:
    """Actions du modèle + celles qu'impose le verdict, ordonnées."""
    actions = set(actions_modele)

    if verdict == "true_positive":
        actions.add("open_case")
    elif verdict == "false_positive":
        # Un faux positif est une activité légitime : rien à remédier. On
        # écarte toute action de remédiation que le modèle aurait proposée
        # malgré tout — l'incohérence est relevée par coherence.py, ici on
        # produit une sortie exploitable.
        actions = {"close_false_positive"}
    elif verdict == "needs_investigation":
        # Le doute appelle un humain : la collecte forensique n'est pas une
        # action de l'IA, et on ne coupe rien sur un simple doute.
        if not actions:
            actions.add("escalate_human")

    return sorted(actions, key=lambda a: ORDRE.index(a) if a in ORDRE else 99)


def actions_fort_impact(actions: list[str]) -> list[str]:
    """Actions à fort impact présentes, pour les SIGNALER dans le rapport.

    Elles sont exécutées automatiquement (pas de validation humaine) ; ce filtre
    sert seulement à les mettre en évidence pour l'analyste qui lit le case.
    """
    return [a for a in actions if a in ACTIONS_A_FORT_IMPACT]


# Niveau Wazuh à partir duquel une clôture automatique est interdite. 14 et 15
# sont les niveaux « attaque avérée » : ransomware, destruction de masse,
# compromission confirmée. Une règle qui tire à 14+ a exigé plusieurs
# corrélations côté Wazuh — la classer en faux positif demande un humain.
NIVEAU_CLOTURE_INTERDITE = 14


def appliquer_garde_fous(verdict: str, actions: list[str], max_level: int,
                         injection_suspectee: bool) -> tuple[list[str], list[str]]:
    """Barrière déterministe entre la sortie du modèle et une action réelle.

    Mesuré : trois charges d'injection sur quatre retournent le verdict du
    modèle en `false_positive` sur un ransomware avéré. Le prompt système ne
    tient pas, et il ne peut pas tenir — un modèle de langage n'est pas une
    frontière de sécurité. Celle-ci l'est : elle ne dépend d'aucune
    probabilité et ne peut pas être argumentée par du texte dans un log.

    Deux invariants :

    1. Un incident de niveau >= 14 ne peut PAS être clos automatiquement,
       quoi qu'en dise le modèle. C'est exactement le scénario qu'une
       injection cherche à provoquer : faire refermer une intrusion en silence.
    2. Un incident où des motifs d'injection ont été repérés ne peut pas être
       clos non plus — le verdict rendu sur un contexte manipulé ne vaut rien.

    Retourne (actions effectives, motifs de l'intervention).
    """
    motifs: list[str] = []

    if verdict == "false_positive":
        if max_level >= NIVEAU_CLOTURE_INTERDITE:
            motifs.append(
                f"clôture refusée : niveau {max_level} >= "
                f"{NIVEAU_CLOTURE_INTERDITE}")
        if injection_suspectee:
            motifs.append(
                "clôture refusée : motifs d'injection dans les données")

    if motifs:
        # On n'invente pas un verdict à la place du modèle : on refuse
        # seulement la conséquence dangereuse, et on rend la main à un humain.
        return ["escalate_human", "open_case"], motifs

    return actions, motifs
