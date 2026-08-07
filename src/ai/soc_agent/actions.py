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
    "propose_kill_process",              # tue un process en cours
    "propose_isolate_host",              # coupe l'hôte du réseau
    "propose_disable_user",              # verrouille un compte (local ou AD)
    "propose_block_ip",                  # coupe un flux réseau
    "propose_quarantine_file",           # met un fichier en quarantaine
    "propose_remove_privileged_group",   # retire d'un groupe AD privilégié
}

# Ordre d'urgence pour la présentation à l'analyste. Tuer le process malveillant
# prime (le plus chirurgical : stoppe l'exécution sans couper la machine) ;
# isoler vient juste après (arrête tout mais coupe aussi l'investigation).
# La collecte forensique n'est PAS une action de l'IA (trop lourde, tirée en
# SSH par le manager, hors périmètre du triage automatique).
ORDRE = [
    "propose_kill_process",
    "propose_quarantine_file",
    "propose_isolate_host",
    "propose_disable_user",
    "propose_remove_privileged_group",
    "propose_block_ip",
    "escalate_human",
    "open_case",
    "close_false_positive",
]


def _ordonner(actions) -> list[str]:
    """Actions triées par urgence de présentation (ORDRE)."""
    return sorted(actions, key=lambda a: ORDRE.index(a) if a in ORDRE else 99)


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

    return _ordonner(actions)


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

# Confinements moins invasifs que l'isolation. Tant que l'un d'eux s'applique,
# il traite la menace sans couper la machine du réseau.
CONFINEMENT_MOINS_INVASIF = (
    "propose_block_ip",
    "propose_kill_process",
    "propose_disable_user",
    "propose_quarantine_file",
    "propose_remove_privileged_group",
)


def appliquer_garde_fous(verdict: str, actions: list[str], max_level: int,
                         injection_suspectee: bool,
                         compromission_active: bool = False,
                         ) -> tuple[list[str], list[str]]:
    """Barrière déterministe entre la sortie du modèle et une action réelle.

    Mesuré : trois charges d'injection sur quatre retournent le verdict du
    modèle en `false_positive` sur un ransomware avéré. Le prompt système ne
    tient pas, et il ne peut pas tenir — un modèle de langage n'est pas une
    frontière de sécurité. Celle-ci l'est : elle ne dépend d'aucune
    probabilité et ne peut pas être argumentée par du texte dans un log.

    Trois invariants :

    1. Un incident de niveau >= 14 ne peut PAS être clos automatiquement,
       quoi qu'en dise le modèle. C'est exactement le scénario qu'une
       injection cherche à provoquer : faire refermer une intrusion en silence.
    2. Un incident où des motifs d'injection ont été repérés ne peut pas être
       clos non plus — le verdict rendu sur un contexte manipulé ne vaut rien.
    3. L'isolation d'un hôte est un DERNIER RECOURS : elle ne part que si aucun
       confinement moins invasif ne s'applique (cf. plus bas) — SAUF si l'hôte
       est en compromission active (post-exploitation avérée), auquel cas
       l'isolation est MAINTENUE malgré la présence d'un confinement moins
       invasif (bloquer une IP ne déloge pas un attaquant déjà installé).

    `compromission_active` : l'incident porte une règle de post-exploitation
    (cf. config.RULES_COMPROMISSION_HOTE) — l'attaquant exécute déjà du code
    sur la machine (webshell, reverse shell, rootkit, persistance root). Le
    calcul du drapeau est fait par l'appelant (triage) à partir des rule_ids
    de l'incident ; la barrière ici ne fait qu'en tenir compte.

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

    # --- Isolation en dernier recours ---------------------------------------
    #
    # Couper un hôte du réseau est l'action la plus chère du catalogue : elle
    # arrête l'attaque, mais aussi le service. Mesuré : un scanner internet
    # cherchant //adminer.php (404, rien servi) a fait isoler un reverse proxy
    # exposant tout un parc. Le blocage de l'IP suffisait, et il était proposé
    # dans le même verdict.
    #
    # Donc : tant qu'un confinement moins invasif s'applique — bloquer l'IP,
    # tuer le process, désactiver le compte — c'est lui qui part, et
    # l'isolation est retirée. Elle n'est PAS silencieusement abandonnée :
    # `escalate_human` prend sa place, l'analyste voit dans le case qu'une
    # isolation a été jugée pertinente et tranche lui-même.
    #
    # Volontairement déterministe et non négociable par le prompt : le modèle
    # est incité à préférer le blocage (prompts/system.md), mais l'incitation
    # ne tient pas face à un log hostile. Cette barrière, si.
    if "propose_isolate_host" in actions:
        moins_invasives = [a for a in CONFINEMENT_MOINS_INVASIF if a in actions]
        if moins_invasives and compromission_active:
            # Compromission active de l'hôte : l'attaquant exécute déjà du code
            # dessus (webshell, reverse shell, rootkit, persistance root). Un
            # confinement moins invasif ne suffit pas — couper une IP laisse le
            # foothold en place. L'isolation EST maintenue, en plus du reste.
            motifs.append(
                "isolation MAINTENUE : compromission active de l'hôte "
                "(post-exploitation avérée) — le confinement moins invasif "
                f"({', '.join(moins_invasives)}) ne déloge pas un attaquant "
                "déjà installé")
        elif moins_invasives:
            actions = [a for a in actions if a != "propose_isolate_host"]
            if "escalate_human" not in actions:
                actions.append("escalate_human")
            actions = _ordonner(actions)
            motifs.append(
                "isolation retirée (dernier recours) : "
                f"{', '.join(moins_invasives)} suffit — escalade à un humain")

    return actions, motifs
