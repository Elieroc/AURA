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
HIGH_IMPACT_ACTIONS = {
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
ORDER = [
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


def _order(actions) -> list[str]:
    """Actions triées par urgence de présentation (ORDRE)."""
    return sorted(actions, key=lambda a: ORDER.index(a) if a in ORDER else 99)


def infer(verdict: str, actions_modele: list[str]) -> list[str]:
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

    return _order(actions)


def high_impact_actions(actions: list[str]) -> list[str]:
    """Actions à fort impact présentes, pour les SIGNALER dans le rapport.

    Elles sont exécutées automatiquement (pas de validation humaine) ; ce filtre
    sert seulement à les mettre en évidence pour l'analyste qui lit le case.
    """
    return [a for a in actions if a in HIGH_IMPACT_ACTIONS]


# Niveau Wazuh à partir duquel une clôture automatique est interdite. 14 et 15
# sont les niveaux « attaque avérée » : ransomware, destruction de masse,
# compromission confirmée. Une règle qui tire à 14+ a exigé plusieurs
# corrélations côté Wazuh — la classer en faux positif demande un humain.
#
# Défaut historique, conservé pour les assets sans priorité connue et pour les
# appels qui ne passent pas de priorité (tests, rejeu d'incidents antérieurs à
# la CMDB). Sur un asset priorisé, c'est `config.CLOTURE_INTERDITE_PAR_PRIORITE`
# qui s'applique : le seuil DESCEND quand l'asset compte (12 sur un contrôleur
# de domaine). Le coût d'un faux négatif y est sans commune mesure avec celui
# d'un case de plus à lire.
LEVEL_CLOSURE_FORBIDDEN = 14

# Confinements moins invasifs que l'isolation. Tant que l'un d'eux s'applique,
# il traite la menace sans couper la machine du réseau.
LEAST_INVASIVE_CONFINEMENT = (
    "propose_block_ip",
    "propose_kill_process",
    "propose_disable_user",
    "propose_quarantine_file",
    "propose_remove_privileged_group",
)


def closure_threshold(priority: int | None) -> int:
    """Niveau au-delà duquel la clôture automatique est refusée, selon l'asset.

    Import local : `actions` est un module pur (aucune I/O, aucune base) et doit
    le rester pour être testable seul ; `config` ne lit que l'environnement.
    """
    from . import config
    if priority is None:
        return LEVEL_CLOSURE_FORBIDDEN
    return config.CLOSURE_FORBIDDEN_BY_PRIORITY.get(
        int(priority), LEVEL_CLOSURE_FORBIDDEN)


def apply_guardrails(verdict: str, actions: list[str], max_level: int,
                         suspected_injection: bool,
                         active_compromise: bool = False,
                         priority: int | None = None,
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
       Le seuil DESCEND sur un asset prioritaire (`priorite`, cf.
       `seuil_cloture`) : 12 sur un contrôleur de domaine ou un pare-feu.
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
    patterns: list[str] = []

    if verdict == "false_positive":
        threshold = closure_threshold(priority)
        if max_level >= threshold:
            patterns.append(
                f"clôture refusée : niveau {max_level} >= {threshold}"
                + (f" (asset P{priority})" if priority else ""))
        if suspected_injection:
            patterns.append(
                "clôture refusée : motifs d'injection dans les données")

    if patterns:
        # On n'invente pas un verdict à la place du modèle : on refuse
        # seulement la conséquence dangereuse, et on rend la main à un humain.
        return ["escalate_human", "open_case"], patterns

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
        less_invasive = [a for a in LEAST_INVASIVE_CONFINEMENT if a in actions]
        if less_invasive and active_compromise:
            # Compromission active de l'hôte : l'attaquant exécute déjà du code
            # dessus (webshell, reverse shell, rootkit, persistance root). Un
            # confinement moins invasif ne suffit pas — couper une IP laisse le
            # foothold en place. L'isolation EST maintenue, en plus du reste.
            patterns.append(
                "isolation MAINTENUE : compromission active de l'hôte "
                "(post-exploitation avérée) — le confinement moins invasif "
                f"({', '.join(less_invasive)}) ne déloge pas un attaquant "
                "déjà installé")
        elif less_invasive:
            actions = [a for a in actions if a != "propose_isolate_host"]
            if "escalate_human" not in actions:
                actions.append("escalate_human")
            actions = _order(actions)
            patterns.append(
                "isolation retirée (dernier recours) : "
                f"{', '.join(less_invasive)} suffit — escalade à un humain")

    return actions, patterns
