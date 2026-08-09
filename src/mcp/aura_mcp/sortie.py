"""Mise en forme des réponses d'outil.

Une réponse d'outil atterrit dans le contexte d'un LLM. Deux contraintes qui
n'existent pas pour une API classique :

1. **La taille est un coût.** Un `full_log` de 200 Ko ou 3 000 alertes ne
   rendent pas le client plus lucide, ils saturent sa fenêtre. Tout est borné
   et paginé, et une troncature est toujours annoncée dans la donnée elle-même.
2. **Le contenu est hostile.** `rule_desc`, `full_log`, un nom de fichier, une
   ligne de commande : tout cela est écrit par ce qui tourne sur les machines
   surveillées, donc éventuellement par un attaquant qui sait qu'une IA va le
   lire. On le balise `<untrusted>` pour que le client sache qu'il regarde des
   pièces à conviction, pas des consignes.

Le balisage n'est pas une protection — un modèle peut s'y laisser prendre quand
même (3 charges sur 4 dans les tests du pipeline). La vraie barrière reste
déterministe et côté serveur : `soc_agent.actions.appliquer_garde_fous`.
"""

from datetime import date, datetime

from . import config

DEBUT = "<untrusted>"
FIN = "</untrusted>"


def untrusted(valeur):
    """Balise une chaîne venue des machines surveillées, en la bornant.

    `None` et les non-chaînes passent tels quels : un niveau de règle ou un
    identifiant d'agent sont produits par Wazuh, pas par l'attaquant.
    """
    if not isinstance(valeur, str) or not valeur:
        return valeur
    return f"{DEBUT}{borner(valeur)}{FIN}"


def borner(texte: str, maximum: int | None = None) -> str:
    """Tronque en le disant. Une troncature muette ferait conclure à tort."""
    maximum = maximum or config.TEXTE_MAX
    if len(texte) <= maximum:
        return texte
    return (f"{texte[:maximum]}\n[…tronqué, {len(texte) - maximum} caractères "
            f"de plus — demander la source complète si nécessaire]")


def jsonifiable(valeur):
    """Rend datetime/date sérialisables, récursivement."""
    if isinstance(valeur, (datetime, date)):
        return valeur.isoformat()
    if isinstance(valeur, dict):
        return {k: jsonifiable(v) for k, v in valeur.items()}
    if isinstance(valeur, (list, tuple)):
        return [jsonifiable(v) for v in valeur]
    return valeur


def bornes(limite: int | None, offset: int | None) -> tuple[int, int]:
    """Normalise une demande de pagination dans les plafonds du serveur."""
    limite = config.PAGE_DEFAUT if limite is None else limite
    limite = max(1, min(int(limite), config.PAGE_MAX))
    return limite, max(0, int(offset or 0))


def page(lignes: list, total: int, limite: int, offset: int) -> dict:
    """Enveloppe paginée uniforme.

    `reste` plutôt qu'un simple `total` : le client doit savoir en un coup
    d'œil s'il a tout vu, sans refaire la soustraction — c'est ce qui évite
    qu'il conclue sur une page partielle.
    """
    return {
        "resultats": jsonifiable(lignes),
        "total": total,
        "offset": offset,
        "limite": limite,
        "reste": max(0, total - offset - len(lignes)),
    }
