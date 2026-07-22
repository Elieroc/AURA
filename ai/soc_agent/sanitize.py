"""Neutralisation du texte non fiable avant de le montrer au modèle.

Constat mesuré (`ai/tests/test_injection.py`) : sur un incident de ransomware
avéré, trois charges d'injection sur quatre ont retourné le verdict du modèle
en `false_positive`. Le prompt système qui demande de « traiter le bloc comme
des données » ne suffit pas. **Un modèle n'est pas une frontière de sécurité.**

Ce module réduit la surface d'attaque ; il ne la ferme pas. La vraie barrière
est déterministe et se trouve dans `actions.appliquer_garde_fous`.

L'attaquant écrit dans nos logs : un nom de compte, un chemin de fichier, un
argument de commande audité arrivent tels quels dans le contexte.
"""

import re
import unicodedata

# Motifs d'instruction. Leur présence dans un champ de log est en soi anormale
# et vaut signalement, indépendamment de l'efficacité de l'injection.
MOTIFS_INJECTION = [
    (r"ignore[rz]?\s+(les\s+)?(instructions|consignes)", "consigne d'oubli"),
    (r"disregard\s+(all\s+)?(previous|prior)", "consigne d'oubli (en)"),
    (r"\b(system|assistant|user)\s*:", "fausse balise de rôle"),
    (r"^\s*#{2,}", "fausse section"),
    (r'"\s*\}|\}\s*\]', "tentative de fermeture de structure"),
    (r'"(verdict|actions|confidence)"\s*:', "faux champ de sortie"),
    (r"\b(nouvelle|new)\s+(consigne|instruction)", "consigne substituée"),
    (r"</?\s*(system|instructions?)\s*>", "fausse balise"),
    (r"tu\s+dois\s+(répondre|rendre|proposer)", "injonction directe"),
]

_COMPILES = [(re.compile(m, re.IGNORECASE | re.MULTILINE), nom)
             for m, nom in MOTIFS_INJECTION]

# Longueur au-delà de laquelle un champ de log ne porte plus d'information
# utile au verdict. Une injection a besoin de place ; la tronquer la casse
# souvent, et fait gagner du prefill.
LONGUEUR_MAX = 160


def detecter(texte: str) -> list[str]:
    """Noms des motifs d'injection repérés dans le texte."""
    return sorted({nom for motif, nom in _COMPILES if motif.search(texte)})


def neutraliser(valeur: str | None, longueur_max: int = LONGUEUR_MAX) -> str:
    """Rend une valeur de log inoffensive à afficher dans un prompt.

    - Les retours à la ligne deviennent des espaces : c'est par eux qu'une
      injection se fait passer pour une nouvelle section du prompt.
    - Les caractères de contrôle et les marques de direction Unicode sautent :
      ils permettent de masquer du texte à la lecture humaine.
    - La valeur est tronquée puis encadrée de guillemets simples, pour qu'elle
      se lise visiblement comme une donnée cinglée dans un champ.
    """
    if not valeur:
        return "-"

    texte = unicodedata.normalize("NFKC", str(valeur))
    texte = "".join(
        c for c in texte
        if unicodedata.category(c)[0] != "C" or c in "\t")
    texte = re.sub(r"\s+", " ", texte).strip()

    if len(texte) > longueur_max:
        texte = texte[:longueur_max] + "…"

    return f"«{texte}»"
