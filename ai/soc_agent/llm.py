"""Appel générique au serveur d'inférence local, sortie contrainte par GBNF.

Extrait du triage pour être réutilisé par la génération de rapport de case.
Mêmes règles qu'au bench : `/v1/chat/completions` (template de chat), sortie
JSON garantie par grammaire, température basse + seed pour la reproductibilité.
"""

import json
import time

import requests

from . import config


def completion(systeme: str, utilisateur: str, grammaire: str,
               max_tokens: int = 500) -> tuple[dict, dict]:
    """Retourne (objet JSON validé par la grammaire, métriques)."""
    debut = time.monotonic()
    rep = requests.post(
        f"{config.LLM_URL}/v1/chat/completions",
        json={
            "messages": [
                {"role": "system", "content": systeme},
                {"role": "user", "content": utilisateur},
            ],
            "grammar": grammaire,
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "seed": 42,
            "cache_prompt": True,
        },
        timeout=300,
    )
    rep.raise_for_status()
    corps = rep.json()
    duree_ms = int((time.monotonic() - debut) * 1000)
    # La grammaire garantit la forme : un JSONDecodeError signalerait une panne
    # serveur, pas une sortie inattendue. On laisse remonter.
    obj = json.loads(corps["choices"][0]["message"]["content"])
    usage = corps.get("usage", {})
    return obj, {"duree_ms": duree_ms,
                 "prompt_tokens": usage.get("prompt_tokens"),
                 "modele": corps.get("model", "?").split("/")[-1]}
