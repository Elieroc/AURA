"""Appel générique au modèle — DeepSeek (API cloud, compatible OpenAI).

Bascule depuis llama.cpp local. DeepSeek n'accepte pas de grammaire GBNF ;
on force un JSON valide via `response_format={"type": "json_object"}`. Cela
garantit un JSON *syntaxiquement* valide, PAS le respect du schéma ni de
l'enum — cette garantie-là est reportée dans le code appelant (coercition
dans triage.py) et dans les garde-fous déterministes d'actions.py.

Note sécurité : tout ce qui passe ici part vers le cloud. Le texte doit être
anonymisé en amont (sanitize.py). Le LLM n'est pas une frontière de sécurité.

Toujours `/chat/completions` (template de chat), jamais un endpoint brut : le
template change le verdict (mesuré au bench).
"""

import json
import time

import requests

from . import config


def completion(systeme: str, utilisateur: str, max_tokens: int = 500,
               temperature: float = 0.2) -> tuple[dict, dict]:
    """Retourne (objet JSON parsé, métriques).

    `response_format` json_object exige que le mot « json » apparaisse dans les
    messages — les prompts système le mentionnent explicitement (« objet JSON »).
    """
    debut = time.monotonic()
    rep = requests.post(
        f"{config.DEEPSEEK_URL}/chat/completions",
        headers={"Authorization": f"Bearer {config.DEEPSEEK_API_KEY}"},
        json={
            "model": config.DEEPSEEK_MODEL,
            "messages": [
                {"role": "system", "content": systeme},
                {"role": "user", "content": utilisateur},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens,
            # Température basse pour un verdict aussi stable que possible.
            # DeepSeek ne garantit pas la reproductibilité par seed (non
            # supportée), contrairement au setup local.
            "temperature": temperature,
            "stream": False,
        },
        timeout=120,
    )
    rep.raise_for_status()
    corps = rep.json()
    duree_ms = int((time.monotonic() - debut) * 1000)

    choix = corps["choices"][0]
    contenu = choix["message"].get("content") or ""
    # Modèles raisonnants (deepseek-v4-*) : le raisonnement est décompté de
    # max_tokens. S'il l'épuise, finish_reason=length et content est VIDE — le
    # verdict n'a jamais été écrit. Erreur explicite plutôt qu'un JSONDecodeError
    # opaque : la correction est d'augmenter TRIAGE_MAX_TOKENS.
    if not contenu.strip():
        raise RuntimeError(
            f"réponse sans content (finish_reason={choix.get('finish_reason')}, "
            f"reasoning épuisant max_tokens={max_tokens} ?) — augmenter le budget")

    # json_object garantit un JSON valide : un JSONDecodeError ici signalerait
    # une panne côté API, pas une sortie mal formée du modèle. On laisse remonter.
    obj = json.loads(contenu)
    usage = corps.get("usage", {})
    return obj, {"duree_ms": duree_ms,
                 "prompt_tokens": usage.get("prompt_tokens"),
                 "completion_tokens": usage.get("completion_tokens"),
                 "modele": corps.get("model", config.DEEPSEEK_MODEL)}
