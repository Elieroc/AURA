"""Appel générique au modèle — DeepSeek (API cloud, compatible OpenAI).

DeepSeek n'accepte aucune contrainte de grammaire ;
on force un JSON valide via `response_format={"type": "json_object"}`. Cela
garantit un JSON *syntaxiquement* valide, PAS le respect du schéma ni de
l'enum — cette garantie-là est reportée dans le code appelant (coercition
dans triage.py) et dans les garde-fous déterministes d'actions.py.

Note sécurité : tout ce qui passe ici part vers le cloud. Le texte doit être
anonymisé en amont (sanitize.py). Le LLM n'est pas une frontière de sécurité.

Toujours `/chat/completions` (template de chat), jamais un endpoint brut : le
template change le verdict (mesuré).
"""

import json
import logging
import time

import requests

from . import config

log = logging.getLogger(__name__)


def _enregistrer(usage: str, modele: str, max_tokens: int, duree_ms: int,
                 metriques: dict | None, incident_id: int | None,
                 erreur: str | None) -> None:
    """Trace l'appel dans `llm_calls`. N'échoue JAMAIS vers l'appelant.

    Point de passage unique : instrumenter ici plutôt que chez chaque appelant
    garantit qu'un nouvel usage du modèle est compté sans qu'on y pense. Et une
    métrique perdue vaut mieux qu'un verdict perdu — d'où le try/except large.

    Import de psycopg à l'intérieur : `llm.py` doit rester utilisable sans base
    (tests, appels ponctuels).
    """
    try:
        import psycopg
        m = metriques or {}
        with psycopg.connect(config.PG_DSN) as conn:
            conn.execute(
                "INSERT INTO llm_calls (usage, modele, prompt_tokens, "
                "completion_tokens, cache_hit_tokens, cache_miss_tokens, "
                "max_tokens, duree_ms, incident_id, ok, erreur) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (usage, m.get("modele") or modele, m.get("prompt_tokens"),
                 m.get("completion_tokens"), m.get("cache_hit_tokens"),
                 m.get("cache_miss_tokens"), max_tokens, duree_ms,
                 incident_id, erreur is None, erreur))
            conn.commit()
    except Exception as e:                                   # noqa: BLE001
        log.debug("métrique LLM non enregistrée : %s", e)


def completion(systeme: str, utilisateur: str, max_tokens: int = 500,
               temperature: float = 0.2, usage: str = "inconnu",
               incident_id: int | None = None) -> tuple[dict, dict]:
    """Retourne (objet JSON parsé, métriques).

    `response_format` json_object exige que le mot « json » apparaisse dans les
    messages — les prompts système le mentionnent explicitement (« objet JSON »).

    `usage` nomme l'appelant ('triage', 'report', …) : c'est la dimension par
    laquelle on lit ensuite la consommation dans le dashboard AI. Les appels en
    échec sont comptés aussi — un timeout ou un budget trop court coûte du
    temps, et parfois des tokens, même sans réponse exploitable.
    """
    debut = time.monotonic()
    try:
        return _completion(systeme, utilisateur, max_tokens, temperature,
                           usage, incident_id, debut)
    except Exception as e:                                   # noqa: BLE001
        _enregistrer(usage, config.DEEPSEEK_MODEL, max_tokens,
                     int((time.monotonic() - debut) * 1000), None,
                     incident_id, f"{type(e).__name__}: {e}"[:500])
        raise


def _completion(systeme: str, utilisateur: str, max_tokens: int,
                temperature: float, usage: str, incident_id: int | None,
                debut: float) -> tuple[dict, dict]:
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
    conso = corps.get("usage", {})
    # DeepSeek ventile l'entrée entre cache hit et cache miss, et le hit est
    # facturé 50x moins cher. Sans cette ventilation, le coût est surestimé :
    # le prompt système est constant d'un incident à l'autre, donc il est
    # presque toujours servi par le cache.
    metriques = {"duree_ms": duree_ms,
                 "prompt_tokens": conso.get("prompt_tokens"),
                 "completion_tokens": conso.get("completion_tokens"),
                 "cache_hit_tokens": conso.get("prompt_cache_hit_tokens"),
                 "cache_miss_tokens": conso.get("prompt_cache_miss_tokens"),
                 "modele": corps.get("model", config.DEEPSEEK_MODEL)}
    _enregistrer(usage, config.DEEPSEEK_MODEL, max_tokens, duree_ms,
                 metriques, incident_id, None)
    return obj, metriques
