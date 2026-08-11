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
import re
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


# Antislash qui n'ouvre PAS une séquence d'échappement JSON valide. C'est
# exactement ce que produit un modèle qui recopie un chemin Windows dans sa
# justification : `C:\Windows\System32` sort tel quel, et `\W` n'est pas un
# échappement légal.
_ANTISLASH_NU = re.compile(r'\\(?!["\\/bfnrtu])')


def _charger_json(contenu: str) -> dict:
    """Parse la réponse du modèle, en réparant les antislashs non échappés.

    `response_format=json_object` était réputé garantir un JSON valide. C'est
    faux, et mesuré : sur un incident Windows (chemins `C:\\...` partout dans le
    contexte), DeepSeek a rendu « Invalid \\escape: line 2 column 68 ». Sans
    réparation, l'incident échoue à CHAQUE cycle — le lot étant trié de façon
    déterministe, il repasse en tête indéfiniment.

    La réparation est délibérément étroite : on ne double que les antislashs qui
    n'ouvrent aucune séquence d'échappement légale. Un JSON déjà correct est
    inchangé (il passe au premier `loads` et n'atteint jamais la regex), et une
    vraie panne d'API remonte toujours.
    """
    try:
        return json.loads(contenu)
    except json.JSONDecodeError:
        repare = _ANTISLASH_NU.sub(r"\\\\", contenu)
        obj = json.loads(repare)   # échoue encore -> vraie sortie inexploitable
        log.warning("JSON du modèle réparé (antislashs non échappés)")
        return obj


def completion(systeme: str, utilisateur: str, usage: str,
               max_tokens: int = 500, temperature: float = 0.2,
               incident_id: int | None = None) -> tuple[dict, dict]:
    """Retourne (objet JSON parsé, métriques).

    `response_format` json_object exige que le mot « json » apparaisse dans les
    messages — les prompts système le mentionnent explicitement (« objet JSON »).

    `usage` nomme l'appelant ('triage', 'report', …) : c'est la dimension par
    laquelle on lit ensuite la consommation dans le dashboard AI. Les appels en
    échec sont comptés aussi — un timeout ou un budget trop court coûte du
    temps, et parfois des tokens, même sans réponse exploitable.

    Paramètre OBLIGATOIRE et placé avant les optionnels, volontairement : avec
    une valeur par défaut, un nouvel appelant qui l'oublie passe inaperçu et sa
    consommation atterrit dans un bucket « inconnu » du dashboard — ce qui est
    exactement arrivé. Sans défaut, l'oubli est une TypeError au premier appel.
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
        # (connexion, lecture) explicites : le second est un délai d'INACTIVITÉ,
        # pas une durée totale. Le cycle tient son verrou consultatif pendant
        # tout son déroulé — un fournisseur qui répond au ralenti ne doit pas
        # l'immobiliser (cf. config.LLM_TIMEOUT_*).
        timeout=(config.LLM_TIMEOUT_CONNECT_S, config.LLM_TIMEOUT_READ_S),
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

    obj = _charger_json(contenu)
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
