"""Ping de l'API DeepSeek.

Nommée `ping_` et non `test_` : sous le préfixe `test_`, pytest ramassait ce
module, dont l'import charge `config` — donc `SystemExit` sur toute machine sans
`.env` complet, et la collecte de TOUTE la suite partait en INTERNALERROR. Ce
n'est de toute façon pas un test : ça consomme du crédit et ça sort du réseau.

Sonde minimale, hors pipeline : vérifie que la clé, l'URL et le modèle
répondent, et mesure la latence d'un aller-retour. Aucune donnée SOC ici —
un simple ping applicatif.

    python -m soc_agent.ping_deepseek

Lit DEEPSEEK_API_KEY depuis l'environnement (ou ai/.env, chargé au préalable).
DeepSeek expose une API compatible OpenAI : /chat/completions, Bearer token.
"""

import os
import sys
import time

import requests

BASE_URL = os.environ.get("DEEPSEEK_URL", "https://api.deepseek.com")
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")


def main() -> int:
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        print("DEEPSEEK_API_KEY absente de l'environnement.", file=sys.stderr)
        return 2

    start = time.monotonic()
    try:
        rep = requests.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": MODEL,
                "messages": [
                    {"role": "user", "content": "réponds uniquement par: pong"},
                ],
                "max_tokens": 8,
                "temperature": 0,
                "stream": False,
            },
            timeout=30,
        )
    except requests.RequestException as e:
        print(f"Échec réseau : {e}", file=sys.stderr)
        return 1

    duration_ms = int((time.monotonic() - start) * 1000)

    if rep.status_code != 200:
        print(f"HTTP {rep.status_code} : {rep.text[:300]}", file=sys.stderr)
        return 1

    body = rep.json()
    content = body["choices"][0]["message"]["content"]
    usage = body.get("usage", {})
    print(f"OK  modèle={body.get('model', '?')}  latence={duration_ms} ms")
    print(f"    réponse={content!r}")
    print(f"    tokens: prompt={usage.get('prompt_tokens')} "
          f"completion={usage.get('completion_tokens')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
