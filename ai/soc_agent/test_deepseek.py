"""Test de connexion à l'API DeepSeek.

Sonde minimale, hors pipeline : vérifie que la clé, l'URL et le modèle
répondent, et mesure la latence d'un aller-retour. Aucune donnée SOC ici —
un simple ping applicatif.

    python -m soc_agent.test_deepseek

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
    cle = os.environ.get("DEEPSEEK_API_KEY")
    if not cle:
        print("DEEPSEEK_API_KEY absente de l'environnement.", file=sys.stderr)
        return 2

    debut = time.monotonic()
    try:
        rep = requests.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {cle}"},
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

    duree_ms = int((time.monotonic() - debut) * 1000)

    if rep.status_code != 200:
        print(f"HTTP {rep.status_code} : {rep.text[:300]}", file=sys.stderr)
        return 1

    corps = rep.json()
    contenu = corps["choices"][0]["message"]["content"]
    usage = corps.get("usage", {})
    print(f"OK  modèle={corps.get('model', '?')}  latence={duree_ms} ms")
    print(f"    réponse={contenu!r}")
    print(f"    tokens: prompt={usage.get('prompt_tokens')} "
          f"completion={usage.get('completion_tokens')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
