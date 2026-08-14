"""Ping of the DeepSeek API.

Named `ping_` and not `test_`: under the `test_` prefix pytest collected this
module, whose import loads `config` — hence `SystemExit` on any machine without
a complete `.env`, and collection of the WHOLE suite ended in INTERNALERROR. It
is not a test anyway: it burns credit and leaves the network.

Minimal probe, outside the pipeline: checks that the key, the URL and the model
answer, and measures the latency of one round trip. No SOC data here — a plain
application-level ping.

    python -m soc_agent.ping_deepseek

Reads DEEPSEEK_API_KEY from the environment (or ai/.env, loaded beforehand).
DeepSeek exposes an OpenAI-compatible API: /chat/completions, Bearer token.
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
        print("DEEPSEEK_API_KEY missing from the environment.", file=sys.stderr)
        return 2

    start = time.monotonic()
    try:
        rep = requests.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": MODEL,
                "messages": [
                    {"role": "user", "content": "answer with just: pong"},
                ],
                "max_tokens": 8,
                "temperature": 0,
                "stream": False,
            },
            timeout=30,
        )
    except requests.RequestException as e:
        print(f"Network failure: {e}", file=sys.stderr)
        return 1

    duration_ms = int((time.monotonic() - start) * 1000)

    if rep.status_code != 200:
        print(f"HTTP {rep.status_code}: {rep.text[:300]}", file=sys.stderr)
        return 1

    body = rep.json()
    content = body["choices"][0]["message"]["content"]
    usage = body.get("usage", {})
    print(f"OK  model={body.get('model', '?')}  latency={duration_ms} ms")
    print(f"    answer={content!r}")
    print(f"    tokens: prompt={usage.get('prompt_tokens')} "
          f"completion={usage.get('completion_tokens')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
