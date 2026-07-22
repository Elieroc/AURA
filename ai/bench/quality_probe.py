#!/usr/bin/env python3
"""Compare quatre façons d'interroger le modèle sur la même alerte.

Deux axes croisés :
  - endpoint : /completion (prompt brut) vs /v1/chat/completions (template de
    chat appliqué, c'est-à-dire le format sur lequel le modèle a été instruit)
  - grammaire : verdict d'abord vs reason d'abord

Appelé par run-quality.sh, qui gère le cycle de vie du serveur.
"""

import json
import sys
import urllib.request

BASE, HERE = sys.argv[1], sys.argv[2]

PROMPT = open(f"{HERE}/prompt-triage.txt").read()
GRAMMARS = {
    "verdict-1er": open(f"{HERE}/triage.gbnf").read(),
    "reason-1er": open(f"{HERE}/triage-reason-first.gbnf").read(),
}

# Le vrai verdict sur cette alerte : brute force SSH aboutie depuis une IP
# notée 96/100 par AbuseIPDB, sur un compte root, sans antécédent en 90 jours.
ATTENDU = "true_positive"


def post(path, payload):
    req = urllib.request.Request(
        f"{BASE}{path}", json.dumps(payload).encode(),
        {"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req).read())


def essai(endpoint, gname):
    grammar = GRAMMARS[gname]
    if endpoint == "raw":
        r = post("/completion", {
            "prompt": PROMPT, "grammar": grammar,
            "n_predict": 400, "temperature": 0.2, "seed": 42,
        })
        content, t = r["content"], r["timings"]
    else:
        r = post("/v1/chat/completions", {
            "messages": [{"role": "user", "content": PROMPT}],
            "grammar": grammar, "max_tokens": 400,
            "temperature": 0.2, "seed": 42, "timings_per_token": True,
        })
        content = r["choices"][0]["message"]["content"]
        t = r.get("timings", {})

    try:
        d = json.loads(content)
    except json.JSONDecodeError:
        print(f"  {endpoint:5s} {gname:12s}  JSON illisible: {content[:120]}")
        return

    ok = "OK " if d["verdict"] == ATTENDU else "FAUX"
    secs = (t.get("prompt_ms", 0) + t.get("predicted_ms", 0)) / 1000
    print(f"  {endpoint:5s} {gname:12s}  {ok}  "
          f"{d['verdict']:20s} {d['confidence']:8s} {d['next_action']:28s} {secs:5.1f}s")
    print(f"        reason: {d['reason'][:150]}")


print("  endpoint grammaire     verdict attendu:", ATTENDU)
for endpoint in ("raw", "chat"):
    for gname in GRAMMARS:
        essai(endpoint, gname)
