#!/usr/bin/env python3
"""Crée les index patterns custom requis par soc-ai-dashboards.ndjson.

gen_dashboard.py ne les génère pas exprès (créer un index pattern écrase sa
liste de champs mise en cache, cf. refresh_index_patterns.py) : ils doivent
exister *avant* l'import du ndjson, sinon les visualisations Linux/Web/Global
échouent silencieusement à l'import (référence vers un index-pattern absent).

Usage : INDEXER_PASSWORD=... python3 create_index_patterns.py
        (ou lancé depuis wazuh/ avec .env chargé)

Idempotent : un index pattern déjà présent (même id) n'est pas recréé.
"""
import json
import os
import subprocess
import sys

DASHBOARD_URL = "https://localhost"
AUTH = f"admin:{os.environ['INDEXER_PASSWORD']}"

# Doit rester synchro avec les IDX_* de gen_dashboard.py.
PATTERNS = {
    "wazuh-linux-*": "wazuh-linux-*",
    "wazuh-web-*": "wazuh-web-*",
    "wazuh-firewall-*": "wazuh-firewall-*",
    "soc-ai-all-alerts": "wazuh-alerts-*,wazuh-linux-*,wazuh-windows-*,wazuh-web-*,wazuh-firewall-*",
}


def req(method, path, data=None):
    cmd = ["curl", "-sk", "-u", AUTH, "-X", method, DASHBOARD_URL + path,
           "-H", "osd-xsrf: true"]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return json.loads(out)


def main():
    existing = {o["id"] for o in
                req("GET", "/api/saved_objects/_find?type=index-pattern&per_page=100")
                .get("saved_objects", [])}
    failed = False
    for pid, title in PATTERNS.items():
        if pid in existing:
            print(f"déjà présent {pid}")
            continue
        r = req("POST", f"/api/saved_objects/index-pattern/{pid}",
                 {"attributes": {"title": title, "timeFieldName": "timestamp"}})
        ok = "id" in r
        failed |= not ok
        print(f"{'créé  ' if ok else 'ECHEC '}{pid} ({title}): {str(r)[:150]}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
