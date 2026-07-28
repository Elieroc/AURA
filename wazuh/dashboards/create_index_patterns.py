#!/usr/bin/env python3
"""Crée les index patterns custom requis par soc-ai-dashboards.ndjson.

gen_dashboard.py ne les génère pas exprès (créer un index pattern écrase sa
liste de champs mise en cache, cf. refresh_index_patterns.py) : ils doivent
exister *avant* l'import du ndjson, sinon les visualisations Linux/Web/Global
échouent silencieusement à l'import (référence vers un index-pattern absent).

Usage : INDEXER_PASSWORD=... python3 create_index_patterns.py
        (ou lancé depuis wazuh/ avec .env chargé)

Idempotent pour les patterns simples : déjà présent -> pas recréé.

`soc-ai-all-alerts` (pattern combiné, utilisé par Global/Threat Intel) est un
cas à part, RECALCULÉ à chaque run : l'API `_fields_for_wildcard` d'OpenSearch
Dashboards rejette le pattern ENTIER (404 no_matching_indices) dès qu'UN SEUL
des sous-patterns listés ne matche aucun index — même si les autres existent
et ont des données (vécu : wazuh-jellyfin-* vide a cassé Global le temps
qu'aucun WRN/ERR Jellyfin ne survienne). Ne joindre que les sous-patterns qui
ont RÉELLEMENT au moins un index au moment du run ; les absents (ex. pas
encore d'agent Windows) sont simplement exclus du pattern combiné jusqu'à ce
qu'ils aient des données, sans qu'il faille relancer quoi que ce soit à la main.
"""
import json
import os
import subprocess
import sys

DASHBOARD_URL = "https://localhost"
INDEXER_URL = "https://localhost:9200"
AUTH = f"admin:{os.environ['INDEXER_PASSWORD']}"

# Doit rester synchro avec les IDX_* de gen_dashboard.py.
SIMPLE_PATTERNS = {
    "wazuh-linux-*": "wazuh-linux-*",
    "wazuh-web-*": "wazuh-web-*",
    "wazuh-firewall-*": "wazuh-firewall-*",
    "wazuh-proxy-*": "wazuh-proxy-*",
    "wazuh-jellyfin-*": "wazuh-jellyfin-*",
    "wazuh-vpn-*": "wazuh-vpn-*",
    "wazuh-dns-*": "wazuh-dns-*",
    "wazuh-yara-*": "wazuh-yara-*",
}

# Candidats du pattern combiné — filtrés à l'existence réelle avant de
# construire soc-ai-all-alerts.
ALL_ALERTS_CANDIDATES = [
    "wazuh-alerts-*", "wazuh-linux-*", "wazuh-windows-*", "wazuh-web-*",
    "wazuh-firewall-*", "wazuh-proxy-*", "wazuh-jellyfin-*", "wazuh-vpn-*", "wazuh-dns-*",
    "wazuh-yara-*",
]


def req(method, path, data=None, base=DASHBOARD_URL, extra_headers=None):
    cmd = ["curl", "-sk", "-u", AUTH, "-X", method, base + path]
    for h in (extra_headers or ["osd-xsrf: true"]):
        cmd += ["-H", h]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return json.loads(out) if out else {}


def pattern_has_indices(pattern):
    r = req("GET", f"/{pattern}/_count", base=INDEXER_URL, extra_headers=[])
    return "count" in r and r.get("_shards", {}).get("successful", 0) > 0


def fetch_fields(title):
    cmd = ["curl", "-sk", "-u", AUTH, "--get", f"{DASHBOARD_URL}/api/index_patterns/_fields_for_wildcard",
           "--data-urlencode", f"pattern={title}"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    r = json.loads(out) if out else {}
    return r.get("fields")


def main():
    existing = {o["id"] for o in
                req("GET", "/api/saved_objects/_find?type=index-pattern&per_page=100")
                .get("saved_objects", [])}
    failed = False

    for pid, title in SIMPLE_PATTERNS.items():
        if pid in existing:
            print(f"déjà présent {pid}")
            continue
        r = req("POST", f"/api/saved_objects/index-pattern/{pid}",
                 {"attributes": {"title": title, "timeFieldName": "timestamp"}})
        ok = "id" in r
        failed |= not ok
        print(f"{'créé  ' if ok else 'ECHEC '}{pid} ({title}): {str(r)[:150]}")

    live = [p for p in ALL_ALERTS_CANDIDATES if pattern_has_indices(p)]
    dropped = [p for p in ALL_ALERTS_CANDIDATES if p not in live]
    if dropped:
        print(f"soc-ai-all-alerts : exclus (aucun index actuellement) : {', '.join(dropped)}")
    title = ",".join(live)
    fields = fetch_fields(title)
    if fields is None:
        print(f"ECHEC soc-ai-all-alerts ({title}): impossible de récupérer les champs")
        failed = True
    else:
        r = req("PUT", "/api/saved_objects/index-pattern/soc-ai-all-alerts",
                 {"attributes": {"title": title, "timeFieldName": "timestamp",
                                 "fields": json.dumps(fields)}})
        ok = "id" in r
        failed |= not ok
        print(f"{'ok    ' if ok else 'ECHEC '}soc-ai-all-alerts ({title}): {len(fields)} champs")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
