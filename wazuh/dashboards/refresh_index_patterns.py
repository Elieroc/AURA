#!/usr/bin/env python3
"""Rafraîchit la liste de champs de tous les index patterns OSD.

À lancer après tout ajout de champ dans le pipeline ingest (ex: rule.severity) :
les index patterns cachent leur liste de champs, un champ inconnu casse les
visualisations ("Could not locate that index-pattern-field").

Usage : INDEXER_PASSWORD=... python3 refresh_index_patterns.py
        (ou lancé depuis wazuh/ avec .env chargé)
"""
import json
import os
import subprocess
import sys
from urllib.parse import quote

DASHBOARD_URL = "https://localhost"
AUTH = f"admin:{os.environ['INDEXER_PASSWORD']}"


def req(method, path, data=None):
    cmd = ["curl", "-sk", "-u", AUTH, "-X", method, DASHBOARD_URL + path,
           "-H", "osd-xsrf: true"]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return json.loads(out)


def main():
    found = req("GET", "/api/saved_objects/_find?type=index-pattern&per_page=100")
    failed = False
    for obj in found["saved_objects"]:
        pid, title = obj["id"], obj["attributes"]["title"]
        fields = req("GET",
                     f"/api/index_patterns/_fields_for_wildcard?pattern={quote(title)}"
                     "&meta_fields=_source&meta_fields=_id&meta_fields=_type"
                     "&meta_fields=_index&meta_fields=_score")
        if "fields" not in fields:
            print(f"ECHEC {pid} ({title}): {str(fields)[:100]}")
            failed = True
            continue
        attrs = obj["attributes"]
        attrs["fields"] = json.dumps(fields["fields"])
        r = req("PUT", f"/api/saved_objects/index-pattern/{pid}", {"attributes": attrs})
        ok = "id" in r
        failed |= not ok
        print(f"{'ok    ' if ok else 'ECHEC '}{pid} ({title}): {len(fields['fields'])} champs")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
