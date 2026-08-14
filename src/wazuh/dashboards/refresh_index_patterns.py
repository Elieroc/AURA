#!/usr/bin/env python3
"""Refreshes the field list of all OSD index patterns.

Run this after any field addition in the ingest pipeline (e.g. rule.severity):
index patterns cache their field list, an unknown field breaks the
visualizations ("Could not locate that index-pattern-field").

Usage: INDEXER_PASSWORD=... python3 refresh_index_patterns.py
        (or run from wazuh/ with .env loaded)
"""
import json
import os
import subprocess
import sys
import tempfile
from urllib.parse import quote

DASHBOARD_URL = "https://localhost"
AUTH = f"admin:{os.environ['INDEXER_PASSWORD']}"


def req(method, path, data=None):
    """The body goes through a FILE (`-d @...`), never through argv.

    Same pitfall as in create_index_patterns.py: the field list we rewrite
    here exceeds the kernel's argv limit for large patterns
    (`OSError: [Errno 7] Argument list too long`), and the script used to die
    partway through — the already-processed patterns refreshed, the
    remaining ones never, without anything reporting it.
    """
    cmd = ["curl", "-sk", "-u", AUTH, "-X", method, DASHBOARD_URL + path,
           "-H", "osd-xsrf: true"]
    tmp = None
    try:
        if data is not None:
            tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            json.dump(data, tmp)
            tmp.close()
            cmd += ["-H", "Content-Type: application/json", "-d", "@" + tmp.name]
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
    finally:
        if tmp is not None:
            os.unlink(tmp.name)
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
            print(f"FAILED {pid} ({title}): {str(fields)[:100]}")
            failed = True
            continue
        attrs = obj["attributes"]
        attrs["fields"] = json.dumps(fields["fields"])
        r = req("PUT", f"/api/saved_objects/index-pattern/{pid}", {"attributes": attrs})
        ok = "id" in r
        failed |= not ok
        print(f"{'ok    ' if ok else 'FAILED '}{pid} ({title}): {len(fields['fields'])} fields")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
