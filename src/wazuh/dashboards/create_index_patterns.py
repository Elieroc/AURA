#!/usr/bin/env python3
"""Creates the custom index patterns required by soc-ai-dashboards.ndjson.

gen_dashboard.py deliberately doesn't generate them (creating an index pattern
overwrites its cached field list, cf. refresh_index_patterns.py): they must
exist *before* the ndjson import, otherwise the Linux/Web/Global
visualizations silently fail on import (reference to a missing index-pattern).

Usage: INDEXER_PASSWORD=... python3 create_index_patterns.py
        (or run from wazuh/ with .env loaded)

Idempotent for the simple patterns: already present -> not recreated.

`soc-ai-all-alerts` (combined pattern, used by Global/Threat Intel) is a
special case, RECOMPUTED on every run: OpenSearch Dashboards' `_fields_for_wildcard`
API rejects the ENTIRE pattern (404 no_matching_indices) as soon as A SINGLE
one of the listed sub-patterns matches no index — even if the others exist
and have data (experienced: an empty wazuh-jellyfin-* broke Global for as long
as no Jellyfin WRN/ERR occurred). Only join the sub-patterns that REALLY
have at least one index at run time; the missing ones (e.g. no Windows agent
yet) are simply excluded from the combined pattern until they have data,
without needing to rerun anything by hand.
"""
import json
import os
import subprocess
import sys
import tempfile

DASHBOARD_URL = "https://localhost"
INDEXER_URL = "https://localhost:9200"
AUTH = f"admin:{os.environ['INDEXER_PASSWORD']}"

# Must stay in sync with the IDX_* of gen_dashboard.py.
SIMPLE_PATTERNS = {
    "wazuh-linux-*": "wazuh-linux-*",
    "wazuh-windows-*": "wazuh-windows-*",
    "wazuh-web-*": "wazuh-web-*",
    "wazuh-firewall-*": "wazuh-firewall-*",
    "wazuh-proxy-*": "wazuh-proxy-*",
    "wazuh-jellyfin-*": "wazuh-jellyfin-*",
    "wazuh-vpn-*": "wazuh-vpn-*",
    "wazuh-dns-*": "wazuh-dns-*",
    "wazuh-yara-*": "wazuh-yara-*",
    # AI metrics (soc-agent-metrics). Deliberately OUTSIDE the combined
    # soc-ai-all-alerts pattern: these are not alerts, counting them together
    # would skew all the Global dashboard totals.
    "wazuh-ai-*": "wazuh-ai-*",
    # VOC (soc-agent-vulns). Outside the combined pattern for the same reason
    # as wazuh-ai-* : these are not alerts. Covers both the dated time-series
    # indices and the stable wazuh-voc-vulns index.
    "wazuh-voc-*": "wazuh-voc-*",
}

# Combined pattern candidates — filtered to actual existence before
# building soc-ai-all-alerts.
ALL_ALERTS_CANDIDATES = [
    "wazuh-alerts-*", "wazuh-linux-*", "wazuh-windows-*", "wazuh-web-*",
    "wazuh-firewall-*", "wazuh-proxy-*", "wazuh-jellyfin-*", "wazuh-vpn-*", "wazuh-dns-*",
    "wazuh-yara-*",
]


def req(method, path, data=None, base=DASHBOARD_URL, extra_headers=None):
    """The body goes through a FILE (`-d @...`), never through argv.

    The cached field list of the combined pattern exceeds the kernel's argv
    limit: `curl ... -d '<json>'` raised `OSError: [Errno 7]
    Argument list too long` — and only for soc-ai-all-alerts, i.e. after the
    simple patterns were successfully created.
    """
    cmd = ["curl", "-sk", "-u", AUTH, "-X", method, base + path]
    for h in (extra_headers or ["osd-xsrf: true"]):
        cmd += ["-H", h]
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
    return json.loads(out) if out else {}


def pattern_has_indices(pattern):
    r = req("GET", f"/{pattern}/_count", base=INDEXER_URL, extra_headers=[])
    return "count" in r and r.get("_shards", {}).get("successful", 0) > 0


def fetch_fields(title):
    """Field list cached in the index pattern.

    `meta_fields` is MANDATORY and easy to forget: without it, `_index`,
    `_id` & co. are missing from the list, and a visualization that
    aggregates on them imports without error then shows "Could not locate
    that index-pattern-field (id: _index)" on opening. The field does exist
    on the OpenSearch side — it's really the cached list that's incomplete.
    Same parameter as in refresh_index_patterns.py, keep the two in sync.
    """
    cmd = ["curl", "-sk", "-u", AUTH, "--get", f"{DASHBOARD_URL}/api/index_patterns/_fields_for_wildcard",
           "--data-urlencode", f"pattern={title}",
           "--data-urlencode", "meta_fields=_source", "--data-urlencode", "meta_fields=_id",
           "--data-urlencode", "meta_fields=_type", "--data-urlencode", "meta_fields=_index",
           "--data-urlencode", "meta_fields=_score"]
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
            print(f"already present {pid}")
            continue
        r = req("POST", f"/api/saved_objects/index-pattern/{pid}",
                 {"attributes": {"title": title, "timeFieldName": "timestamp"}})
        ok = "id" in r
        failed |= not ok
        print(f"{'created' if ok else 'FAILED '}{pid} ({title}): {str(r)[:150]}")

    live = [p for p in ALL_ALERTS_CANDIDATES if pattern_has_indices(p)]
    dropped = [p for p in ALL_ALERTS_CANDIDATES if p not in live]
    if dropped:
        print(f"soc-ai-all-alerts: excluded (no index currently) : {', '.join(dropped)}")
    title = ",".join(live)
    fields = fetch_fields(title)
    if fields is None:
        print(f"FAILED soc-ai-all-alerts ({title}): could not fetch fields")
        failed = True
    else:
        r = req("PUT", "/api/saved_objects/index-pattern/soc-ai-all-alerts",
                 {"attributes": {"title": title, "timeFieldName": "timestamp",
                                 "fields": json.dumps(fields)}})
        ok = "id" in r
        failed |= not ok
        print(f"{'ok    ' if ok else 'FAILED '}soc-ai-all-alerts ({title}): {len(fields)} fields")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
