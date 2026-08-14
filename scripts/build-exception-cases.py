#!/usr/bin/env python3
"""Builds the test case set for EXCLUSIONS, from real alerts.

Why not synthetic logs (unlike test-detection-rules.sh): Wazuh's auditd
decoder does not accept just any field order. A hand-written SYSCALL line
loses `euid`, `auid` and `cwd` on decoding - verified in phase 2 of
wazuh-logtest. And these are exactly the fields the 100665/100713/100714/100649
exclusions rely on. Tested with synthetic logs, they all look broken when
they actually work (and vice versa).

So we pull a REAL full_log per scenario from the indexer, and MUTATE it to
build the counter-example: the same event, but with an attacker's signature
(login session present, cwd in a docroot). A pair of excluded-FP /
still-detected-by-exclusion-TP.

Output: a TSV `expected \t description \t log`, to be replayed with
scripts/test-rule-exceptions.sh on the manager host.

Usage:
    INDEXER_URL=https://127.0.0.1:9200 INDEXER_USER=admin INDEXER_PASSWORD=... \
        python3 scripts/build-exception-cases.py > /tmp/cases.tsv
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.request

URL = os.environ.get("INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
USER = os.environ.get("INDEXER_USER", "admin")
PASSWORD = os.environ["INDEXER_PASSWORD"]

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_auth = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


def _full_log(rule: str, contains: str | None = None, agent: str | None = None):
    """The full_log of the most recent alert for this rule, filtered on a pattern."""
    noise_filter: list[dict] = [{"term": {"rule.id": rule}}]
    if agent:
        noise_filter.append({"term": {"agent.name": agent}})
    body = {"size": 200, "sort": [{"timestamp": "desc"}],
             "query": {"bool": {"filter": noise_filter}}}
    req = urllib.request.Request(
        f"{URL}/wazuh-*/_search", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + _auth})
    rep = json.load(urllib.request.urlopen(req, context=_ctx, timeout=30))
    for h in rep["hits"]["hits"]:
        fl = h["_source"].get("full_log") or ""
        if contains and contains not in fl:
            continue
        # wazuh-logtest reads ONE LINE = ONE LOG (cf. test-detection-rules.sh).
        return fl.replace("\n", " ")
    return None


cases: list[tuple[str, str, str]] = []


def add(desc: str, expected: str, log: str | None) -> None:
    if log is None:
        print(f"MISSING (no real alert): {desc}", file=sys.stderr)
        return
    cases.append((expected, desc, log))


# --- 100665 / 100653: the SCA's `stat`, and its mutation into an attacker.
sca = _full_log("100653", contains='cwd="/var/ossec"')
add("100665 SCA stat (real: cwd /var/ossec, auid unset)", "100665", sca)
if sca:
    add("100653 same stat by a human (mutated: auid+cwd)", "100653",
           sca.replace("auid=4294967295", "auid=1001")
              .replace('cwd="/var/ossec"', 'cwd="/home/eve"'))
    add("100653 stat cwd /var/ossec but session present (mutated: auid)",
           "100653", sca.replace("auid=4294967295", "auid=1001"))

# --- 100645: the -f / -F case bug. 80700 = benign auditd catch-all.
add("100645 nft -j -f - from a firewall service (FP: should no longer fire)", "80700",
       _full_log("100645", contains='a2="-f"', agent="host-pve"))
add("100645 nft -f - from our active response (FP: should no longer fire)",
       "80700", _full_log("100645", contains='cwd="/var/ossec"'))

# --- 100713 / 100711: s6-overlay, and its mutation into an RCE in a docroot.
s6 = _full_log("100711", contains='cwd="/config"')
add("100713 s6-overlay LinuxServer (real: euid 911, cwd /config)", "100713", s6)
if s6:
    add("100711 same interpreter but cwd in docroot (mutated: cwd)", "100711",
           s6.replace('cwd="/config"', 'cwd="/var/www/html"'))
    add("100711 same interpreter with a login session (mutated: auid)",
           "100711", s6.replace("auid=4294967295", "auid=1001")
                       .replace('cwd="/config"', 'cwd="/tmp"'))

# --- 100714 / 100711: apt dropping privileges to _apt.
apt = _full_log("100711", contains="euid=42")
add("100714 apt as _apt (real: euid 42, auid 0)", "100714", apt)
if apt:
    add("100711 euid 42 WITHOUT root session (mutated: auid)", "100711",
           apt.replace("auid=0 ", "auid=4294967295 "))

# --- 100649 / 100643: debconf, and the real web true positives.
add("100649 debconf (real: perl, comm dpkg-preconfigu)", "100649",
       _full_log("100643", contains="dpkg-preconfigu"))
add("100643 php-fpm reading /etc/shadow (real, TRUE POSITIVE)", "100643",
       _full_log("100643", contains="php-fpm"))
add("100643 cat from a docroot (real, TRUE POSITIVE)", "100643",
       _full_log("100643", contains='comm="cat"'))

# --- 100636 / 100634: the gpg-agent snippet, and its mutation into a real
# tmpfs implant (the path then comes from a KEY=value assignment).
gpg = _full_log("100634", contains="gnupg/S.gpg-agent.ssh")
add("100636 gpg-agent snippet (real: tmpfs path = env value)", "100636", gpg)
if gpg:
    add("100634 script from /dev/shm (mutated: real implant path)", "100634",
           gpg.replace("SSH_AUTH_SOCK=/run/user/0/gnupg/S.gpg-agent.ssh",
                       "/dev/shm/payload.sh"))

# --- 100904 / 100901: YARA. The pfSense diag page is excluded, the
# 2026-07-29 web shell (removed since, but the alert stays indexed) must fire.
add("100904 pfSense diag_command.php (real, should be excluded)", "100904",
       _full_log("100901", contains="diag_command.php"))
add("100901 .status.php web shell (real, TRUE POSITIVE)", "100901",
       _full_log("100901", contains=".status.php"))

# --- 100760: level 7 since 2026-08-01, formerly 13.
add("100760 module load (real, should be level 7)", "100760",
       _full_log("100760"))

for expected, desc, log in cases:
    print(f"{expected}\t{desc}\t{log}")
print(f"{len(cases)} cases", file=sys.stderr)
