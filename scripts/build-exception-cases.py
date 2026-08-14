#!/usr/bin/env python3
"""Construit le jeu de cas de test des EXCLUSIONS, à partir des vraies alertes.

Pourquoi pas de logs de synthèse (contrairement à test-detection-rules.sh) : le
décodeur auditd de Wazuh n'accepte pas n'importe quel ordre de champs. Une ligne
SYSCALL écrite à la main perd `euid`, `auid` et `cwd` au décodage — vérifié en
phase 2 de wazuh-logtest. Or ce sont exactement les champs sur lesquels reposent
les exclusions 100665/100713/100714/100649. Testées avec des logs de synthèse,
elles paraissent toutes cassées alors qu'elles fonctionnent (et inversement).

On tire donc un full_log RÉEL par scénario depuis l'indexer, et on le MUTE pour
fabriquer le contre-exemple : le même événement, mais avec la signature d'un
attaquant (session de login présente, cwd dans un docroot). Un couple
FP-exclu / TP-toujours-détecté par exclusion.

Sortie : un TSV `attendu \t description \t log`, à rejouer avec
scripts/test-rule-exceptions.sh sur l'hôte du manager.

Usage :
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
    """Le full_log de l'alerte la plus récente de cette règle, filtré sur un motif."""
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
        # wazuh-logtest lit UNE LIGNE = UN LOG (cf. test-detection-rules.sh).
        return fl.replace("\n", " ")
    return None


cases: list[tuple[str, str, str]] = []


def add(desc: str, expected: str, log: str | None) -> None:
    if log is None:
        print(f"MANQUANT (aucune alerte réelle) : {desc}", file=sys.stderr)
        return
    cases.append((expected, desc, log))


# --- 100665 / 100653 : le `stat` du SCA, et sa mutation en attaquant.
sca = _full_log("100653", contains='cwd="/var/ossec"')
add("100665 stat du SCA (reel: cwd /var/ossec, auid unset)", "100665", sca)
if sca:
    add("100653 meme stat par un humain (mute: auid+cwd)", "100653",
           sca.replace("auid=4294967295", "auid=1001")
              .replace('cwd="/var/ossec"', 'cwd="/home/eve"'))
    add("100653 stat cwd /var/ossec mais session presente (mute: auid)",
           "100653", sca.replace("auid=4294967295", "auid=1001"))

# --- 100645 : le bug de casse -f / -F. 80700 = fourre-tout auditd bénin.
add("100645 nft -j -f - d'un service de pare-feu (FP: ne doit plus tirer)", "80700",
       _full_log("100645", contains='a2="-f"', agent="host-pve"))
add("100645 nft -f - de notre active response (FP: ne doit plus tirer)",
       "80700", _full_log("100645", contains='cwd="/var/ossec"'))

# --- 100713 / 100711 : s6-overlay, et sa mutation en RCE dans un docroot.
s6 = _full_log("100711", contains='cwd="/config"')
add("100713 s6-overlay LinuxServer (reel: euid 911, cwd /config)", "100713", s6)
if s6:
    add("100711 meme interpreteur mais cwd docroot (mute: cwd)", "100711",
           s6.replace('cwd="/config"', 'cwd="/var/www/html"'))
    add("100711 meme interpreteur avec une session de login (mute: auid)",
           "100711", s6.replace("auid=4294967295", "auid=1001")
                       .replace('cwd="/config"', 'cwd="/tmp"'))

# --- 100714 / 100711 : apt qui descend en _apt.
apt = _full_log("100711", contains="euid=42")
add("100714 apt en _apt (reel: euid 42, auid 0)", "100714", apt)
if apt:
    add("100711 euid 42 SANS session root (mute: auid)", "100711",
           apt.replace("auid=0 ", "auid=4294967295 "))

# --- 100649 / 100643 : debconf, et les vrais positifs web.
add("100649 debconf (reel: perl, comm dpkg-preconfigu)", "100649",
       _full_log("100643", contains="dpkg-preconfigu"))
add("100643 php-fpm lisant /etc/shadow (reel, VRAI POSITIF)", "100643",
       _full_log("100643", contains="php-fpm"))
add("100643 cat depuis un docroot (reel, VRAI POSITIF)", "100643",
       _full_log("100643", contains='comm="cat"'))

# --- 100636 / 100634 : le snippet gpg-agent, et sa mutation en vrai implant
# tmpfs (le chemin sort alors d'une affectation CLE=valeur).
gpg = _full_log("100634", contains="gnupg/S.gpg-agent.ssh")
add("100636 snippet gpg-agent (reel: chemin tmpfs = valeur d'env)", "100636", gpg)
if gpg:
    add("100634 script depuis /dev/shm (mute: vrai chemin d'implant)", "100634",
           gpg.replace("SSH_AUTH_SOCK=/run/user/0/gnupg/S.gpg-agent.ssh",
                       "/dev/shm/payload.sh"))

# --- 100904 / 100901 : YARA. La page de diag pfSense est exclue, le web shell
# du 2026-07-29 (supprimé depuis, mais l'alerte reste indexée) doit tirer.
add("100904 diag_command.php pfSense (reel, doit etre exclu)", "100904",
       _full_log("100901", contains="diag_command.php"))
add("100901 web shell .status.php (reel, VRAI POSITIF)", "100901",
       _full_log("100901", contains=".status.php"))

# --- 100760 : niveau 7 depuis le 2026-08-01, plus 13.
add("100760 chargement de module (reel, doit etre niv 7)", "100760",
       _full_log("100760"))

for expected, desc, log in cases:
    print(f"{expected}\t{desc}\t{log}")
print(f"{len(cases)} cas", file=sys.stderr)
