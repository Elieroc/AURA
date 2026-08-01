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


def _full_log(rule: str, contient: str | None = None, agent: str | None = None):
    """Le full_log de l'alerte la plus récente de cette règle, filtré sur un motif."""
    filtre: list[dict] = [{"term": {"rule.id": rule}}]
    if agent:
        filtre.append({"term": {"agent.name": agent}})
    corps = {"size": 200, "sort": [{"timestamp": "desc"}],
             "query": {"bool": {"filter": filtre}}}
    req = urllib.request.Request(
        f"{URL}/wazuh-*/_search", data=json.dumps(corps).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + _auth})
    rep = json.load(urllib.request.urlopen(req, context=_ctx, timeout=30))
    for h in rep["hits"]["hits"]:
        fl = h["_source"].get("full_log") or ""
        if contient and contient not in fl:
            continue
        # wazuh-logtest lit UNE LIGNE = UN LOG (cf. test-detection-rules.sh).
        return fl.replace("\n", " ")
    return None


cas: list[tuple[str, str, str]] = []


def ajoute(desc: str, attendu: str, log: str | None) -> None:
    if log is None:
        print(f"MANQUANT (aucune alerte réelle) : {desc}", file=sys.stderr)
        return
    cas.append((attendu, desc, log))


# --- 100665 / 100653 : le `stat` du SCA, et sa mutation en attaquant.
sca = _full_log("100653", contient='cwd="/var/ossec"')
ajoute("100665 stat du SCA (reel: cwd /var/ossec, auid unset)", "100665", sca)
if sca:
    ajoute("100653 meme stat par un humain (mute: auid+cwd)", "100653",
           sca.replace("auid=4294967295", "auid=1001")
              .replace('cwd="/var/ossec"', 'cwd="/home/eve"'))
    ajoute("100653 stat cwd /var/ossec mais session presente (mute: auid)",
           "100653", sca.replace("auid=4294967295", "auid=1001"))

# --- 100645 : le bug de casse -f / -F. 80700 = fourre-tout auditd bénin.
ajoute("100645 nft -j -f - de pve-firewall (FP: ne doit plus tirer)", "80700",
       _full_log("100645", contient='a2="-f"', agent="home-s-pve01"))
ajoute("100645 nft -f - de notre active response (FP: ne doit plus tirer)",
       "80700", _full_log("100645", contient='cwd="/var/ossec"'))

# --- 100713 / 100711 : s6-overlay, et sa mutation en RCE dans un docroot.
s6 = _full_log("100711", contient='cwd="/config"')
ajoute("100713 s6-overlay LinuxServer (reel: euid 911, cwd /config)", "100713", s6)
if s6:
    ajoute("100711 meme interpreteur mais cwd docroot (mute: cwd)", "100711",
           s6.replace('cwd="/config"', 'cwd="/var/www/html"'))
    ajoute("100711 meme interpreteur avec une session de login (mute: auid)",
           "100711", s6.replace("auid=4294967295", "auid=1001")
                       .replace('cwd="/config"', 'cwd="/tmp"'))

# --- 100714 / 100711 : apt qui descend en _apt.
apt = _full_log("100711", contient="euid=42")
ajoute("100714 apt en _apt (reel: euid 42, auid 0)", "100714", apt)
if apt:
    ajoute("100711 euid 42 SANS session root (mute: auid)", "100711",
           apt.replace("auid=0 ", "auid=4294967295 "))

# --- 100649 / 100643 : debconf, et les vrais positifs web.
ajoute("100649 debconf (reel: perl, comm dpkg-preconfigu)", "100649",
       _full_log("100643", contient="dpkg-preconfigu"))
ajoute("100643 php-fpm lisant /etc/shadow (reel, VRAI POSITIF)", "100643",
       _full_log("100643", contient="php-fpm"))
ajoute("100643 cat depuis un docroot (reel, VRAI POSITIF)", "100643",
       _full_log("100643", contient='comm="cat"'))

# --- 100760 : niveau 7 depuis le 2026-08-01, plus 13.
ajoute("100760 chargement de module (reel, doit etre niv 7)", "100760",
       _full_log("100760"))

for attendu, desc, log in cas:
    print(f"{attendu}\t{desc}\t{log}")
print(f"{len(cas)} cas", file=sys.stderr)
