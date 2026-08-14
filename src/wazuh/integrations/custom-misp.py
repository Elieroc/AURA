#!/usr/bin/env python3
# Intégration Wazuh -> CTI (MISP)
#
# Cherche, dans chaque alerte, les indicateurs qu'elle transporte (IP, domaine,
# URL, empreinte de fichier) et les confronte au cache d'IOC produit par
# `python -m soc_agent.cti`. En cas de correspondance, réinjecte un événement
# enrichi dans l'analyseur Wazuh, qui matche les règles 100950-100956.
#
# Appelé par wazuh-integratord : custom-misp <alert_file> <api_key> <hook_url>
# (api_key et hook_url ne servent pas : ce script ne parle à personne, il lit un
# fichier local — voir l'en-tête de soc_agent/cti.py pour le pourquoi.)
#
# Le cache est monté en lecture seule sur /var/ossec/integrations/cti/ioc.db.

import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from socket import AF_UNIX, SOCK_DGRAM, socket
from urllib.parse import quote

SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
CACHE = os.environ.get("CTI_CACHE", "/var/ossec/integrations/cti/ioc.db")

# Péremption du cache, et anti-répétition de l'alerte correspondante. Sans le
# second, une CTI périmée produirait une alerte par alerte traitée — le SOC
# noyé par son propre voyant de panne.
EXPIRY_HOURS = int(os.environ.get("CTI_EXPIRY_HOURS", "24"))
EXPIRY_WITNESS = "/var/ossec/tmp/custom-misp-perime"
EXPIRY_REMINDER_S = 3600

# Identifiants de nos propres règles CTI. Une alerte produite par ces règles
# porte les mêmes IOC que celle qui l'a déclenchée : la retraiter relancerait
# le script, qui réinjecterait un événement, qui rematcherait... Boucle
# infinie, et elle serait alimentée par le trafic normal du parc. Le garde-fou
# est en tête de main() et ne doit jamais être contourné.
OUR_RULES = range(100950, 100960)


# Ordre de confiance des sources, du plus sûr au moins sûr. Une même valeur peut
# être portée par plusieurs sources : c'est la MEILLEURE qui décide du niveau de
# l'alerte, donc de ce qui devient un incident.
#   curated   feed d'un CERT ou d'un projet reconnu     -> 100951/100952/100955
#   extracted IOC tiré d'un article par le modèle       -> 100957
#   bulk      liste de réputation de masse              -> 100953
WEIGHT_CONFIDENCE = {"curated": 3, "extracted": 2, "bulk": 1}
ORDER_CONFIDENCE_SQL = (
    "CASE confiance WHEN 'curated' THEN 0 WHEN 'extracted' THEN 1 ELSE 2 END ASC")


def send(event):
    msg = f"1:custom-misp:{json.dumps(event)}"
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(msg.encode())
    sock.close()


# ---------------------------------------------------------------------------
# Normalisation — RÉIMPLÉMENTATION de soc_agent/cti.py::normaliser().
#
# Le manager tourne avec l'interpréteur embarqué de Wazuh et n'a pas le paquet
# soc_agent : le code ne peut pas être partagé. Les deux versions sont donc
# tenues identiques par un test (tests/test_cti.py, qui charge CE fichier par
# son chemin et compare les sorties). Écrire le cache dans une forme et le
# chercher dans une autre ne lève aucune erreur : ça ne matche simplement
# jamais.
# ---------------------------------------------------------------------------

HEX = set("0123456789abcdef")


def normalize(type_cache, value):
    v = (value or "").strip()
    if not v:
        return None

    if type_cache == "ip":
        # Forme canonique et non la valeur brute : une IPv6 s'écrit de
        # plusieurs façons ("2001:0db8::1" / "2001:db8::1"), et les deux côtés
        # doivent tomber sur la même clé.
        v = v.split("|", 1)[0].strip().strip("[]")
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None

    if type_cache == "domain":
        v = v.split("|", 1)[0].strip().lower().rstrip(".")
        return v if "." in v and " " not in v else None

    if type_cache == "url":
        v = v.strip().rstrip("/")
        return v.lower() if v.lower().startswith(("http://", "https://")) else None

    if type_cache == "hash":
        v = v.split("|")[-1].strip().lower()
        return v if len(v) in (32, 40, 64) and all(c in HEX for c in v) else None

    return None


# ---------------------------------------------------------------------------
# Extraction des candidats
# ---------------------------------------------------------------------------

# Champs d'IP, avec la DIRECTION qu'ils impliquent. C'est cette direction qui
# fait la différence entre « une IP malveillante nous a parlé » (bruit de fond
# d'internet) et « une de nos machines a parlé à une IP malveillante » (elle
# est compromise) — d'où deux règles de niveaux différents, 100951 et 100952.
FIELDS_IP = [
    ("data.srcip", "inbound"), ("data.src_ip", "inbound"),
    ("data.dstip", "outbound"), ("data.dest_ip", "outbound"),
    ("data.win.eventdata.destinationIp", "outbound"),
    ("data.win.eventdata.sourceIp", "inbound"),
]

FIELDS_DOMAIN = [
    "data.dns.rrname", "data.dns.question.name", "data.dns_query",
    "data.tls.sni", "data.http.hostname", "data.hostname", "data.query",
    "data.win.eventdata.queryName", "data.win.eventdata.destinationHostname",
]

FIELDS_URL = ["data.url", "data.http.url", "data.win.eventdata.destinationHostname"]

FIELDS_HASH = [
    "syscheck.md5_after", "syscheck.sha1_after", "syscheck.sha256_after",
    "data.virustotal.source.md5", "data.virustotal.source.sha1",
    "data.md5", "data.sha1", "data.sha256",
]

# Sysmon empile ses empreintes dans un seul champ : "SHA1=...,MD5=...,SHA256=..."
FIELD_HASHES_SYSMON = "data.win.eventdata.hashes"
PATTERN_HASH = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")

# Préfixes d'adresses non routables. Une IP privée ne peut pas être un IOC
# public : la chercher, c'est au mieux perdre du temps, au pire matcher une
# machine à nous parce qu'un feed a publié du 192.168.x par erreur (ça arrive).
PRIVATE = ("10.", "127.", "192.168.", "169.254.", "0.", "255.", "::1", "fe80:",
           "fc", "fd") + tuple(f"172.{n}." for n in range(16, 32)) \
    + tuple(f"100.{n}." for n in range(64, 128))


def read(alert, path):
    """Valeur d'un champ en notation pointée, ou None."""
    current = alert
    for chunk in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(chunk)
        if current is None:
            return None
    return current if isinstance(current, (str, int)) else None


def candidates(alert):
    """(type, valeur normalisée, champ d'origine, direction) sans doublon."""
    seen = set()
    output = []

    def add(type_cache, raw, field, direction):
        value = normalize(type_cache, str(raw))
        if not value or (type_cache, value) in seen:
            return
        seen.add((type_cache, value))
        output.append((type_cache, value, field, direction))

    for field, direction in FIELDS_IP:
        raw = read(alert, field)
        if raw and not str(raw).startswith(PRIVATE):
            add("ip", raw, field, direction)

    for field in FIELDS_DOMAIN:
        raw = read(alert, field)
        if raw:
            add("domain", raw, field, "outbound")

    for field in FIELDS_URL:
        raw = read(alert, field)
        if raw:
            add("url", raw, field, "outbound")

    # Suricata et les logs web livrent l'hôte et le chemin séparément : pris
    # isolément, le chemin (`/wp-login.php`) ne vaut rien comme IOC, recollé à
    # son hôte il redevient l'URL publiée par URLhaus.
    host = read(alert, "data.http.hostname")
    path = read(alert, "data.http.url") or read(alert, "data.url")
    if host and path and str(path).startswith("/"):
        add("url", f"http://{host}{path}", "data.http.url", "outbound")
        add("url", f"https://{host}{path}", "data.http.url", "outbound")

    for field in FIELDS_HASH:
        raw = read(alert, field)
        if raw:
            add("hash", raw, field, "artifact")

    fingerprints = read(alert, FIELD_HASHES_SYSMON)
    if fingerprints:
        for found in PATTERN_HASH.findall(str(fingerprints)):
            add("hash", found, FIELD_HASHES_SYSMON, "artifact")

    return output


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def open_cache():
    return sqlite3.connect(f"file:{CACHE}?mode=ro", uri=True)


def cache_age(conn):
    """Âge du cache en heures, ou None si la métadonnée manque."""
    line = conn.execute(
        "SELECT value FROM meta WHERE key = 'synchronise_a'").fetchone()
    if not line or not line[0]:
        return None
    timestamp = datetime.fromisoformat(line[0])
    return (datetime.now(timezone.utc) - timestamp).total_seconds() / 3600


def base_url(conn):
    """URL publique de MISP, posée dans le cache par cti.py.

    Elle vient du cache et non d'une variable d'environnement du manager :
    c'est déjà le seul canal entre la CTI et la détection, y dupliquer la
    configuration MISP ferait deux endroits à tenir à jour — et le jour où ils
    divergent, les liens des alertes pointent en silence vers une instance qui
    n'existe plus.
    """
    try:
        line = conn.execute(
            "SELECT value FROM meta WHERE key = 'base_url'").fetchone()
    except sqlite3.Error:
        return ""
    return (line[0] if line and line[0] else "").rstrip("/")


def links(base, event_id, value):
    """(event_url, search_url) — vides si l'URL publique est inconnue.

    Deux liens et non un seul : un IOC curé a un événement MISP à ouvrir, une
    IP de blocklist n'en a pas (ces listes sont en cache Redis, sans
    événement). Sans le lien de recherche, l'analyste n'aurait aucun point
    d'entrée pour la moitié la plus volumineuse du renseignement.
    """
    if not base:
        return "", ""
    event_url = f"{base}/events/view/{event_id}" if event_id else ""
    return event_url, f"{base}/events/index/searchall:{quote(str(value), safe='')}"


def report_expiry(pattern, alert):
    """Alerte sur une CTI qui ne se met plus à jour — au plus une fois par heure.

    `motif` est en ANGLAIS : il ressort tel quel dans la description de la
    règle 100956, elle-même en anglais comme tout le ruleset.

    Un cache figé ne produit aucune erreur : il continue de répondre, avec des
    IOC de plus en plus faux. C'est exactement le mode de panne « capteur muet »
    qui a coûté deux heures d'aveuglement au SOC le 2026-07-26 (cf. règles
    100800+), et il se traite pareil : par un signal positif.
    """
    try:
        if os.path.exists(EXPIRY_WITNESS) and \
                time.time() - os.path.getmtime(EXPIRY_WITNESS) < EXPIRY_REMINDER_S:
            return
        os.makedirs(os.path.dirname(EXPIRY_WITNESS), exist_ok=True)
        with open(EXPIRY_WITNESS, "w") as f:
            f.write(pattern)
    except OSError:
        pass  # /var/ossec/tmp indisponible : mieux vaut répéter que taire
    send({"integration": "custom-misp",
             "misp": {"error": pattern,
                      "cache": CACHE,
                      "source_alert_rule_id": str(
                          (alert.get("rule") or {}).get("id", ""))}})


# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    try:
        with open(sys.argv[1]) as f:
            alert = json.load(f)
    except (OSError, ValueError):
        sys.exit(1)

    # --- Garde-fou anti-boucle. À garder EN PREMIER : tout ce qui suit
    # réinjecte des événements dans l'analyseur.
    rule = alert.get("rule") or {}
    try:
        if int(rule.get("id", 0)) in OUR_RULES:
            return
    except (TypeError, ValueError):
        pass
    # Événement déjà produit par une intégration (custom-misp, custom-abuseipdb,
    # virustotal) : ses IOC ont déjà été jugés à l'alerte d'origine.
    if read(alert, "data.integration"):
        return

    found = candidates(alert)
    if not found:
        return

    try:
        conn = open_cache()
    except sqlite3.Error:
        report_expiry("indicator cache missing or unreadable", alert)
        return

    try:
        base = base_url(conn)
        age = cache_age(conn)
        if age is None or age > EXPIRY_HOURS:
            report_expiry(
                f"indicator cache stale ({age:.0f} h old)" if age is not None
                else "indicator cache has no synchronisation timestamp", alert)

        best = None
        total = 0
        for type_cache, value, field, direction in found:
            lines = conn.execute(
                "SELECT source, categorie, evenement, event_id, tags, "
                "niveau_menace, confiance FROM ioc WHERE value = ? AND type = ? "
                "ORDER BY " + ORDER_CONFIDENCE_SQL + ", niveau_menace ASC",
                (value, type_cache)).fetchall()
            if not lines:
                continue
            total += len(lines)
            source, category, event, event_id, tags, threat, confidence = lines[0]
            # Ordre de gravité : la confiance de la source d'abord, puis le
            # flux SORTANT sur le flux entrant — c'est la seule des deux
            # directions qui dit « chez nous ».
            rank = (WEIGHT_CONFIDENCE.get(confidence, 0),
                    direction == "outbound", -int(threat or 4))
            if best is None or rank > best[0]:
                # Noms de champs EN ANGLAIS : ils partent dans les alertes, les
                # dashboards et les cases IRIS, aux côtés des champs natifs de
                # Wazuh — même règle que pour les descriptions de règles.
                event_url, search_url = links(base, event_id, value)
                best = (rank, {
                    "ioc": value, "ioc_type": type_cache, "field": field,
                    "direction": direction, "source": source,
                    "category": category or "", "event_info": event or "",
                    "event_id": event_id or "", "event_url": event_url,
                    "search_url": search_url, "tags": tags or "",
                    "threat_level": str(threat or 4), "confidence": confidence,
                })
    finally:
        conn.close()

    if not best:
        return

    misp = best[1]
    misp["match_count"] = str(total)
    misp["source_alert_rule_id"] = str(rule.get("id", ""))
    misp["source_alert_description"] = str(rule.get("description", ""))[:200]
    misp["agent"] = str((alert.get("agent") or {}).get("name", ""))
    misp["agent_id"] = str((alert.get("agent") or {}).get("id", ""))

    event = {"integration": "custom-misp", "misp": misp}
    # srcip à la racine -> data.srcip après décodage, donc géolocalisé par le
    # pipeline d'ingest de l'indexer, comme pour custom-abuseipdb. Uniquement
    # pour un IOC d'IP : mettre là une IP qui n'est pas l'indicateur induirait
    # la carte en erreur.
    if misp["ioc_type"] == "ip":
        event["srcip"] = misp["ioc"]

    send(event)


if __name__ == "__main__":
    main()
