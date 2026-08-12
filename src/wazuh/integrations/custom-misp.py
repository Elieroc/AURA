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
PEREMPTION_HEURES = int(os.environ.get("CTI_PEREMPTION_HEURES", "24"))
TEMOIN_PEREMPTION = "/var/ossec/tmp/custom-misp-perime"
PEREMPTION_RAPPEL_S = 3600

# Identifiants de nos propres règles CTI. Une alerte produite par ces règles
# porte les mêmes IOC que celle qui l'a déclenchée : la retraiter relancerait
# le script, qui réinjecterait un événement, qui rematcherait... Boucle
# infinie, et elle serait alimentée par le trafic normal du parc. Le garde-fou
# est en tête de main() et ne doit jamais être contourné.
NOS_REGLES = range(100950, 100960)


def envoyer(evenement):
    msg = f"1:custom-misp:{json.dumps(evenement)}"
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

HEXA = set("0123456789abcdef")


def normaliser(type_cache, valeur):
    v = (valeur or "").strip()
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
        return v if len(v) in (32, 40, 64) and all(c in HEXA for c in v) else None

    return None


# ---------------------------------------------------------------------------
# Extraction des candidats
# ---------------------------------------------------------------------------

# Champs d'IP, avec la DIRECTION qu'ils impliquent. C'est cette direction qui
# fait la différence entre « une IP malveillante nous a parlé » (bruit de fond
# d'internet) et « une de nos machines a parlé à une IP malveillante » (elle
# est compromise) — d'où deux règles de niveaux différents, 100951 et 100952.
CHAMPS_IP = [
    ("data.srcip", "inbound"), ("data.src_ip", "inbound"),
    ("data.dstip", "outbound"), ("data.dest_ip", "outbound"),
    ("data.win.eventdata.destinationIp", "outbound"),
    ("data.win.eventdata.sourceIp", "inbound"),
]

CHAMPS_DOMAINE = [
    "data.dns.rrname", "data.dns.question.name", "data.dns_query",
    "data.tls.sni", "data.http.hostname", "data.hostname", "data.query",
    "data.win.eventdata.queryName", "data.win.eventdata.destinationHostname",
]

CHAMPS_URL = ["data.url", "data.http.url", "data.win.eventdata.destinationHostname"]

CHAMPS_HASH = [
    "syscheck.md5_after", "syscheck.sha1_after", "syscheck.sha256_after",
    "data.virustotal.source.md5", "data.virustotal.source.sha1",
    "data.md5", "data.sha1", "data.sha256",
]

# Sysmon empile ses empreintes dans un seul champ : "SHA1=...,MD5=...,SHA256=..."
CHAMP_HASHES_SYSMON = "data.win.eventdata.hashes"
MOTIF_HASH = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")

# Préfixes d'adresses non routables. Une IP privée ne peut pas être un IOC
# public : la chercher, c'est au mieux perdre du temps, au pire matcher une
# machine à nous parce qu'un feed a publié du 192.168.x par erreur (ça arrive).
PRIVEES = ("10.", "127.", "192.168.", "169.254.", "0.", "255.", "::1", "fe80:",
           "fc", "fd") + tuple(f"172.{n}." for n in range(16, 32)) \
    + tuple(f"100.{n}." for n in range(64, 128))


def lire(alerte, chemin):
    """Valeur d'un champ en notation pointée, ou None."""
    courant = alerte
    for morceau in chemin.split("."):
        if not isinstance(courant, dict):
            return None
        courant = courant.get(morceau)
        if courant is None:
            return None
    return courant if isinstance(courant, (str, int)) else None


def candidats(alerte):
    """(type, valeur normalisée, champ d'origine, direction) sans doublon."""
    vus = set()
    sortie = []

    def ajouter(type_cache, brut, champ, direction):
        valeur = normaliser(type_cache, str(brut))
        if not valeur or (type_cache, valeur) in vus:
            return
        vus.add((type_cache, valeur))
        sortie.append((type_cache, valeur, champ, direction))

    for champ, direction in CHAMPS_IP:
        brut = lire(alerte, champ)
        if brut and not str(brut).startswith(PRIVEES):
            ajouter("ip", brut, champ, direction)

    for champ in CHAMPS_DOMAINE:
        brut = lire(alerte, champ)
        if brut:
            ajouter("domain", brut, champ, "outbound")

    for champ in CHAMPS_URL:
        brut = lire(alerte, champ)
        if brut:
            ajouter("url", brut, champ, "outbound")

    # Suricata et les logs web livrent l'hôte et le chemin séparément : pris
    # isolément, le chemin (`/wp-login.php`) ne vaut rien comme IOC, recollé à
    # son hôte il redevient l'URL publiée par URLhaus.
    hote = lire(alerte, "data.http.hostname")
    chemin = lire(alerte, "data.http.url") or lire(alerte, "data.url")
    if hote and chemin and str(chemin).startswith("/"):
        ajouter("url", f"http://{hote}{chemin}", "data.http.url", "outbound")
        ajouter("url", f"https://{hote}{chemin}", "data.http.url", "outbound")

    for champ in CHAMPS_HASH:
        brut = lire(alerte, champ)
        if brut:
            ajouter("hash", brut, champ, "artifact")

    empreintes = lire(alerte, CHAMP_HASHES_SYSMON)
    if empreintes:
        for trouve in MOTIF_HASH.findall(str(empreintes)):
            ajouter("hash", trouve, CHAMP_HASHES_SYSMON, "artifact")

    return sortie


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def ouvrir_cache():
    return sqlite3.connect(f"file:{CACHE}?mode=ro", uri=True)


def age_cache(conn):
    """Âge du cache en heures, ou None si la métadonnée manque."""
    ligne = conn.execute(
        "SELECT valeur FROM meta WHERE cle = 'synchronise_a'").fetchone()
    if not ligne or not ligne[0]:
        return None
    horodatage = datetime.fromisoformat(ligne[0])
    return (datetime.now(timezone.utc) - horodatage).total_seconds() / 3600


def base_url(conn):
    """URL publique de MISP, posée dans le cache par cti.py.

    Elle vient du cache et non d'une variable d'environnement du manager :
    c'est déjà le seul canal entre la CTI et la détection, y dupliquer la
    configuration MISP ferait deux endroits à tenir à jour — et le jour où ils
    divergent, les liens des alertes pointent en silence vers une instance qui
    n'existe plus.
    """
    try:
        ligne = conn.execute(
            "SELECT valeur FROM meta WHERE cle = 'base_url'").fetchone()
    except sqlite3.Error:
        return ""
    return (ligne[0] if ligne and ligne[0] else "").rstrip("/")


def liens(base, event_id, valeur):
    """(event_url, search_url) — vides si l'URL publique est inconnue.

    Deux liens et non un seul : un IOC curé a un événement MISP à ouvrir, une
    IP de blocklist n'en a pas (ces listes sont en cache Redis, sans
    événement). Sans le lien de recherche, l'analyste n'aurait aucun point
    d'entrée pour la moitié la plus volumineuse du renseignement.
    """
    if not base:
        return "", ""
    event_url = f"{base}/events/view/{event_id}" if event_id else ""
    return event_url, f"{base}/events/index/searchall:{quote(str(valeur), safe='')}"


def signaler_peremption(motif, alerte):
    """Alerte sur une CTI qui ne se met plus à jour — au plus une fois par heure.

    `motif` est en ANGLAIS : il ressort tel quel dans la description de la
    règle 100956, elle-même en anglais comme tout le ruleset.

    Un cache figé ne produit aucune erreur : il continue de répondre, avec des
    IOC de plus en plus faux. C'est exactement le mode de panne « capteur muet »
    qui a coûté deux heures d'aveuglement au SOC le 2026-07-26 (cf. règles
    100800+), et il se traite pareil : par un signal positif.
    """
    try:
        if os.path.exists(TEMOIN_PEREMPTION) and \
                time.time() - os.path.getmtime(TEMOIN_PEREMPTION) < PEREMPTION_RAPPEL_S:
            return
        os.makedirs(os.path.dirname(TEMOIN_PEREMPTION), exist_ok=True)
        with open(TEMOIN_PEREMPTION, "w") as f:
            f.write(motif)
    except OSError:
        pass  # /var/ossec/tmp indisponible : mieux vaut répéter que taire
    envoyer({"integration": "custom-misp",
             "misp": {"error": motif,
                      "cache": CACHE,
                      "source_alert_rule_id": str(
                          (alerte.get("rule") or {}).get("id", ""))}})


# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    try:
        with open(sys.argv[1]) as f:
            alerte = json.load(f)
    except (OSError, ValueError):
        sys.exit(1)

    # --- Garde-fou anti-boucle. À garder EN PREMIER : tout ce qui suit
    # réinjecte des événements dans l'analyseur.
    regle = alerte.get("rule") or {}
    try:
        if int(regle.get("id", 0)) in NOS_REGLES:
            return
    except (TypeError, ValueError):
        pass
    # Événement déjà produit par une intégration (custom-misp, custom-abuseipdb,
    # virustotal) : ses IOC ont déjà été jugés à l'alerte d'origine.
    if lire(alerte, "data.integration"):
        return

    trouves = candidats(alerte)
    if not trouves:
        return

    try:
        conn = ouvrir_cache()
    except sqlite3.Error:
        signaler_peremption("indicator cache missing or unreadable", alerte)
        return

    try:
        base = base_url(conn)
        age = age_cache(conn)
        if age is None or age > PEREMPTION_HEURES:
            signaler_peremption(
                f"indicator cache stale ({age:.0f} h old)" if age is not None
                else "indicator cache has no synchronisation timestamp", alerte)

        meilleur = None
        total = 0
        for type_cache, valeur, champ, direction in trouves:
            lignes = conn.execute(
                "SELECT source, categorie, evenement, event_id, tags, "
                "niveau_menace, confiance FROM ioc WHERE valeur = ? AND type = ? "
                "ORDER BY confiance = 'curated' DESC, niveau_menace ASC",
                (valeur, type_cache)).fetchall()
            if not lignes:
                continue
            total += len(lignes)
            source, categorie, evenement, event_id, tags, menace, confiance = lignes[0]
            # Ordre de gravité : le renseignement curé prime sur la réputation
            # de masse, et un flux SORTANT prime sur un flux entrant — c'est
            # la seule des deux directions qui dit « chez nous ».
            rang = (confiance == "curated", direction == "outbound", -int(menace or 4))
            if meilleur is None or rang > meilleur[0]:
                # Noms de champs EN ANGLAIS : ils partent dans les alertes, les
                # dashboards et les cases IRIS, aux côtés des champs natifs de
                # Wazuh — même règle que pour les descriptions de règles.
                event_url, search_url = liens(base, event_id, valeur)
                meilleur = (rang, {
                    "ioc": valeur, "ioc_type": type_cache, "field": champ,
                    "direction": direction, "source": source,
                    "category": categorie or "", "event_info": evenement or "",
                    "event_id": event_id or "", "event_url": event_url,
                    "search_url": search_url, "tags": tags or "",
                    "threat_level": str(menace or 4), "confidence": confiance,
                })
    finally:
        conn.close()

    if not meilleur:
        return

    misp = meilleur[1]
    misp["match_count"] = str(total)
    misp["source_alert_rule_id"] = str(regle.get("id", ""))
    misp["source_alert_description"] = str(regle.get("description", ""))[:200]
    misp["agent"] = str((alerte.get("agent") or {}).get("name", ""))
    misp["agent_id"] = str((alerte.get("agent") or {}).get("id", ""))

    evenement = {"integration": "custom-misp", "misp": misp}
    # srcip à la racine -> data.srcip après décodage, donc géolocalisé par le
    # pipeline d'ingest de l'indexer, comme pour custom-abuseipdb. Uniquement
    # pour un IOC d'IP : mettre là une IP qui n'est pas l'indicateur induirait
    # la carte en erreur.
    if misp["ioc_type"] == "ip":
        evenement["srcip"] = misp["ioc"]

    envoyer(evenement)


if __name__ == "__main__":
    main()
