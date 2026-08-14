"""CTI : alimente MISP en feeds, et Wazuh en IOC détectables.

Le volet CTI d'Aura-SOC tient en trois pièces, dont deux vivent ici :

  1. MISP (docker-compose.yml) — la MÉMOIRE : événements, campagnes, tags,
     corrélations, contexte d'investigation. C'est ce qu'on ouvre quand on
     veut comprendre.
  2. `cti.py` — le PONT : il déclare les feeds à MISP (`--feeds`), puis extrait
     périodiquement les IOC exploitables vers un cache SQLite (`--sync`).
  3. `src/wazuh/integrations/custom-misp.py` — la DÉTECTION : à chaque alerte,
     il cherche les IOC de l'alerte dans ce cache et réinjecte un événement
     enrichi dans l'analyseur, qui matche les règles 100950-100956.

Pourquoi un cache plutôt qu'un appel à MISP par alerte — le choix structurant
de ce module. L'intégration Wazuh est appelée par `wazuh-integratord`, en série,
pour chaque alerte retenue. Une requête HTTP vers MISP à cet endroit met la
détection de tout le parc derrière la latence, la disponibilité et la charge
d'un service PHP : MISP indisponible ou lent, et c'est l'ensemble du pipeline
d'alertes qui prend du retard, sans que rien ne le signale. Le cache inverse la
dépendance — la détection lit un fichier local, MISP peut tomber sans rien
casser, et la péremption du cache est elle-même détectée (règle 100956).

Le cache ne contient QUE ce qui sert à décider : la valeur, son type, sa
source, son contexte court. L'investigation, elle, se fait dans MISP.

    python -m soc_agent.cti --feeds        # déclare/active les feeds (idempotent)
    python -m soc_agent.cti                # synchronise le cache d'IOC
    python -m soc_agent.cti --etat         # ce que contient le cache, et son âge
    python -m soc_agent.cti --test IOC     # interroge le cache sur une valeur
    python -m soc_agent.cti --simulation   # compte sans écrire le cache
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

import requests
import urllib3
import yaml

from . import config

log = logging.getLogger("cti")

if not config.MISP_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 120

# Confiance portée par la SOURCE, et non par l'IOC. Elle décide du niveau de la
# règle Wazuh, donc de ce qui devient un incident :
#   cure    -> renseignement contextualisé, publié par un CERT ou un projet
#              reconnu (MISP)                       -> 100951/100952, niveau 12-14
#   extraite-> IOC tiré d'un article public par le modèle (cf. cti_articles.py).
#              La menace est réelle, l'extraction est automatique et le média
#              n'est pas un CERT                    -> 100957, niveau 12
#   masse   -> réputation de volume (blocklists)    -> 100953, niveau 10
CONFIDENCE_CURATED = "curated"
CONFIDENCE_EXTRACTED = "extracted"
CONFIDENCE_BULK = "bulk"

# Tag posé par cti_articles.py sur les événements qu'il crée. C'est lui qui
# porte la distinction de confiance depuis MISP jusqu'à la règle Wazuh : sans
# ce marquage, un IOC deviné dans un article de presse serait indiscernable
# d'un IOC signé CERT-FR, et déclencherait au même niveau.
TAG_EXTRACTION = "aura:source:extracted"

# Marquage de la taxonomie MISP pour un événement produit par un automate, sans
# vérification humaine. Ces événements sont traités comme de la RÉPUTATION DE
# MASSE, pas comme du renseignement curé.
#
# Ce n'est pas un principe, c'est une mesure : le feed OSINT du CIRCL relaie les
# publications quotidiennes de Maltrail (agrégation de blacklists), soit 255 361
# des 692 543 IOC « curés » du cache le 2026-08-12 — 37 %, tous avec to_ids=1.
# Les laisser en `curated` les faisait matcher aux niveaux 12 à 14, donc ouvrir
# un incident et payer un triage LLM sur ce qui est, par construction, la même
# chose qu'une blocklist. La taxonomie MISP l'annonce elle-même ; il suffisait
# de la lire.
TAG_NON_SUPERVISED = 'misp:automation-level="unsupervised"'


# ---------------------------------------------------------------------------
# Normalisation
#
# ATTENTION : ces règles sont RÉIMPLÉMENTÉES à l'identique dans
# src/wazuh/integrations/custom-misp.py. Le manager tourne avec l'interpréteur
# embarqué de Wazuh et n'a pas le paquet soc_agent : impossible de partager le
# code. La symétrie est donc vérifiée par un test
# (tests/test_cti.py::test_normalisation_identique_cote_wazuh), qui charge le
# script d'intégration par son chemin et compare les deux fonctions. Toute
# modification ici doit être reportée là-bas, sinon le cache est écrit dans une
# forme que la détection ne cherche jamais — et rien ne matche, en silence.
# ---------------------------------------------------------------------------

# Types MISP -> type de cache. Plusieurs types MISP retombent sur le même :
# une alerte Wazuh ne sait pas si l'IP qu'elle porte a été publiée comme
# source ou comme destination.
TYPES = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "filename|md5": "hash",
    "filename|sha1": "hash",
    "filename|sha256": "hash",
}


def normalize(type_cache: str, value: str) -> str | None:
    """Forme canonique d'un IOC, ou None s'il est inutilisable.

    Volontairement conservatrice : on ne « répare » pas une valeur douteuse,
    on la jette. Un IOC mal normalisé ne fait pas d'erreur, il fait un faux
    négatif permanent.
    """
    v = (value or "").strip()
    if not v:
        return None

    if type_cache == "ip":
        # Le port est parfois collé à la valeur (types `ip-dst|port`), et une
        # partie des feeds livre l'IP entre crochets pour la « défanger ».
        v = v.split("|", 1)[0].strip().strip("[]")
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None

    if type_cache == "domain":
        v = v.split("|", 1)[0].strip().lower().rstrip(".")
        # Un domaine sans point n'en est pas un : c'est un nom de machine
        # interne, et il matcherait le hostname de nos propres agents.
        return v if "." in v and " " not in v else None

    if type_cache == "url":
        v = v.strip().rstrip("/")
        # Sans schéma, on ne compare pas la même chose des deux côtés : les
        # alertes web de Wazuh portent souvent un simple chemin (`/wp-login`),
        # qui matcherait n'importe quel IOC de même chemin, tous domaines
        # confondus.
        return v.lower() if v.lower().startswith(("http://", "https://")) else None

    if type_cache == "hash":
        v = v.split("|")[-1].strip().lower()
        return v if len(v) in (32, 40, 64) and all(
            c in "0123456789abcdef" for c in v) else None

    return None


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

def load_catalog(path: str | None = None) -> dict:
    with open(path or config.CTI_CATALOG) as f:
        cat = yaml.safe_load(f) or {}
    return {"misp_feeds": cat.get("misp_feeds") or [],
            "blocklists": cat.get("blocklists") or [],
            # Sources d'articles, exploitées par cti_articles.py. Elles ne sont
            # PAS des feeds MISP : rien à déclarer côté MISP, c'est nous qui y
            # écrivons les événements après extraction.
            "articles": cat.get("articles") or []}


# ---------------------------------------------------------------------------
# API MISP
# ---------------------------------------------------------------------------

def _misp(method: str, path: str, body: dict | None = None) -> dict | list:
    if not config.MISP_KEY:
        sys.exit("MISP_KEY manquant : la clé d'API MISP est requise (cf. .env.example)")
    response = requests.request(
        method,
        f"{config.MISP_URL.rstrip('/')}{path}",
        headers={"Authorization": config.MISP_KEY,
                 "Accept": "application/json",
                 "Content-Type": "application/json"},
        json=body,
        verify=config.MISP_VERIFY_TLS,
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _feed_body(feed: dict) -> dict:
    """Payload MISP pour un feed du catalogue.

    `cache_seulement` est le point important : un feed mis en cache est
    interrogeable (corrélation, recherche) mais ne crée PAS d'événements. C'est
    le seul régime tenable pour une blocklist de 100 000 IP tournante — en
    ingestion, elle réécrit la base MISP à chaque passe.
    """
    cache = bool(feed.get("cache_seulement"))
    return {
        "name": feed["name"],
        "provider": feed.get("fournisseur", feed["name"]),
        "url": feed["url"],
        "source_format": feed.get("format", "misp"),
        "input_source": "network",
        "enabled": not cache,
        "caching_enabled": True,
        "distribution": "0",          # organisation seule : ce lab ne pousse rien
        "fixed_event": cache,
        "delta_merge": cache,
        "publish": False,
        "override_ids": False,
        "tag_id": "0",
    }


def _url_key(url: str) -> str:
    """Forme de comparaison d'une URL de feed.

    Le slash final est ignoré : MISP livre d'origine le feed CIRCL sous
    `.../feed-osint` et le catalogue l'écrit `.../feed-osint/`. Sans cette
    normalisation, le bootstrap ne reconnaît pas le feed préinstallé et en crée
    un second — mesuré en prod le 2026-08-12, deux entrées pour CIRCL et deux
    pour Botvrij. Les deux exemplaires activés, MISP tire le même feed deux
    fois et double les événements.
    """
    return (url or "").strip().rstrip("/").lower()


def bootstrap_feeds(simulation: bool = False, catalogue: dict | None = None) -> dict:
    """Déclare et active dans MISP les feeds du catalogue. Idempotent.

    Rapproché sur l'URL et non sur le nom : c'est l'URL qui identifie un feed,
    et c'est elle qui casse quand un fournisseur déménage. Un feed déjà présent
    — y compris ceux livrés d'origine par MISP — est mis à jour, jamais
    dupliqué : la fonction peut tourner à chaque démarrage.
    """
    cat = catalogue or load_catalog()
    wanted = list(cat["misp_feeds"]) + [
        # Une blocklist est déclarée à MISP en cache seul : elle reste
        # interrogeable depuis l'UI (« cette IP est-elle connue ? ») sans
        # peser sur MariaDB. La détection, elle, ne passe pas par là : cti.py
        # tire ces listes en direct (cf. blocklists() plus bas).
        {"name": f"{bl['name']} (cache)", "url": url,
         "fournisseur": bl.get("fournisseur", bl["name"]),
         "format": "freetext", "cache_seulement": True}
        for bl in cat["blocklists"] for url in bl["urls"]
    ]

    existing = {_url_key(f["Feed"]["url"]): f["Feed"]
                 for f in _misp("GET", "/feeds/index")
                 if isinstance(f, dict) and "Feed" in f} if not simulation else {}

    resume = {"crees": [], "mis_a_jour": [], "inchanges": []}
    for feed in wanted:
        body = _feed_body(feed)
        already = existing.get(_url_key(feed["url"]))
        if simulation:
            resume["crees" if not already else "mis_a_jour"].append(feed["name"])
            continue
        if not already:
            _misp("POST", "/feeds/add", {"Feed": body})
            resume["crees"].append(feed["name"])
        elif any(str(already.get(k, "")).lower() != str(v).lower()
                 for k, v in (("enabled", body["enabled"]),
                              ("caching_enabled", body["caching_enabled"]))):
            _misp("POST", f"/feeds/edit/{already['id']}", {"Feed": body})
            resume["mis_a_jour"].append(feed["name"])
        else:
            resume["inchanges"].append(feed["name"])
    return resume


def refresh_feeds(simulation: bool = False) -> None:
    """Demande à MISP de tirer ses feeds maintenant, sans attendre son cron.

    Les deux appels sont asynchrones (MISP met des jobs en file) : ils rendent
    la main tout de suite, et le premier `--sync` utile peut donc arriver
    quelques minutes plus tard. C'est normal, pas une panne.

    `fetchFromAllFeeds` et non `fetchFromFeed/all` : le second attend un
    identifiant numérique et répond 404 sur « all » (mesuré en prod le
    2026-08-12). Seul `cacheFeeds` accepte une portée nommée.
    """
    if simulation:
        return
    _misp("POST", "/feeds/fetchFromAllFeeds")
    _misp("POST", "/feeds/cacheFeeds/all")


# ---------------------------------------------------------------------------
# Extraction des IOC
# ---------------------------------------------------------------------------

def _confidence(tags: list[str]) -> str:
    """Confiance d'un attribut MISP, d'après les tags de son événement.

    L'ordre des deux tests compte : un événement produit par NOTRE extraction
    porte les deux marquages possibles dans certains cas, et c'est le plus
    prudent qui doit gagner. Un automate non supervisé (Maltrail et assimilés,
    relayés par les feeds OSINT) est de la réputation de masse, quelle que soit
    l'organisation qui le publie.
    """
    if TAG_NON_SUPERVISED in tags:
        return CONFIDENCE_BULK
    if TAG_EXTRACTION in tags:
        return CONFIDENCE_EXTRACTED
    return CONFIDENCE_CURATED


def _ip_expired(type_cache: str, event: dict) -> bool:
    """Une IP dont l'événement d'origine est trop vieux ne vaut plus rien.

    `CTI_FENETRE` ne filtre PAS l'âge du renseignement : le paramètre `last` de
    MISP porte sur la date de dernière MODIFICATION de l'attribut, et tout ce
    qu'un feed vient d'importer est modifié aujourd'hui. Mesuré au premier
    import en prod le 2026-08-12 : des IP publiées comme C2 en 2015 (rapport
    Rocket Kitten) se retrouvaient dans le cache, prêtes à déclencher une
    alerte de niveau 12 à 14.

    Une adresse IP est le seul type d'IOC qui change de main : une IP de C2 de
    2015 est aujourd'hui, au mieux, un hébergeur mutualisé, au pire le CDN de
    quelqu'un. Un HASH, lui, ne périme jamais — le fichier est le même — et un
    domaine reste rattaché à qui l'a déposé. D'où une péremption qui ne vise
    que les IP, sur la date de l'ÉVÉNEMENT et non celle de l'attribut.
    """
    if type_cache != "ip" or not config.CTI_IP_MAX_DAYS:
        return False
    date = (event or {}).get("date") or ""
    if not date:
        return False   # sans date, on ne jette pas : on ne sait pas
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(date).replace(tzinfo=timezone.utc)).days
    except ValueError:
        return False
    return age > config.CTI_IP_MAX_DAYS


def misp_attributes(page_size: int = 5000):
    """IOC curés de MISP : attributs `to_ids`, publiés, dans la fenêtre.

    `to_ids=1` est le filtre décisif. MISP contient beaucoup d'attributs de
    CONTEXTE (l'IP d'un sinkhole, le domaine d'un rapport, une adresse de
    scanner citée en exemple) qui ne sont pas destinés à la détection ; leurs
    auteurs le disent précisément avec ce drapeau. Les ignorer, c'est
    fabriquer des faux positifs signés « CERT-FR », c'est-à-dire les plus
    coûteux à réfuter.
    """
    page = 1
    total = 0
    while True:
        response = _misp("POST", "/attributes/restSearch", {
            "returnFormat": "json",
            "type": config.CTI_TYPES_MISP,
            "to_ids": 1,
            "deleted": 0,
            "published": 1,
            "enforceWarninglist": 1,   # écarte ce que MISP sait être bénin
            "includeEventTags": 1,
            "last": config.CTI_WINDOW,
            "limit": page_size,
            "page": page,
        })
        batch = (response or {}).get("response", {}).get("Attribute", [])
        if not batch:
            return
        for attr in batch:
            type_cache = TYPES.get(attr.get("type", ""))
            if not type_cache:
                continue
            value = normalize(type_cache, attr.get("value", ""))
            if not value:
                continue
            event = attr.get("Event") or {}
            if _ip_expired(type_cache, event):
                continue
            tags = [t.get("name", "") for t in (attr.get("Tag") or [])]
            yield {
                "value": value,
                "type": type_cache,
                "source": (event.get("Orgc") or {}).get("name") or "MISP",
                "categorie": attr.get("category", ""),
                "evenement": (event.get("info") or "")[:200],
                "event_id": str(attr.get("event_id") or ""),
                "tags": ",".join(t for t in tags if t)[:300],
                "niveau_menace": int(event.get("threat_level_id") or 4),
                # Tout remonte par le même chemin — c'est voulu, MISP est la
                # seule mémoire — mais tout ne vaut pas la même chose, et les
                # tags sont le seul endroit où la différence survit.
                "confiance": _confidence(tags),
            }
            total += 1
            if total > config.CTI_MAX_IOC:
                raise RuntimeError(
                    f"extraction MISP au-delà de CTI_MAX_IOC ({config.CTI_MAX_IOC})")
        page += 1


def blocklists(catalogue: dict | None = None):
    """IOC de masse, tirés directement chez le fournisseur.

    Court-circuiter MISP est délibéré (cf. cti_feeds.yaml) : ces listes n'ont
    pas de contexte à corréler, et leur volume rendrait la base MISP
    inutilisable pour ce qu'elle sait faire de mieux.
    """
    cat = catalogue or load_catalog()
    for bl in cat["blocklists"]:
        type_cache = bl.get("type", "ip")
        for url in bl["urls"]:
            try:
                response = requests.get(url, timeout=TIMEOUT)
                response.raise_for_status()
            except Exception as exc:
                # Un feed indisponible ne doit pas faire échouer les autres :
                # le cache est reconstruit en entier à chaque passe, perdre
                # une source, c'est perdre sa couverture, pas toute la CTI.
                log.warning("blocklist %s injoignable (%s) : %s", bl["name"], url, exc)
                continue
            account = 0
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", ";", "//")):
                    continue
                value = normalize(type_cache, line.split()[0])
                if not value:
                    continue
                account += 1
                if account > config.CTI_MAX_IOC:
                    raise RuntimeError(
                        f"{bl['name']} au-delà de CTI_MAX_IOC ({config.CTI_MAX_IOC})")
                yield {
                    "value": value,
                    "type": type_cache,
                    "source": bl["name"],
                    "categorie": bl.get("categorie", ""),
                    "evenement": bl.get("comment", ""),
                    "event_id": "",
                    "tags": ",".join(bl.get("tags") or [])[:300],
                    # Pas de niveau de menace : une liste de masse ne qualifie
                    # rien. 4 = « indéterminé » dans MISP, et c'est exact.
                    "niveau_menace": 4,
                    "confiance": CONFIDENCE_BULK,
                }
            log.info("blocklist %s : %d IOC (%s)", bl["name"], account, url)


# ---------------------------------------------------------------------------
# Cache de lookup
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE ioc (
  value        TEXT NOT NULL,
  type          TEXT NOT NULL,
  source        TEXT NOT NULL,
  categorie     TEXT,
  evenement     TEXT,
  event_id      TEXT,
  tags          TEXT,
  niveau_menace INTEGER,
  confiance     TEXT NOT NULL,
  PRIMARY KEY (value, type, source)
);
CREATE INDEX idx_ioc_valeur ON ioc(value);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"""


def write_cache(iocs, path: str | None = None) -> dict:
    """Reconstruit le cache en entier, puis le substitue d'un seul coup.

    Écriture dans un fichier temporaire du MÊME répertoire puis `os.replace` :
    le remplacement est atomique, donc l'intégration Wazuh ne peut jamais lire
    un cache à moitié écrit. Une reconstruction complète (et non un delta) est
    ce qui fait DISPARAÎTRE les IOC retirés des feeds — sans quoi une IP
    réhabilitée continuerait d'alerter indéfiniment.
    """
    path = path or config.CTI_CACHE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                                      prefix=".ioc-", suffix=".db")
    os.close(fd)
    os.unlink(temporary)

    account = {}
    try:
        conn = sqlite3.connect(temporary)
        try:
            conn.executescript(SCHEMA)
            batch = []
            for ioc in iocs:
                account[ioc["confiance"]] = account.get(ioc["confiance"], 0) + 1
                batch.append((ioc["value"], ioc["type"], ioc["source"],
                            ioc.get("categorie", ""), ioc.get("evenement", ""),
                            ioc.get("event_id", ""), ioc.get("tags", ""),
                            ioc.get("niveau_menace", 4), ioc["confiance"]))
                if len(batch) >= 10000:
                    conn.executemany("INSERT OR REPLACE INTO ioc VALUES (?,?,?,?,?,?,?,?,?)", batch)
                    batch = []
            if batch:
                conn.executemany("INSERT OR REPLACE INTO ioc VALUES (?,?,?,?,?,?,?,?,?)", batch)
            conn.execute("INSERT INTO meta VALUES ('synchronise_a', ?)",
                         (datetime.now(timezone.utc).isoformat(),))
            conn.execute("INSERT INTO meta VALUES ('compte', ?)",
                         (json.dumps(account),))
            # URL publique embarquée dans le cache : c'est elle qui rend les
            # liens des alertes cliquables depuis un poste d'analyste. La poser
            # ici évite de redéclarer la configuration MISP côté manager — le
            # cache est déjà le seul canal entre les deux.
            conn.execute("INSERT INTO meta VALUES ('base_url', ?)",
                         (config.MISP_BASE_URL.rstrip("/"),))
            conn.commit()
        finally:
            conn.close()
        # Lisible par l'utilisateur wazuh du manager, qui n'est pas le nôtre.
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return account


def query(value: str, path: str | None = None) -> list[dict]:
    """Toutes les correspondances d'une valeur, meilleure source d'abord."""
    path = path or config.CTI_CACHE
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        lines = conn.execute(
            "SELECT * FROM ioc WHERE value = ? ORDER BY "
            "CASE confiance WHEN 'curated' THEN 0 WHEN 'extracted' THEN 1 "
            "ELSE 2 END ASC, niveau_menace ASC",
            (value,)).fetchall()
    finally:
        conn.close()
    return [dict(l) for l in lines]


def state(path: str | None = None) -> dict:
    path = path or config.CTI_CACHE
    if not os.path.exists(path):
        return {"present": False}
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
        by_type = conn.execute(
            "SELECT type, confiance, COUNT(*) FROM ioc GROUP BY type, confiance"
        ).fetchall()
        by_source = conn.execute(
            "SELECT source, COUNT(*) c FROM ioc GROUP BY source ORDER BY c DESC"
        ).fetchall()
    finally:
        conn.close()
    synced_at = meta.get("synchronise_a", "")
    age = None
    if synced_at:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(synced_at)).total_seconds() / 3600
    return {"present": True, "synchronise_a": synced_at,
            "age_heures": age, "perime": age is not None
            and age > config.CTI_EXPIRY_HOURS,
            "par_type": by_type, "par_source": by_source}


# ---------------------------------------------------------------------------

def sync(simulation: bool = False, catalogue: dict | None = None) -> dict:
    cat = catalogue or load_catalog()

    def tout():
        yield from misp_attributes()
        yield from blocklists(cat)

    if simulation:
        account = {}
        for ioc in tout():
            account[ioc["confiance"]] = account.get(ioc["confiance"], 0) + 1
        return account
    return write_cache(tout())


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parseur = argparse.ArgumentParser(description=__doc__)
    parseur.add_argument("--feeds", action="store_true",
                         help="déclare/active les feeds dans MISP, puis les rafraîchit")
    parseur.add_argument("--etat", action="store_true",
                         help="contenu et fraîcheur du cache d'IOC")
    parseur.add_argument("--test", metavar="IOC",
                         help="interroge le cache sur une valeur")
    parseur.add_argument("--simulation", action="store_true",
                         help="compte les IOC sans écrire le cache")
    args = parseur.parse_args()

    if args.state:
        e = state()
        if not e["present"]:
            sys.exit(f"cache absent : {config.CTI_CACHE} — lancer `python -m soc_agent.cti`")
        print(f"cache        {config.CTI_CACHE}")
        print(f"synchronisé  {e['synchronise_a']} ({e['age_heures']:.1f} h)"
              + ("  ** PÉRIMÉ **" if e["perime"] else ""))
        for type_, confidence, n in e["par_type"]:
            print(f"  {type_:8} {confidence:8} {n:>8}")
        print("sources :")
        for source, n in e["par_source"]:
            print(f"  {source:30} {n:>8}")
        return

    if args.test:
        guessed_type = next((t for t in ("ip", "hash", "url", "domain")
                            if normalize(t, args.test)), None)
        if not guessed_type:
            sys.exit(f"valeur inexploitable : {args.test}")
        results = query(normalize(guessed_type, args.test))
        print(json.dumps(results, indent=2, ensure_ascii=False)
              if results else "aucune correspondance")
        return

    if args.feeds:
        resume = bootstrap_feeds(simulation=args.simulation)
        log.info("feeds MISP : %d créés, %d mis à jour, %d inchangés",
                 len(resume["crees"]), len(resume["mis_a_jour"]),
                 len(resume["inchanges"]))
        refresh_feeds(simulation=args.simulation)
        return

    account = sync(simulation=args.simulation)
    log.info("cache d'IOC%s : %s", " (simulation)" if args.simulation else "",
             ", ".join(f"{k}={v}" for k, v in sorted(account.items())) or "vide")


if __name__ == "__main__":
    main()
