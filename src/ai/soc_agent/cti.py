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

# Confiance portée par la source, et non par l'IOC. Elle décide du niveau de la
# règle Wazuh, donc de ce qui devient un incident :
#   cure -> renseignement contextualisé (MISP)     -> 100951/100952, niveau 12-14
#   masse -> réputation de volume (blocklists)      -> 100953, niveau 10
CONFIANCE_CUREE = "curated"
CONFIANCE_MASSE = "bulk"


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
    "domain": "domaine",
    "hostname": "domaine",
    "domain|ip": "domaine",
    "url": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "filename|md5": "hash",
    "filename|sha1": "hash",
    "filename|sha256": "hash",
}


def normaliser(type_cache: str, valeur: str) -> str | None:
    """Forme canonique d'un IOC, ou None s'il est inutilisable.

    Volontairement conservatrice : on ne « répare » pas une valeur douteuse,
    on la jette. Un IOC mal normalisé ne fait pas d'erreur, il fait un faux
    négatif permanent.
    """
    v = (valeur or "").strip()
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

    if type_cache == "domaine":
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

def charger_catalogue(chemin: str | None = None) -> dict:
    with open(chemin or config.CTI_CATALOGUE) as f:
        cat = yaml.safe_load(f) or {}
    return {"misp_feeds": cat.get("misp_feeds") or [],
            "blocklists": cat.get("blocklists") or []}


# ---------------------------------------------------------------------------
# API MISP
# ---------------------------------------------------------------------------

def _misp(methode: str, chemin: str, corps: dict | None = None) -> dict | list:
    if not config.MISP_KEY:
        sys.exit("MISP_KEY manquant : la clé d'API MISP est requise (cf. .env.example)")
    reponse = requests.request(
        methode,
        f"{config.MISP_URL.rstrip('/')}{chemin}",
        headers={"Authorization": config.MISP_KEY,
                 "Accept": "application/json",
                 "Content-Type": "application/json"},
        json=corps,
        verify=config.MISP_VERIFY_TLS,
        timeout=TIMEOUT,
    )
    reponse.raise_for_status()
    return reponse.json()


def _corps_feed(feed: dict) -> dict:
    """Payload MISP pour un feed du catalogue.

    `cache_seulement` est le point important : un feed mis en cache est
    interrogeable (corrélation, recherche) mais ne crée PAS d'événements. C'est
    le seul régime tenable pour une blocklist de 100 000 IP tournante — en
    ingestion, elle réécrit la base MISP à chaque passe.
    """
    cache = bool(feed.get("cache_seulement"))
    return {
        "name": feed["nom"],
        "provider": feed.get("fournisseur", feed["nom"]),
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


def bootstrap_feeds(simulation: bool = False, catalogue: dict | None = None) -> dict:
    """Déclare et active dans MISP les feeds du catalogue. Idempotent.

    Rapproché sur l'URL et non sur le nom : c'est l'URL qui identifie un feed,
    et c'est elle qui casse quand un fournisseur déménage. Un feed déjà présent
    est mis à jour, jamais dupliqué — la fonction peut tourner à chaque
    démarrage.
    """
    cat = catalogue or charger_catalogue()
    voulus = list(cat["misp_feeds"]) + [
        # Une blocklist est déclarée à MISP en cache seul : elle reste
        # interrogeable depuis l'UI (« cette IP est-elle connue ? ») sans
        # peser sur MariaDB. La détection, elle, ne passe pas par là : cti.py
        # tire ces listes en direct (cf. blocklists() plus bas).
        {"nom": f"{bl['nom']} (cache)", "url": url,
         "fournisseur": bl.get("fournisseur", bl["nom"]),
         "format": "freetext", "cache_seulement": True}
        for bl in cat["blocklists"] for url in bl["urls"]
    ]

    existants = {f["Feed"]["url"]: f["Feed"] for f in _misp("GET", "/feeds/index")
                 if isinstance(f, dict) and "Feed" in f} if not simulation else {}

    resume = {"crees": [], "mis_a_jour": [], "inchanges": []}
    for feed in voulus:
        corps = _corps_feed(feed)
        deja = existants.get(feed["url"])
        if simulation:
            resume["crees" if not deja else "mis_a_jour"].append(feed["nom"])
            continue
        if not deja:
            _misp("POST", "/feeds/add", {"Feed": corps})
            resume["crees"].append(feed["nom"])
        elif any(str(deja.get(k, "")).lower() != str(v).lower()
                 for k, v in (("enabled", corps["enabled"]),
                              ("caching_enabled", corps["caching_enabled"]))):
            _misp("POST", f"/feeds/edit/{deja['id']}", {"Feed": corps})
            resume["mis_a_jour"].append(feed["nom"])
        else:
            resume["inchanges"].append(feed["nom"])
    return resume


def rafraichir_feeds(simulation: bool = False) -> None:
    """Demande à MISP de tirer ses feeds maintenant, sans attendre son cron.

    Les deux appels sont asynchrones (MISP met des jobs en file) : ils rendent
    la main tout de suite, et le premier `--sync` utile peut donc arriver
    quelques minutes plus tard. C'est normal, pas une panne.
    """
    if simulation:
        return
    _misp("POST", "/feeds/fetchFromFeed/all")
    _misp("POST", "/feeds/cacheFeeds/all")


# ---------------------------------------------------------------------------
# Extraction des IOC
# ---------------------------------------------------------------------------

def attributs_misp(page_taille: int = 5000):
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
        reponse = _misp("POST", "/attributes/restSearch", {
            "returnFormat": "json",
            "type": config.CTI_TYPES_MISP,
            "to_ids": 1,
            "deleted": 0,
            "published": 1,
            "enforceWarninglist": 1,   # écarte ce que MISP sait être bénin
            "includeEventTags": 1,
            "last": config.CTI_FENETRE,
            "limit": page_taille,
            "page": page,
        })
        lot = (reponse or {}).get("response", {}).get("Attribute", [])
        if not lot:
            return
        for attr in lot:
            type_cache = TYPES.get(attr.get("type", ""))
            if not type_cache:
                continue
            valeur = normaliser(type_cache, attr.get("value", ""))
            if not valeur:
                continue
            evenement = attr.get("Event") or {}
            tags = [t.get("name", "") for t in (attr.get("Tag") or [])]
            yield {
                "valeur": valeur,
                "type": type_cache,
                "source": (evenement.get("Orgc") or {}).get("name") or "MISP",
                "categorie": attr.get("category", ""),
                "evenement": (evenement.get("info") or "")[:200],
                "event_id": str(attr.get("event_id") or ""),
                "tags": ",".join(t for t in tags if t)[:300],
                "niveau_menace": int(evenement.get("threat_level_id") or 4),
                "confiance": CONFIANCE_CUREE,
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
    cat = catalogue or charger_catalogue()
    for bl in cat["blocklists"]:
        type_cache = bl.get("type", "ip")
        for url in bl["urls"]:
            try:
                reponse = requests.get(url, timeout=TIMEOUT)
                reponse.raise_for_status()
            except Exception as exc:
                # Un feed indisponible ne doit pas faire échouer les autres :
                # le cache est reconstruit en entier à chaque passe, perdre
                # une source, c'est perdre sa couverture, pas toute la CTI.
                log.warning("blocklist %s injoignable (%s) : %s", bl["nom"], url, exc)
                continue
            compte = 0
            for ligne in reponse.text.splitlines():
                ligne = ligne.strip()
                if not ligne or ligne.startswith(("#", ";", "//")):
                    continue
                valeur = normaliser(type_cache, ligne.split()[0])
                if not valeur:
                    continue
                compte += 1
                if compte > config.CTI_MAX_IOC:
                    raise RuntimeError(
                        f"{bl['nom']} au-delà de CTI_MAX_IOC ({config.CTI_MAX_IOC})")
                yield {
                    "valeur": valeur,
                    "type": type_cache,
                    "source": bl["nom"],
                    "categorie": bl.get("categorie", ""),
                    "evenement": bl.get("commentaire", ""),
                    "event_id": "",
                    "tags": ",".join(bl.get("tags") or [])[:300],
                    # Pas de niveau de menace : une liste de masse ne qualifie
                    # rien. 4 = « indéterminé » dans MISP, et c'est exact.
                    "niveau_menace": 4,
                    "confiance": CONFIANCE_MASSE,
                }
            log.info("blocklist %s : %d IOC (%s)", bl["nom"], compte, url)


# ---------------------------------------------------------------------------
# Cache de lookup
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE ioc (
  valeur        TEXT NOT NULL,
  type          TEXT NOT NULL,
  source        TEXT NOT NULL,
  categorie     TEXT,
  evenement     TEXT,
  event_id      TEXT,
  tags          TEXT,
  niveau_menace INTEGER,
  confiance     TEXT NOT NULL,
  PRIMARY KEY (valeur, type, source)
);
CREATE INDEX idx_ioc_valeur ON ioc(valeur);
CREATE TABLE meta (cle TEXT PRIMARY KEY, valeur TEXT);
"""


def ecrire_cache(iocs, chemin: str | None = None) -> dict:
    """Reconstruit le cache en entier, puis le substitue d'un seul coup.

    Écriture dans un fichier temporaire du MÊME répertoire puis `os.replace` :
    le remplacement est atomique, donc l'intégration Wazuh ne peut jamais lire
    un cache à moitié écrit. Une reconstruction complète (et non un delta) est
    ce qui fait DISPARAÎTRE les IOC retirés des feeds — sans quoi une IP
    réhabilitée continuerait d'alerter indéfiniment.
    """
    chemin = chemin or config.CTI_CACHE
    os.makedirs(os.path.dirname(chemin) or ".", exist_ok=True)
    fd, temporaire = tempfile.mkstemp(dir=os.path.dirname(chemin) or ".",
                                      prefix=".ioc-", suffix=".db")
    os.close(fd)
    os.unlink(temporaire)

    compte = {}
    try:
        conn = sqlite3.connect(temporaire)
        try:
            conn.executescript(SCHEMA)
            lot = []
            for ioc in iocs:
                compte[ioc["confiance"]] = compte.get(ioc["confiance"], 0) + 1
                lot.append((ioc["valeur"], ioc["type"], ioc["source"],
                            ioc.get("categorie", ""), ioc.get("evenement", ""),
                            ioc.get("event_id", ""), ioc.get("tags", ""),
                            ioc.get("niveau_menace", 4), ioc["confiance"]))
                if len(lot) >= 10000:
                    conn.executemany("INSERT OR REPLACE INTO ioc VALUES (?,?,?,?,?,?,?,?,?)", lot)
                    lot = []
            if lot:
                conn.executemany("INSERT OR REPLACE INTO ioc VALUES (?,?,?,?,?,?,?,?,?)", lot)
            conn.execute("INSERT INTO meta VALUES ('synchronise_a', ?)",
                         (datetime.now(timezone.utc).isoformat(),))
            conn.execute("INSERT INTO meta VALUES ('compte', ?)",
                         (json.dumps(compte),))
            conn.commit()
        finally:
            conn.close()
        # Lisible par l'utilisateur wazuh du manager, qui n'est pas le nôtre.
        os.chmod(temporaire, 0o644)
        os.replace(temporaire, chemin)
    except BaseException:
        if os.path.exists(temporaire):
            os.unlink(temporaire)
        raise
    return compte


def interroger(valeur: str, chemin: str | None = None) -> list[dict]:
    """Toutes les correspondances d'une valeur, meilleure source d'abord."""
    chemin = chemin or config.CTI_CACHE
    conn = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        lignes = conn.execute(
            "SELECT * FROM ioc WHERE valeur = ? "
            "ORDER BY confiance = 'curated' DESC, niveau_menace ASC",
            (valeur,)).fetchall()
    finally:
        conn.close()
    return [dict(l) for l in lignes]


def etat(chemin: str | None = None) -> dict:
    chemin = chemin or config.CTI_CACHE
    if not os.path.exists(chemin):
        return {"present": False}
    conn = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True)
    try:
        meta = dict(conn.execute("SELECT cle, valeur FROM meta").fetchall())
        par_type = conn.execute(
            "SELECT type, confiance, COUNT(*) FROM ioc GROUP BY type, confiance"
        ).fetchall()
        par_source = conn.execute(
            "SELECT source, COUNT(*) c FROM ioc GROUP BY source ORDER BY c DESC"
        ).fetchall()
    finally:
        conn.close()
    synchronise_a = meta.get("synchronise_a", "")
    age = None
    if synchronise_a:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(synchronise_a)).total_seconds() / 3600
    return {"present": True, "synchronise_a": synchronise_a,
            "age_heures": age, "perime": age is not None
            and age > config.CTI_PEREMPTION_HEURES,
            "par_type": par_type, "par_source": par_source}


# ---------------------------------------------------------------------------

def synchroniser(simulation: bool = False, catalogue: dict | None = None) -> dict:
    cat = catalogue or charger_catalogue()

    def tout():
        yield from attributs_misp()
        yield from blocklists(cat)

    if simulation:
        compte = {}
        for ioc in tout():
            compte[ioc["confiance"]] = compte.get(ioc["confiance"], 0) + 1
        return compte
    return ecrire_cache(tout())


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

    if args.etat:
        e = etat()
        if not e["present"]:
            sys.exit(f"cache absent : {config.CTI_CACHE} — lancer `python -m soc_agent.cti`")
        print(f"cache        {config.CTI_CACHE}")
        print(f"synchronisé  {e['synchronise_a']} ({e['age_heures']:.1f} h)"
              + ("  ** PÉRIMÉ **" if e["perime"] else ""))
        for type_, confiance, n in e["par_type"]:
            print(f"  {type_:8} {confiance:8} {n:>8}")
        print("sources :")
        for source, n in e["par_source"]:
            print(f"  {source:30} {n:>8}")
        return

    if args.test:
        type_devine = next((t for t in ("ip", "hash", "url", "domaine")
                            if normaliser(t, args.test)), None)
        if not type_devine:
            sys.exit(f"valeur inexploitable : {args.test}")
        resultats = interroger(normaliser(type_devine, args.test))
        print(json.dumps(resultats, indent=2, ensure_ascii=False)
              if resultats else "aucune correspondance")
        return

    if args.feeds:
        resume = bootstrap_feeds(simulation=args.simulation)
        log.info("feeds MISP : %d créés, %d mis à jour, %d inchangés",
                 len(resume["crees"]), len(resume["mis_a_jour"]),
                 len(resume["inchanges"]))
        rafraichir_feeds(simulation=args.simulation)
        return

    compte = synchroniser(simulation=args.simulation)
    log.info("cache d'IOC%s : %s", " (simulation)" if args.simulation else "",
             ", ".join(f"{k}={v}" for k, v in sorted(compte.items())) or "vide")


if __name__ == "__main__":
    main()
