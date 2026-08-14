"""CTI : extraire les IOC des articles publics de sécurité, vers MISP.

Les feeds MISP (cf. cti.py) livrent du renseignement DÉJÀ structuré. L'essentiel
de ce qui se publie ne l'est pas : un rapport de BleepingComputer, un article de
The Hacker News ou un billet RST Cloud décrit l'infrastructure d'une campagne
en prose, avec les indicateurs au milieu du texte, parfois « défangés »
(hxxp://evil[.]com), parfois dans un tableau, parfois dans une annexe. Aucun
format commun, aucune API.

Ce module comble cet écart en trois étages, et le découpage est le point
important :

  1. RÉCUPÉRATION (déterministe) — RSS ou annuaire, puis texte de l'article.
  2. CANDIDATS (déterministe) — défanging + expressions régulières. Trouve tout
     ce qui RESSEMBLE à un IOC, sans chercher à juger.
  3. ARBITRAGE (LLM) — décide lesquels sont des indicateurs de la menace, et
     leur rôle.

Pourquoi le LLM au troisième étage, et pas une regex de plus. Un article de
presse cite en permanence des domaines parfaitement légitimes : le média
lui-même, ses sources, l'éditeur qui a publié le rapport, les plateformes
citées, la victime, les outils détournés. Une extraction purement régulière
produit donc surtout des faux indicateurs — et un faux IOC vaut ici plus cher
qu'un IOC manqué : il fait alerter au niveau 12 sur du trafic normal, et
s'il finit en remédiation autonome, il coupe une machine saine. Seule la lecture
du CONTEXTE permet de trancher « evil-c2[.]com » de « microsoft.com cité comme
victime », et c'est précisément ce que le modèle sait faire.

Mais le LLM n'est PAS une frontière de sécurité (cf. README) : sa sortie est
donc revérifiée par du code, dans cet ordre —

  - présence LITTÉRALE de chaque valeur dans les candidats (anti-hallucination :
    un indicateur inventé est rejeté, pas discuté) ;
  - exclusions dures : IP privées, infrastructure du SOC, nos réseaux, domaines
    des médias sources eux-mêmes ;
  - warninglists de MISP (`/warninglists/checkValue`), qui connaissent les
    domaines et IP à ne jamais traiter comme IOC ;
  - plafond d'indicateurs par article.

Les IOC retenus deviennent un ÉVÉNEMENT MISP, pas une entrée directe dans le
cache de détection : c'est ce qui leur donne une existence consultable (lien
vers l'article, famille de malware, corrélation avec le reste du
renseignement), et ce qui fait que `cti.py` les récupère ensuite par le même
chemin que tous les autres feeds. Ils sont tagués `aura:source:extracted`, ce
qui les fait matcher la règle 100957 (niveau 12) et non 100951/100952
(niveau 12-14) : une extraction automatique d'article de presse ne vaut pas un
IOC publié par le CERT-FR, et le ruleset doit le dire.

    python -m soc_agent.cti_articles                  # une passe sur toutes les sources
    python -m soc_agent.cti_articles --amorcage       # marque l'existant comme vu, sans traiter
    python -m soc_agent.cti_articles --source thehackernews --max 3
    python -m soc_agent.cti_articles --simulation     # extrait et affiche, n'écrit ni MISP ni base
    python -m soc_agent.cti_articles --url https://...  # un article précis, à la demande
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import psycopg
import requests
import urllib3

from . import config, cti, llm

log = logging.getLogger("cti_articles")

if not config.MISP_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROMPTS = Path(__file__).parent / "prompts"
TIMEOUT = 60

# Confiance et tag vivent dans cti.py, avec les deux autres niveaux : c'est
# cti.py qui relit ce tag pour classer l'IOC, les deux doivent donc bouger
# ensemble ou pas du tout.
TAG_SOURCE = cti.TAG_EXTRACTION

# Plafond d'IOC publiés pour UN article, surchargeable par source
# (`max_iocs` dans le catalogue). Au-delà, on ne publie rien et on le dit :
# soit l'article est un dump de blocklist, soit l'extraction est partie de
# travers, et un événement de plusieurs milliers d'attributs pollue MISP
# durablement.
#
# 300 et non 60 : mesuré sur un « RST TI Report Digest », un seul billet porte
# 400 candidats dont la majorité sont de vrais indicateurs — c'est le format
# même de la source. Un plafond serré rejetait donc l'article le plus riche des
# quatre sources, ce qui est le contraire du but.
MAX_IOC_ARTICLE = 300

# Candidats soumis au modèle par appel, et budget de sortie.
#
# Un digest en produit plusieurs centaines. Les envoyer d'un bloc épuise le
# budget et l'appel échoue sur `finish_reason=length` SANS RIEN RENDRE : le
# modèle est raisonnant, son raisonnement est décompté du même budget que la
# réponse (piège documenté dans llm.py). Mesuré sur un digest RST Cloud de 403
# candidats : 60 candidats / 3 000 tokens échoue, 40 / 4 000 échoue aussi.
#
# Le surcoût du découpage est faible parce que le prompt système et l'article
# sont IDENTIQUES d'un lot à l'autre : DeepSeek les sert depuis son cache de
# préfixe (50x moins cher, cf. LLM_COUT_USD_PAR_MTOKEN_IN_CACHE). Ce sont les
# candidats, en fin de prompt, qui changent.
BATCH_CANDIDATES = int(os.environ.get("CTI_ARTICLES_LOT", "20"))
MAX_TOKENS = int(os.environ.get("CTI_ARTICLES_MAX_TOKENS", "12000"))

# Garde-fou de dernier recours sur le nombre d'appels par article. Ce qui
# dépasse est écarté, mais JAMAIS en silence (cf. `arbitrer`) : un plafond muet
# donnerait l'illusion d'un article entièrement couvert.
MAX_BATCHES = int(os.environ.get("CTI_ARTICLES_MAX_LOTS", "16"))

# Volume de texte envoyé au modèle. Les articles utiles font 5 à 20 k
# caractères ; au-delà, c'est du commentaire, de la navigation et des articles
# liés. Tronquer borne le coût sans perdre la section « Indicators of
# Compromise », qui est presque toujours en fin de corps mais avant les
# commentaires — d'où la conservation du DÉBUT et de la FIN.
MAX_TEXT = 24000


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def sources(catalogue: dict | None = None) -> list[dict]:
    cat = catalogue or cti.load_catalog()
    return [s for s in (cat.get("articles") or []) if s.get("active", True)]


def _http(url: str) -> requests.Response:
    # User-Agent explicite : plusieurs médias renvoient 403 à un client sans
    # agent, et un agent mensonger serait une mauvaise manière de se présenter
    # à des sites qu'on lit gratuitement.
    response = requests.get(
        url, timeout=TIMEOUT,
        headers={"User-Agent": "AURA-SOC CTI collector (+threat intel, contact SOC)"})
    response.raise_for_status()
    return response


def rss_entries(source: dict, since: datetime) -> list[dict]:
    """Articles d'un flux RSS/Atom, plus récents que `depuis`.

    Le contenu complet est repris du flux quand il y est (Medium le fournit
    intégralement) : autant d'articles à ne pas retélécharger, et une page HTML
    de moins à nettoyer.
    """
    root = ET.fromstring(_http(source["url"]).content)
    entries = []
    for item in root.findall(".//item") or root.findall(
            ".//{http://www.w3.org/2005/Atom}entry"):
        def text(*names):
            for name in names:
                el = item.find(name)
                if el is not None and el.text:
                    return el.text.strip()
            return ""

        link = text("link", "{http://www.w3.org/2005/Atom}id") or ""
        if not link.startswith("http"):
            el = item.find("{http://www.w3.org/2005/Atom}link")
            link = el.get("href", "") if el is not None else ""
        if not link:
            continue

        published = _rss_date(text("pubDate", "{http://purl.org/dc/elements/1.1/}date",
                                 "{http://www.w3.org/2005/Atom}published"))
        if published and published < since:
            continue
        entries.append({
            "url": link,
            "titre": text("title", "{http://www.w3.org/2005/Atom}title"),
            "publie": published,
            "contenu": text("{http://purl.org/rss/1.0/modules/content/}encoded",
                             "description",
                             "{http://www.w3.org/2005/Atom}content"),
            "contexte": "",
        })
    return entries


def _rss_date(raw: str) -> datetime | None:
    if not raw:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            d = datetime.strptime(raw.strip(), fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def malpedia_entries(source: dict, already_seen: set[str]) -> list[dict]:
    """Nouveaux rapports de la bibliographie Malpedia, avec leur attribution.

    Malpedia n'expose pas d'IOC sans clé d'API (`/api/list/samples` répond 403),
    mais `/api/get/references` est un annuaire rapport -> familles de malware et
    acteurs. En mémorisant les URL déjà vues, il devient un flux de NOUVEAUTÉS,
    et il apporte ce qu'aucun article ne donne de lui-même : l'attribution,
    faite par des chercheurs.

    Corollaire à connaître : la bibliographie complète compte des dizaines de
    milliers d'entrées, dont l'immense majorité est ancienne. Le premier passage
    doit donc être un AMORÇAGE (`--amorcage`), qui marque tout comme vu sans
    rien traiter. Sans lui, la première exécution essaierait de télécharger et
    de faire lire au modèle l'intégralité de la littérature du domaine.
    """
    data = _http(source["url"]).json()
    references = data.get("references", data) or {}
    entries = []
    for url, targets in references.items():
        if not url.startswith("http") or url in already_seen:
            continue
        families = [c.get("common_name") or c.get("id", "")
                    for c in (targets or []) if isinstance(c, dict)]
        entries.append({
            "url": url,
            "titre": "",          # la bibliographie ne porte pas de titre
            "publie": None,       # ni de date : le curseur joue ce rôle
            "contenu": "",
            "contexte": ", ".join(f for f in families if f)[:300],
        })
    return entries


# ---------------------------------------------------------------------------
# Texte
# ---------------------------------------------------------------------------

_BLOCKS_USELESS = re.compile(
    r"<(script|style|noscript|nav|footer|header|form)\b.*?</\1>", re.S | re.I)
_TAGS = re.compile(r"<[^>]+>")
_SPACES = re.compile(r"[ \t\r\f\v]+")
_LINES = re.compile(r"\n{3,}")


def plain_text(html_source: str) -> str:
    """Texte lisible d'une page, sans dépendance de parsing HTML.

    Un vrai extracteur de contenu (readability, trafilatura) ferait mieux, mais
    ajouterait une dépendance pour un gain nul ici : on ne cherche pas à
    reproduire la mise en forme, seulement à donner au modèle une suite de
    phrases contenant les indicateurs. Les blocs de navigation et de script
    sont retirés parce qu'ils sont pleins de domaines tiers — donc de faux
    candidats.
    """
    without_blocks = _BLOCKS_USELESS.sub(" ", html_source or "")
    # Les balises deviennent des sauts de ligne : sans ça, un tableau d'IOC
    # ressort collé en un seul mot et plus aucune valeur n'est reconnaissable.
    text = _TAGS.sub("\n", without_blocks)
    text = html.unescape(text)
    text = _SPACES.sub(" ", text)
    return _LINES.sub("\n\n", text).strip()


def truncate(text: str, cap: int = MAX_TEXT) -> str:
    if len(text) <= cap:
        return text
    half = cap // 2
    return f"{text[:half]}\n\n[...]\n\n{text[-half:]}"


# ---------------------------------------------------------------------------
# Candidats
# ---------------------------------------------------------------------------

# Défanging : les publications neutralisent les indicateurs pour qu'ils ne
# soient pas cliquables. Sans cette réécriture, la quasi-totalité des IOC
# réellement présents dans un article passent inaperçus — c'est LA raison pour
# laquelle une extraction naïve ne trouve rien sur ces sources.
DEFANG = [
    (re.compile(r"\bh(?:xx|XX|tt)p(s?)\s*(?::|\[:\])//", re.I), r"http\1://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(?:@|at)\s*\]", re.I), "@"),
    (re.compile(r"\bmeow\b|\bhxxp\b", re.I), "http"),
]

PATTERN_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATTERN_URL = re.compile(r"https?://[^\s\"'<>\)\]]{4,300}")
PATTERN_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|top|xyz|club|online|site|shop|icu|vip|cc|io|"
    r"co|me|tv|pw|su|ws|link|live|fun|store|space|website|host|press|tech|app|dev|"
    r"cloud|de|fr|uk|nl|eu|br|in|ir|kr|jp|pl|tk|ml|ga|cf|gq|zip|mov)\b", re.I)
PATTERN_HASH = re.compile(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b")

# Domaines à ne jamais retenir : ceux des médias sources et des plateformes
# qu'ils citent en boucle. Le modèle les écarte déjà (le prompt le lui demande),
# mais une exclusion en code ne dépend pas de son humeur. Un IOC légitimement
# hébergé sur un de ces domaines est perdu — c'est le prix, et il est faible
# devant une alerte de niveau 12 sur github.com.
DOMAINS_EXCLUDED = {
    "thehackernews.com", "bleepingcomputer.com", "medium.com", "malpedia.caad.fkie.fraunhofer.de",
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com", "reddit.com",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "windows.com",
    "office.com", "live.com", "azure.com", "apple.com", "icloud.com", "amazon.com",
    "aws.amazon.com", "cloudflare.com", "akamai.com", "fastly.net",
    "mitre.org", "nist.gov", "cisa.gov", "cve.org", "first.org", "virustotal.com",
    "wikipedia.org", "archive.org", "blogspot.com", "wordpress.com", "substack.com",
    "cisco.com", "talosintelligence.com", "crowdstrike.com", "mandiant.com",
    "sentinelone.com", "sophos.com", "trendmicro.com", "kaspersky.com", "eset.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com", "checkpoint.com",
    "welivesecurity.com", "securelist.com", "symantec.com", "fortinet.com",
    "proofpoint.com", "recordedfuture.com", "intezer.com", "any.run", "joesandbox.com",
    "hybrid-analysis.com", "abuse.ch", "circl.lu", "botvrij.eu", "shodan.io", "censys.io",
    "example.com", "example.org", "localhost", "schema.org", "w3.org",
}

# Réseaux de documentation et de test (RFC 5737, RFC 3849, TEST-NET) : les
# articles s'en servent pour illustrer sans exposer une vraie cible.
NETWORKS_DOC = [ipaddress.ip_network(r) for r in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "233.252.0.0/24")]


def defanger(text: str) -> str:
    for pattern, replacement in DEFANG:
        text = pattern.sub(replacement, text)
    return text


def _domain_excluded(value: str) -> bool:
    host = (urlparse(value).hostname if value.startswith("http") else value) or ""
    host = host.lower().rstrip(".")
    # Comparaison par suffixe : `cdn.microsoft.com` doit tomber avec
    # `microsoft.com`, sinon l'exclusion ne tient que sur le domaine nu.
    return any(host == d or host.endswith("." + d) for d in DOMAINS_EXCLUDED)


def _ip_to_ignore(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
            or ip.is_reserved or ip.is_unspecified:
        return True
    if any(ip in network for network in NETWORKS_DOC):
        return True
    # L'infrastructure du SOC et nos propres réseaux ne peuvent pas être des
    # IOC publiés par un tiers. Si ça arrive, c'est une erreur de l'article ou
    # de l'extraction, et la conséquence serait de faire alerter — voire agir —
    # le SOC contre lui-même.
    if str(ip) in config.SOC_INFRA_IPS:
        return True
    return any(ip in network for network in _internal_networks())


def _internal_networks() -> list:
    """`config.RESEAUX_INTERNES` converti en réseaux comparables.

    La configuration les livre en CHAÎNES ("192.168.1.0/24, ..."), et
    `ip in "192.168.1.0/24"` lève un TypeError — vu en prod le 2026-08-12, il a
    emporté toute la source The Hacker News au milieu d'une passe. Une entrée
    mal écrite est ignorée plutôt que fatale : elle ne doit pas décider de la
    disponibilité de la veille.
    """
    networks = []
    for raw in getattr(config, "NETWORKS_INTERNAL", None) or []:
        if isinstance(raw, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks.append(raw)
            continue
        try:
            networks.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            log.debug("RESEAUX_INTERNES : entrée ignorée %r", raw)
    return networks


def candidates(text: str) -> dict[str, list[str]]:
    """Valeurs qui ressemblent à un IOC, par type, déjà filtrées du bruit dur.

    Ne juge PAS la malveillance : c'est le rôle de l'étage suivant. Ne fait ici
    que retirer ce qui ne peut structurellement pas être un indicateur.
    """
    plain = defanger(text)
    found = {"ip": [], "domain": [], "url": [], "hash": []}
    seen = set()

    def add(type_, raw):
        value = cti.normalize(type_, raw)
        if not value or value in seen:
            return
        if type_ == "ip" and _ip_to_ignore(value):
            return
        if type_ in ("domain", "url") and _domain_excluded(value):
            return
        seen.add(value)
        found[type_].append(value)

    for raw in PATTERN_URL.findall(plain):
        add("url", raw.rstrip(".,;:)"))
    for raw in PATTERN_IP.findall(plain):
        add("ip", raw)
    for raw in PATTERN_DOMAIN.findall(plain):
        add("domain", raw)
    for raw in PATTERN_HASH.findall(plain):
        add("hash", raw)
    return found


# ---------------------------------------------------------------------------
# Arbitrage par le modèle
# ---------------------------------------------------------------------------

def _batches(found: dict[str, list[str]]) -> list[list[tuple[str, str]]]:
    """Candidats découpés en lots de taille bornée, tous types mélangés."""
    plat = [(type_, v) for type_, values in found.items() for v in values]
    return [plat[i:i + BATCH_CANDIDATES]
            for i in range(0, len(plat), BATCH_CANDIDATES)][:MAX_BATCHES]


def arbitrate(article: dict, found: dict[str, listing[str]]) -> dict:
    """Demande au modèle lesquels des candidats sont des IOC de la menace.

    Pas de pseudonymisation ici, contrairement au triage (cf. anonymize.py) :
    ce qui part est le texte d'un article PUBLIC et des indicateurs publiés par
    son auteur. Il n'y a rien de notre infrastructure dans ce prompt — et c'est
    une propriété à préserver si ce module évolue.

    Le texte est envoyé en entier à CHAQUE lot de candidats, et c'est
    volontaire : c'est le contexte qui permet de trancher, le tronçonner ferait
    juger des valeurs sans le récit qui les qualifie. Le préfixe étant
    identique d'un appel à l'autre, il est servi par le cache du fournisseur.
    """
    system = (PROMPTS / "cti_extraction.md").read_text()
    header = (
        f"TITRE : {article.get('titre') or '(inconnu)'}\n"
        f"URL : {article['url']}\n"
        + (f"FAMILLES ASSOCIÉES (attribution Malpedia) : {article['contexte']}\n"
           if article.get("contexte") else ""))
    article_body = f"\nARTICLE :\n{truncate(article['texte'])}\n"

    def request(batch: listing[tuple[str, str]], label: str) -> dict | None:
        """Un appel au modèle sur un lot de candidats. None si l'appel échoue.

        Rejoue une fois en DEUX MOITIÉS quand le budget a été épuisé : le
        modèle est raisonnant et la longueur de son raisonnement n'est pas
        prévisible (mesuré : le même budget suffit pour un lot et pas pour le
        suivant). Diviser le lot est la seule réponse qui ne consiste pas à
        surdimensionner le budget de tous les appels pour les rares qui
        débordent.
        """
        by_type: dict[str, listing[str]] = {}
        for type_, value in batch:
            by_type.setdefault(type_, []).append(value)
        listing = "\n".join(f"{t} : " + ", ".join(v) for t, v in by_type.items())
        try:
            response, _ = llm.completion(
                system, header + article_body + f"\nCANDIDATS ({label}) :\n{listing}\n",
                usage="cti_extraction", max_tokens=MAX_TOKENS)
            return response
        except Exception as exc:                              # noqa: BLE001
            budget_exhausted = "finish_reason=length" in str(exc) or "Unterminated" in str(exc)
            if budget_exhausted and len(batch) > 4:
                middle = len(batch) // 2
                log.info("lot %s trop lourd pour le budget, redécoupé en deux",
                         label)
                left = request(batch[:middle], f"{label}a")
                right = request(batch[middle:], f"{label}b")
                if left is None and right is None:
                    return None
                return {"iocs": (left or {}).get("iocs", [])
                                + (right or {}).get("iocs", []),
                        "threat": (left or right or {}).get("threat", ""),
                        "resume": (left or right or {}).get("resume", ""),
                        "confiance": (left or right or {}).get("confiance", "")}
            # Un lot perdu ne doit pas emporter l'article : les autres ont
            # peut-être livré de vrais indicateurs, et les jeter pour un
            # accident d'API serait payer deux fois.
            log.warning("lot %s en échec sur %s : %s", label, article["url"], exc)
            return None

    merge = {"iocs": [], "threat": "", "resume": "", "confiance": ""}
    batches = _batches(found)
    total = sum(len(v) for v in found.values())
    covered = sum(len(batch) for batch in batches)
    if covered < total:
        log.warning("%s : %d candidats sur %d soumis au modèle (plafond de "
                    "%d lots) — %d NON examinés", article["url"], covered,
                    total, MAX_BATCHES, total - covered)
    for number, batch in enumerate(batches, 1):
        response = request(batch, f"{number}/{len(batches)}")
        if response is None:
            continue
        merge["iocs"].extend(response.get("iocs") or [])
        # Menace, résumé et confiance sont des propriétés de l'ARTICLE, pas du
        # lot : on garde la première réponse non vide plutôt que d'écraser à
        # chaque tour, un lot ne contenant parfois aucun IOC et donc aucun
        # contexte.
        for key in ("threat", "resume", "confiance"):
            if not merge[key] and response.get(key):
                merge[key] = str(response[key])
    return merge


def validate(response: dict, found: dict[str, list[str]]) -> list[dict]:
    """Garde-fou déterministe sur la sortie du modèle.

    Trois rejets, dans cet ordre, et aucun n'est négociable :

    1. valeur absente des candidats -> HALLUCINATION. Le modèle n'a pas le
       droit de produire un indicateur que le texte ne contient pas ; c'est le
       seul mode de défaillance qui fabriquerait des IOC de toutes pièces.
    2. type incohérent avec la valeur -> on reclasse d'après la valeur, jamais
       d'après ce que le modèle annonce.
    3. exclusions dures rejouées. Le prompt les demande déjà, mais un prompt
       n'est pas un contrôle.
    """
    allowed = {v: t for t, values in found.items() for v in values}
    kept, seen = [], set()
    for raw in (response.get("iocs") or [])[:MAX_IOC_ARTICLE * 2]:
        if not isinstance(raw, dict):
            continue
        value = str(raw.get("value", "")).strip()
        announced_type = str(raw.get("type", "")).strip().lower()
        # Normalise avec le type annoncé s'il est plausible, sinon avec celui
        # sous lequel le candidat a réellement été trouvé.
        value = cti.normalize(announced_type, value) or cti.normalize(
            allowed.get(value, ""), value) or value
        real_type = allowed.get(value)
        if not real_type:
            log.warning("IOC rejeté (absent des candidats) : %r", raw.get("value"))
            continue
        if value in seen:
            continue
        if real_type == "ip" and _ip_to_ignore(value):
            continue
        if real_type in ("domain", "url") and _domain_excluded(value):
            continue
        seen.add(value)
        kept.append({"value": value, "type": real_type,
                        "role": str(raw.get("role", ""))[:100]})
    return kept


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------

# Type de cache -> type d'attribut MISP. `ip-dst` et non `ip-src` : un IOC
# d'article désigne une infrastructure d'attaquant, donc une DESTINATION vue
# depuis chez nous. Le cache retombe de toute façon sur « ip » (cf. cti.TYPES),
# la distinction ne sert qu'à la lisibilité dans MISP.
TYPE_MISP = {"ip": "ip-dst", "domain": "domain", "url": "url"}


def _type_hash(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def filter_warninglists(values: list[str]) -> set[str]:
    """Valeurs que MISP connaît comme NE DEVANT PAS être des IOC.

    Les warninglists de MISP recensent ce qu'un indicateur ne devrait jamais
    être : domaines du top 1000, résolveurs DNS publics, plages de cloud
    providers, adresses de documentation... Exactement la population de faux
    positifs qu'un article de presse génère. Les interroger ici évite de
    publier ce que `cti.py` écarterait ensuite en silence à la lecture
    (`enforceWarninglist`) — publier un IOC inutilisable est pire que ne pas le
    publier : il donne l'illusion d'une couverture.

    En cas d'échec de l'appel, on ne filtre rien plutôt que de tout jeter : la
    perte serait invisible.
    """
    if not values:
        return set()
    try:
        response = cti._misp("POST", "/warninglists/checkValue", values)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("warninglists MISP injoignables (%s) : aucun filtrage", exc)
        return set()
    if isinstance(response, dict):
        return {v for v, lists in response.items() if lists}
    return set()


def create_event(article: dict, iocs: list[dict], response: dict,
                    source: dict) -> int | None:
    """Publie un événement MISP portant les IOC de l'article.

    L'événement est la BONNE granularité : un article = une menace = un
    ensemble d'indicateurs qui se corrèlent entre eux. Un attribut isolé dans
    un événement fourre-tout perdrait le contexte, donc l'essentiel.

    `to_ids` est vrai (ce sont des indicateurs de détection) mais le tag
    `aura:source:extracted` les distingue du renseignement curé jusque dans le
    niveau de la règle Wazuh. `analysis: 2` (terminé) et publication immédiate :
    sans publication, `cti.py` ne les verrait jamais (il filtre `published=1`).
    """
    threat = str(response.get("threat") or "").strip()
    resume = str(response.get("resume") or "").strip()
    title = (article.get("titre") or article["url"])[:200]
    info = f"[AURA/{source['name']}] {threat + ' — ' if threat else ''}{title}"

    attributes = [{
        "type": "link", "category": "External analysis", "value": article["url"],
        "to_ids": False, "comment": "Source article",
    }]
    for ioc in iocs:
        type_misp = TYPE_MISP.get(ioc["type"]) or _type_hash(ioc["value"])
        attributes.append({
            "type": type_misp,
            "category": "Payload delivery" if ioc["type"] == "hash"
                        else "Network activity",
            "value": ioc["value"],
            "to_ids": True,
            "comment": ioc["role"] or resume[:100],
        })

    tags = [{"name": TAG_SOURCE}, {"name": f"aura:feed:{source['name']}"},
            {"name": "tlp:clear"}]
    confidence = str(response.get("confiance") or "").lower()
    if confidence in ("haute", "moyenne", "basse"):
        tags.append({"name": f"aura:extraction-confidence:{confidence}"})
    if article.get("contexte"):
        tags.append({"name": "aura:attribution:malpedia"})

    body = {"Event": {
        "info": info[:255],
        "date": (article.get("publie") or datetime.now(timezone.utc)).strftime("%Y-%m-%d"),
        "analysis": "2",
        "threat_level_id": "2",
        "distribution": "0",
        "published": True,
        "Attribute": attributes,
        "Tag": tags,
    }}
    misp_response = cti._misp("POST", "/events/add", body)
    event = (misp_response or {}).get("Event") or {}
    return int(event["id"]) if event.get("id") else None


# ---------------------------------------------------------------------------
# Curseur
# ---------------------------------------------------------------------------

def _connection():
    return psycopg.connect(config.PG_DSN)


def already_seen(conn, source: str) -> set[str]:
    return {u for (u,) in conn.execute(
        "SELECT url FROM cti_articles WHERE source = %s", (source,))}


def mark(conn, source: str, url: str, nb_iocs: int, event_id: int | None,
            threat: str = "", pattern: str = "") -> None:
    conn.execute(
        "INSERT INTO cti_articles (source, url, iocs_kept, misp_event_id, "
        "threat, pattern) VALUES (%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (url) DO UPDATE SET iocs_kept = EXCLUDED.iocs_kept, "
        "misp_event_id = COALESCE(EXCLUDED.misp_event_id, cti_articles.misp_event_id), "
        "threat = EXCLUDED.threat, pattern = EXCLUDED.pattern",
        (source, url, nb_iocs, event_id, threat[:200], pattern[:200]))
    conn.commit()


# ---------------------------------------------------------------------------
# Traitement
# ---------------------------------------------------------------------------

def load_text(article: dict) -> str:
    """Texte de l'article : celui du flux s'il est complet, sinon la page."""
    du_flux = plain_text(article.get("contenu") or "")
    # Un extrait RSS fait quelques centaines de caractères : il ne contient
    # jamais la section des IOC. On ne s'en contente que s'il est substantiel.
    if len(du_flux) > 3000:
        return du_flux
    return plain_text(_http(article["url"]).text)


def process(article: dict, source: dict, simulation: bool = False) -> dict:
    """Un article, de la récupération à l'événement MISP.

    Rend un compte rendu, y compris quand rien n'est retenu : « aucun IOC »
    est le résultat normal pour la majorité des articles de presse, et le
    tracer évite de retraiter le même texte à chaque passe.
    """
    result = {"url": article["url"], "iocs": [], "event_id": None,
                "threat": "", "pattern": ""}
    try:
        article["texte"] = load_text(article)
    except Exception as exc:                                  # noqa: BLE001
        result["pattern"] = f"article illisible : {exc}"
        return result
    if len(article["texte"]) < 500:
        result["pattern"] = "texte trop court pour être un rapport"
        return result

    found = candidates(article["texte"])
    if not any(found.values()):
        result["pattern"] = "aucun candidat dans le texte"
        return result

    response = arbitrate(article, found)
    iocs = validate(response, found)
    result["threat"] = str(response.get("threat") or "")[:200]
    if not iocs:
        result["pattern"] = "aucun IOC retenu par l'arbitrage"
        return result
    cap = int(source.get("max_iocs") or MAX_IOC_ARTICLE)
    if len(iocs) > cap:
        # Ne pas publier plutôt que publier n'importe quoi, et le DIRE : une
        # troncature muette laisserait croire à une couverture complète.
        result["pattern"] = (f"{len(iocs)} IOC extraits, au-delà du plafond "
                             f"de {cap} : article non publié")
        log.warning("%s : %s", article["url"], result["pattern"])
        return result

    known = filter_warninglists([i["value"] for i in iocs])
    if known:
        log.info("%d IOC écartés par les warninglists MISP", len(known))
    iocs = [i for i in iocs if i["value"] not in known]
    result["iocs"] = iocs
    if not iocs:
        result["pattern"] = "tous les IOC écartés par les warninglists MISP"
        return result

    if not simulation:
        result["event_id"] = create_event(article, iocs, response, source)
    return result


# Sources qui n'ont ni date ni flux de nouveautés : c'est le curseur des URL
# vues qui en tient lieu, donc elles DOIVENT être amorcées avant la première
# passe. Les flux RSS, eux, sont déjà bornés par leur fenêtre de fraîcheur.
TYPES_TO_BOOTSTRAP = {"malpedia_references"}


def collect(source: dict, already: set[str], since: datetime,
              maximum: int, bootstrap: bool, simulation: bool,
              ledger=None) -> list[dict]:
    if bootstrap and source.get("type") not in TYPES_TO_BOOTSTRAP:
        # Ne PAS marquer les flux RSS pendant un amorçage : ce serait griller
        # les articles récents, qui sont précisément ceux qu'on veut traiter à
        # la première vraie passe. L'amorçage n'existe que pour les sources sans
        # date (cf. TYPES_A_AMORCER).
        log.info("%s : rien à amorcer (source datée)", source["name"])
        return []

    if source.get("type") == "malpedia_references":
        entries = malpedia_entries(source, already)
    else:
        entries = [e for e in rss_entries(source, since) if e["url"] not in already]
    log.info("%s : %d entrée(s) nouvelle(s)", source["name"], len(entries))

    if bootstrap:
        # Marquer sans traiter : c'est ce qui rend la première exécution
        # possible sur une bibliographie de plusieurs dizaines de milliers de
        # rapports.
        return [{"url": e["url"], "iocs": [], "event_id": None, "threat": "",
                 "pattern": "amorçage"} for e in entries]

    results = []
    for entry in entries[:maximum]:
        log.info("→ %s", entry["url"])
        result = process(entry, source, simulation=simulation)
        results.append(result)
        # Marquage IMMÉDIAT, article par article, et non à la fin de la source :
        # une panne au milieu d'une passe (ou un arrêt du conteneur) perdrait
        # sinon le travail déjà fait, appels au modèle compris. Constaté en prod
        # le 2026-08-12 sur une erreur de type — l'article traité juste avant a
        # été payé puis oublié.
        if ledger is not None and not simulation:
            mark(ledger, source["name"], result["url"],
                    len(result["iocs"]), result["event_id"],
                    result["threat"], result["pattern"])
    return results


def passe(source_name: str | None = None, maximum: int = 10,
          hours: int = 48, bootstrap: bool = False,
          simulation: bool = False) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    tous = []
    with _connection() as conn:
        for source in sources():
            if source_name and source["name"] != source_name:
                continue
            already = already_seen(conn, source["name"])
            try:
                results = collect(source, already, since, maximum, bootstrap,
                                      simulation, ledger=conn)
            except Exception as exc:                          # noqa: BLE001
                # Une source en panne ne doit pas emporter les autres : elles
                # sont indépendantes, et le renseignement perdu serait celui
                # de tout le monde. Les articles déjà traités de cette source
                # sont, eux, déjà enregistrés (marquage au fil de l'eau).
                log.warning("source %s en échec : %s", source["name"], exc)
                continue
            for r in results:
                if bootstrap and not simulation:
                    mark(conn, source["name"], r["url"], 0, None, "", "amorçage")
                if r["iocs"]:
                    log.info("%d IOC publiés (event %s) — %s", len(r["iocs"]),
                             r["event_id"], r["threat"] or "menace non nommée")
            tous.extend(results)
    return tous


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", help="ne traiter qu'une source (nom du catalogue)")
    p.add_argument("--max", type=int, default=10,
                   help="articles traités par source et par passe (défaut 10)")
    p.add_argument("--heures", type=int, default=48,
                   help="fenêtre de fraîcheur des flux RSS (défaut 48)")
    p.add_argument("--amorcage", action="store_true",
                   help="marque l'existant comme vu SANS rien traiter "
                        "(obligatoire au premier lancement, cf. Malpedia)")
    p.add_argument("--simulation", action="store_true",
                   help="extrait et affiche, n'écrit ni dans MISP ni en base")
    p.add_argument("--url", help="traiter un article précis, hors flux")
    args = p.parse_args()

    if args.url:
        source = {"name": args.source or "manuel"}
        r = process({"url": args.url, "titre": "", "publie": None,
                     "contenu": "", "contexte": ""}, source,
                    simulation=args.simulation)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    results = passe(args.source, args.max, args.hours, args.bootstrap,
                      args.simulation)
    published = sum(len(r["iocs"]) for r in results)
    log.info("%d article(s) traité(s), %d IOC%s", len(results), published,
             " (simulation)" if args.simulation else " publiés dans MISP")
    if args.simulation:
        print(json.dumps([r for r in results if r["iocs"] or r["pattern"]],
                         indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
