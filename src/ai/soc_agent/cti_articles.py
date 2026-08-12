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
LOT_CANDIDATS = int(os.environ.get("CTI_ARTICLES_LOT", "20"))
MAX_TOKENS = int(os.environ.get("CTI_ARTICLES_MAX_TOKENS", "12000"))

# Garde-fou de dernier recours sur le nombre d'appels par article. Ce qui
# dépasse est écarté, mais JAMAIS en silence (cf. `arbitrer`) : un plafond muet
# donnerait l'illusion d'un article entièrement couvert.
MAX_LOTS = int(os.environ.get("CTI_ARTICLES_MAX_LOTS", "16"))

# Volume de texte envoyé au modèle. Les articles utiles font 5 à 20 k
# caractères ; au-delà, c'est du commentaire, de la navigation et des articles
# liés. Tronquer borne le coût sans perdre la section « Indicators of
# Compromise », qui est presque toujours en fin de corps mais avant les
# commentaires — d'où la conservation du DÉBUT et de la FIN.
TEXTE_MAX = 24000


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def sources(catalogue: dict | None = None) -> list[dict]:
    cat = catalogue or cti.charger_catalogue()
    return [s for s in (cat.get("articles") or []) if s.get("active", True)]


def _http(url: str) -> requests.Response:
    # User-Agent explicite : plusieurs médias renvoient 403 à un client sans
    # agent, et un agent mensonger serait une mauvaise manière de se présenter
    # à des sites qu'on lit gratuitement.
    reponse = requests.get(
        url, timeout=TIMEOUT,
        headers={"User-Agent": "AURA-SOC CTI collector (+threat intel, contact SOC)"})
    reponse.raise_for_status()
    return reponse


def entrees_rss(source: dict, depuis: datetime) -> list[dict]:
    """Articles d'un flux RSS/Atom, plus récents que `depuis`.

    Le contenu complet est repris du flux quand il y est (Medium le fournit
    intégralement) : autant d'articles à ne pas retélécharger, et une page HTML
    de moins à nettoyer.
    """
    racine = ET.fromstring(_http(source["url"]).content)
    entrees = []
    for item in racine.findall(".//item") or racine.findall(
            ".//{http://www.w3.org/2005/Atom}entry"):
        def texte(*noms):
            for nom in noms:
                el = item.find(nom)
                if el is not None and el.text:
                    return el.text.strip()
            return ""

        lien = texte("link", "{http://www.w3.org/2005/Atom}id") or ""
        if not lien.startswith("http"):
            el = item.find("{http://www.w3.org/2005/Atom}link")
            lien = el.get("href", "") if el is not None else ""
        if not lien:
            continue

        publie = _date_rss(texte("pubDate", "{http://purl.org/dc/elements/1.1/}date",
                                 "{http://www.w3.org/2005/Atom}published"))
        if publie and publie < depuis:
            continue
        entrees.append({
            "url": lien,
            "titre": texte("title", "{http://www.w3.org/2005/Atom}title"),
            "publie": publie,
            "contenu": texte("{http://purl.org/rss/1.0/modules/content/}encoded",
                             "description",
                             "{http://www.w3.org/2005/Atom}content"),
            "contexte": "",
        })
    return entrees


def _date_rss(brut: str) -> datetime | None:
    if not brut:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            d = datetime.strptime(brut.strip(), fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def entrees_malpedia(source: dict, deja_vues: set[str]) -> list[dict]:
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
    donnees = _http(source["url"]).json()
    references = donnees.get("references", donnees) or {}
    entrees = []
    for url, cibles in references.items():
        if not url.startswith("http") or url in deja_vues:
            continue
        familles = [c.get("common_name") or c.get("id", "")
                    for c in (cibles or []) if isinstance(c, dict)]
        entrees.append({
            "url": url,
            "titre": "",          # la bibliographie ne porte pas de titre
            "publie": None,       # ni de date : le curseur joue ce rôle
            "contenu": "",
            "contexte": ", ".join(f for f in familles if f)[:300],
        })
    return entrees


# ---------------------------------------------------------------------------
# Texte
# ---------------------------------------------------------------------------

_BLOCS_INUTILES = re.compile(
    r"<(script|style|noscript|nav|footer|header|form)\b.*?</\1>", re.S | re.I)
_BALISES = re.compile(r"<[^>]+>")
_ESPACES = re.compile(r"[ \t\r\f\v]+")
_LIGNES = re.compile(r"\n{3,}")


def texte_brut(html_source: str) -> str:
    """Texte lisible d'une page, sans dépendance de parsing HTML.

    Un vrai extracteur de contenu (readability, trafilatura) ferait mieux, mais
    ajouterait une dépendance pour un gain nul ici : on ne cherche pas à
    reproduire la mise en forme, seulement à donner au modèle une suite de
    phrases contenant les indicateurs. Les blocs de navigation et de script
    sont retirés parce qu'ils sont pleins de domaines tiers — donc de faux
    candidats.
    """
    sans_blocs = _BLOCS_INUTILES.sub(" ", html_source or "")
    # Les balises deviennent des sauts de ligne : sans ça, un tableau d'IOC
    # ressort collé en un seul mot et plus aucune valeur n'est reconnaissable.
    texte = _BALISES.sub("\n", sans_blocs)
    texte = html.unescape(texte)
    texte = _ESPACES.sub(" ", texte)
    return _LIGNES.sub("\n\n", texte).strip()


def tronquer(texte: str, plafond: int = TEXTE_MAX) -> str:
    if len(texte) <= plafond:
        return texte
    moitie = plafond // 2
    return f"{texte[:moitie]}\n\n[...]\n\n{texte[-moitie:]}"


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

MOTIF_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MOTIF_URL = re.compile(r"https?://[^\s\"'<>\)\]]{4,300}")
MOTIF_DOMAINE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|top|xyz|club|online|site|shop|icu|vip|cc|io|"
    r"co|me|tv|pw|su|ws|link|live|fun|store|space|website|host|press|tech|app|dev|"
    r"cloud|de|fr|uk|nl|eu|br|in|ir|kr|jp|pl|tk|ml|ga|cf|gq|zip|mov)\b", re.I)
MOTIF_HASH = re.compile(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b")

# Domaines à ne jamais retenir : ceux des médias sources et des plateformes
# qu'ils citent en boucle. Le modèle les écarte déjà (le prompt le lui demande),
# mais une exclusion en code ne dépend pas de son humeur. Un IOC légitimement
# hébergé sur un de ces domaines est perdu — c'est le prix, et il est faible
# devant une alerte de niveau 12 sur github.com.
DOMAINES_EXCLUS = {
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
RESEAUX_DOC = [ipaddress.ip_network(r) for r in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "233.252.0.0/24")]


def defanger(texte: str) -> str:
    for motif, remplacement in DEFANG:
        texte = motif.sub(remplacement, texte)
    return texte


def _domaine_exclu(valeur: str) -> bool:
    hote = (urlparse(valeur).hostname if valeur.startswith("http") else valeur) or ""
    hote = hote.lower().rstrip(".")
    # Comparaison par suffixe : `cdn.microsoft.com` doit tomber avec
    # `microsoft.com`, sinon l'exclusion ne tient que sur le domaine nu.
    return any(hote == d or hote.endswith("." + d) for d in DOMAINES_EXCLUS)


def _ip_a_ignorer(valeur: str) -> bool:
    try:
        ip = ipaddress.ip_address(valeur)
    except ValueError:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
            or ip.is_reserved or ip.is_unspecified:
        return True
    if any(ip in reseau for reseau in RESEAUX_DOC):
        return True
    # L'infrastructure du SOC et nos propres réseaux ne peuvent pas être des
    # IOC publiés par un tiers. Si ça arrive, c'est une erreur de l'article ou
    # de l'extraction, et la conséquence serait de faire alerter — voire agir —
    # le SOC contre lui-même.
    if str(ip) in config.SOC_INFRA_IPS:
        return True
    return any(ip in reseau for reseau in getattr(config, "RESEAUX_INTERNES", []) or [])


def candidats(texte: str) -> dict[str, list[str]]:
    """Valeurs qui ressemblent à un IOC, par type, déjà filtrées du bruit dur.

    Ne juge PAS la malveillance : c'est le rôle de l'étage suivant. Ne fait ici
    que retirer ce qui ne peut structurellement pas être un indicateur.
    """
    clair = defanger(texte)
    trouves = {"ip": [], "domain": [], "url": [], "hash": []}
    vus = set()

    def ajouter(type_, brut):
        valeur = cti.normaliser(type_, brut)
        if not valeur or valeur in vus:
            return
        if type_ == "ip" and _ip_a_ignorer(valeur):
            return
        if type_ in ("domain", "url") and _domaine_exclu(valeur):
            return
        vus.add(valeur)
        trouves[type_].append(valeur)

    for brut in MOTIF_URL.findall(clair):
        ajouter("url", brut.rstrip(".,;:)"))
    for brut in MOTIF_IP.findall(clair):
        ajouter("ip", brut)
    for brut in MOTIF_DOMAINE.findall(clair):
        ajouter("domain", brut)
    for brut in MOTIF_HASH.findall(clair):
        ajouter("hash", brut)
    return trouves


# ---------------------------------------------------------------------------
# Arbitrage par le modèle
# ---------------------------------------------------------------------------

def _lots(trouves: dict[str, list[str]]) -> list[list[tuple[str, str]]]:
    """Candidats découpés en lots de taille bornée, tous types mélangés."""
    plat = [(type_, v) for type_, valeurs in trouves.items() for v in valeurs]
    return [plat[i:i + LOT_CANDIDATS]
            for i in range(0, len(plat), LOT_CANDIDATS)][:MAX_LOTS]


def arbitrer(article: dict, trouves: dict[str, list[str]]) -> dict:
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
    systeme = (PROMPTS / "cti_extraction.md").read_text()
    entete = (
        f"TITRE : {article.get('titre') or '(inconnu)'}\n"
        f"URL : {article['url']}\n"
        + (f"FAMILLES ASSOCIÉES (attribution Malpedia) : {article['contexte']}\n"
           if article.get("contexte") else ""))
    corps_article = f"\nARTICLE :\n{tronquer(article['texte'])}\n"

    def demander(lot: list[tuple[str, str]], etiquette: str) -> dict | None:
        """Un appel au modèle sur un lot de candidats. None si l'appel échoue.

        Rejoue une fois en DEUX MOITIÉS quand le budget a été épuisé : le
        modèle est raisonnant et la longueur de son raisonnement n'est pas
        prévisible (mesuré : le même budget suffit pour un lot et pas pour le
        suivant). Diviser le lot est la seule réponse qui ne consiste pas à
        surdimensionner le budget de tous les appels pour les rares qui
        débordent.
        """
        par_type: dict[str, list[str]] = {}
        for type_, valeur in lot:
            par_type.setdefault(type_, []).append(valeur)
        liste = "\n".join(f"{t} : " + ", ".join(v) for t, v in par_type.items())
        try:
            reponse, _ = llm.completion(
                systeme, entete + corps_article + f"\nCANDIDATS ({etiquette}) :\n{liste}\n",
                usage="cti_extraction", max_tokens=MAX_TOKENS)
            return reponse
        except Exception as exc:                              # noqa: BLE001
            budget_epuise = "finish_reason=length" in str(exc) or "Unterminated" in str(exc)
            if budget_epuise and len(lot) > 4:
                milieu = len(lot) // 2
                log.info("lot %s trop lourd pour le budget, redécoupé en deux",
                         etiquette)
                gauche = demander(lot[:milieu], f"{etiquette}a")
                droite = demander(lot[milieu:], f"{etiquette}b")
                if gauche is None and droite is None:
                    return None
                return {"iocs": (gauche or {}).get("iocs", [])
                                + (droite or {}).get("iocs", []),
                        "menace": (gauche or droite or {}).get("menace", ""),
                        "resume": (gauche or droite or {}).get("resume", ""),
                        "confiance": (gauche or droite or {}).get("confiance", "")}
            # Un lot perdu ne doit pas emporter l'article : les autres ont
            # peut-être livré de vrais indicateurs, et les jeter pour un
            # accident d'API serait payer deux fois.
            log.warning("lot %s en échec sur %s : %s", etiquette, article["url"], exc)
            return None

    fusion = {"iocs": [], "menace": "", "resume": "", "confiance": ""}
    lots = _lots(trouves)
    total = sum(len(v) for v in trouves.values())
    couverts = sum(len(lot) for lot in lots)
    if couverts < total:
        log.warning("%s : %d candidats sur %d soumis au modèle (plafond de "
                    "%d lots) — %d NON examinés", article["url"], couverts,
                    total, MAX_LOTS, total - couverts)
    for numero, lot in enumerate(lots, 1):
        reponse = demander(lot, f"{numero}/{len(lots)}")
        if reponse is None:
            continue
        fusion["iocs"].extend(reponse.get("iocs") or [])
        # Menace, résumé et confiance sont des propriétés de l'ARTICLE, pas du
        # lot : on garde la première réponse non vide plutôt que d'écraser à
        # chaque tour, un lot ne contenant parfois aucun IOC et donc aucun
        # contexte.
        for cle in ("menace", "resume", "confiance"):
            if not fusion[cle] and reponse.get(cle):
                fusion[cle] = str(reponse[cle])
    return fusion


def valider(reponse: dict, trouves: dict[str, list[str]]) -> list[dict]:
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
    autorises = {v: t for t, valeurs in trouves.items() for v in valeurs}
    retenus, vus = [], set()
    for brut in (reponse.get("iocs") or [])[:MAX_IOC_ARTICLE * 2]:
        if not isinstance(brut, dict):
            continue
        valeur = str(brut.get("valeur", "")).strip()
        type_annonce = str(brut.get("type", "")).strip().lower()
        # Normalise avec le type annoncé s'il est plausible, sinon avec celui
        # sous lequel le candidat a réellement été trouvé.
        valeur = cti.normaliser(type_annonce, valeur) or cti.normaliser(
            autorises.get(valeur, ""), valeur) or valeur
        type_reel = autorises.get(valeur)
        if not type_reel:
            log.warning("IOC rejeté (absent des candidats) : %r", brut.get("valeur"))
            continue
        if valeur in vus:
            continue
        if type_reel == "ip" and _ip_a_ignorer(valeur):
            continue
        if type_reel in ("domain", "url") and _domaine_exclu(valeur):
            continue
        vus.add(valeur)
        retenus.append({"valeur": valeur, "type": type_reel,
                        "role": str(brut.get("role", ""))[:100]})
    return retenus


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------

# Type de cache -> type d'attribut MISP. `ip-dst` et non `ip-src` : un IOC
# d'article désigne une infrastructure d'attaquant, donc une DESTINATION vue
# depuis chez nous. Le cache retombe de toute façon sur « ip » (cf. cti.TYPES),
# la distinction ne sert qu'à la lisibilité dans MISP.
TYPE_MISP = {"ip": "ip-dst", "domain": "domain", "url": "url"}


def _type_hash(valeur: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(valeur)]


def filtrer_warninglists(valeurs: list[str]) -> set[str]:
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
    if not valeurs:
        return set()
    try:
        reponse = cti._misp("POST", "/warninglists/checkValue", valeurs)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("warninglists MISP injoignables (%s) : aucun filtrage", exc)
        return set()
    if isinstance(reponse, dict):
        return {v for v, listes in reponse.items() if listes}
    return set()


def creer_evenement(article: dict, iocs: list[dict], reponse: dict,
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
    menace = str(reponse.get("menace") or "").strip()
    resume = str(reponse.get("resume") or "").strip()
    titre = (article.get("titre") or article["url"])[:200]
    info = f"[AURA/{source['nom']}] {menace + ' — ' if menace else ''}{titre}"

    attributs = [{
        "type": "link", "category": "External analysis", "value": article["url"],
        "to_ids": False, "comment": "Source article",
    }]
    for ioc in iocs:
        type_misp = TYPE_MISP.get(ioc["type"]) or _type_hash(ioc["valeur"])
        attributs.append({
            "type": type_misp,
            "category": "Payload delivery" if ioc["type"] == "hash"
                        else "Network activity",
            "value": ioc["valeur"],
            "to_ids": True,
            "comment": ioc["role"] or resume[:100],
        })

    tags = [{"name": TAG_SOURCE}, {"name": f"aura:feed:{source['nom']}"},
            {"name": "tlp:clear"}]
    confiance = str(reponse.get("confiance") or "").lower()
    if confiance in ("haute", "moyenne", "basse"):
        tags.append({"name": f"aura:extraction-confidence:{confiance}"})
    if article.get("contexte"):
        tags.append({"name": "aura:attribution:malpedia"})

    corps = {"Event": {
        "info": info[:255],
        "date": (article.get("publie") or datetime.now(timezone.utc)).strftime("%Y-%m-%d"),
        "analysis": "2",
        "threat_level_id": "2",
        "distribution": "0",
        "published": True,
        "Attribute": attributs,
        "Tag": tags,
    }}
    reponse_misp = cti._misp("POST", "/events/add", corps)
    evenement = (reponse_misp or {}).get("Event") or {}
    return int(evenement["id"]) if evenement.get("id") else None


# ---------------------------------------------------------------------------
# Curseur
# ---------------------------------------------------------------------------

def _connexion():
    return psycopg.connect(config.PG_DSN)


def deja_vues(conn, source: str) -> set[str]:
    return {u for (u,) in conn.execute(
        "SELECT url FROM cti_articles WHERE source = %s", (source,))}


def marquer(conn, source: str, url: str, nb_iocs: int, event_id: int | None,
            menace: str = "", motif: str = "") -> None:
    conn.execute(
        "INSERT INTO cti_articles (source, url, iocs_retenus, misp_event_id, "
        "menace, motif) VALUES (%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (url) DO UPDATE SET iocs_retenus = EXCLUDED.iocs_retenus, "
        "misp_event_id = COALESCE(EXCLUDED.misp_event_id, cti_articles.misp_event_id), "
        "menace = EXCLUDED.menace, motif = EXCLUDED.motif",
        (source, url, nb_iocs, event_id, menace[:200], motif[:200]))
    conn.commit()


# ---------------------------------------------------------------------------
# Traitement
# ---------------------------------------------------------------------------

def charger_texte(article: dict) -> str:
    """Texte de l'article : celui du flux s'il est complet, sinon la page."""
    du_flux = texte_brut(article.get("contenu") or "")
    # Un extrait RSS fait quelques centaines de caractères : il ne contient
    # jamais la section des IOC. On ne s'en contente que s'il est substantiel.
    if len(du_flux) > 3000:
        return du_flux
    return texte_brut(_http(article["url"]).text)


def traiter(article: dict, source: dict, simulation: bool = False) -> dict:
    """Un article, de la récupération à l'événement MISP.

    Rend un compte rendu, y compris quand rien n'est retenu : « aucun IOC »
    est le résultat normal pour la majorité des articles de presse, et le
    tracer évite de retraiter le même texte à chaque passe.
    """
    resultat = {"url": article["url"], "iocs": [], "event_id": None,
                "menace": "", "motif": ""}
    try:
        article["texte"] = charger_texte(article)
    except Exception as exc:                                  # noqa: BLE001
        resultat["motif"] = f"article illisible : {exc}"
        return resultat
    if len(article["texte"]) < 500:
        resultat["motif"] = "texte trop court pour être un rapport"
        return resultat

    trouves = candidats(article["texte"])
    if not any(trouves.values()):
        resultat["motif"] = "aucun candidat dans le texte"
        return resultat

    reponse = arbitrer(article, trouves)
    iocs = valider(reponse, trouves)
    resultat["menace"] = str(reponse.get("menace") or "")[:200]
    if not iocs:
        resultat["motif"] = "aucun IOC retenu par l'arbitrage"
        return resultat
    plafond = int(source.get("max_iocs") or MAX_IOC_ARTICLE)
    if len(iocs) > plafond:
        # Ne pas publier plutôt que publier n'importe quoi, et le DIRE : une
        # troncature muette laisserait croire à une couverture complète.
        resultat["motif"] = (f"{len(iocs)} IOC extraits, au-delà du plafond "
                             f"de {plafond} : article non publié")
        log.warning("%s : %s", article["url"], resultat["motif"])
        return resultat

    connus = filtrer_warninglists([i["valeur"] for i in iocs])
    if connus:
        log.info("%d IOC écartés par les warninglists MISP", len(connus))
    iocs = [i for i in iocs if i["valeur"] not in connus]
    resultat["iocs"] = iocs
    if not iocs:
        resultat["motif"] = "tous les IOC écartés par les warninglists MISP"
        return resultat

    if not simulation:
        resultat["event_id"] = creer_evenement(article, iocs, reponse, source)
    return resultat


# Sources qui n'ont ni date ni flux de nouveautés : c'est le curseur des URL
# vues qui en tient lieu, donc elles DOIVENT être amorcées avant la première
# passe. Les flux RSS, eux, sont déjà bornés par leur fenêtre de fraîcheur.
TYPES_A_AMORCER = {"malpedia_references"}


def collecter(source: dict, deja: set[str], depuis: datetime,
              maximum: int, amorcage: bool, simulation: bool) -> list[dict]:
    if amorcage and source.get("type") not in TYPES_A_AMORCER:
        # Ne PAS marquer les flux RSS pendant un amorçage : ce serait griller
        # les articles récents, qui sont précisément ceux qu'on veut traiter à
        # la première vraie passe. L'amorçage n'existe que pour les sources sans
        # date (cf. TYPES_A_AMORCER).
        log.info("%s : rien à amorcer (source datée)", source["nom"])
        return []

    if source.get("type") == "malpedia_references":
        entrees = entrees_malpedia(source, deja)
    else:
        entrees = [e for e in entrees_rss(source, depuis) if e["url"] not in deja]
    log.info("%s : %d entrée(s) nouvelle(s)", source["nom"], len(entrees))

    if amorcage:
        # Marquer sans traiter : c'est ce qui rend la première exécution
        # possible sur une bibliographie de plusieurs dizaines de milliers de
        # rapports.
        return [{"url": e["url"], "iocs": [], "event_id": None, "menace": "",
                 "motif": "amorçage"} for e in entrees]

    resultats = []
    for entree in entrees[:maximum]:
        log.info("→ %s", entree["url"])
        resultats.append(traiter(entree, source, simulation=simulation))
    return resultats


def passe(nom_source: str | None = None, maximum: int = 10,
          heures: int = 48, amorcage: bool = False,
          simulation: bool = False) -> list[dict]:
    depuis = datetime.now(timezone.utc) - timedelta(hours=heures)
    tous = []
    with _connexion() as conn:
        for source in sources():
            if nom_source and source["nom"] != nom_source:
                continue
            deja = deja_vues(conn, source["nom"])
            try:
                resultats = collecter(source, deja, depuis, maximum, amorcage,
                                      simulation)
            except Exception as exc:                          # noqa: BLE001
                # Une source en panne ne doit pas emporter les autres : elles
                # sont indépendantes, et le renseignement perdu serait celui
                # de tout le monde.
                log.warning("source %s en échec : %s", source["nom"], exc)
                continue
            for r in resultats:
                if not simulation:
                    marquer(conn, source["nom"], r["url"], len(r["iocs"]),
                            r["event_id"], r["menace"], r["motif"])
                if r["iocs"]:
                    log.info("%d IOC publiés (event %s) — %s", len(r["iocs"]),
                             r["event_id"], r["menace"] or "menace non nommée")
            tous.extend(resultats)
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
        source = {"nom": args.source or "manuel"}
        r = traiter({"url": args.url, "titre": "", "publie": None,
                     "contenu": "", "contexte": ""}, source,
                    simulation=args.simulation)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    resultats = passe(args.source, args.max, args.heures, args.amorcage,
                      args.simulation)
    publies = sum(len(r["iocs"]) for r in resultats)
    log.info("%d article(s) traité(s), %d IOC%s", len(resultats), publies,
             " (simulation)" if args.simulation else " publiés dans MISP")
    if args.simulation:
        print(json.dumps([r for r in resultats if r["iocs"] or r["motif"]],
                         indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
