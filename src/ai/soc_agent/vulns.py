"""VOC : cycle de vie des vulnérabilités du parc, et exposition par machine.

Wazuh sait DÉTECTER les vulnérabilités (module Vulnerability Detection) mais pas
en SUIVRE la gestion. Son index `wazuh-states-vulnerabilities-*` est un index
d'état : quand un paquet est corrigé, le document est supprimé. On y lit donc en
permanence « où on en est », jamais « est-ce qu'on progresse ». Les trois
questions d'un VOC — la dette baisse-t-elle, en combien de temps corrige-t-on,
qui est hors délai — n'ont aucune réponse dans cet index, et les alertes 23504+
n'aident pas : elles datent la DÉTECTION, jamais la résolution.

Ce module construit l'historique manquant :

  scan  -> table `vulnerabilites` (journal : vue_a / derniere_vue / corrigee_a)
        -> index `wazuh-voc-*` (séries temporelles pour le dashboard VOC)
        -> `exposition()` (score de risque d'une machine, pour les cases IRIS)

Le score de risque pondère la charge de vulnérabilités par la priorité CMDB de
la machine (cf. assets.py) : compter les CVE à poids égal sur le contrôleur de
domaine et sur un poste de lab fait patcher dans le désordre.

    python -m soc_agent.vulns                  # scan + export
    python -m soc_agent.vulns --etat           # exposition du parc, sans écrire
    python -m soc_agent.vulns --agent 013      # détail d'une machine
    python -m soc_agent.vulns --simulation     # montre les documents, n'écrit pas
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import re
from datetime import datetime, timezone

import psycopg
import requests
import urllib3
from psycopg.rows import dict_row

from . import assets, config

log = logging.getLogger("vulns")

if not config.INDEXER_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------------------------------------------------
# Sévérité et poids
# --------------------------------------------------------------------------

# Seuils CVSS v3 officiels, pour reclasser une vulnérabilité dont le feed ne
# donne PAS de sévérité mais donne un score. Mesuré le 2026-08-12 : 334 CVE par
# hôte Debian arrivent avec `vulnerability.severity` vide. Les laisser toutes au
# poids « inconnu » revient à jeter l'information qu'on a effectivement.
_SEUILS_CVSS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def severite_effective(severite: str | None, score_base: float | None) -> str:
    """Sévérité exploitable : celle du feed, sinon celle déduite du score CVSS."""
    s = (severite or "").strip().lower()
    if s and s not in ("untriaged", "unknown", "none"):
        return s
    if score_base is not None:
        for seuil, nom in _SEUILS_CVSS:
            if score_base >= seuil:
                return nom
    return ""


def poids(severite: str) -> float:
    return config.VULN_POIDS_SEVERITE.get(severite, 0.5)


def sla_jours(severite: str, priorite: int) -> int | None:
    """Délai de correction attendu. None si la sévérité n'est pas classée —
    on ne réclame pas le respect d'une échéance qu'on n'a pas su fixer."""
    ligne = config.VOC_SLA_JOURS.get(severite)
    if not ligne:
        return None
    return ligne[max(1, min(4, int(priorite))) - 1]


def score_risque(charge: float) -> int:
    """Indice d'exposition 0-100 d'une machine, à partir de sa charge pondérée.

    Log-compressé (cf. `VOC_CHARGE_MAX`). Le revers est assumé et doit être dit
    partout où le score est affiché : au-delà du plafond, il SATURE — deux
    machines à 100 ne sont plus comparables entre elles, seuls les compteurs
    bruts exportés à côté les départagent.
    """
    if charge <= 0:
        return 0
    return max(0, min(100, round(
        100 * math.log10(1 + charge) / math.log10(1 + config.VOC_CHARGE_MAX))))


# Bornes de lecture du score. Purement descriptives : elles servent à écrire
# « exposition élevée » dans un case IRIS plutôt que « 68 », qui ne dit rien à
# qui n'a pas le reste du parc en tête.
def niveau_risque(score: int) -> str:
    if score >= 80:
        return "critique"
    if score >= 60:
        return "élevée"
    if score >= 35:
        return "modérée"
    if score > 0:
        return "faible"
    return "nulle"


# --------------------------------------------------------------------------
# Lecture de l'index d'état Wazuh
# --------------------------------------------------------------------------

def _scanner() -> list[dict]:
    """Toutes les vulnérabilités ouvertes du parc, telles que Wazuh les voit.

    API `scroll` et non `search_after` : la clé métier (agent, CVE, paquet) sert
    déjà de clé d'unicité en base, mais `package.name` est absent de certains
    documents Windows — un tri total dessus n'est donc pas garanti, et une
    pagination par `search_after` sauterait silencieusement des lignes. Le
    volume (quelques dizaines de milliers de documents, un shard) rend le scroll
    sans coût réel.
    """
    corps = {
        "size": 1000,
        "query": {"match_all": {}},
        "_source": ["agent.id", "agent.name", "package.name", "package.version",
                    "vulnerability.id", "vulnerability.severity",
                    "vulnerability.score.base", "vulnerability.published_at",
                    "vulnerability.detected_at", "host.os.full"],
    }
    verify = config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False
    auth = (config.INDEXER_USER, config.INDEXER_PASSWORD)

    r = requests.post(
        f"{config.INDEXER_URL}/{config.VULN_INDICES}/_search",
        params={"scroll": "2m"}, json=corps, auth=auth, verify=verify,
        timeout=120)
    # 404 = le module VD n'a jamais écrit (pas activé, ou premier feed en cours).
    # Cas normal d'un déploiement neuf : on rend une liste vide, l'appelant
    # n'écrit alors RIEN — surtout pas une clôture massive.
    if r.status_code == 404:
        log.warning("aucun index %s : module Vulnerability Detection inactif ?",
                    config.VULN_INDICES)
        return []
    r.raise_for_status()
    corps_rep = r.json()
    scroll_id = corps_rep.get("_scroll_id")
    hits = corps_rep["hits"]["hits"]
    tout: list[dict] = []

    try:
        while hits:
            tout += [h["_source"] for h in hits]
            r = requests.post(
                f"{config.INDEXER_URL}/_search/scroll",
                json={"scroll": "2m", "scroll_id": scroll_id},
                auth=auth, verify=verify, timeout=120)
            r.raise_for_status()
            corps_rep = r.json()
            scroll_id = corps_rep.get("_scroll_id")
            hits = corps_rep["hits"]["hits"]
    finally:
        if scroll_id:
            requests.delete(f"{config.INDEXER_URL}/_search/scroll",
                            json={"scroll_id": [scroll_id]}, auth=auth,
                            verify=verify, timeout=30)
    return tout


def _aplatir(src: dict) -> dict | None:
    """Document indexer -> ligne de `vulnerabilites`. None si inexploitable."""
    agent = src.get("agent") or {}
    paquet = src.get("package") or {}
    vuln = src.get("vulnerability") or {}
    cve = vuln.get("id")
    agent_id = agent.get("id")
    if not cve or not agent_id:
        return None
    score = (vuln.get("score") or {}).get("base")
    return {
        "agent_id": str(agent_id),
        "agent_name": agent.get("name"),
        "cve": str(cve),
        # Le paquet manque sur certaines entrées Windows (vulnérabilité de l'OS
        # lui-même, corrigée par un hotfix) : on retombe sur un libellé stable
        # plutôt que sur NULL, qui casserait la clé d'unicité.
        "paquet": paquet.get("name") or "(système)",
        "version": paquet.get("version"),
        "severite": severite_effective(vuln.get("severity"), score),
        "score_base": float(score) if score is not None else None,
        "publiee_a": vuln.get("published_at"),
        "os_nom": ((src.get("host") or {}).get("os") or {}).get("full"),
    }


# --------------------------------------------------------------------------
# Synchronisation : le journal
# --------------------------------------------------------------------------

UPSERT = """
INSERT INTO vulnerabilites (agent_id, agent_name, cve, paquet, version,
                            severite, score_base, publiee_a, os_nom,
                            vue_a, derniere_vue, statut)
VALUES (%(agent_id)s, %(agent_name)s, %(cve)s, %(paquet)s, %(version)s,
        %(severite)s, %(score_base)s, %(publiee_a)s, %(os_nom)s,
        now(), now(), 'ouverte')
ON CONFLICT (agent_id, cve, paquet) DO UPDATE SET
    agent_name   = EXCLUDED.agent_name,
    version      = EXCLUDED.version,
    severite     = EXCLUDED.severite,
    score_base   = EXCLUDED.score_base,
    publiee_a    = EXCLUDED.publiee_a,
    os_nom       = EXCLUDED.os_nom,
    derniere_vue = now(),
    -- `vue_a` n'est JAMAIS réécrite : c'est elle qui fait courir le SLA. Une
    -- vulnérabilité qui réapparaît après avoir été corrigée redémarre en
    -- revanche à zéro — c'est une régression, pas la poursuite de l'ancienne.
    vue_a        = CASE WHEN vulnerabilites.statut = 'corrigee'
                        THEN now() ELSE vulnerabilites.vue_a END,
    corrigee_a   = NULL,
    statut       = 'ouverte'
RETURNING (xmax = 0) AS cree
"""

# Clôture : uniquement sur les agents qui ont RÉPONDU à ce scan. Un agent
# arrêté, ou dont syscollector est cassé, sort de l'index d'état avec toutes ses
# vulnérabilités — sans ce filtre, le diff conclurait à une remédiation massive.
# Le burn-down serait parfait et le parc invisible : exactement le mensonge que
# ce module existe pour éviter.
CLOTURE = """
UPDATE vulnerabilites
   SET statut = 'corrigee', corrigee_a = now()
 WHERE statut = 'ouverte'
   AND agent_id = ANY(%(agents)s)
   AND derniere_vue < %(debut)s
"""


def synchroniser(conn, lignes: list[dict] | None = None) -> dict:
    """Confronte l'inventaire Wazuh au journal. Retourne le résumé du scan."""
    debut = datetime.now(timezone.utc)
    brut = _scanner() if lignes is None else lignes
    vues = [v for v in (_aplatir(s) for s in brut) if v]

    # Dédoublonnage sur la clé métier AVANT insertion : deux documents Wazuh
    # peuvent porter la même (machine, CVE, paquet) pour deux versions
    # différentes du paquet (cohabitation de noyaux). `ON CONFLICT` ne sait pas
    # traiter deux fois la même clé dans un seul `executemany` sous psycopg —
    # il lève `CardinalityViolation`. On garde la plus grave des deux.
    par_cle: dict[tuple, dict] = {}
    for v in vues:
        cle = (v["agent_id"], v["cve"], v["paquet"])
        ancien = par_cle.get(cle)
        if ancien is None or poids(v["severite"]) > poids(ancien["severite"]):
            par_cle[cle] = v
    vues = list(par_cle.values())

    agents_vus = sorted({v["agent_id"] for v in vues})
    if not vues:
        # Rien du tout : indexer vide, VD inactif, ou scan en cours. On ne
        # clôture rien et on le dit — un scan sans donnée n'est pas un parc sain.
        log.warning("scan de vulnérabilités vide : aucune clôture appliquée")
        with conn.cursor() as cur:
            cur.execute("INSERT INTO vuln_scans (agents_vus, vulns_vues) "
                        "VALUES (0, 0)")
        conn.commit()
        return {"agents_vus": 0, "vulns_vues": 0, "nouvelles": 0,
                "corrigees": 0, "agents_muets": []}

    nouvelles = 0
    with conn.cursor(row_factory=dict_row) as cur:
        for v in vues:
            r = cur.execute(UPSERT, v).fetchone()
            nouvelles += 1 if r["cree"] else 0
        cur.execute(CLOTURE, {"agents": agents_vus, "debut": debut})
        corrigees = max(cur.rowcount, 0)

        # Agents connus de la CMDB mais absents du scan. Deux causes très
        # différentes qu'on ne peut pas distinguer ici — OS non couvert par le
        # feed (pfSense/BSD, l'image du manager) ou capteur en panne — d'où la
        # trace brute, exploitée par le panneau « couverture » du dashboard.
        connus = {r["agent_id"] for r in cur.execute(
            "SELECT agent_id FROM assets").fetchall()}
        muets = sorted(connus - set(agents_vus))
        cur.execute(
            "INSERT INTO vuln_scans (agents_vus, vulns_vues, nouvelles, "
            "                        corrigees, agents_muets) "
            "VALUES (%s, %s, %s, %s, %s)",
            (len(agents_vus), len(vues), nouvelles, corrigees, muets))
    conn.commit()
    return {"agents_vus": len(agents_vus), "vulns_vues": len(vues),
            "nouvelles": nouvelles, "corrigees": corrigees,
            "agents_muets": muets}


# --------------------------------------------------------------------------
# Exposition d'une machine
# --------------------------------------------------------------------------

SQL_OUVERTES = """
SELECT cve, paquet, version, severite, score_base, publiee_a, vue_a,
       extract(epoch FROM now() - vue_a) / 86400 AS age_jours
  FROM vulnerabilites
 WHERE agent_id = %s AND statut = 'ouverte'
"""


def exposition(conn, agent_id: str) -> dict:
    """Exposition d'une machine : score, répartition, retard, pires CVE.

    Fonction de LECTURE, sans effet de bord : c'est elle que consomment la
    section IRIS et le serveur MCP. Rend un dict même quand la machine n'a
    aucune donnée — `couverte: False` — parce que « aucune vulnérabilité
    connue » et « jamais inventoriée » sont deux affirmations opposées qu'un
    rapport ne doit surtout pas confondre.
    """
    prio = assets.priorite_agent(conn, str(agent_id))
    lignes = [dict(r) for r in conn.execute(SQL_OUVERTES, (str(agent_id),))]
    facteur = config.VOC_FACTEUR_PRIORITE.get(prio["priorite"], 1.0)

    par_severite: dict[str, int] = {}
    charge = 0.0
    hors_sla: list[dict] = []
    for v in lignes:
        sev = v["severite"] or ""
        par_severite[sev] = par_severite.get(sev, 0) + 1
        charge += poids(sev)
        delai = sla_jours(sev, prio["priorite"])
        if delai is not None and v["age_jours"] > delai:
            hors_sla.append({**v, "sla_jours": delai,
                             "retard_jours": round(v["age_jours"] - delai, 1)})

    score = score_risque(charge * facteur)
    # Tri des « pires » : sévérité d'abord, puis score CVSS, puis ancienneté.
    # L'ancienneté départage volontairement en dernier — une critical d'hier
    # passe avant une high de l'an dernier.
    pires = sorted(
        lignes,
        key=lambda v: (-poids(v["severite"] or ""), -(v["score_base"] or 0),
                       -v["age_jours"]))[:config.VOC_MAX_CVE_RAPPORT]

    corrigees = conn.execute(
        "SELECT count(*) AS n, "
        "       avg(extract(epoch FROM corrigee_a - vue_a) / 86400) AS mttr "
        "  FROM vulnerabilites "
        " WHERE agent_id = %s AND statut = 'corrigee' "
        "   AND corrigee_a >= now() - interval '90 days'",
        (str(agent_id),)).fetchone()

    return {
        "agent_id": str(agent_id),
        # Nom résolu ici et non chez l'appelant : la CLI, l'export vers
        # l'indexer et la note IRIS doivent désigner la machine de la même
        # façon. La CMDB fait foi (elle suit les renommages du manager), le nom
        # figé dans le journal ne sert que de repli.
        "agent_name": _nom_agent(conn, str(agent_id)),
        "couverte": bool(lignes) or _deja_scanne(conn, str(agent_id)),
        "priorite": prio["priorite"],
        "role": prio["role"],
        "score": score,
        "niveau": niveau_risque(score),
        "charge": round(charge, 1),
        "facteur_priorite": facteur,
        "total": len(lignes),
        "par_severite": par_severite,
        "critiques": par_severite.get("critical", 0),
        "elevees": par_severite.get("high", 0),
        "hors_sla": sorted(hors_sla, key=lambda v: -v["retard_jours"]),
        "hors_sla_total": len(hors_sla),
        "plus_ancienne_jours": round(max((v["age_jours"] for v in lignes),
                                         default=0), 1),
        "pires": pires,
        "corrigees_90j": corrigees["n"],
        "mttr_jours": round(corrigees["mttr"], 1) if corrigees["mttr"] else None,
    }


def _nom_agent(conn, agent_id: str) -> str | None:
    ligne = conn.execute(
        "SELECT coalesce(a.nom, v.agent_name) AS nom "
        "  FROM (SELECT %s::text AS id) x "
        "  LEFT JOIN assets a ON a.agent_id = x.id "
        "  LEFT JOIN LATERAL (SELECT agent_name FROM vulnerabilites "
        "                      WHERE agent_id = x.id LIMIT 1) v ON true",
        (agent_id,)).fetchone()
    return ligne["nom"] if ligne else None


def _deja_scanne(conn, agent_id: str) -> bool:
    """Cet agent a-t-il DÉJÀ figuré dans un inventaire ? Distingue « rien à
    signaler » de « jamais vu » quand la liste ouverte est vide."""
    return bool(conn.execute(
        "SELECT 1 FROM vulnerabilites WHERE agent_id = %s LIMIT 1",
        (agent_id,)).fetchone())


def exposition_parc(conn) -> list[dict]:
    """Exposition de chaque machine ayant au moins une vulnérabilité connue."""
    ids = [r["agent_id"] for r in conn.execute(
        "SELECT DISTINCT agent_id FROM vulnerabilites ORDER BY agent_id")]
    return sorted((exposition(conn, a) for a in ids),
                  key=lambda e: -e["score"])


# --------------------------------------------------------------------------
# Rapprochement avec un incident
# --------------------------------------------------------------------------

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Techniques ATT&CK dont la réussite SUPPOSE une vulnérabilité logicielle. Leur
# présence dans un incident ne prouve pas qu'une CVE de la machine a été
# exploitée — c'est une piste, et la section le dit en toutes lettres. Sans ce
# garde-fou de formulation, un rapport transformerait une corrélation en cause.
TECHNIQUES_EXPLOIT = {
    "T1190",      # exploitation d'une application exposée
    "T1210",      # exploitation d'un service distant
    "T1068",      # élévation de privilèges par exploitation
    "T1211",      # contournement de défense par exploitation
    "T1212",      # exploitation pour l'accès aux identifiants
    "T1203",      # exécution par exploitation côté client
}


def cves_citees(alertes: list[dict]) -> set[str]:
    """Identifiants CVE apparaissant littéralement dans les alertes.

    C'est le SEUL lien certain entre un incident et une vulnérabilité : une CVE
    écrite dans une ligne de commande ou un nom de fichier (règle locale 100660,
    « CVE identifier in command ») dit ce que l'attaquant CHERCHAIT. Tout le
    reste est une hypothèse.
    """
    trouvees: set[str] = set()
    for a in alertes:
        raw = a.get("raw")
        if isinstance(raw, (dict, list)):
            raw = json.dumps(raw)
        for champ in (a.get("rule_desc"), raw):
            if champ:
                trouvees |= {m.upper() for m in _CVE.findall(str(champ))}
    return trouvees


def lien_incident(conn, agent_id: str, alertes: list[dict],
                  expo: dict | None = None) -> dict:
    """Ce qui rattache l'exposition de la machine à CET incident.

    Trois degrés de certitude, jamais mélangés :

    - `confirmees` : la CVE est citée dans les alertes ET ouverte sur la
      machine. Fait, pas déduction.
    - `citees_non_ouvertes` : la CVE est citée mais n'est pas (ou plus) ouverte
      ici. Information à part entière — tentative sur une machine non
      vulnérable, ou vulnérabilité déjà corrigée.
    - `vecteurs_possibles` : l'incident porte une technique d'exploitation et la
      machine a des vulnérabilités graves ouvertes. Aucune preuve de lien.
    """
    expo = expo or exposition(conn, agent_id)
    citees = cves_citees(alertes)
    ouvertes = {v["cve"]: v for v in conn.execute(
        SQL_OUVERTES, (str(agent_id),))} if citees else {}

    techniques = set()
    for a in alertes:
        techniques |= {str(m).upper() for m in (a.get("mitre_ids") or [])}
    exploit = sorted(techniques & TECHNIQUES_EXPLOIT)

    confirmees = [dict(ouvertes[c]) for c in sorted(citees) if c in ouvertes]
    return {
        "confirmees": confirmees,
        "citees_non_ouvertes": sorted(citees - set(ouvertes)),
        "techniques_exploit": exploit,
        # Les vecteurs ne sont proposés que si l'incident porte réellement une
        # technique d'exploitation : sinon la section listerait les pires CVE de
        # la machine à côté d'un incident qui n'a rien à voir, et l'analyste
        # ferait le lien à notre place.
        "vecteurs_possibles": (
            [v for v in expo["pires"]
             if (v["severite"] or "") in ("critical", "high")][:5]
            if exploit else []),
    }


# --------------------------------------------------------------------------
# Export vers l'indexer (dashboard VOC)
# --------------------------------------------------------------------------

def _index_serie(ts: datetime) -> str:
    """Index quotidien des séries temporelles (`wazuh-voc-YYYY.MM.DD`)."""
    return f"{config.VOC_INDEX_PREFIX}-{ts.astimezone(timezone.utc):%Y.%m.%d}"


# Index STABLE et non daté pour les documents de cycle de vie. Leur `_id` est
# déterministe (une vulnérabilité = un document, réécrit à chaque passage) : le
# ranger dans un index daté en créerait une copie par jour, chacune figée sur
# l'état de son jour, et les compteurs seraient multipliés par la rétention.
INDEX_VULNS = "vulns"


def _id_vuln(v: dict) -> str:
    cle = f"{v['agent_id']}|{v['cve']}|{v['paquet']}"
    return "vuln-" + hashlib.sha1(cle.encode("utf-8")).hexdigest()[:24]


def _doc_vuln(v: dict, priorite: int) -> dict:
    """Une vulnérabilité et son cycle de vie. @timestamp = première observation :
    un document se lit à la date où le problème est apparu, pas à celle du run."""
    sev = v["severite"] or ""
    delai = sla_jours(sev, priorite)
    age = (v["age_jours"] if v["corrigee_a"] is None
           else (v["corrigee_a"] - v["vue_a"]).total_seconds() / 86400)
    return {
        "@timestamp": v["vue_a"].astimezone(timezone.utc).isoformat(),
        "timestamp": v["vue_a"].astimezone(timezone.utc).isoformat(),
        "event_type": "voc_vuln",
        "agent": {"id": v["agent_id"], "name": v["agent_name"]},
        "asset": {"priorite": priorite, "priorite_label": f"P{priorite}"},
        "vulnerability": {
            "id": v["cve"],
            "severity": sev or "unknown",
            "score_base": v["score_base"],
            "published_at": (v["publiee_a"].astimezone(timezone.utc).isoformat()
                             if v["publiee_a"] else None),
        },
        "package": {"name": v["paquet"], "version": v["version"]},
        "voc": {
            "statut": v["statut"],
            "resolue": v["statut"] == "corrigee",
            "vue_a": v["vue_a"].astimezone(timezone.utc).isoformat(),
            "corrigee_a": (v["corrigee_a"].astimezone(timezone.utc).isoformat()
                           if v["corrigee_a"] else None),
            # Un seul champ pour deux sens selon le statut, et c'est voulu :
            # c'est l'âge tant que c'est ouvert, le délai de correction une fois
            # résolu. Le MTTR se lit donc en filtrant sur `voc.resolue: true`.
            "age_jours": round(age, 2),
            "sla_jours": delai,
            "hors_sla": bool(delai is not None and v["statut"] == "ouverte"
                             and age > delai),
            "retard_jours": (round(age - delai, 2)
                             if delai is not None and age > delai else 0),
            "poids": poids(sev),
        },
    }


def _doc_asset(e: dict, maintenant: datetime) -> dict:
    """Exposition d'une machine à l'instant du run — le point de la courbe."""
    return {
        "@timestamp": maintenant.isoformat(),
        "timestamp": maintenant.isoformat(),
        "event_type": "voc_asset",
        "agent": {"id": e["agent_id"], "name": e.get("agent_name")},
        "asset": {"priorite": e["priorite"], "priorite_label": f"P{e['priorite']}",
                  "role": e["role"]},
        "voc": {
            "score": e["score"],
            "niveau": e["niveau"],
            "charge": e["charge"],
            "ouvertes": e["total"],
            "critical": e["par_severite"].get("critical", 0),
            "high": e["par_severite"].get("high", 0),
            "medium": e["par_severite"].get("medium", 0),
            "low": e["par_severite"].get("low", 0),
            "inconnue": e["par_severite"].get("", 0),
            # `hors_sla_total` et non `hors_sla` : sur un document `voc_vuln`,
            # `voc.hors_sla` est un BOOLÉEN. Deux types sous le même nom de
            # champ dans un même index font rejeter le document par
            # OpenSearch — et un rejet en bulk est silencieux si l'on ne lit pas
            # la réponse.
            "hors_sla_total": e["hors_sla_total"],
            "plus_ancienne_jours": e["plus_ancienne_jours"],
            "corrigees_90j": e["corrigees_90j"],
            "mttr_jours": e["mttr_jours"],
        },
    }


def _doc_parc(conn, expos: list[dict], scan: dict, maintenant: datetime) -> dict:
    """Vue parc. Porte la COUVERTURE en premier : une dette qui baisse parce que
    des machines ont cessé de répondre n'est pas une amélioration, et c'est le
    seul chiffre qui permet de le voir."""
    inventories = {r["agent_id"] for r in conn.execute(
        "SELECT DISTINCT agent_id FROM vulnerabilites")}
    total_assets = conn.execute(
        "SELECT count(*) AS n FROM assets").fetchone()["n"]
    somme = lambda cle: sum(e["par_severite"].get(cle, 0) for e in expos)  # noqa: E731
    return {
        "@timestamp": maintenant.isoformat(),
        "timestamp": maintenant.isoformat(),
        "event_type": "voc_parc",
        "voc": {
            "machines_inventoriees": len(inventories),
            "machines_scannees": scan["agents_vus"],
            "machines_connues": total_assets,
            "couverture_pct": (round(100 * scan["agents_vus"] / total_assets, 1)
                               if total_assets else None),
            "machines_muettes": len(scan["agents_muets"]),
            "ouvertes": sum(e["total"] for e in expos),
            "critical": somme("critical"),
            "high": somme("high"),
            "medium": somme("medium"),
            "low": somme("low"),
            "hors_sla_total": sum(e["hors_sla_total"] for e in expos),
            "nouvelles": scan["nouvelles"],
            "corrigees": scan["corrigees"],
            "score_max": max((e["score"] for e in expos), default=0),
            "score_moyen": (round(sum(e["score"] for e in expos) / len(expos), 1)
                            if expos else 0),
        },
    }


def _bulk(lignes: list[str]) -> tuple[int, list[str]]:
    if not lignes:
        return 0, []
    r = requests.post(
        f"{config.INDEXER_URL}/_bulk",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data="".join(lignes).encode("utf-8"),
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=180)
    r.raise_for_status()
    corps = r.json()
    erreurs = []
    if corps.get("errors"):
        for item in corps.get("items", []):
            info = next(iter(item.values()))
            if info.get("error"):
                erreurs.append(json.dumps(info["error"])[:300])
    return len(corps.get("items", [])) - len(erreurs), erreurs


def _ligne(index: str, doc_id: str, doc: dict) -> list[str]:
    return [json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n",
            json.dumps(doc, default=str) + "\n"]


SQL_DETAIL = """
SELECT agent_id, agent_name, cve, paquet, version, severite, score_base,
       publiee_a, vue_a, corrigee_a, statut,
       extract(epoch FROM now() - vue_a) / 86400 AS age_jours
  FROM vulnerabilites
 WHERE (statut = 'ouverte' AND severite = ANY(%(sev)s))
    OR (statut = 'corrigee' AND corrigee_a >= now() - interval '180 days')
"""


def exporter(conn, scan: dict, simulation: bool = False) -> dict:
    """Écrit les séries VOC dans l'indexer. Idempotent (`_id` déterministe)."""
    maintenant = datetime.now(timezone.utc)
    expos = exposition_parc(conn)
    lignes: list[str] = []
    resume = {"voc_asset": 0, "voc_parc": 0, "voc_vuln": 0}

    # `_id` à l'HEURE : le job tourne plus souvent que ça (rattrapage, relance
    # manuelle) et on ne veut ni écraser le point précédent ni empiler dix
    # points par heure. Une courbe horaire suffit largement pour une dette qui
    # bouge à la journée.
    heure = f"{maintenant:%Y%m%d%H}"
    for e in expos:
        lignes += _ligne(_index_serie(maintenant),
                         f"asset-{e['agent_id']}-{heure}",
                         _doc_asset(e, maintenant))
        resume["voc_asset"] += 1

    lignes += _ligne(_index_serie(maintenant), f"parc-{heure}",
                     _doc_parc(conn, expos, scan, maintenant))
    resume["voc_parc"] = 1

    prios = {e["agent_id"]: e["priorite"] for e in expos}
    for v in conn.execute(SQL_DETAIL,
                          {"sev": sorted(config.VOC_SEVERITES_DETAIL)}):
        prio = prios.get(v["agent_id"], config.PRIORITE_DEFAUT)
        lignes += _ligne(f"{config.VOC_INDEX_PREFIX}-{INDEX_VULNS}",
                         _id_vuln(v), _doc_vuln(dict(v), prio))
        resume["voc_vuln"] += 1

    if simulation:
        for l in lignes:
            print(l, end="")
        return resume

    ecrits, erreurs = _bulk(lignes)
    resume["ecrits"] = ecrits
    resume["erreurs"] = erreurs
    return resume


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _afficher_parc(expos: list[dict]) -> None:
    print(f"{'agent':<6}{'machine':<22}{'P':<4}{'score':>6}  "
          f"{'crit':>5}{'high':>6}{'ouvert':>8}{'horsSLA':>9}  niveau")
    print("-" * 82)
    for e in expos:
        print(f"{e['agent_id']:<6}{(e.get('agent_name') or '?')[:21]:<22}"
              f"P{e['priorite']:<3}{e['score']:>6}  "
              f"{e['par_severite'].get('critical', 0):>5}"
              f"{e['par_severite'].get('high', 0):>6}"
              f"{e['total']:>8}{e['hors_sla_total']:>9}  {e['niveau']}")


def _afficher_agent(e: dict) -> None:
    print(f"Agent {e['agent_id']} — P{e['priorite']} "
          f"({e['role'] or 'rôle non déclaré'})")
    if not e["couverte"]:
        print("  JAMAIS INVENTORIÉE : aucune donnée de vulnérabilité. "
              "« 0 CVE » ne veut pas dire « à jour ».")
        return
    print(f"  score d'exposition : {e['score']}/100 ({e['niveau']}) — "
          f"charge {e['charge']} x{e['facteur_priorite']} (priorité)")
    print(f"  ouvertes : {e['total']} "
          + ", ".join(f"{k or 'sans sévérité'}={v}"
                      for k, v in sorted(e["par_severite"].items())))
    print(f"  hors SLA : {e['hors_sla_total']} — plus ancienne : "
          f"{e['plus_ancienne_jours']} j")
    if e["mttr_jours"] is not None:
        print(f"  corrigées sur 90 j : {e['corrigees_90j']} "
              f"(délai moyen {e['mttr_jours']} j)")
    print("  pires vulnérabilités :")
    for v in e["pires"]:
        print(f"    {v['cve']:<18}{(v['severite'] or '?'):<10}"
              f"{(v['score_base'] or 0):>5}  {v['paquet'][:32]:<34}"
              f"{v['age_jours']:.0f} j")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--etat", action="store_true",
                    help="exposition du parc, sans scanner ni écrire")
    ap.add_argument("--agent", metavar="AGENT_ID",
                    help="détail de l'exposition d'une machine")
    ap.add_argument("--sans-export", action="store_true",
                    help="scanne et met à jour le journal, sans exporter")
    ap.add_argument("--simulation", action="store_true",
                    help="affiche les documents au lieu de les indexer")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if args.agent:
            _afficher_agent(exposition(conn, args.agent))
            return
        if args.etat:
            _afficher_parc(exposition_parc(conn))
            return

        scan = synchroniser(conn)
        print(f"{scan['vulns_vues']} vulnérabilité(s) sur "
              f"{scan['agents_vus']} machine(s) : {scan['nouvelles']} nouvelle(s), "
              f"{scan['corrigees']} corrigée(s)")
        if scan["agents_muets"]:
            print(f"  {len(scan['agents_muets'])} machine(s) sans inventaire : "
                  f"{', '.join(scan['agents_muets'])} — OS non couvert par le "
                  f"feed, ou syscollector muet. Rien n'a été clôturé pour elles.")
        if args.sans_export:
            return
        r = exporter(conn, scan, args.simulation)
        if args.simulation:
            return
        print(f"  {r['ecrits']} document(s) indexés "
              f"({r['voc_asset']} machines, {r['voc_vuln']} vulnérabilités, "
              f"1 vue parc)")
        for e in r["erreurs"]:
            print(f"  ERREUR {e}")


if __name__ == "__main__":
    main()
