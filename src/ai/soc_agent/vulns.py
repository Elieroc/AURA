"""VOC : cycle de vie des vulnérabilités du parc, et exposition par machine.

Wazuh sait DÉTECTER les vulnérabilités (module Vulnerability Detection) mais pas
en SUIVRE la gestion. Son index `wazuh-states-vulnerabilities-*` est un index
d'état : quand un paquet est corrigé, le document est supprimé. On y lit donc en
permanence « où on en est », jamais « est-ce qu'on progresse ». Les trois
questions d'un VOC — la dette baisse-t-elle, en combien de temps corrige-t-on,
qui est hors délai — n'ont aucune réponse dans cet index, et les alertes 23504+
n'aident pas : elles datent la DÉTECTION, jamais la résolution.

Ce module construit l'historique manquant :

  scan  -> table `vulnerabilites` (journal : first_seen / derniere_vue / corrigee_a)
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
_THRESHOLDS_CVSS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def effective_severity(severity: str | None, score_base: float | None) -> str:
    """Sévérité exploitable : celle du feed, sinon celle déduite du score CVSS."""
    s = (severity or "").strip().lower()
    if s and s not in ("untriaged", "unknown", "none"):
        return s
    if score_base is not None:
        for threshold, name in _THRESHOLDS_CVSS:
            if score_base >= threshold:
                return name
    return ""


def weight(severity: str) -> float:
    return config.VULN_SEVERITY_WEIGHT.get(severity, 0.5)


def sla_days(severity: str, priority: int) -> int | None:
    """Délai de correction attendu. None si la sévérité n'est pas classée —
    on ne réclame pas le respect d'une échéance qu'on n'a pas su fixer."""
    line = config.VOC_SLA_DAYS.get(severity)
    if not line:
        return None
    return line[max(1, min(4, int(priority))) - 1]


def risk_score(charge: float) -> int:
    """Indice d'exposition 0-100 d'une machine, à partir de sa charge pondérée.

    Log-compressé (cf. `VOC_MAX_LOAD`). Le revers est assumé et doit être dit
    partout où le score est affiché : au-delà du plafond, il SATURE — deux
    machines à 100 ne sont plus comparables entre elles, seuls les compteurs
    bruts exportés à côté les départagent.
    """
    if charge <= 0:
        return 0
    return max(0, min(100, round(
        100 * math.log10(1 + charge) / math.log10(1 + config.VOC_MAX_LOAD))))


# Bornes de lecture du score. Purement descriptives : elles servent à écrire
# « exposition élevée » dans un case IRIS plutôt que « 68 », qui ne dit rien à
# qui n'a pas le reste du parc en tête.
def risk_level(score: int) -> str:
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

def _scan() -> list[dict]:
    """Toutes les vulnérabilités ouvertes du parc, telles que Wazuh les voit.

    API `scroll` et non `search_after` : la clé métier (agent, CVE, paquet) sert
    déjà de clé d'unicité en base, mais `package.name` est absent de certains
    documents Windows — un tri total dessus n'est donc pas garanti, et une
    pagination par `search_after` sauterait silencieusement des lignes. Le
    volume (quelques dizaines de milliers de documents, un shard) rend le scroll
    sans coût réel.
    """
    body = {
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
        params={"scroll": "2m"}, json=body, auth=auth, verify=verify,
        timeout=120)
    # 404 = le module VD n'a jamais écrit (pas activé, ou premier feed en cours).
    # Cas normal d'un déploiement neuf : on rend une liste vide, l'appelant
    # n'écrit alors RIEN — surtout pas une clôture massive.
    if r.status_code == 404:
        log.warning("aucun index %s : module Vulnerability Detection inactif ?",
                    config.VULN_INDICES)
        return []
    r.raise_for_status()
    resp_body = r.json()
    scroll_id = resp_body.get("_scroll_id")
    hits = resp_body["hits"]["hits"]
    tout: list[dict] = []

    try:
        while hits:
            tout += [h["_source"] for h in hits]
            r = requests.post(
                f"{config.INDEXER_URL}/_search/scroll",
                json={"scroll": "2m", "scroll_id": scroll_id},
                auth=auth, verify=verify, timeout=120)
            r.raise_for_status()
            resp_body = r.json()
            scroll_id = resp_body.get("_scroll_id")
            hits = resp_body["hits"]["hits"]
    finally:
        if scroll_id:
            requests.delete(f"{config.INDEXER_URL}/_search/scroll",
                            json={"scroll_id": [scroll_id]}, auth=auth,
                            verify=verify, timeout=30)
    return tout


def _flatten(src: dict) -> dict | None:
    """Document indexer -> ligne de `vulnerabilites`. None si inexploitable."""
    agent = src.get("agent") or {}
    package = src.get("package") or {}
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
        "package": package.get("name") or "(système)",
        "version": package.get("version"),
        "severity": effective_severity(vuln.get("severity"), score),
        "base_score": float(score) if score is not None else None,
        "published_at": vuln.get("published_at"),
        "os_name": ((src.get("host") or {}).get("os") or {}).get("full"),
    }


# --------------------------------------------------------------------------
# Synchronisation : le journal
# --------------------------------------------------------------------------

UPSERT = """
INSERT INTO vulnerabilities (agent_id, agent_name, cve, package, version,
                            severity, base_score, published_at, os_name,
                            first_seen, last_seen, status)
VALUES (%(agent_id)s, %(agent_name)s, %(cve)s, %(package)s, %(version)s,
        %(severity)s, %(base_score)s, %(published_at)s, %(os_name)s,
        now(), now(), 'open')
ON CONFLICT (agent_id, cve, package) DO UPDATE SET
    agent_name   = EXCLUDED.agent_name,
    version      = EXCLUDED.version,
    severity     = EXCLUDED.severity,
    base_score   = EXCLUDED.base_score,
    published_at    = EXCLUDED.published_at,
    os_name       = EXCLUDED.os_name,
    last_seen = now(),
    -- `first_seen` n'est JAMAIS réécrite : c'est elle qui fait courir le SLA. Une
    -- vulnérabilité qui réapparaît après avoir été corrigée redémarre en
    -- revanche à zéro — c'est une régression, pas la poursuite de l'ancienne.
    first_seen        = CASE WHEN vulnerabilities.status = 'fixed'
                        THEN now() ELSE vulnerabilities.first_seen END,
    fixed_at   = NULL,
    status       = 'open'
RETURNING (xmax = 0) AS cree
"""

# Clôture : uniquement sur les agents qui ont RÉPONDU à ce scan. Un agent
# arrêté, ou dont syscollector est cassé, sort de l'index d'état avec toutes ses
# vulnérabilités — sans ce filtre, le diff conclurait à une remédiation massive.
# Le burn-down serait parfait et le parc invisible : exactement le mensonge que
# ce module existe pour éviter.
CLOSURE = """
UPDATE vulnerabilities
   SET status = 'fixed', fixed_at = now()
 WHERE status = 'open'
   AND agent_id = ANY(%(agents)s)
   AND last_seen < %(start_ts)s
"""


def sync(conn, lines: list[dict] | None = None) -> dict:
    """Confronte l'inventaire Wazuh au journal. Retourne le résumé du scan."""
    start = datetime.now(timezone.utc)
    raw = _scan() if lines is None else lines
    seen = [v for v in (_flatten(s) for s in raw) if v]

    # Dédoublonnage sur la clé métier AVANT insertion : deux documents Wazuh
    # peuvent porter la même (machine, CVE, paquet) pour deux versions
    # différentes du paquet (cohabitation de noyaux). `ON CONFLICT` ne sait pas
    # traiter deux fois la même clé dans un seul `executemany` sous psycopg —
    # il lève `CardinalityViolation`. On garde la plus grave des deux.
    by_key: dict[tuple, dict] = {}
    for v in seen:
        key = (v["agent_id"], v["cve"], v["package"])
        old = by_key.get(key)
        if old is None or weight(v["severity"]) > weight(old["severity"]):
            by_key[key] = v
    seen = list(by_key.values())

    agents_seen = sorted({v["agent_id"] for v in seen})
    if not seen:
        # Rien du tout : indexer vide, VD inactif, ou scan en cours. On ne
        # clôture rien et on le dit — un scan sans donnée n'est pas un parc sain.
        log.warning("scan de vulnérabilités vide : aucune clôture appliquée")
        with conn.cursor() as cur:
            cur.execute("INSERT INTO vuln_scans (agents_seen, vulns_seen) "
                        "VALUES (0, 0)")
        conn.commit()
        return {"agents_seen": 0, "vulns_seen": 0, "new_count": 0,
                "fixed_count": 0, "silent_agents": []}

    new = 0
    with conn.cursor(row_factory=dict_row) as cur:
        for v in seen:
            r = cur.execute(UPSERT, v).fetchone()
            new += 1 if r["cree"] else 0
        cur.execute(CLOSURE, {"agents": agents_seen, "start_ts": start})
        fixed = max(cur.rowcount, 0)

        # Agents connus de la CMDB mais absents du scan. Deux causes très
        # différentes qu'on ne peut pas distinguer ici — OS non couvert par le
        # feed (pfSense/BSD, l'image du manager) ou capteur en panne — d'où la
        # trace brute, exploitée par le panneau « couverture » du dashboard.
        known = {r["agent_id"] for r in cur.execute(
            "SELECT agent_id FROM assets").fetchall()}
        silent = sorted(known - set(agents_seen))
        cur.execute(
            "INSERT INTO vuln_scans (agents_seen, vulns_seen, new_count, "
            "                        fixed_count, silent_agents) "
            "VALUES (%s, %s, %s, %s, %s)",
            (len(agents_seen), len(seen), new, fixed, silent))
    conn.commit()
    return {"agents_seen": len(agents_seen), "vulns_seen": len(seen),
            "new_count": new, "fixed_count": fixed,
            "silent_agents": silent}


# --------------------------------------------------------------------------
# Exposition d'une machine
# --------------------------------------------------------------------------

SQL_OPEN = """
SELECT cve, package, version, severity, base_score, published_at, first_seen,
       extract(epoch FROM now() - first_seen) / 86400 AS age_jours
  FROM vulnerabilities
 WHERE agent_id = %s AND status = 'open'
"""


def exposure(conn, agent_id: str) -> dict:
    """Exposition d'une machine : score, répartition, retard, pires CVE.

    Fonction de LECTURE, sans effet de bord : c'est elle que consomment la
    section IRIS et le serveur MCP. Rend un dict même quand la machine n'a
    aucune donnée — `couverte: False` — parce que « aucune vulnérabilité
    connue » et « jamais inventoriée » sont deux affirmations opposées qu'un
    rapport ne doit surtout pas confondre.
    """
    prio = assets.agent_priority(conn, str(agent_id))
    lines = [dict(r) for r in conn.execute(SQL_OPEN, (str(agent_id),))]
    factor = config.VOC_PRIORITY_FACTOR.get(prio["priority"], 1.0)

    by_severity: dict[str, int] = {}
    charge = 0.0
    outside_sla: list[dict] = []
    for v in lines:
        sev = v["severity"] or ""
        by_severity[sev] = by_severity.get(sev, 0) + 1
        charge += weight(sev)
        delay = sla_days(sev, prio["priority"])
        if delay is not None and v["age_jours"] > delay:
            outside_sla.append({**v, "sla_jours": delay,
                             "retard_jours": round(v["age_jours"] - delay, 1)})

    score = risk_score(charge * factor)
    # Tri des « pires » : sévérité d'abord, puis score CVSS, puis ancienneté.
    # L'ancienneté départage volontairement en dernier — une critical d'hier
    # passe avant une high de l'an dernier.
    worst = sorted(
        lines,
        key=lambda v: (-weight(v["severity"] or ""), -(v["base_score"] or 0),
                       -v["age_jours"]))[:config.VOC_MAX_CVE_REPORT]

    fixed = conn.execute(
        "SELECT count(*) AS n, "
        "       avg(extract(epoch FROM fixed_at - first_seen) / 86400) AS mttr "
        "  FROM vulnerabilities "
        " WHERE agent_id = %s AND status = 'fixed' "
        "   AND fixed_at >= now() - interval '90 days'",
        (str(agent_id),)).fetchone()

    return {
        "agent_id": str(agent_id),
        # Nom résolu ici et non chez l'appelant : la CLI, l'export vers
        # l'indexer et la note IRIS doivent désigner la machine de la même
        # façon. La CMDB fait foi (elle suit les renommages du manager), le nom
        # figé dans le journal ne sert que de repli.
        "agent_name": _agent_name(conn, str(agent_id)),
        "couverte": bool(lines) or _already_scanned(conn, str(agent_id)),
        "priority": prio["priority"],
        "role": prio["role"],
        "score": score,
        "niveau": risk_level(score),
        "charge": round(charge, 1),
        "facteur_priorite": factor,
        "total": len(lines),
        "par_severite": by_severity,
        "critiques": by_severity.get("critical", 0),
        "elevees": by_severity.get("high", 0),
        "hors_sla": sorted(outside_sla, key=lambda v: -v["retard_jours"]),
        "hors_sla_total": len(outside_sla),
        "plus_ancienne_jours": round(max((v["age_jours"] for v in lines),
                                         default=0), 1),
        "journal_jours": log_age(conn),
        "pires": worst,
        "corrigees_90j": fixed["n"],
        "mttr_jours": round(fixed["mttr"], 1) if fixed["mttr"] else None,
    }


def log_age(conn) -> float | None:
    """Âge du journal en jours, ou None s'il n'a jamais tourné.

    Indispensable pour lire honnêtement l'ancienneté et le retard : ces deux
    grandeurs se comptent depuis NOTRE première observation, pas depuis la
    publication de la CVE. Un journal de trois jours affiche donc « plus ancienne
    ouverte : 3 jours » et « 0 hors délai » sur un parc qui traîne des CVE de
    2019 — chiffres exacts, conclusion inverse de la vérité si l'on ne dit pas
    depuis quand on mesure.
    """
    line = conn.execute(
        "SELECT extract(epoch FROM now() - min(started_at)) / 86400 AS j "
        "  FROM vuln_scans").fetchone()
    return round(line["j"], 1) if line and line["j"] is not None else None


def _agent_name(conn, agent_id: str) -> str | None:
    line = conn.execute(
        "SELECT coalesce(a.name, v.agent_name) AS name "
        "  FROM (SELECT %s::text AS id) x "
        "  LEFT JOIN assets a ON a.agent_id = x.id "
        "  LEFT JOIN LATERAL (SELECT agent_name FROM vulnerabilities "
        "                      WHERE agent_id = x.id LIMIT 1) v ON true",
        (agent_id,)).fetchone()
    return line["name"] if line else None


def _already_scanned(conn, agent_id: str) -> bool:
    """Cet agent a-t-il DÉJÀ figuré dans un inventaire ? Distingue « rien à
    signaler » de « jamais vu » quand la liste ouverte est vide."""
    return bool(conn.execute(
        "SELECT 1 FROM vulnerabilities WHERE agent_id = %s LIMIT 1",
        (agent_id,)).fetchone())


def fleet_exposure(conn) -> list[dict]:
    """Exposition de chaque machine ayant au moins une vulnérabilité connue."""
    ids = [r["agent_id"] for r in conn.execute(
        "SELECT DISTINCT agent_id FROM vulnerabilities ORDER BY agent_id")]
    return sorted((exposure(conn, a) for a in ids),
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


def cited_cves(alerts: list[dict]) -> set[str]:
    """Identifiants CVE apparaissant littéralement dans les alertes.

    C'est le SEUL lien certain entre un incident et une vulnérabilité : une CVE
    écrite dans une ligne de commande ou un nom de fichier (règle locale 100660,
    « CVE identifier in command ») dit ce que l'attaquant CHERCHAIT. Tout le
    reste est une hypothèse.
    """
    found: set[str] = set()
    for a in alerts:
        raw = a.get("raw")
        if isinstance(raw, (dict, list)):
            raw = json.dumps(raw)
        for field in (a.get("rule_desc"), raw):
            if field:
                found |= {m.upper() for m in _CVE.findall(str(field))}
    return found


def incident_link(conn, agent_id: str, alerts: list[dict],
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
    expo = expo or exposure(conn, agent_id)
    cited = cited_cves(alerts)
    open_by_cve = {v["cve"]: v for v in conn.execute(
        SQL_OPEN, (str(agent_id),))} if cited else {}

    techniques = set()
    for a in alerts:
        techniques |= {str(m).upper() for m in (a.get("mitre_ids") or [])}
    exploit = sorted(techniques & TECHNIQUES_EXPLOIT)

    confirmed = [dict(open_by_cve[c]) for c in sorted(cited) if c in open_by_cve]
    return {
        "confirmees": confirmed,
        "citees_non_ouvertes": sorted(cited - set(open_by_cve)),
        "techniques_exploit": exploit,
        # Les vecteurs ne sont proposés que si l'incident porte réellement une
        # technique d'exploitation : sinon la section listerait les pires CVE de
        # la machine à côté d'un incident qui n'a rien à voir, et l'analyste
        # ferait le lien à notre place.
        "vecteurs_possibles": (
            [v for v in expo["pires"]
             if (v["severity"] or "") in ("critical", "high")][:5]
            if exploit else []),
    }


# --------------------------------------------------------------------------
# Export vers l'indexer (dashboard VOC)
# --------------------------------------------------------------------------

def _series_index(ts: datetime) -> str:
    """Index quotidien des séries temporelles (`wazuh-voc-YYYY.MM.DD`)."""
    return f"{config.VOC_INDEX_PREFIX}-{ts.astimezone(timezone.utc):%Y.%m.%d}"


# Index STABLE et non daté pour les documents de cycle de vie. Leur `_id` est
# déterministe (une vulnérabilité = un document, réécrit à chaque passage) : le
# ranger dans un index daté en créerait une copie par jour, chacune figée sur
# l'état de son jour, et les compteurs seraient multipliés par la rétention.
INDEX_VULNS = "vulns"


def _vuln_id(v: dict) -> str:
    key = f"{v['agent_id']}|{v['cve']}|{v['package']}"
    return "vuln-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:24]


def _vuln_doc(v: dict, priority: int) -> dict:
    """Une vulnérabilité et son cycle de vie. @timestamp = première observation :
    un document se lit à la date où le problème est apparu, pas à celle du run."""
    sev = v["severity"] or ""
    delay = sla_days(sev, priority)
    age = (v["age_jours"] if v["fixed_at"] is None
           else (v["fixed_at"] - v["first_seen"]).total_seconds() / 86400)
    return {
        "@timestamp": v["first_seen"].astimezone(timezone.utc).isoformat(),
        "timestamp": v["first_seen"].astimezone(timezone.utc).isoformat(),
        "event_type": "voc_vuln",
        "agent": {"id": v["agent_id"], "name": v["agent_name"]},
        "asset": {"priority": priority, "priorite_label": f"P{priority}"},
        "vulnerability": {
            "id": v["cve"],
            "severity": sev or "unknown",
            "base_score": v["base_score"],
            "published_at": (v["published_at"].astimezone(timezone.utc).isoformat()
                             if v["published_at"] else None),
        },
        "package": {"name": v["package"], "version": v["version"]},
        "voc": {
            "status": v["status"],
            "resolue": v["status"] == "corrigee",
            "first_seen": v["first_seen"].astimezone(timezone.utc).isoformat(),
            "fixed_at": (v["fixed_at"].astimezone(timezone.utc).isoformat()
                           if v["fixed_at"] else None),
            # Un seul champ pour deux sens selon le statut, et c'est voulu :
            # c'est l'âge tant que c'est ouvert, le délai de correction une fois
            # résolu. Le MTTR se lit donc en filtrant sur `voc.resolue: true`.
            "age_jours": round(age, 2),
            "sla_jours": delay,
            "hors_sla": bool(delay is not None and v["status"] == "ouverte"
                             and age > delay),
            "retard_jours": (round(age - delay, 2)
                             if delay is not None and age > delay else 0),
            "poids": weight(sev),
        },
    }


def _asset_doc(e: dict, maintenant: datetime) -> dict:
    """Exposition d'une machine à l'instant du run — le point de la courbe."""
    return {
        "@timestamp": maintenant.isoformat(),
        "timestamp": maintenant.isoformat(),
        "event_type": "voc_asset",
        "agent": {"id": e["agent_id"], "name": e.get("agent_name")},
        "asset": {"priority": e["priority"], "priorite_label": f"P{e['priority']}",
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


def _fleet_doc(conn, expos: list[dict], scan: dict, maintenant: datetime) -> dict:
    """Vue parc. Porte la COUVERTURE en premier : une dette qui baisse parce que
    des machines ont cessé de répondre n'est pas une amélioration, et c'est le
    seul chiffre qui permet de le voir."""
    inventories = {r["agent_id"] for r in conn.execute(
        "SELECT DISTINCT agent_id FROM vulnerabilities")}
    total_assets = conn.execute(
        "SELECT count(*) AS n FROM assets").fetchone()["n"]
    total_of = lambda key: total_of(e["par_severite"].get(key, 0) for e in expos)  # noqa: E731
    return {
        "@timestamp": maintenant.isoformat(),
        "timestamp": maintenant.isoformat(),
        "event_type": "voc_parc",
        "voc": {
            "machines_inventoriees": len(inventories),
            "machines_scannees": scan["agents_seen"],
            "machines_connues": total_assets,
            "couverture_pct": (round(100 * scan["agents_seen"] / total_assets, 1)
                               if total_assets else None),
            "machines_muettes": len(scan["silent_agents"]),
            "ouvertes": total_of(e["total"] for e in expos),
            "critical": total_of("critical"),
            "high": total_of("high"),
            "medium": total_of("medium"),
            "low": total_of("low"),
            "hors_sla_total": total_of(e["hors_sla_total"] for e in expos),
            "new_count": scan["new_count"],
            "fixed_count": scan["fixed_count"],
            "score_max": max((e["score"] for e in expos), default=0),
            "score_moyen": (round(total_of(e["score"] for e in expos) / len(expos), 1)
                            if expos else 0),
        },
    }


def _bulk(lines: list[str]) -> tuple[int, list[str]]:
    if not lines:
        return 0, []
    r = requests.post(
        f"{config.INDEXER_URL}/_bulk",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data="".join(lines).encode("utf-8"),
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=180)
    r.raise_for_status()
    body = r.json()
    errors = []
    if body.get("errors"):
        for item in body.get("items", []):
            info = next(iter(item.values()))
            if info.get("error"):
                errors.append(json.dumps(info["error"])[:300])
    return len(body.get("items", [])) - len(errors), errors


def _line(index: str, doc_id: str, doc: dict) -> list[str]:
    return [json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n",
            json.dumps(doc, default=str) + "\n"]


SQL_DETAIL = """
SELECT agent_id, agent_name, cve, package, version, severity, base_score,
       published_at, first_seen, fixed_at, status,
       extract(epoch FROM now() - first_seen) / 86400 AS age_jours
  FROM vulnerabilities
 WHERE (status = 'open' AND severity = ANY(%(sev)s))
    OR (status = 'fixed' AND fixed_at >= now() - interval '180 days')
"""


def export(conn, scan: dict, simulation: bool = False) -> dict:
    """Écrit les séries VOC dans l'indexer. Idempotent (`_id` déterministe)."""
    maintenant = datetime.now(timezone.utc)
    expos = fleet_exposure(conn)
    lines: list[str] = []
    resume = {"voc_asset": 0, "voc_parc": 0, "voc_vuln": 0}

    # `_id` à l'HEURE : le job tourne plus souvent que ça (rattrapage, relance
    # manuelle) et on ne veut ni écraser le point précédent ni empiler dix
    # points par heure. Une courbe horaire suffit largement pour une dette qui
    # bouge à la journée.
    hour = f"{maintenant:%Y%m%d%H}"
    for e in expos:
        lines += _line(_series_index(maintenant),
                         f"asset-{e['agent_id']}-{hour}",
                         _asset_doc(e, maintenant))
        resume["voc_asset"] += 1

    lines += _line(_series_index(maintenant), f"parc-{hour}",
                     _fleet_doc(conn, expos, scan, maintenant))
    resume["voc_parc"] = 1

    prios = {e["agent_id"]: e["priority"] for e in expos}
    for v in conn.execute(SQL_DETAIL,
                          {"sev": sorted(config.VOC_SEVERITIES_DETAIL)}):
        prio = prios.get(v["agent_id"], config.DEFAULT_PRIORITY)
        lines += _line(f"{config.VOC_INDEX_PREFIX}-{INDEX_VULNS}",
                         _vuln_id(v), _vuln_doc(dict(v), prio))
        resume["voc_vuln"] += 1

    if simulation:
        for l in lines:
            print(l, end="")
        return resume

    written, errors = _bulk(lines)
    resume["ecrits"] = written
    resume["erreurs"] = errors
    return resume


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _show_fleet(expos: list[dict]) -> None:
    print(f"{'agent':<6}{'machine':<22}{'P':<4}{'score':>6}  "
          f"{'crit':>5}{'high':>6}{'ouvert':>8}{'horsSLA':>9}  niveau")
    print("-" * 82)
    for e in expos:
        print(f"{e['agent_id']:<6}{(e.get('agent_name') or '?')[:21]:<22}"
              f"P{e['priority']:<3}{e['score']:>6}  "
              f"{e['par_severite'].get('critical', 0):>5}"
              f"{e['par_severite'].get('high', 0):>6}"
              f"{e['total']:>8}{e['hors_sla_total']:>9}  {e['niveau']}")


def _show_agent(e: dict) -> None:
    print(f"Agent {e['agent_id']} — P{e['priority']} "
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
    if e.get("journal_jours") is not None and e["journal_jours"] < 30:
        print(f"  (journal de {e['journal_jours']:.0f} j seulement : "
              f"l'ancienneté et le retard mesurent la durée de la MESURE, pas "
              f"l'état du parc)")
    if e["mttr_jours"] is not None:
        print(f"  corrigées sur 90 j : {e['corrigees_90j']} "
              f"(délai moyen {e['mttr_jours']} j)")
    print("  pires vulnérabilités :")
    for v in e["pires"]:
        print(f"    {v['cve']:<18}{(v['severity'] or '?'):<10}"
              f"{(v['base_score'] or 0):>5}  {v['package'][:32]:<34}"
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
            _show_agent(exposure(conn, args.agent))
            return
        if args.state:
            _show_fleet(fleet_exposure(conn))
            return

        scan = sync(conn)
        print(f"{scan['vulns_seen']} vulnérabilité(s) sur "
              f"{scan['agents_seen']} machine(s) : {scan['new_count']} nouvelle(s), "
              f"{scan['fixed_count']} corrigée(s)")
        if scan["silent_agents"]:
            print(f"  {len(scan['silent_agents'])} machine(s) sans inventaire : "
                  f"{', '.join(scan['silent_agents'])} — OS non couvert par le "
                  f"feed, ou syscollector muet. Rien n'a été clôturé pour elles.")
        if args.sans_export:
            return
        r = export(conn, scan, args.simulation)
        if args.simulation:
            return
        print(f"  {r['ecrits']} document(s) indexés "
              f"({r['voc_asset']} machines, {r['voc_vuln']} vulnérabilités, "
              f"1 vue parc)")
        for e in r["erreurs"]:
            print(f"  ERREUR {e}")


if __name__ == "__main__":
    main()
