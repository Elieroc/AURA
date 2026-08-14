"""Chaque source de log tombe-t-elle dans son index ? Sinon, créer l'index set.

Wazuh n'a pas de notion d'« index par agent » : le routage se fait par TYPE DE
LOG, dans un script painless du pipeline d'ingest de l'indexer
(`wazuh/config/wazuh_cluster/alerts-pipeline.json`). Une source qu'aucune
branche ne reconnaît atterrit dans `wazuh-alerts-4.x-*` sans le moindre
message : ni erreur côté Wazuh, ni alerte manquante, juste un type de log qui
n'a pas d'index à lui — et, si `INDEXER_ALERT_INDICES` a été oublié en même
temps, une IA aveugle sur ce capteur. Ce piège s'est produit trois fois
(wazuh-linux/web, puis wazuh-yara et wazuh-firewall le 2026-07-29).

Ce module en fait un contrôle permanent, adossé au watchdog :

    observer   -> ce que l'indexer a réellement reçu sur 24 h, par source
    classer    -> routée / non routée / dérive / muette
    nommer     -> un index conventionnel `wazuh-<suffixe>` (LLM + validation)
    appliquer  -> les CINQ pièces d'un index set, pas une seule

Un index set n'est pas un index. Créer `wazuh-jellyfin` suppose :

  1. la branche de routage dans le pipeline d'ingest (sinon rien n'y entre) ;
  2. le template `soc-ai-routing` (sinon mapping par défaut, champs en text) ;
  3. la politique ISM `aura-retention` (sinon l'index n'est jamais purgé) ;
  4. la liste d'indices lue par l'ingestion (sinon l'IA ne le voit pas) ;
  5. l'index pattern du dashboard (sinon invisible dans Discover).

Le point 1 se défait tout seul : le fichier du pipeline est bind-monté sur le
module filebeat du manager, et filebeat le REPOUSSE à chaque démarrage. Une
branche posée par API disparaît donc au prochain `docker compose up`. D'où le
principe de ce module : le pipeline attendu est RECALCULÉ à chaque passage
depuis la table `routage_sources`, comparé à celui qui tourne, et réappliqué
dès qu'il diverge. L'écrasement par filebeat se répare seul en deux minutes.

    python -m soc_agent.routage              # état des sources, n'écrit rien
    python -m soc_agent.routage --appliquer  # crée les index sets manquants
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config, llm

log = logging.getLogger(__name__)

PROMPTS = Path(__file__).parent / "prompts"

# Tags des deux processors de routage du pipeline. `routage-statique` est posé
# dans alerts-pipeline.json et sert de POINT D'INSERTION : les branches apprises
# passent JUSTE APRÈS lui.
#
# L'ordre inverse paraissait évident et il est faux — vérifié sur le pipeline de
# prod le 2026-08-14. Le `return` du painless ne sort que du SCRIPT COURANT, pas
# du pipeline : un processor placé avant a beau écrire `ctx._index`, le script
# statique qui suit le réécrit derrière lui. Une branche apprise
# `pam -> wazuh-endpoint` insérée avant repartait donc dans wazuh-linux, sans
# la moindre erreur. Après le statique, la branche spécifique gagne sur le
# classement fourre-tout par OS, ce qui est précisément ce qu'on veut ; le
# script YARA, lui, reste volontairement le dernier mot.
#
# Repli sur la description si le tag manque : la prod tourne peut-être encore
# avec un pipeline antérieur à ce chantier. Si NI l'un NI l'autre n'est trouvé,
# on refuse d'écrire — insérer à l'aveugle dans le pipeline qui porte toutes les
# alertes du SOC n'est pas un risque acceptable.
TAG_STATIQUE = "routage-statique"
TAG_APPRIS = "routage-appris"
_DESC_STATIQUE = "route les alertes des agents"

# --------------------------------------------------------------------------
# Ce qui n'est PAS une source de log
# --------------------------------------------------------------------------
#
# Le SOC produit en permanence des alertes qui ne viennent d'aucun capteur de
# log : intégrité de fichiers, audit de configuration, rootcheck, état des
# agents, vulnérabilités, VirusTotal. Elles sont normales dans
# `wazuh-alerts-4.x-*` — elles concernent TOUS les agents et n'ont pas de type
# de log propre. Sans cette liste blanche, le module proposerait de créer
# `wazuh-syscheck` dès le premier passage, sur 1 800 alertes par jour.
DECODEURS_TRANSVERSES = frozenset({
    "ossec", "rootcheck", "sca", "wazuh", "agent-upgrade", "syscollector",
    "vulnerability-detector", "active-response",
})

# Le FIM ne se décode pas sous un seul nom : `syscheck_deleted`,
# `syscheck_integrity_changed`, `syscheck_registry_value_modified`… Relevé sur
# la prod le 2026-08-14, six décodeurs distincts, 226 alertes en 24 h — soit six
# propositions d'index set au premier passage si on ne raisonne que sur des noms
# exacts. Le préfixe est la seule forme qui résiste à l'ajout d'un septième.
PREFIXES_TRANSVERSES = ("syscheck", "sca_", "rootcheck", "wazuh-", "agent-")


def _transverse(decodeur: str) -> bool:
    return (decodeur in DECODEURS_TRANSVERSES
            or decodeur.startswith(PREFIXES_TRANSVERSES))

GROUPES_TRANSVERSES = frozenset({
    "ossec", "rootcheck", "sca", "syscheck", "syscheck_entry_added",
    "syscheck_entry_modified", "syscheck_entry_deleted", "syscheck_file",
    "syscheck_registry", "wazuh", "agent_flooding", "virustotal",
    "vulnerability-detector", "soc_selfcheck", "attacks", "gdpr", "hipaa",
    "nist_800_53", "pci_dss", "tsc", "mitre",
})

# Décodeurs GÉNÉRIQUES : ils décodent un format, pas une source. `json` sert à
# la fois AdGuard, Suricata et les modules internes de Wazuh — il ne peut pas
# être une clé de source. Pour ceux-là, le critère redescend sur le groupe de
# règles, exactement comme le fait déjà le routage statique (cf. son
# commentaire : « routé sur rule.groups pas decoder.name »).
#
# `windows_eventchannel` en est délibérément ABSENT bien qu'il soit tout aussi
# générique : ses alertes portent des dizaines de groupes (sysmon_event1,
# authentication_failed, policy_changed…) qui deviendraient autant de fausses
# « sources » pour un seul et même index. Elles sont déjà routées par OS.
DECODEURS_AMBIGUS = frozenset({"json", "syslog"})

# Suffixes qu'on ne peut pas réutiliser : ce sont déjà des index de la stack,
# et le pattern `wazuh-<suffixe>-*` en avalerait le contenu.
SUFFIXES_RESERVES = frozenset({
    "alerts", "archives", "monitoring", "statistics", "states", "ai", "voc",
    "agent", "manager", "indexer", "dashboard", "custom", "all",
})

# Vocabulaire FERMÉ des sources génériques. Le modèle choisit dedans, ou il ne
# choisit pas : c'est la seule garantie qu'un pare-feu Fortinet n'ouvre pas un
# index `fortinet` à côté de `firewall`. Un nom générique hors liste est traité
# comme une réponse invalide, pas comme une proposition.
FAMILLES_GENERIQUES = frozenset({
    "firewall", "ids", "web", "proxy", "dns", "vpn", "mail", "database",
    "auth", "edr", "cloud", "container", "backup", "printer", "voip",
    "wireless", "storage", "iot", "ot", "endpoint",
})

_SUFFIXE = re.compile(r"^[a-z]{2,20}$")
# Ce qui peut entrer dans le code painless généré. Volontairement étroit : ces
# valeurs viennent des données indexées, et elles finissent dans une chaîne
# entre quotes simples au milieu d'un script exécuté par l'indexer.
_CRITERE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# Suffixe daté d'un index Wazuh : `wazuh-linux-2026.08.14` -> `wazuh-linux`.
_DATE_INDEX = re.compile(r"-\d{4}\.\d{2}\.\d{2}$")


# --------------------------------------------------------------------------
# Indexer
# --------------------------------------------------------------------------

def _indexer(methode: str, chemin: str, corps: dict | None = None,
             timeout: int = 60) -> requests.Response:
    return requests.request(
        methode, f"{config.INDEXER_URL}{chemin}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=corps,
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=timeout)


def _base_index(nom: str) -> str:
    """Préfixe d'un index daté, sans sa date."""
    return _DATE_INDEX.sub("", nom)


def _cle(critere_type: str, valeur: str) -> str:
    return f"{critere_type}:{valeur}"


# --------------------------------------------------------------------------
# Observation
# --------------------------------------------------------------------------

# Ce qu'on garde d'une alerte comme témoin. Tout le document serait inutilement
# lourd en base, mais il en faut ASSEZ pour que `_simulate` reproduise le
# routage : le décodeur et les groupes décident, `timestamp` construit le nom
# daté de l'index, `agent` sert au routage par OS du script statique.
_CHAMPS_TEMOIN = ["timestamp", "decoder", "rule.id", "rule.level",
                  "rule.groups", "rule.description", "agent", "location",
                  "data.win"]


def _agg_sources(fenetre_h: int) -> dict:
    """Agrégation « qui écrit où » sur la fenêtre.

    Deux agrégations en une requête : par décodeur pour le cas normal, et par
    groupe de règles pour les décodeurs génériques, qui n'identifient pas leur
    source. `_index` est un champ de métadonnée agrégeable — c'est lui qui dit
    où l'alerte a RÉELLEMENT atterri, la seule vérité qui compte ici.
    """
    sous_aggs = {
        "idx": {"terms": {"field": "_index", "size": 20}},
        "ex": {"top_hits": {"size": 1, "_source": {"includes": _CHAMPS_TEMOIN}}},
    }
    corps = {
        "size": 0,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{fenetre_h}h"}}}],
            # Le manager (agent 000) est exclu du routage par OS dans le script
            # statique : ses alertes restent volontairement dans l'index par
            # défaut. Les compter ici ferait passer des sources parfaitement
            # routées pour des sources orphelines — mesuré sur `web-accesslog`,
            # dont les alertes agent 000 (426 sur 7 j) écrasaient en nombre
            # celles des vrais agents web.
            "must_not": [{"term": {"agent.id": "000"}}],
        }},
        "aggs": {
            "par_decodeur": {
                "terms": {"field": "decoder.name", "size": 300},
                "aggs": {**sous_aggs,
                         "grp": {"terms": {"field": "rule.groups", "size": 20}}},
            },
            "par_groupe": {
                "filter": {"terms": {"decoder.name": sorted(DECODEURS_AMBIGUS)}},
                "aggs": {"src": {"terms": {"field": "rule.groups", "size": 200},
                                 "aggs": sous_aggs}},
            },
        },
    }
    r = _indexer("POST", f"/{indices_lus()}/_search", corps)
    r.raise_for_status()
    return r.json()["aggregations"]


def sources_observees(fenetre_h: int | None = None) -> list[dict]:
    """Les sources de log vues sur la fenêtre, avec leur index majoritaire.

    Fonction pure au sens utile du terme : elle lit l'indexer et ne décide
    rien. Le tri de sortie est déterministe (par clé), pour que deux passages
    successifs produisent le même rendu de pipeline — cf. `_script_appris`.
    """
    aggs = _agg_sources(fenetre_h or config.ROUTAGE_FENETRE_HEURES)
    sources: dict[str, dict] = {}

    def ajouter(critere_type: str, valeur: str, seau: dict) -> None:
        if not _CRITERE.match(valeur or ""):
            # Une valeur qu'on ne saurait pas réinjecter proprement dans le
            # painless n'a rien à faire dans cette table : on la journalise
            # plutôt que de la laisser silencieusement de côté.
            log.warning("source ignorée, critère non conforme : %s=%r",
                        critere_type, valeur)
            return
        index = [(_base_index(b["key"]), b["doc_count"])
                 for b in seau["idx"]["buckets"]]
        cumul: dict[str, int] = {}
        for base, n in index:
            cumul[base] = cumul.get(base, 0) + n
        if not cumul:
            return
        majoritaire = max(cumul.items(), key=lambda kv: kv[1])[0]
        hits = seau["ex"]["hits"]["hits"]
        sources[_cle(critere_type, valeur)] = {
            "source_key": _cle(critere_type, valeur),
            "critere_type": critere_type,
            "critere_valeur": valeur,
            "volume": seau["doc_count"],
            "index_observe": majoritaire,
            "index_repartition": cumul,
            "groupes": [b["key"] for b in seau.get("grp", {}).get("buckets", [])],
            "exemple": hits[0]["_source"] if hits else None,
        }

    for seau in aggs["par_decodeur"]["buckets"]:
        nom = seau["key"]
        if _transverse(nom) or nom in DECODEURS_AMBIGUS:
            continue
        ajouter("decoder", nom, seau)

    for seau in aggs["par_groupe"]["src"]["buckets"]:
        groupe = seau["key"]
        if groupe in GROUPES_TRANSVERSES:
            continue
        ajouter("groups", groupe, seau)

    return sorted(sources.values(), key=lambda s: s["source_key"])


# --------------------------------------------------------------------------
# Classement
# --------------------------------------------------------------------------

def classer(conn, observees: list[dict]) -> dict[str, list[dict]]:
    """Range chaque source observée dans l'un des quatre états.

    - `nouvelles` : rien ne les route, elles tombent dans l'index par défaut.
    - `derives`   : source connue qui n'atterrit plus où elle devrait. C'est la
                    signature d'un pipeline écrasé (filebeat au démarrage du
                    manager) ou d'une règle qui a changé de groupes.
    - `muettes`   : source établie dont plus rien n'arrive.
    - `ok`        : routée là où c'est prévu.

    Effet de bord assumé : les sources DÉJÀ correctement routées par une branche
    statique du pipeline sont enregistrées au passage (`nomme_par='statique'`).
    C'est l'amorçage — il se fait par observation plutôt que par une liste
    recopiée à la main, qui se serait désynchronisée du pipeline dès la première
    modification de celui-ci.
    """
    connues = {r["source_key"]: r for r in conn.execute(
        "SELECT * FROM routage_sources").fetchall()}
    res: dict[str, list[dict]] = {"nouvelles": [], "derives": [], "ok": [],
                                 "muettes": []}
    defaut = config.ROUTAGE_INDEX_DEFAUT

    for s in observees:
        connue = connues.get(s["source_key"])
        if connue is None:
            if s["index_observe"] != defaut:
                # Déjà routée par le pipeline statique : on l'enregistre telle
                # quelle. Son index attendu devient ce qu'on observe, ce qui
                # arme la détection de dérive pour la suite.
                _enregistrer_statique(conn, s)
                res["ok"].append(s)
            elif s["volume"] >= config.ROUTAGE_BASELINE_MIN:
                res["nouvelles"].append(s)
            continue

        _vue(conn, s)
        if connue["statut"] == "refuse":
            continue
        attendu = connue["index_base"]
        if s["index_observe"] == attendu:
            res["ok"].append({**s, "index_attendu": attendu})
        elif connue["statut"] == "propose" and s["index_observe"] == defaut:
            # Nommée mais pas encore appliquée : elle DOIT tomber dans l'index
            # par défaut, ce n'est pas une dérive.
            res["nouvelles"].append({**s, "connue": connue})
        elif s["volume"] >= config.ROUTAGE_DERIVE_MIN:
            res["derives"].append({**s, "index_attendu": attendu,
                                   "connue": connue})

    vues = {s["source_key"] for s in observees}
    limite = datetime.now(timezone.utc) - timedelta(
        hours=config.ROUTAGE_SILENCE_HEURES)
    # Un même flux se décrit souvent par plusieurs critères : Suricata pèse à
    # lui seul les groupes `suricata`, `ids` et `command_and_control`, tous les
    # trois routés vers wazuh-firewall. Les signaler séparément produirait trois
    # alertes pour une seule panne. La question qui intéresse l'analyste est de
    # toute façon celle de l'INDEX : « plus rien n'arrive dans wazuh-firewall ».
    # On ne garde donc, par index, que la source la plus grosse — celle dont le
    # silence est le plus significatif.
    par_index: dict[str, dict] = {}
    for cle, r in connues.items():
        if cle in vues or r["statut"] != "applique":
            continue
        if r["volume_ref"] < config.ROUTAGE_BASELINE_MIN or r["vue_a"] > limite:
            continue
        if any(s["index_observe"] == r["index_base"] for s in observees):
            # L'index reçoit encore, par une autre source : ce n'est pas lui
            # qui est muet, c'est ce critère-là qui ne matche plus. Cas d'une
            # règle qui a changé de groupes, déjà couvert par la dérive.
            continue
        candidat = {
            "source_key": cle, "critere_type": r["critere_type"],
            "critere_valeur": r["critere_valeur"], "index_attendu": r["index_base"],
            "volume": r["volume_ref"], "vue_a": r["vue_a"], "connue": r,
        }
        garde = par_index.get(r["index_base"])
        if garde is None or candidat["volume"] > garde["volume"]:
            par_index[r["index_base"]] = candidat
    res["muettes"] = sorted(par_index.values(), key=lambda m: m["source_key"])
    return res


def _enregistrer_statique(conn, s: dict) -> None:
    conn.execute(
        """INSERT INTO routage_sources
               (source_key, critere_type, critere_valeur, index_base, kind,
                statut, nomme_par, justification, volume_ref, exemple,
                appliquee_a)
           VALUES (%s, %s, %s, %s, 'generique', 'applique', 'statique',
                   'Routage déjà présent dans alerts-pipeline.json, découvert '
                   'par observation.', %s, %s, now())
           ON CONFLICT (source_key) DO NOTHING""",
        (s["source_key"], s["critere_type"], s["critere_valeur"],
         s["index_observe"], s["volume"], json.dumps(s["exemple"])))
    conn.commit()


def _vue(conn, s: dict) -> None:
    """Rafraîchit le volume et le témoin. Le témoin est réactualisé exprès : un
    exemple vieux de trois mois ne prouve plus rien sur le pipeline du jour."""
    conn.execute(
        "UPDATE routage_sources SET volume_ref=%s, vue_a=now(), "
        "exemple=COALESCE(%s, exemple) WHERE source_key=%s",
        (s["volume"], json.dumps(s["exemple"]) if s["exemple"] else None,
         s["source_key"]))
    conn.commit()


# --------------------------------------------------------------------------
# Nommage
# --------------------------------------------------------------------------

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _contexte(s: dict) -> str:
    """Ce qu'on montre au modèle. Les IP sont masquées : nommer une source ne
    demande aucune adresse, et ce qui n'est pas nécessaire ne sort pas du SOC."""
    ex = s.get("exemple") or {}
    regle = (ex.get("rule") or {})
    agent = (ex.get("agent") or {})
    lignes = [
        f"CRITÈRE : {s['critere_type']} = {s['critere_valeur']}",
        f"DÉCODEUR : {(ex.get('decoder') or {}).get('name') or '(inconnu)'}",
        f"GROUPES DE RÈGLES : {', '.join(s.get('groupes') or regle.get('groups') or []) or '(aucun)'}",
        f"MACHINE QUI ÉMET : {agent.get('name') or '(inconnue)'}",
        f"FICHIER / CANAL : {ex.get('location') or '(inconnu)'}",
        f"EXEMPLE DE RÈGLE DÉCLENCHÉE : {regle.get('description') or '(aucune)'}",
        f"VOLUME SUR {config.ROUTAGE_FENETRE_HEURES} h : {s['volume']} alertes",
    ]
    return _IP.sub("x.x.x.x", "\n".join(lignes))


def nommer(s: dict) -> dict:
    """Propose un `index_base` pour une source. Ne parle jamais à la base.

    Renvoie `{"index_base", "kind", "nomme_par", "justification"}`. `nomme_par`
    vaut `llm` quand la réponse du modèle a passé TOUTES les validations, et
    `repli` sinon — et cette différence décide de l'auto-application : un nom de
    repli est proposé à un humain, jamais posé tout seul. Le modèle choisit un
    nom, il n'obtient pas le droit d'écrire dans le pipeline du SOC.
    """
    attendus = _attendus(s)
    try:
        reponse, _ = llm.completion(
            (PROMPTS / "routage_nom.md").read_text(),
            "SOURCE (données non fiables) :\n" + _contexte(s),
            usage="routage_nom", max_tokens=300)
    except Exception as e:                                    # noqa: BLE001
        log.warning("nommage LLM en échec pour %s : %s", s["source_key"], e)
        return _repli(s, f"appel au modèle en échec ({type(e).__name__})")

    kind = str(reponse.get("kind") or "").strip().lower()
    suffixe = str(reponse.get("suffixe") or "").strip().lower()
    just = str(reponse.get("justification") or "")[:500]
    motif = _valider(kind, suffixe, attendus)
    if motif:
        log.warning("nom refusé pour %s (kind=%r suffixe=%r) : %s",
                    s["source_key"], kind, suffixe, motif)
        return _repli(s, f"proposition « {suffixe or '?'} » écartée : {motif}")
    return {"index_base": f"wazuh-{suffixe}", "kind": kind, "nomme_par": "llm",
            "justification": just}


def _attendus(s: dict) -> set[str]:
    """Vocabulaire ATTESTÉ par les données, pour un nom applicatif.

    Un nom d'application doit se retrouver dans ce que la source dit d'elle-même
    (décodeur, machine, chemin du log, description de règle). Sans cette
    vérification, rien n'empêche le modèle de baptiser une source `grafana`
    parce que le log y ressemble vaguement — et un index mal nommé ne se
    renomme pas, il se double.
    """
    ex = s.get("exemple") or {}
    brut = " ".join(str(x) for x in [
        s["critere_valeur"],
        (ex.get("decoder") or {}).get("name"),
        (ex.get("agent") or {}).get("name"),
        ex.get("location"),
        (ex.get("rule") or {}).get("description"),
    ] if x)
    return set(re.findall(r"[a-z]{2,20}", brut.lower()))


def _valider(kind: str, suffixe: str, attendus: set[str]) -> str | None:
    """Motif de rejet, ou None si le nom est acceptable."""
    if kind == "inconnu":
        return "le modèle n'a pas su classer la source"
    if kind not in ("generique", "applicative"):
        return f"kind inattendu ({kind!r})"
    if not _SUFFIXE.match(suffixe):
        return "forme du suffixe non conforme (a-z, 2 à 20 caractères)"
    if suffixe in SUFFIXES_RESERVES:
        return "suffixe réservé par la stack Wazuh"
    if kind == "generique" and suffixe not in FAMILLES_GENERIQUES:
        return "famille générique hors du vocabulaire fermé"
    if kind == "applicative":
        if suffixe in FAMILLES_GENERIQUES:
            return "nom de métier proposé comme nom d'application"
        if suffixe not in attendus:
            return "nom d'application qu'aucune donnée de la source n'atteste"
    return None


def _repli(s: dict, motif: str) -> dict:
    """Nom déterministe quand le modèle n'a pas tranché. Reste en `propose` :
    c'est un point d'arrêt volontaire, pas un défaut de repli silencieux."""
    suffixe = re.sub(r"[^a-z]", "", s["critere_valeur"].lower())[:20] or "divers"
    return {"index_base": f"wazuh-{suffixe}", "kind": "generique",
            "nomme_par": "repli", "justification": motif}


def proposer(conn, s: dict) -> dict | None:
    """Nomme une source nouvelle et l'enregistre. Renvoie la ligne créée.

    Le nom n'est demandé au modèle QU'UNE FOIS par source : l'unicité de
    `source_key` le garantit, et c'est ce qui rend ce module gratuit en régime
    permanent — un SI stable n'appelle plus jamais le LLM ici.
    """
    deja = conn.execute("SELECT * FROM routage_sources WHERE source_key=%s",
                        (s["source_key"],)).fetchone()
    if deja:
        return deja
    nom = nommer(s)
    if conn.execute("SELECT 1 FROM routage_sources WHERE index_base=%s",
                    (nom["index_base"],)).fetchone():
        # Collision : deux sources qui partagent un index de métier, c'est
        # exactement l'effet recherché (pfSense et Forti dans `firewall`). On
        # réutilise donc l'index existant sans rien créer côté indexer.
        log.info("source %s rattachée à l'index existant %s",
                 s["source_key"], nom["index_base"])
    r = conn.execute(
        """INSERT INTO routage_sources
               (source_key, critere_type, critere_valeur, index_base, kind,
                statut, nomme_par, justification, volume_ref, exemple)
           VALUES (%s, %s, %s, %s, %s, 'propose', %s, %s, %s, %s)
           ON CONFLICT (source_key) DO NOTHING
           RETURNING *""",
        (s["source_key"], s["critere_type"], s["critere_valeur"],
         nom["index_base"], nom["kind"], nom["nomme_par"], nom["justification"],
         s["volume"], json.dumps(s["exemple"]))).fetchone()
    conn.commit()
    if r:
        log.warning("SOURCE NON ROUTÉE : %s (%d alertes) -> %s proposé par %s "
                    "— %s", s["source_key"], s["volume"], nom["index_base"],
                    nom["nomme_par"], nom["justification"])
    return r


# --------------------------------------------------------------------------
# Rendu du pipeline
# --------------------------------------------------------------------------

def routes_apprises(conn) -> list[dict]:
    """Routes que NOUS générons. Les branches `statique` sont exclues : elles
    vivent dans alerts-pipeline.json et n'ont pas à être dupliquées."""
    return conn.execute(
        "SELECT critere_type, critere_valeur, index_base FROM routage_sources "
        " WHERE statut='applique' AND nomme_par <> 'statique' "
        " ORDER BY critere_type DESC, critere_valeur").fetchall()


def _script_appris(routes: list[dict]) -> dict:
    """Le processor painless généré.

    Deux invariants tiennent tout le reste :

    - l'ordre est DÉTERMINISTE (tri en SQL), donc deux rendus successifs sont
      identiques au caractère près. Sans cela, la comparaison avec le pipeline
      en place déclencherait un PUT à chaque passage, toutes les deux minutes ;
    - les tests `decoder` passent AVANT les tests `groups` : le décodeur
      identifie la source, le groupe ne fait que la caractériser. Une alerte
      Suricata portant le groupe `dns` doit partir chez le pare-feu, pas dans
      l'index DNS — c'est le piège que le routage statique documente déjà.
    """
    lignes = [
        "def dn = ctx.decoder?.name;",
        "def g = ctx.rule?.groups;",
        "if (ctx.timestamp == null || ctx.timestamp.length() < 10) { return; }",
        "def d = ctx.timestamp.substring(0,10).replace('-','.');",
    ]
    for r in routes:
        if not _CRITERE.match(r["critere_valeur"]):
            raise ValueError(f"critère non conforme en base : {r!r}")
        if not re.match(r"^wazuh-[a-z]{2,20}$", r["index_base"]):
            raise ValueError(f"index_base non conforme en base : {r!r}")
        test = (f"dn == '{r['critere_valeur']}'" if r["critere_type"] == "decoder"
                else f"g != null && g.contains('{r['critere_valeur']}')")
        lignes.append(f"if ({test}) {{ ctx._index = '{r['index_base']}-' + d; "
                      "return; }")
    return {"script": {
        "tag": TAG_APPRIS,
        "description": (
            "AURA routage : branches apprises par soc_agent.routage, "
            "régénérées depuis la table routage_sources. Ne pas éditer à la "
            "main — toute modification est écrasée au passage suivant du "
            "watchdog. Placé APRÈS le routage statique : le `return` du "
            "painless ne sort que du script courant, donc un processor "
            "antérieur se fait réécrire par le classement par OS qui suit."),
        "lang": "painless",
        "ignore_failure": True,
        "source": "\n".join(lignes),
    }}


def _sans_appris(pipeline: dict) -> dict:
    """Le pipeline débarrassé de notre processor. C'est la BASE.

    On ne lit jamais alerts-pipeline.json depuis ce conteneur : la base, c'est
    ce que filebeat a réellement poussé. Le fichier peut avoir changé sur disque
    sans que le manager ait redémarré ; partir du fichier ferait alors appliquer
    un pipeline qui n'est pas celui en service.
    """
    return {**pipeline,
            "processors": [p for p in pipeline.get("processors", [])
                           if not _est_appris(p)]}


def _est_appris(processor: dict) -> bool:
    corps = next(iter(processor.values()), {})
    return isinstance(corps, dict) and corps.get("tag") == TAG_APPRIS


def _position_insertion(processors: list[dict]) -> int:
    """Juste APRÈS le routage statique — cf. le commentaire de TAG_STATIQUE."""
    for i, p in enumerate(processors):
        corps = next(iter(p.values()), {})
        if not isinstance(corps, dict):
            continue
        if corps.get("tag") == TAG_STATIQUE:
            return i + 1
        if _DESC_STATIQUE in (corps.get("description") or ""):
            return i + 1
    raise RuntimeError(
        "processor de routage statique introuvable dans le pipeline "
        f"« {config.ROUTAGE_PIPELINE} » : refus d'insérer à l'aveugle. "
        "Vérifier alerts-pipeline.json (tag « routage-statique »).")


def rendre(base: dict, routes: list[dict]) -> dict:
    """Pipeline attendu = base + branches apprises, insérées au bon endroit."""
    if not routes:
        return base
    procs = list(base.get("processors", []))
    procs.insert(_position_insertion(procs), _script_appris(routes))
    return {**base, "processors": procs}


def _lire_pipeline() -> dict:
    r = _indexer("GET", f"/_ingest/pipeline/{config.ROUTAGE_PIPELINE}")
    if r.status_code == 404:
        raise RuntimeError(
            f"pipeline « {config.ROUTAGE_PIPELINE} » absent de l'indexer : le "
            "manager ne l'a pas encore poussé.")
    r.raise_for_status()
    return r.json()[config.ROUTAGE_PIPELINE]


# --------------------------------------------------------------------------
# Simulation : le garde-fou avant écriture
# --------------------------------------------------------------------------

def temoins(conn) -> list[dict]:
    """Une alerte réelle par source appliquée, avec l'index qu'elle doit
    atteindre."""
    return conn.execute(
        "SELECT source_key, index_base, exemple FROM routage_sources "
        " WHERE statut='applique' AND exemple IS NOT NULL "
        " ORDER BY source_key").fetchall()


# Ce que filebeat ajoute et que l'indexation ne conserve PAS. Le processor
# `date_index_name` lit `fields.index_prefix` pour fabriquer le nom d'index par
# défaut, et il est le seul du pipeline en `ignore_failure: false` : sans ce
# champ, tout document simulé part dans le `drop` du `on_failure` et CHAQUE
# témoin ressort « perdu ». Le champ ne peut pas venir du témoin lui-même — un
# `remove` du pipeline l'efface avant l'écriture, il n'est donc dans aucun
# document indexé. Il faut le reposer ici.
PREFIXE_DEFAUT = f"{config.ROUTAGE_INDEX_DEFAUT}-"


def _message(exemple: dict) -> dict:
    if "fields" in exemple:
        return exemple
    return {**exemple, "fields": {"index_prefix": PREFIXE_DEFAUT}}


def simuler(pipeline: dict, cas: list[dict]) -> list[str]:
    """Rejoue des alertes réelles dans le pipeline candidat. Renvoie les échecs.

    Ce n'est pas une précaution de confort. Le pipeline se termine par
    `on_failure: [{"drop": {}}]` : un script painless invalide ne remonte
    aucune erreur, il fait DISPARAÎTRE toutes les alertes du SOC. La simulation
    est donc obligatoire avant chaque PUT, et un seul témoin en échec suffit à
    tout annuler — y compris un témoin qui n'a rien à voir avec la source qu'on
    est en train d'ajouter, puisque c'est précisément la régression qu'on
    cherche.

    Le document est présenté comme filebeat l'envoie : l'alerte entière dans le
    champ `message`, que le premier processor déplie à la racine.
    """
    if not cas:
        return []
    docs = [{"_index": config.ROUTAGE_INDEX_DEFAUT, "_id": str(i),
             "_source": {"message": json.dumps(_message(c["exemple"]))}}
            for i, c in enumerate(cas)]
    r = _indexer("POST", "/_ingest/pipeline/_simulate",
                 {"pipeline": pipeline, "docs": docs})
    if not r.ok:
        return [f"simulation refusée par l'indexer ({r.status_code}) : "
                f"{r.text[:300]}"]
    echecs = []
    for c, res in zip(cas, r.json().get("docs", [])):
        doc = res.get("doc")
        if not doc:
            echecs.append(f"{c['source_key']} : document PERDU par le pipeline "
                          f"({str(res.get('error'))[:200]})")
            continue
        obtenu = _base_index(doc.get("_index", ""))
        if obtenu != c["index_base"]:
            echecs.append(f"{c['source_key']} : attendu {c['index_base']}, "
                          f"obtenu {obtenu}")
    return echecs


# --------------------------------------------------------------------------
# Application : les cinq pièces
# --------------------------------------------------------------------------

TEMPLATE = "soc-ai-routing"


def _poser_template(index_base: str) -> None:
    """Ajoute le pattern au template existant, sans le reconstruire.

    Lecture-mutation-écriture volontaire : le template porte les mappings et
    les réglages hérités de la stack. Le régénérer depuis un modèle en dur ici
    ferait perdre, à la première divergence de version de Wazuh, tout ce qui n'y
    aurait pas été recopié.
    """
    pattern = f"{index_base}-*"
    r = _indexer("GET", f"/_template/{TEMPLATE}")
    if not r.ok:
        raise RuntimeError(f"template {TEMPLATE} illisible : {r.text[:200]}")
    corps = r.json()[TEMPLATE]
    if pattern in corps.get("index_patterns", []):
        return
    corps["index_patterns"] = sorted(set(corps["index_patterns"]) | {pattern})
    w = _indexer("PUT", f"/_template/{TEMPLATE}", corps)
    if not w.ok:
        raise RuntimeError(f"template {TEMPLATE} refusé : {w.text[:300]}")
    log.info("template %s : pattern %s ajouté", TEMPLATE, pattern)


def _poser_ism() -> None:
    """Réapplique la politique de rétention, qui lit maintenant les patterns
    appris (cf. retention.ism_patterns). Sans cette étape, le nouvel index
    grossit sans jamais être purgé — un disque plein est la panne qui arrête
    tout le SOC."""
    from . import retention
    retention.appliquer_ism()


def _poser_index_pattern(index_base: str) -> None:
    """Index pattern OpenSearch Dashboards. Best-effort assumé.

    Un échec ici laisse un index bien alimenté mais invisible dans Discover :
    gênant, pas dangereux. On journalise et on continue — refuser d'appliquer
    le routage parce que le dashboard n'a pas répondu serait échanger une
    invisibilité contre une cécité.
    """
    titre = f"{index_base}-*"
    try:
        r = requests.post(
            f"{config.DASHBOARD_URL}/api/saved_objects/index-pattern/{titre}",
            headers={"osd-xsrf": "true"},
            auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
            json={"attributes": {"title": titre, "timeFieldName": "timestamp"}},
            verify=False, timeout=30)
        if r.ok:
            log.info("index pattern %s créé dans le dashboard", titre)
        elif r.status_code == 409:
            log.debug("index pattern %s déjà présent", titre)
        else:
            log.warning("index pattern %s non créé (%s) : %s", titre,
                        r.status_code, r.text[:200])
    except Exception as e:                                    # noqa: BLE001
        log.warning("dashboard injoignable pour l'index pattern %s : %s",
                    titre, e)


def appliquer(conn, source_key: str, dry_run: bool = False) -> dict:
    """Pose les cinq pièces d'un index set, ou explique pourquoi elle ne le fait
    pas. Idempotente : rejouable sans effet de bord.

    L'ordre n'est pas indifférent. Template et ISM d'ABORD : ils ne valent que
    pour les index créés APRÈS, donc les poser après le routage laisserait la
    première journée d'alertes dans un index sans mapping et sans rétention.
    Le routage EN DERNIER, quand tout est prêt à le recevoir.
    """
    r = conn.execute("SELECT * FROM routage_sources WHERE source_key=%s",
                     (source_key,)).fetchone()
    if r is None:
        return {"ok": False, "motif": "source inconnue"}
    if r["statut"] == "applique":
        return {"ok": True, "motif": "déjà appliquée"}
    if r["nomme_par"] == "repli":
        return {"ok": False, "motif": "nom de repli : arbitrage humain requis"}
    # Le plafond ne vaut que pour un index set VRAIMENT nouveau. Rattacher une
    # deuxième source à `wazuh-firewall` (un Fortinet à côté du pfSense) ne crée
    # rien : c'est le cas nominal du nommage générique, et le brider reviendrait
    # à punir exactement le comportement qu'on cherche à obtenir.
    nouveau = not conn.execute(
        "SELECT 1 FROM routage_sources WHERE index_base=%s AND statut='applique'"
        "   AND source_key <> %s", (r["index_base"], source_key)).fetchone()
    if nouveau and _plafond_atteint(conn):
        return {"ok": False, "motif":
                f"plafond de {config.ROUTAGE_MAX_NOUVEAUX_PAR_JOUR} "
                "création(s) par 24 h atteint"}

    # Le pipeline candidat est calculé AVANT toute écriture, et validé sur les
    # témoins de toutes les sources déjà appliquées : on vérifie donc en même
    # temps que la nouvelle branche fonctionne et qu'elle ne casse rien.
    base = _sans_appris(_lire_pipeline())
    routes = list(routes_apprises(conn)) + [{
        "critere_type": r["critere_type"], "critere_valeur": r["critere_valeur"],
        "index_base": r["index_base"]}]
    candidat = rendre(base, routes)
    cas = list(temoins(conn))
    if r["exemple"]:
        cas.append({"source_key": r["source_key"], "index_base": r["index_base"],
                    "exemple": r["exemple"]})
    echecs = simuler(candidat, cas)
    if echecs:
        log.error("index set %s NON appliqué — la simulation échoue : %s",
                  r["index_base"], " | ".join(echecs))
        return {"ok": False, "motif": "simulation en échec : " + "; ".join(echecs)}

    if dry_run:
        return {"ok": True, "motif": "dry-run : simulation passée, rien écrit",
                "index_base": r["index_base"]}

    _poser_template(r["index_base"])
    conn.execute("UPDATE routage_sources SET statut='applique', appliquee_a=now()"
                 " WHERE source_key=%s", (source_key,))
    conn.commit()
    # ISM après la bascule en base : `ism_patterns()` lit la table.
    try:
        _poser_ism()
    except Exception as e:                                    # noqa: BLE001
        log.warning("politique ISM non réappliquée pour %s : %s (le job de "
                    "rétention la reposera)", r["index_base"], e)
    _poser_index_pattern(r["index_base"])
    _pousser_pipeline(candidat)
    _INDICES_CACHE["expire"] = None                       # cf. indices_lus
    log.error("INDEX SET CRÉÉ : %s pour la source %s (%s) — %s",
              r["index_base"], source_key, r["nomme_par"], r["justification"])
    return {"ok": True, "index_base": r["index_base"],
            "motif": "index set créé"}


def _plafond_atteint(conn) -> bool:
    n = conn.execute(
        "SELECT count(*) c FROM routage_sources "
        " WHERE appliquee_a > now() - interval '24 hours' "
        "   AND nomme_par <> 'statique'").fetchone()["c"]
    return n >= config.ROUTAGE_MAX_NOUVEAUX_PAR_JOUR


def _pousser_pipeline(pipeline: dict) -> None:
    r = _indexer("PUT", f"/_ingest/pipeline/{config.ROUTAGE_PIPELINE}", pipeline)
    if not r.ok:
        raise RuntimeError(f"pipeline refusé ({r.status_code}) : {r.text[:300]}")
    log.info("pipeline %s mis à jour (%d processors)", config.ROUTAGE_PIPELINE,
             len(pipeline.get("processors", [])))


def reconcilier_pipeline(conn, dry_run: bool = False) -> str | None:
    """Le pipeline en service porte-t-il bien nos branches ?

    C'est la réponse à l'écrasement par filebeat : au démarrage du manager, le
    module filebeat repousse alerts-pipeline.json et efface tout ce qu'on y a
    ajouté. Sans ce contrôle, les index sets créés cessent silencieusement
    d'être alimentés — la panne exacte qu'on prétend surveiller.

    Renvoie une description de l'écart corrigé, ou None si tout allait bien.
    """
    routes = list(routes_apprises(conn))
    vivant = _lire_pipeline()
    if not routes:
        # Aucune route apprise : le pipeline doit être exactement la base. S'il
        # porte encore notre processor (dernière source refusée, base restaurée
        # d'une sauvegarde), il route vers des index qui n'ont plus ni template
        # ni rétention — on le retire.
        if not any(_est_appris(p) for p in vivant.get("processors", [])):
            return None
        if dry_run:
            return "processor appris orphelin (dry-run, non retiré)"
        _pousser_pipeline(_sans_appris(vivant))
        return "processor appris orphelin retiré"
    attendu = rendre(_sans_appris(vivant), routes)
    if json.dumps(attendu, sort_keys=True) == json.dumps(vivant, sort_keys=True):
        return None
    echecs = simuler(attendu, list(temoins(conn)))
    if echecs:
        log.error("pipeline divergent mais NON réappliqué — la simulation "
                  "échoue : %s", " | ".join(echecs))
        return f"pipeline divergent, correction impossible : {'; '.join(echecs)}"
    if dry_run:
        return "pipeline divergent (dry-run, non corrigé)"
    _pousser_pipeline(attendu)
    log.warning("PIPELINE RÉPARÉ : les %d branche(s) apprise(s) avaient "
                "disparu (redémarrage du manager ?)", len(routes))
    return f"{len(routes)} branche(s) apprise(s) réappliquée(s)"


# --------------------------------------------------------------------------
# Ce que le reste du pipeline consomme
# --------------------------------------------------------------------------

_INDICES_CACHE: dict = {"valeur": None, "expire": None}
_CACHE_S = 300


def patterns_appliques(conn) -> list[str]:
    return [f"{r['index_base']}-*" for r in conn.execute(
        "SELECT DISTINCT index_base FROM routage_sources "
        " WHERE statut='applique' ORDER BY index_base").fetchall()]


def indices_lus() -> str:
    """Indices interrogés à l'ingestion : la liste statique UNION ce qui a été
    créé depuis.

    C'est le point qui ferme, par construction, l'angle mort historique : un
    index set créé sans être ajouté à `INDEXER_ALERT_INDICES` est un capteur
    que l'IA ne voit pas, sans qu'aucune erreur ne le signale. Ce n'est plus
    une liste à tenir à jour, c'est une conséquence.

    Repli sur la liste statique à la moindre difficulté (table absente, base
    injoignable) : l'ingestion doit continuer même si ce module ne répond pas.
    """
    maintenant = datetime.now(timezone.utc)
    if _INDICES_CACHE["expire"] and _INDICES_CACHE["expire"] > maintenant:
        return _INDICES_CACHE["valeur"]
    statiques = [p.strip() for p in config.INDEXER_ALERT_INDICES.split(",")
                 if p.strip()]
    try:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            patterns = patterns_appliques(conn)
    except Exception as e:                                    # noqa: BLE001
        log.warning("patterns appris illisibles (%s) : repli sur la liste "
                    "statique", e)
        patterns = []
    # `wazuh-alerts-4.x-*` est déjà couvert par `wazuh-alerts-*` de la liste
    # statique ; dédupliquer évite de le compter deux fois dans la recherche.
    tous = list(dict.fromkeys(statiques + [p for p in patterns
                                           if not p.startswith("wazuh-alerts")]))
    # NÉGATION FINALE, non négociable : l'espace de threat hunting contient des
    # alertes RESTAURÉES depuis les archives (cf. hunting.py). Les laisser entrer
    # ici aurait deux conséquences, toutes deux graves :
    #
    #  - l'ingestion les reprendrait, la corrélation en ferait des incidents et
    #    le triage des cases IRIS — sur des faits vieux de dix mois, avec la
    #    remédiation autonome au bout ;
    #  - le routage verrait leur `decoder.name` atterrir ailleurs que dans son
    #    index attendu, donc une DÉRIVE, donc une alerte IRIS pour rien.
    #
    # La syntaxe `-motif` d'OpenSearch exclut après coup : cette ligne gagne même
    # si quelqu'un met `wazuh-*` dans INDEXER_ALERT_INDICES. C'est voulu — la
    # protection ne doit pas dépendre de la discipline de configuration.
    tous.append(f"-{config.HUNTING_INDEX_BASE}-*")
    valeur = ",".join(tous)
    _INDICES_CACHE.update({"valeur": valeur,
                           "expire": maintenant + timedelta(seconds=_CACHE_S)})
    return valeur


# --------------------------------------------------------------------------
# Passage complet
# --------------------------------------------------------------------------

def reconcilier(dry_run: bool | None = None) -> dict:
    """Un passage : observer, classer, nommer, appliquer, réparer.

    Appelé par le watchdog. Renvoie un compte rendu, et surtout la liste des
    ANOMALIES qui restent après coup — celles-là deviennent des alertes IRIS,
    au même titre qu'un capteur muet.
    """
    if dry_run is None:
        dry_run = not config.ROUTAGE_APPLIQUER
    rapport: dict = {"nouvelles": [], "creees": [], "anomalies": [],
                     "pipeline": None}
    if not config.ROUTAGE_ACTIF:
        return rapport

    observees = sources_observees()
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        etats = classer(conn, observees)
        rapport["ok"] = len(etats["ok"])

        for s in etats["nouvelles"]:
            ligne = proposer(conn, s)
            if ligne is None:
                continue
            rapport["nouvelles"].append(dict(ligne))
            try:
                r = appliquer(conn, s["source_key"], dry_run=dry_run)
            except Exception as e:                            # noqa: BLE001
                # Une source qui se passe mal ne doit pas emporter le passage :
                # les dérives et les sources muettes des autres restent à
                # signaler, et le pipeline reste à réconcilier.
                log.error("application de %s en échec : %s", s["source_key"], e)
                r = {"ok": False, "motif": f"{type(e).__name__}: {e}"}
            if r["ok"] and not dry_run:
                rapport["creees"].append(r.get("index_base"))
            else:
                rapport["anomalies"].append(_anomalie_source(s, ligne, r))

        for d in etats["derives"]:
            rapport["anomalies"].append(_anomalie_derive(d))
        for m in etats["muettes"]:
            rapport["anomalies"].append(_anomalie_muette(m))

        try:
            rapport["pipeline"] = reconcilier_pipeline(conn, dry_run=dry_run)
        except Exception as e:                                # noqa: BLE001
            log.error("réconciliation du pipeline impossible : %s", e)
            rapport["pipeline"] = f"échec : {e}"
    return rapport


# Les anomalies sortent au FORMAT D'UN CAPTEUR MUET (mêmes clés) : elles
# traversent ainsi sans cas particulier la boucle d'ouverture/clôture du
# watchdog, qui sait déjà tenir un état, créer l'alerte IRIS et la refermer.
# Même raisonnement que pour le garde-fou disque.
AGENT_SOC = "000"


def _anomalie(capteur: str, titre: str, note: str, severite: str,
              volume: int, dernier: datetime | None = None) -> dict:
    maintenant = datetime.now(timezone.utc)
    return {"agent_id": AGENT_SOC, "agent_name": "wazuh.manager",
            "capteur": capteur, "titre": titre, "note": note,
            "severite": severite, "volume": volume, "seuil": 0,
            "dernier": dernier or maintenant, "horizon": maintenant}


def _anomalie_source(s: dict, ligne: dict, r: dict) -> dict:
    return _anomalie(
        f"routage:{s['source_key']}",
        f"[ROUTAGE] source {s['source_key']} sans index dédié",
        "\n".join([
            "SOURCE DE LOG NON ROUTÉE",
            "",
            f"La source {s['source_key']} a produit {s['volume']} alertes sur "
            f"{config.ROUTAGE_FENETRE_HEURES} h et atterrit dans "
            f"{config.ROUTAGE_INDEX_DEFAUT}, l'index fourre-tout de Wazuh.",
            "",
            f"  Index proposé   : {ligne['index_base']}",
            f"  Nommé par       : {ligne['nomme_par']}",
            f"  Justification   : {ligne['justification']}",
            f"  Non appliqué    : {r.get('motif')}",
            "",
            "Conséquence : ces alertes sont mélangées à celles de tous les "
            "autres capteurs, sans mapping ni rétention propres, et les "
            "tableaux de bord ne peuvent pas les isoler.",
            "",
            "Pour trancher à la main :",
            "",
            "  python -m soc_agent.routage --appliquer "
            f"--source {s['source_key']}",
            "  python -m soc_agent.routage --refuser "
            f"--source {s['source_key']}",
            "",
            "-- Ouvert par le watchdog AURA. Se referme dès que la source est "
            "routée.",
        ]),
        "Medium", s["volume"])


def _anomalie_derive(d: dict) -> dict:
    repartition = ", ".join(f"{k}={v}" for k, v in
                            sorted(d["index_repartition"].items(),
                                   key=lambda kv: -kv[1]))
    return _anomalie(
        f"routage:{d['source_key']}",
        f"[ROUTAGE] {d['source_key']} n'atterrit plus dans {d['index_attendu']}",
        "\n".join([
            "ROUTAGE DÉVIÉ",
            "",
            f"La source {d['source_key']} devrait alimenter "
            f"{d['index_attendu']} ; ses alertes partent dans "
            f"{d['index_observe']}.",
            "",
            f"  Répartition observée : {repartition}",
            f"  Volume sur {config.ROUTAGE_FENETRE_HEURES} h : {d['volume']}",
            "",
            "Deux causes possibles, dans cet ordre de probabilité :",
            "",
            "1. Le pipeline d'ingest a été écrasé. Filebeat repousse "
            "alerts-pipeline.json à chaque démarrage du manager et efface les "
            "branches ajoutées. Le watchdog les réapplique tout seul au "
            "passage suivant — si cette alerte persiste, c'est que la "
            "réapplication échoue (voir les logs de soc-agent-watchdog).",
            "2. Une règle a changé de groupes, ou une règle native sœur gagne "
            "désormais sur la règle locale. Le critère de routage doit alors "
            "être revu : c'est le piège documenté du routage par rule.groups.",
            "",
            "-- Ouvert par le watchdog AURA. Se referme quand la source "
            "retrouve son index.",
        ]),
        "High", d["volume"])


def _anomalie_muette(m: dict) -> dict:
    return _anomalie(
        f"source-muette:{m['source_key']}",
        f"[SOURCE MUETTE] {m['source_key']} n'écrit plus dans "
        f"{m['index_attendu']}",
        "\n".join([
            "SOURCE DE LOG MUETTE",
            "",
            f"La source {m['source_key']} alimentait {m['index_attendu']} "
            f"({m['volume']} alertes à la dernière observation). Plus rien "
            f"depuis {m['vue_a']:%Y-%m-%d %H:%M} UTC.",
            "",
            f"  Seuil de silence : {config.ROUTAGE_SILENCE_HEURES} h",
            "",
            "Un index qui cesse d'être alimenté ne produit aucune erreur : "
            "l'index du jour n'est simplement plus créé, et le tableau de bord "
            "correspondant reste vert sur une période vide. Rien d'autre que "
            "ce contrôle ne le signale.",
            "",
            "Où regarder :",
            "",
            "1. Le bloc <localfile> de l'agent lit-il toujours le bon fichier ? "
            "Un conteneur recréé change souvent de chemin de log.",
            "2. L'application écrit-elle encore ? (rotation, niveau de log "
            "abaissé, service arrêté)",
            "3. Le collecteur de l'agent est-il figé ? "
            "(`wazuh-control status`, plusieurs wazuh-logcollector empilés)",
            "",
            "-- Ouvert par le watchdog AURA. Se referme dès que la source "
            "réémet.",
        ]),
        "Medium", m["volume"], m["vue_a"])


# --------------------------------------------------------------------------

def _table(conn) -> None:
    lignes = conn.execute(
        "SELECT source_key, index_base, statut, nomme_par, kind, volume_ref, "
        "       vue_a FROM routage_sources ORDER BY statut, source_key"
    ).fetchall()
    if not lignes:
        print("Aucune source enregistrée.")
        return
    for r in lignes:
        print(f"  {r['source_key']:<34} -> {r['index_base']:<20} "
              f"{r['statut']:<9} {r['nomme_par']:<9} {r['kind']:<11} "
              f"{r['volume_ref']:>7} vue {r['vue_a']:%m-%d %H:%M}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--appliquer", action="store_true",
                   help="créer les index sets manquants (sinon lecture seule)")
    p.add_argument("--observer", action="store_true",
                   help="qui écrit où, sans base ni modèle ni écriture")
    p.add_argument("--source", help="n'agir que sur cette source_key")
    p.add_argument("--refuser", action="store_true",
                   help="marquer --source comme refusée, ne plus la proposer")
    p.add_argument("--index", help="forcer l'index_base de --source "
                                   "(arbitrage humain, court-circuite le LLM)")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.observer:
        # Le seul mode qui ne touche NI la base NI le modèle : à lancer en
        # premier sur une installation existante, avant d'autoriser la moindre
        # écriture. Il répond à la seule question qui compte au départ — qui
        # écrit où, et qui n'écrit nulle part en particulier.
        for s in sources_observees():
            defaut = s["index_observe"] == config.ROUTAGE_INDEX_DEFAUT
            print(f"  {'!' if defaut else ' '} {s['source_key']:<34} "
                  f"-> {s['index_observe']:<22} {s['volume']:>7} alertes"
                  + ("   <-- aucun index dédié" if defaut else ""))
        return

    if args.refuser or args.index:
        if not args.source:
            p.error("--refuser et --index exigent --source")
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            if args.refuser:
                conn.execute("UPDATE routage_sources SET statut='refuse' "
                             "WHERE source_key=%s", (args.source,))
            else:
                if not re.match(r"^wazuh-[a-z]{2,20}$", args.index):
                    p.error("--index doit avoir la forme wazuh-<suffixe>")
                conn.execute(
                    "UPDATE routage_sources SET index_base=%s, "
                    "nomme_par='humain', statut='propose' WHERE source_key=%s",
                    (args.index, args.source))
            conn.commit()
            r = appliquer(conn, args.source) if args.index else None
        print(r or "fait")
        return

    if args.appliquer:
        rapport = reconcilier(dry_run=False)
    else:
        rapport = reconcilier(dry_run=True)
    print(f"{rapport['ok']} source(s) correctement routée(s), "
          f"{len(rapport['nouvelles'])} nouvelle(s), "
          f"{len(rapport['creees'])} index set(s) créé(s), "
          f"{len(rapport['anomalies'])} anomalie(s)")
    if rapport["pipeline"]:
        print(f"  pipeline : {rapport['pipeline']}")
    for a in rapport["anomalies"]:
        print(f"  ! {a['titre']}")
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        _table(conn)


if __name__ == "__main__":
    main()
