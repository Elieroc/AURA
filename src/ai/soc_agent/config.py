"""Configuration du soc-agent, lue depuis l'environnement.

Aucune valeur par défaut pour les secrets : une absence doit faire échouer le
démarrage, pas passer silencieusement sur une valeur de repli.
"""

import ipaddress
import os
import sys
from urllib.parse import urlparse


def _requis(nom: str) -> str:
    val = os.environ.get(nom)
    if not val:
        sys.exit(f"Variable d'environnement manquante : {nom} (cf. ai/.env.example)")
    return val


# --- Indexer Wazuh (source des alertes) ------------------------------------
#
# On lit l'indexer plutôt que d'être poussé par l'integrator du manager : le
# GeoIP est appliqué par un pipeline d'ingest côté indexer, donc l'enrichissement
# n'existe QUE dans cette copie. L'integrator, lui, se déclenche en amont et
# verrait des alertes sans géoloc.
INDEXER_URL = os.environ.get("INDEXER_URL", "https://127.0.0.1:9200")
INDEXER_USER = os.environ.get("INDEXER_USER", "admin")
INDEXER_PASSWORD = _requis("INDEXER_PASSWORD")

# Certificats auto-signés générés par la stack Wazuh. À passer à true (avec
# INDEXER_CA) dès que l'indexer n'est plus sur la loopback.
INDEXER_VERIFY_TLS = os.environ.get("INDEXER_VERIFY_TLS", "false").lower() == "true"
INDEXER_CA = os.environ.get("INDEXER_CA") or None

# Indices interrogés pour l'ingestion. Un pipeline d'ingest indexer
# (wazuh/config/wazuh_cluster/alerts-pipeline.json) route les alertes par type :
# tout préfixe qu'il sait produire DOIT figurer ici, sinon l'IA est aveugle à ce
# capteur — en silence, puisqu'il n'y a ni erreur ni alerte manquante côté Wazuh,
# juste zéro ligne en base.
#
# Deux fois le même piège en pratique : d'abord wazuh-linux-*/wazuh-web-*, puis
# le 2026-07-29 wazuh-yara-* (5 alertes de niveau 12, dont un web shell) et
# wazuh-firewall-* (tout Suricata, routé la veille). D'où la liste exhaustive
# ci-dessous, alignée sur les `index` du pipeline : la tenir à jour EN MÊME TEMPS
# que lui.
INDEXER_ALERT_INDICES = os.environ.get(
    "INDEXER_ALERT_INDICES",
    "wazuh-alerts-*,wazuh-linux-*,wazuh-web-*,wazuh-yara-*,wazuh-firewall-*,"
    "wazuh-proxy-*,wazuh-dns-*,wazuh-vpn-*,wazuh-jellyfin-*,wazuh-windows-*")

# --- Base du soc-agent ------------------------------------------------------
PG_DSN = os.environ.get(
    "PG_DSN",
    "postgresql://{u}:{p}@127.0.0.1:{port}/{db}".format(
        u=os.environ.get("PGUSER", "socagent"),
        p=_requis("PGPASSWORD"),
        port=os.environ.get("PGPORT", "5433"),
        db=os.environ.get("PGDATABASE", "socagent"),
    ),
)

# Plafond de durée d'UNE requête, appliqué à toutes les connexions du soc-agent.
#
# Sans lui, une requête partie de travers immobilise sa session sans fin, et
# tout ce qui a besoin d'un verrou sur les mêmes tables attend derrière —
# constaté le 2026-08-11, un `ALTER TABLE` de migration resté bloqué derrière
# des sessions du cycle. Une requête de ce pipeline qui dépasse cinq minutes est
# de toute façon anormale : les gros lots sont découpés (INGEST_LOT, UEBA_LOT).
#
# Volontairement PAS de idle_in_transaction_session_timeout : le cycle tient son
# verrou consultatif dans une transaction ouverte pendant toute son exécution
# (cf. cycle.VERROU). Le tuer sur inactivité libérerait le verrou et
# autoriserait deux cycles concurrents — la panne serait pire que le mal.
PG_STATEMENT_TIMEOUT_MS = int(
    os.environ.get("PG_STATEMENT_TIMEOUT_MS", "300000"))


def _avec_statement_timeout(dsn: str, ms: int) -> str:
    """Ajoute `options=-c statement_timeout=<ms>` au DSN, sans rien écraser.

    Passer par le DSN plutôt que par un `SET` après connexion : il n'existe pas
    un point de passage unique où toutes les connexions sont ouvertes (chaque
    module fait son `psycopg.connect`), donc le seul endroit qui les couvre
    toutes est la chaîne de connexion elle-même.
    """
    if ms <= 0 or "options=" in dsn:
        return dsn
    opt = f"-c statement_timeout={ms}"
    if dsn.startswith(("postgresql://", "postgres://")):
        from urllib.parse import quote
        return f"{dsn}{'&' if '?' in dsn else '?'}options={quote(opt)}"
    return f"{dsn} options='{opt}'"


PG_DSN = _avec_statement_timeout(PG_DSN, PG_STATEMENT_TIMEOUT_MS)

# --- Filtrage ---------------------------------------------------------------
#
# Niveau Wazuh minimal pour OUVRIR un incident (graine). 12 = seuil HIGH de
# l'échelle 0-15 (12-14 high, 15 critical) : un case IRIS + analyse IA ne se
# déclenchent QUE sur une alerte HIGH/CRITICAL. En dessous, une alerte n'ouvre
# jamais d'incident mais peut être RATTACHÉE à un incident déjà confirmé pour
# l'enrichir (cf. ATTACH_MIN_LEVEL) — l'analyse voit tout, l'ouverture reste
# réservée au signal fort.
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "12"))

# --- Filtre VirusTotal des exécutables légitimes -----------------------------
#
# Avant corrélation, une alerte qui porte un HASH d'exécutable (Sysmon, FIM,
# intégration VT) est confrontée à la réputation VirusTotal du hash. Un binaire
# jugé LÉGITIME (aucun moteur positif, hash connu de VT) fait suppress l'alerte :
# un exe propre ne doit pas peser dans un case, ni en ouvrir un s'il est seul.
# Filtre déterministe (pas le LLM) ; audit complet (suppress_reason + cache VT).
#
# Réutilise la clé de l'intégration VirusTotal de Wazuh. Sans clé, le filtre est
# inactif (aucun appel, rien n'est suppressé).
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
VT_URL = os.environ.get("VT_URL", "https://www.virustotal.com/api/v3")
# Ne confronte à VT que les exécutables d'alertes d'au moins ce niveau : celles
# qui pourraient graine/rejoindre un case. En dessous, le noise filter suffit.
VT_EXE_MIN_LEVEL = int(os.environ.get("VT_EXE_MIN_LEVEL", "7"))
# Un verdict VT est recalculé au-delà de cet âge (un hash inconnu peut devenir
# malveillant). Sous ce TTL, on lit le cache.
VT_CACHE_TTL_DAYS = int(os.environ.get("VT_CACHE_TTL_DAYS", "14"))
# Plafond d'appels VT réseau par passage (API publique : 4 req/min, 500/jour).
# Le cache absorbe le reste ; les non-résolus seront retentés au cycle suivant.
VT_MAX_LOOKUPS = int(os.environ.get("VT_MAX_LOOKUPS", "4"))
# Nombre minimal de moteurs ayant analysé le hash pour croire un verdict « clean »
# (un hash à peine connu ne prouve pas la légitimité). En deçà : 'unknown', on ne
# suppress pas (dans le doute, on garde l'alerte).
VT_MIN_ENGINES = int(os.environ.get("VT_MIN_ENGINES", "5"))
# Ne jamais suppress un exécutable situé dans un répertoire système : un binaire
# signé de System32 (powershell.exe, certutil.exe…) est propre pour VT mais peut
# être détourné (LOLBin) — la détection y est COMPORTEMENTALE, pas sur le fichier.
# On ne filtre que les exécutables DÉPOSÉS ailleurs (temp, profils, /tmp, /home…).
VT_DIRS_SYSTEME = tuple(d.lower() for d in os.environ.get(
    "VT_DIRS_SYSTEME",
    r"c:\windows,c:\program files,c:\program files (x86),"
    "/usr/bin,/usr/sbin,/bin,/sbin,/usr/lib,/lib").split(","))

# Enrichissement de périmètre : une fois un incident FORMÉ par une graine
# (>= MIN_LEVEL), on lui rattache TOUTES les alertes du même agent dans sa
# fenêtre à partir de ce niveau. Descendu à 3 pour capter l'audit de commande
# (règle 80792, niv. 3) : c'est là que vivent l'énumération et l'exploitation
# (find SUID, chmod, cat /etc/shadow, useradd…). Le but est de reconstituer
# TOUT ce qu'a fait l'attaquant sur la machine compromise, pas seulement les
# pics. Ces alertes NE créENT JAMAIS d'incident seules (trop fréquentes) : elles
# ne complètent qu'un incident déjà confirmé. 0 désactive l'enrichissement.
ATTACH_MIN_LEVEL = int(os.environ.get("ATTACH_MIN_LEVEL", "3"))

# Niveau en dessous duquel on n'ingère même pas. 0 = tout stocker, ce qui donne
# les statistiques complètes ; monter à MIN_LEVEL une fois la mesure faite.
INGEST_MIN_LEVEL = int(os.environ.get("INGEST_MIN_LEVEL", "0"))

# --- Rattrapage des alertes indexées en retard ------------------------------
#
# Le curseur d'ingestion avance sur `@timestamp`, la date de l'ÉVÉNEMENT, pas
# celle de son indexation. Toute alerte qui devient visible à la recherche APRÈS
# que le curseur a dépassé son horodatage est définitivement sautée. Deux
# échelles de retard, deux parades.
#
# 1. Skew d'indexation (secondes à minutes) : transit agent -> manager ->
#    indexer + refresh de l'index. On reprend l'ingestion un peu avant la
#    position enregistrée. Le recouvrement est gratuit, l'insertion étant
#    idempotente (ON CONFLICT DO NOTHING sur l'id natif Wazuh).
INGEST_LOOKBACK_MINUTES = int(os.environ.get("INGEST_LOOKBACK_MINUTES", "15"))

# 2. Rejeu d'un agent (heures à jours) : un agent coupé du manager bufferise ses
#    logs et les rejoue à la reconnexion AVEC leur horodatage d'origine. Le
#    lookback ci-dessus ne va pas assez loin. D'où un balayage périodique et
#    complet de cette fenêtre, indépendant du curseur, qui ne récupère que ce
#    qui manque. 48 h couvre une coupure de week-end.
INGEST_SWEEP_HOURS = int(os.environ.get("INGEST_SWEEP_HOURS", "48"))

# Cadence du balayage. Le cycle tourne toutes les 5 min ; sweeper à chaque tour
# serait du gâchis, une heure de latence sur des alertes déjà en retard de
# plusieurs heures ne change rien.
INGEST_SWEEP_INTERVAL_MINUTES = int(
    os.environ.get("INGEST_SWEEP_INTERVAL_MINUTES", "60"))

# --- Modèle : DeepSeek (API cloud, compatible OpenAI) -----------------------
#
# Seul chemin d'inférence : cette machine n'a ni GPU ni la RAM pour un modèle en
# continu, et il n'y a pas de repli local. DeepSeek expose une API compatible OpenAI
# (/chat/completions, Bearer token). Conséquence de sécurité MAJEURE : les
# données SOC quittent l'hôte. La pseudonymisation est EN PLACE et obligatoire
# (`anonymize.py`) : jetons stables par incident, `verifier_fuite` refuse l'appel
# si une valeur réelle a survécu, réhydratation à la réponse pour que l'analyste
# voie les vraies valeurs dans IRIS. Ne pas confondre avec `sanitize.py`, qui
# neutralise le texte hostile — autre problème, autre module.
#
# Aucune contrainte de grammaire possible : DeepSeek garantit un JSON valide
# (response_format), pas le respect du schéma ni de l'enum. La
# barrière est donc dans le code : coercition/validation dans triage.py, en
# plus des garde-fous déterministes d'actions.py.
DEEPSEEK_API_KEY = _requis("DEEPSEEK_API_KEY")
# Les modèles v4 raisonnent : les tokens de raisonnement (reasoning_content)
# sont décomptés de max_tokens AVANT le content. Un budget trop court (l'ancien
# 400, calé sur le chat non raisonnant) est intégralement consommé par le
# raisonnement → finish_reason=length et content VIDE. Il faut de la marge pour
# le raisonnement + le JSON de verdict.
TRIAGE_MAX_TOKENS = int(os.environ.get("TRIAGE_MAX_TOKENS", "6000"))
# Plafond de taille du PROMPT de triage (entrée). Au-delà, l'incident était
# ignoré — ce qui faisait taire les plus gros/graves. Relevé à 5000.
PLAFOND_PROMPT_TOKENS = int(os.environ.get("TRIAGE_PROMPT_MAX_TOKENS", "5000"))
# Le rapport TP est un récit markdown multi-sections, plus long que le verdict ;
# avec le raisonnement en plus, il lui faut davantage de marge encore.
#
# 6000 ne suffisait pas. Mesuré à un exercice purple-team : deux rapports
# d'incidents AD (plusieurs milliers d'alertes, 20 règles montrées au modèle)
# ont rendu `finish_reason=length` avec un content VIDE — le raisonnement avait
# mangé tout le budget. Le repli écrivait alors `triage.reason` À LA FOIS dans
# `resume` et dans `analyse`, d'où deux sections identiques dans le rapport.
# Les rapports qui ont abouti consommaient déjà 4000-5700 tokens de content :
# 6000 ne laissait aucune place au raisonnement. 14000 donne la marge.
REPORT_MAX_TOKENS = int(os.environ.get("REPORT_MAX_TOKENS", "14000"))
# Nom de case : sortie minuscule (nom de code + titre court) mais le modèle
# raisonne quand même — il lui faut de quoi ne pas tronquer avant le JSON.
CASE_NAME_MAX_TOKENS = int(os.environ.get("CASE_NAME_MAX_TOKENS", "1500"))
# Réponse à une tâche WHITELIST (décision ou question) : sortie courte, mais
# même marge de raisonnement que le nom de case.
WHITELIST_TASK_MAX_TOKENS = int(os.environ.get("WHITELIST_TASK_MAX_TOKENS", "1500"))
DEEPSEEK_URL = os.environ.get("DEEPSEEK_URL", "https://api.deepseek.com")
# deepseek-chat déprécié (l'API ne l'accepte plus, 400). Tiers actuels :
# deepseek-v4-flash (rapide/économique, équivalent le plus proche du chat sur
# lequel le pipeline a été calé) et deepseek-v4-pro (verdict plus robuste).
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")

# Délais d'attente de l'appel LLM, en secondes : (connexion, lecture).
#
# Les deux comptent séparément dans `requests`, et le second est un délai
# d'INACTIVITÉ, pas une durée totale : un serveur qui envoie un octet toutes les
# 100 s ne déclenche jamais un timeout de lecture de 120 s. C'est pour cela
# qu'ils sont explicites ici plutôt qu'écrits en dur — un fournisseur lent ou en
# panne partielle ne doit pas immobiliser le cycle, qui tient son verrou
# consultatif pendant toute son exécution.
#
# Connexion courte (10 s) : si le TCP ne s'établit pas, réessayer plus tard est
# la bonne réponse. Lecture longue (120 s) : un modèle raisonnant met du temps à
# produire le premier octet, et couper trop tôt gaspille des tokens déjà payés.
LLM_TIMEOUT_CONNECT_S = float(os.environ.get("LLM_TIMEOUT_CONNECT_S", "10"))
LLM_TIMEOUT_READ_S = float(os.environ.get("LLM_TIMEOUT_READ_S", "120"))


# --- DFIR-IRIS (case management) --------------------------------------------
#
# Un case par incident trié. Le pipeline y écrit en dfir-iris-client direct
# (déterministe) ; le serveur MCP IRIS, lui, sert l'investigation interactive.
IRIS_URL = os.environ.get("IRIS_URL", "https://127.0.0.1:8443")
IRIS_API_KEY = os.environ.get("IRIS_API_KEY", "")
# Certificat auto-signé sur la loopback. À passer à true si IRIS est exposé.
IRIS_VERIFY_TLS = os.environ.get("IRIS_VERIFY_TLS", "false").lower() == "true"
# Client IRIS (dossier « customer ») rattaché aux cases. 1 = client par défaut.
IRIS_CUSTOMER = int(os.environ.get("IRIS_CUSTOMER", "1"))

# --- Lien pivot vers le dashboard Wazuh -------------------------------------
#
# Chaque évènement de timeline IRIS porte un lien Discover filtré sur sa règle
# et son agent : l'analyste passe du dossier au log Wazuh brut en un clic.
# URL vue depuis le NAVIGATEUR de l'analyste (pas depuis cet hôte) — d'où un
# défaut sur le nom d'hôte public plutôt que la loopback ; à ajuster.
# Le chemin Discover dépend de la version du dashboard (OpenSearch Dashboards
# 2.x sur Wazuh 4.9 = /app/data-explorer/discover) : surchargeable au besoin.
# Pas de défaut utilisable : « localhost » pointerait sur la machine de
# l'analyste (le lien est ouvert depuis SON navigateur, pas depuis cet hôte)
# et casserait le lien. À définir dans .env avec l'URL réellement joignable
# du dashboard (ex. https://soc.exemple.local).
WAZUH_DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "")
WAZUH_DASHBOARD_DISCOVER_PATH = os.environ.get(
    "WAZUH_DASHBOARD_DISCOVER_PATH", "/app/data-explorer/discover")
# Index-pattern couvrant les indices réellement alimentés (cf. le routage
# wazuh-linux/web). « soc-ai-all-alerts » existe déjà côté dashboard.
WAZUH_DASHBOARD_INDEX_PATTERN = os.environ.get(
    "WAZUH_DASHBOARD_INDEX_PATTERN", "soc-ai-all-alerts")

# --- Sous-réseaux internes du parc ------------------------------------------
#
# Sert à qualifier les IOC IP : une cible /dev/tcp ou une IP source DANS ces
# plages = mouvement latéral interne, PAS un C2. Ne PAS assimiler « privé
# RFC1918 » à « interne » : un C2 peut lui-même être en RFC1918 (VPN, cloud
# privé...) — le classer « interne » le blanchirait. Lister explicitement les
# subnets du parc surveillé ; tout le reste (dont un C2 en RFC1918) est externe.
RESEAUX_INTERNES = [
    r.strip() for r in os.environ.get("RESEAUX_INTERNES", "").split(",")
    if r.strip()]

# --- Remédiation (exécution des actions) ------------------------------------
#
# Passage de « proposer » à « exécuter ». Deux canaux d'écriture :
#  - Shuffle SOAR (webhooks) pour l'isolation d'hôte et le kill de process :
#    workflows existants, réversibles, Shuffle porte l'auth Wazuh.
#  - API Wazuh directe pour le blocage d'IP et la désactivation de compte
#    (pas de workflow Shuffle dédié). Active-response poussée sur 1514.
#
# MITIGATE_EXECUTE=false par défaut : DRY-RUN. Rien n'est réellement déclenché,
# le module montre le payload et écrit des notes IRIS marquées [SIMULATION].
# Une action à fort impact sur la prod ne doit pas s'armer par accident.
MITIGATE_EXECUTE = os.environ.get("MITIGATE_EXECUTE", "false").lower() == "true"

# Nombre max d'émissions d'une même remédiation restée 'émis' (partie mais jamais
# confirmée par un `ar-result`). Au-delà, on cesse de réémettre : un canal
# fire-and-forget qui ne confirme jamais ne doit pas être sollicité à chaque
# cycle indéfiniment. 3 : deux retentatives après le premier essai.
MITIGATE_MAX_TENTATIVES = int(os.environ.get("MITIGATE_MAX_TENTATIVES", "3"))

# Intervalle minimal (s) entre deux active-responses Wazuh émises. Une rafale
# d'AR de même commande vers un même agent sature `wazuh-execd`, qui en drope
# silencieusement une partie AVANT le script (purple-team #3 : 2 quarantaines/
# agent perdues, ni log ni `ar-result`). On sérialise les envois côté émetteur.
MITIGATE_AR_GAP_SECONDS = float(os.environ.get("MITIGATE_AR_GAP_SECONDS", "1.5"))

SHUFFLE_URL = os.environ.get("SHUFFLE_URL", "http://localhost:5001")
SHUFFLE_WEBHOOK_ISOLATE = os.environ.get(
    "SHUFFLE_WEBHOOK_ISOLATE", "webhook_00000000-0000-0000-0000-00000000a001")
SHUFFLE_WEBHOOK_KILL = os.environ.get(
    "SHUFFLE_WEBHOOK_KILL", "webhook_00000000-0000-0000-0000-00000000a002")

# API Wazuh (user wazuh-wui). Même mot de passe que API_PASSWORD dans wazuh/.env.
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")

# SSH vers les agents, pour lire le marqueur d'isolation (/var/ossec/isolated).
# Réservé à la LECTURE d'état : jamais de shell piloté par le LLM (cf. CLAUDE.md).
# La règle d'isolation n'autorise SSH que depuis le manager — ce lecteur doit
# donc tourner sur l'hôte du manager pour rester fiable même agent isolé.
SSH_KEY = os.path.expanduser(
    os.environ.get("SSH_KEY", "~/.ssh/wazuh_ops_ed25519"))
SSH_USER = os.environ.get("SSH_USER", "wazuh-admin")
ISOLATION_MARKER = os.environ.get("ISOLATION_MARKER", "/var/ossec/isolated")

# Agents qu'aucune remédiation ne peut prendre pour cible, quel que soit le
# verdict. 000 est le manager : l'isoler coupe la collecte de TOUT le parc, la
# console, l'API — et donc le seul canal par lequel on pourrait le dé-isoler.
# C'est un suicide du SOC, et il n'a rien d'hypothétique : le 2026-07-29 un
# incident YARA porté par l'agent `wazuh.manager` (les alertes YARITRUST sont
# émises par le manager, alors que le fichier suspect est sur une AUTRE machine)
# a fait sortir `propose_isolate_host` sur 000. L'action est partie ; seule
# l'absence de `nft` dans le conteneur l'a rendue inoffensive.
#
# À laisser en tête des garde-fous déterministes : le modèle ne voit qu'un
# `agent_id` dans son contexte et n'a aucun moyen de savoir lequel porte le SOC.
AGENTS_PROTEGES = {
    a.strip() for a in os.environ.get("AGENTS_PROTEGES", "000").split(",")
    if a.strip()}

# Agents « capteur d'hôte » : leur télémétrie décrit l'activité d'AUTRES machines
# (ex. l'auditd de l'hôte Proxmox voit les execve de ses conteneurs LXC et les
# attribue à lui-même). Une remédiation ne doit JAMAIS viser un tel agent : le
# vrai théâtre est ailleurs (le conteneur), et agir sur le capteur est soit
# inutile (désactiver un compte qui n'y vit pas — le bug constaté), soit trop
# large (isoler tout l'hôte pour un seul conteneur). Dans le doute sur la vraie
# machine, on n'agit pas.
#
# Deux formes, la seconde souvent oubliée :
#
#  - capteur d'HÔTE : l'hôte Proxmox d'une flotte de LXC, dont l'auditd voit les
#    execve de tous les conteneurs et se les attribue. Isoler l'hôte pour un seul
#    conteneur coupe tout ce qu'il héberge.
#  - capteur RÉSEAU : la passerelle qui porte l'IDS et le pare-feu. Suricata et
#    filterlog décrivent le trafic des AUTRES machines, mais les alertes portent
#    l'agent de la passerelle. Un beacon C2 émis par un poste du LAN ouvre donc
#    un incident sur l'agent du pare-feu — et une remédiation calculée là-dessus
#    viserait l'équipement qui achemine tout le réseau, SOC compris. Constaté le
#    2026-08-11 : incident #2697 (926 alertes de C2) attribué à home-r-pf01
#    alors que la machine coupable était 192.168.5.15.
#
# Aucun défaut : à lister explicitement par déploiement (id d'agent Wazuh) via
# AGENTS_CAPTEURS.
AGENTS_CAPTEURS = {
    a.strip() for a in os.environ.get("AGENTS_CAPTEURS", "").split(",")
    if a.strip()}

# Agents tournant sous Windows : la même action logique (isoler, bloquer, tuer,
# désactiver un compte) part sur une active-response différente selon l'OS —
# les scripts Windows/AD (wazuh/active-response/windows/) au lieu des .sh Linux.
# Aucun défaut : à lister explicitement par déploiement (id d'agent Wazuh).
AGENTS_WINDOWS = {
    a.strip() for a in os.environ.get("AGENTS_WINDOWS", "").split(",")
    if a.strip()}

# Contrôleurs de domaine : EXÉCUTEURS des actions de domaine (désactiver un
# compte AD, retirer d'un groupe privilégié). Une action de domaine ne part PAS
# sur l'hôte membre compromis — le compte n'y est pas local — mais sur un DC,
# quel que soit l'hôte où la preuve est apparue (analogue inverse d'AGENTS_CAPTEURS).
# Aucun défaut : à lister explicitement par déploiement (id d'agent Wazuh).
AGENTS_DC = {
    a.strip() for a in os.environ.get("AGENTS_DC", "").split(",")
    if a.strip()}

# IP(s) que l'isolation d'un hôte Windows laisse joignables (le manager Wazuh,
# pour que l'agent continue de reporter et que le SOC puisse investiguer en
# WinRM). Passées en extra_args à win-host-isolate.exe. Aucun défaut : à
# définir par déploiement (IP du manager telle que l'agent la joint).
MITIGATE_ISOLATE_ALLOW = [
    ip.strip() for ip in os.environ.get("MITIGATE_ISOLATE_ALLOW", "").split(",")
    if ip.strip()]

# Règles Wazuh qui signent une COMPROMISSION ACTIVE de l'hôte lui-même :
# post-exploitation avérée (l'attaquant exécute déjà du code sur la machine),
# pas une simple tentative entrante. Sert au garde-fou d'isolation : sur ces
# règles, l'isolation N'EST PLUS rétrogradée vers un confinement moins invasif
# (bloquer une IP ne délogera pas un attaquant déjà installé — reverse shell,
# rootkit, persistance root, webshell qui exécute). Mesuré au purple-team du
# 2026-07-31 : l'hôte web .15, RCE + webshell + persistance root + rootkit en
# cours, n'a reçu qu'un block_ip (isolation retirée) et est resté joignable.
#
# On liste des IDENTIFIANTS (stables), pas du texte de description (cf. le piège
# rule_desc de correlate.py). Catégories : webshell qui exécute (100701/710/750),
# reverse shell / C2 / tunnel (100650/651/652/764), rootkit / implant kernel /
# ld.so.preload (100748/760/763/772, 521), persistance root (100740/741/742/
# 749/770), accès aux identifiants (100643/653). PAS les probes web entrantes
# seules (100700 RCE-attempt, 100702 LFI/SQLi) : un scanner qui tape une URL
# n'est pas une compromission — c'est le cas que le garde-fou d'isolation
# protège (block_ip suffit). L'ensemble est surchargable par l'env.
RULES_COMPROMISSION_HOTE = {
    r.strip() for r in os.environ.get(
        "RULES_COMPROMISSION_HOTE",
        "100701,100710,100750,"          # webshell : commande exécutée
        "100650,100651,100652,100764,"   # reverse shell / C2 / tunnel sortant
        "100748,100760,100763,100772,521,"  # rootkit / kernel / ld.so.preload
        "100740,100741,100742,100749,100770,"  # persistance root
        "100643,100653").split(",")      # accès /etc/shadow
    if r.strip()}

# Groupes Wazuh dont les agents ne sont JAMAIS isolés du réseau.
#
# L'isolation ne doit concerner que des ENDPOINTS — des machines dont on peut
# couper le réseau sans couper celui des autres. Un pare-feu, un reverse proxy,
# un résolveur DNS ou une passerelle VPN acheminent le trafic D'AUTRUI :
# les isoler ne contient pas l'incident, ça provoque une panne générale, et sur
# un pare-feu ça coupe aussi le lien par lequel on rétablirait la situation.
#
# Le rôle est porté par les groupes Wazuh plutôt que par une liste d'ID en dur :
# c'est le mécanisme d'inventaire natif, il survit à l'ajout d'un agent, et
# l'opérateur qui enrôle une machine déclare son rôle au même endroit que le
# reste de sa configuration. Cf. wazuh/README.md pour la création du groupe.
ISOLATION_GROUPES_INTERDITS = {
    g.strip().lower()
    for g in os.environ.get("ISOLATION_GROUPES_INTERDITS", "infrastructure").split(",")
    if g.strip()}

# Que faire quand on n'arrive PAS à connaître les groupes d'un agent (API
# injoignable, agent supprimé) : par défaut on refuse l'isolation.
#
# C'est un choix, et c'est le bon sens du garde-fou : l'isolation est l'action
# la plus destructrice du catalogue, et ne pas pouvoir vérifier qu'une machine
# est un endpoint est une raison de s'abstenir, pas de tenter. Le pire cas d'un
# refus est un incident non contenu que l'analyste voit dans le case (l'action
# bascule en escalate_human) ; le pire cas d'une autorisation par défaut est le
# pare-feu du site coupé sur une panne d'API.
ISOLATION_REFUS_SI_ROLE_INCONNU = os.environ.get(
    "ISOLATION_REFUS_SI_ROLE_INCONNU", "true").lower() == "true"


# --- CMDB : rôle et priorité des assets (assets.py) -------------------------
#
# Toutes les machines ne se valent pas. Le même comportement — un binaire inédit
# qui s'exécute, un compte créé — n'a pas la même portée sur un contrôleur de
# domaine et sur un poste de test. Le pipeline ne connaissait jusqu'ici que
# `rule_level`, qui décrit la RÈGLE et pas la MACHINE : un niveau 12 sur le DC et
# un niveau 12 sur un poste jetable arrivaient dans la même file, dans le même
# ordre, avec les mêmes garde-fous.
#
# Le rôle est porté par les groupes Wazuh (mécanisme d'inventaire natif, déjà
# utilisé par ISOLATION_GROUPES_INTERDITS), préfixés pour ne pas collisionner
# avec les groupes de configuration : `role-dc`, `role-firewall`…
CMDB_GROUPE_PREFIXE = os.environ.get("CMDB_GROUPE_PREFIXE", "role-")

# Rôle -> priorité (1 = le plus critique). Le classement suit ce qu'on perd si
# la machine tombe :
#
#  P1 — la compromission fait perdre le domaine (dc), le réseau (firewall), la
#       capacité de détection (soc), tout ce qui est hébergé (hypervisor), la
#       confiance (pki) ou la capacité de restauration (backup).
#  P2 — service exposé ou porteur de données : pivot classique d'une intrusion.
#  P3 — serveur interne sans exposition ni donnée sensible.
#  P4 — poste client, lab, machine éphémère, et tout rôle non déclaré.
PRIORITE_ROLES: dict[str, int] = {
    "dc": 1, "firewall": 1, "soc": 1, "hypervisor": 1, "pki": 1, "backup": 1,
    "web": 2, "db": 2, "mail": 2, "proxy": 2, "dns": 2, "vpn": 2,
    "fileserver": 2,
    "serveur": 3, "admin": 3,
    "endpoint": 4, "lab": 4,
}
# Surcharge/ajout par déploiement : PRIORITE_ROLES="nas=1,jellyfin=3".
for _paire in os.environ.get("PRIORITE_ROLES", "").split(","):
    if "=" in _paire:
        _role, _p = _paire.split("=", 1)
        try:
            PRIORITE_ROLES[_role.strip().lower()] = int(_p)
        except ValueError:
            sys.exit(f"PRIORITE_ROLES : priorité invalide dans « {_paire} »")

# Priorité d'une machine dont le rôle n'est PAS déclaré (aucun groupe `role-`,
# agent absent de la CMDB, API injoignable). P4 : décision opérateur — un asset
# non déclaré ne prend pas la place d'un asset critique dans la file.
#
# Le revers est réel : une machine importante mais jamais déclarée est traitée
# comme un poste jetable. C'est pourquoi la source de la priorité est TRACÉE
# (`assets.priorite_source = 'defaut'`) et remontée par le rapport de couverture
# — la dette d'inventaire doit être visible, pas devinée.
PRIORITE_DEFAUT = int(os.environ.get("PRIORITE_DEFAUT", "4"))

# Décalage appliqué au niveau Wazuh pour obtenir la sévérité EFFECTIVE de
# l'incident, par priorité (P1..P4). `max_level` n'est jamais modifié : il
# décrit ce que la règle a vu, et tout le reste du pipeline (corrélation, UEBA,
# RULES_COMPROMISSION_HOTE) s'appuie dessus. La sévérité est une seconde
# grandeur, qui ajoute « sur quoi ».
SEVERITE_BONUS_PRIORITE = {
    p + 1: int(v) for p, v in enumerate(
        os.environ.get("SEVERITE_BONUS_PRIORITE", "2,1,0,-1").split(","))}

# Niveau à partir duquel une clôture automatique en faux positif est interdite,
# PAR PRIORITÉ (cf. actions.appliquer_garde_fous). Sur un asset P1, on ne laisse
# pas le modèle refermer un incident de niveau 12 : le coût d'un faux négatif y
# est sans commune mesure avec celui d'un case à lire.
CLOTURE_INTERDITE_PAR_PRIORITE = {
    p + 1: int(v) for p, v in enumerate(
        os.environ.get("CLOTURE_INTERDITE_PAR_PRIORITE", "12,13,14,14").split(","))}

# Priorité forcée pour un agent CAPTEUR (AGENTS_CAPTEURS). Sa télémétrie décrit
# l'activité d'AUTRES machines : le pare-feu qui porte Suricata est bien un
# asset P1, mais les alertes qu'il REMONTE parlent des postes du LAN. Sans ce
# rabattement, chaque scan vu par l'IDS deviendrait un incident P1 et noierait la
# file — la priorisation dégraderait le tri au lieu de l'améliorer.
PRIORITE_CAPTEUR = int(os.environ.get("PRIORITE_CAPTEUR", "3"))


# --- Corrélation ------------------------------------------------------------
#
# Deux alertes du même agent séparées de moins de CORRELATION_GAP_MINUTES et
# partageant un point commun (tactique MITRE, groupe de règle ou entité) sont
# rattachées au même incident. Chaînage par proximité : A-B et B-C rattachent
# aussi A-C, même si A et C sont éloignés.
CORRELATION_GAP_MINUTES = int(os.environ.get("CORRELATION_GAP_MINUTES", "30"))

# Fenêtre élargie pour les liens FORTS — même IP source, même fichier, même
# compte. Une IP hostile qui revient trois fois dans la journée est une seule
# campagne ; avec la seule fenêtre de 30 minutes, elle produisait trois
# incidents distincts, donc trois triages LLM pour le même sujet.
ENTITY_GAP_MINUTES = int(os.environ.get("ENTITY_GAP_MINUTES", "360"))

# Garde-fou contre le chaînage sans fin : sur un hôte bruyant, une alerte toutes
# les 25 minutes fusionnerait une semaine entière en un seul incident illisible.
MAX_INCIDENT_HOURS = int(os.environ.get("MAX_INCIDENT_HOURS", "6"))

# Fenêtre de fusion CAMPAGNE (approche A) : incidents de plusieurs hôtes réunis
# dans un seul case quand ils partagent un marqueur FORT appartenant à
# l'attaquant (compte créé, IP C2 externe, fichier malveillant). Plus large que
# MAX_INCIDENT_HOURS car une campagne s'étale sur des jours ; le risque de
# sur-fusion est borné par l'exigence d'un marqueur d'attaquant partagé (jamais
# une IP interne ni une entité générique). 0 désactive la fusion campagne.
CAMPAGNE_GAP_HOURS = int(os.environ.get("CAMPAGNE_GAP_HOURS", "48"))

# Durée de vie du RE-TRIAGE automatique d'un incident (correctif #4, explosion
# de tokens du 2026-07-30). Passé ce délai depuis `first_seen`, un incident déjà
# trié n'est plus re-trié même s'il gagne des alertes (`needs_refresh`) : sinon
# un incident du parc bruyant se fait ré-analyser par le LLM tous les 5 min à
# vie (constaté : des incidents vieux de plusieurs jours brûlaient encore
# 18-25 appels LLM/24h). Une intrusion nouvelle rouvre de toute façon un
# incident neuf via les fenêtres de corrélation. 0 désactive le plafond (re-
# triage sans limite d'âge). Ne touche PAS la création (un incident jamais trié
# est toujours trié, quel que soit son âge).
INCIDENT_REFRESH_TTL_HOURS = int(
    os.environ.get("INCIDENT_REFRESH_TTL_HOURS", "48"))

# --- Watchdog « capteur muet » (watchdog.py) ---------------------------------
# Un capteur qui parlait puis se tait est un angle mort qu'aucune règle ne voit.
# Groupes de règles surveillés : leur silence rend inertes des pans entiers du
# ruleset (audit -> 1006xx/1007xx ; suricata -> détection réseau ; sshd/pam ->
# brute-force). Ajout facile d'un groupe applicatif si besoin.
WATCHDOG_CAPTEURS = tuple(os.environ.get(
    "WATCHDOG_CAPTEURS", "audit,suricata,sshd,syscheck").split(","))
# Fenêtre de référence : sur combien d'heures un capteur est jugé « établi ».
WATCHDOG_REF_HEURES = int(os.environ.get("WATCHDOG_REF_HEURES", "168"))  # 7 j
# Volume minimal sur la fenêtre de référence pour ne pas alerter sur un capteur
# anecdotique (un unique event isolé n'est pas une base).
WATCHDOG_BASELINE_MIN = int(os.environ.get("WATCHDOG_BASELINE_MIN", "20"))
# Silence toléré avant de déclarer la PANNE. 10 min, réglage opérateur du
# 2026-08-11, cohérent avec la cadence réelle des capteurs continus mesurée sur
# 7 jours de base : écart entre deux événements, p95 / max
#
#     audit      5,4 min / 8,3 min
#     suricata   0,0 min / 3,7 min
#
# Un silence de 10 min sur ces deux-là ne s'explique donc plus par un creux de
# trafic. Les capteurs ÉVÉNEMENTIELS (sshd, syscheck) ont leur propre seuil
# ci-dessous : chez eux le silence est l'état normal.
WATCHDOG_SILENCE_MINUTES = int(os.environ.get("WATCHDOG_SILENCE_MINUTES", "10"))

# Seuil PAR CAPTEUR, pour ceux qui n'émettent pas en continu.
#
# syscheck n'est pas un flux : le FIM n'alerte que sur un CHANGEMENT (règles
# 550/553/554/594/750 — il n'existe aucun événement de fin de scan à quoi
# s'accrocher), et le scan planifié tourne toutes les 12 h (défaut Wazuh,
# aucun <frequency> dans l'agent.conf partagé). Un SI calme ne produit donc
# rien pendant des heures, ce qui est le comportement voulu. Avec les 90 min
# du défaut, le watchdog criait « capteur muet » sur tous les agents tous les
# jours entre midi et 23 h : une alarme permanente qui apprend à ignorer le
# watchdog, ce qui coûte plus cher que le trou qu'elle prétend couvrir.
#
# 840 min (12 h de cycle + 2 h) était encore trop court, et le 2026-08-12 l'a
# montré : case #212 ouvert sur `admin` pour un capteur parfaitement sain. Le
# scan tournait à l'heure (dernier le 2026-08-11 23:12, 2004 fichiers suivis),
# et la dernière MODIFICATION datait du 2026-08-10 — un `update-ca-certificates`.
# Il ne s'était simplement rien passé sur cette machine depuis.
#
# Écart maximal réellement observé entre deux évènements syscheck, sur 30 jours :
#
#     wazuh.manager  52 h        debian2  19 h
#     admin          29 h        debian3  17 h
#
# 4320 min (3 j) passe au-dessus du maximum mesuré avec de la marge. C'est un
# pansement assumé : le bon signal pour ce capteur n'est pas l'alerte (qui
# dépend d'un changement) mais le SCAN lui-même, que l'API Wazuh expose
# (`/syscheck/<agent>/last_scan`). Tant qu'on ne le lit pas, un syscheckd
# réellement figé reste invisible jusqu'à trois jours.
#
# sshd relève du même raisonnement, mesuré le 2026-08-11 sur 7 jours : écart
# médian entre deux événements 0,2 min, mais p95 à 254 min et maximum à 63 h.
# Un hôte sur lequel personne ne se connecte n'émet RIEN, et c'est normal — au
# seuil de 10 min, chaque machine au repos serait déclarée en panne. Pire, un
# hôte isolé par la remédiation n'accepte plus le SSH que depuis le manager :
# son capteur sshd se tait par construction (constaté sur debian2/3/4, muets
# depuis le 2026-08-09 parce qu'isolés, pas parce que cassés).
#
# 1440 min (24 h) : au-delà, même une machine oubliée aurait dû voir passer une
# session ou un scan. Un lecteur journald réellement figé finit donc par sortir,
# sans noyer l'analyste d'ici là.
WATCHDOG_SILENCE_PAR_CAPTEUR = {
    "syscheck": int(os.environ.get("WATCHDOG_SILENCE_SYSCHECK", "4320")),
    "sshd": int(os.environ.get("WATCHDOG_SILENCE_SSHD", "1440")),
}

# Ouvrir un case IRIS quand une panne est constatée. Un capteur muet est un
# angle mort du SOC lui-même : il mérite un dossier traçable, pas seulement une
# ligne de log que personne ne lit. Un case par panne (agent + capteur), fermé
# automatiquement au rétablissement.
WATCHDOG_CASE_IRIS = os.environ.get(
    "WATCHDOG_CASE_IRIS", "true").lower() == "true"

# Retard d'ingestion au-delà duquel le watchdog se tait plutôt que de crier.
#
# Il mesure le silence des capteurs contre l'horizon d'ingestion, pas contre
# l'horloge. Si l'ingestion elle-même cale, cet horizon se fige : plus aucun
# capteur ne paraît muet et la surveillance devient un mensonge tranquille. On
# détecte donc ce cas séparément, contre l'horloge cette fois, et on suspend le
# reste — un pipeline arrêté est UNE panne, pas une par capteur.
#
# 30 min = six cycles d'ingestion (300 s) : au-delà, ce n'est plus un cycle qui
# a pris du retard.
WATCHDOG_RETARD_INGEST_MAX = int(
    os.environ.get("WATCHDOG_RETARD_INGEST_MAX", "30"))

# Reconstruction des commandes (rapport IRIS) : le compte compromis est souvent
# aussi une session légitime (le même uid génère du bruit de login — gpg-agent,
# générateurs systemd). On ne montre que les commandes RATTACHÉES à l'attaque :
# celles qui forment un cluster temporel (gap max ci-dessous) touchant une
# alerte malveillante. Le bruit de session, séparé par un silence plus long,
# est écarté. Assez large pour garder une chaîne recon→exploit→persistance
# contiguë, assez court pour couper le burst d'init de session.
COMMAND_CLUSTER_GAP_S = int(os.environ.get("COMMAND_CLUSTER_GAP_S", "60"))

# --- Whitelist automatique --------------------------------------------------
#
# Nombre d'incidents distincts jugés false_positive, sur une même signature,
# avant qu'une exception soit créée automatiquement. Un seul FP peut être un
# accident ; la récurrence est le signal.
WHITELIST_MIN_FP = int(os.environ.get("WHITELIST_MIN_FP", "3"))

# --- Métriques d'IA exportées vers l'indexer (metrics.py) -------------------
#
# Index dédié plutôt qu'un champ dans les alertes : ces documents ne sont pas
# des alertes, ils n'ont ni agent ni règle, et les mélanger fausserait tous les
# compteurs d'alertes existants.
METRICS_INDEX_PREFIX = os.environ.get("METRICS_INDEX_PREFIX", "wazuh-ai")

# Fenêtre réexportée à chaque passage. Largement supérieure à la cadence du job
# (5 min) : l'export étant idempotent (_id déterministe), un recouvrement large
# rattrape gratuitement une panne d'indexer de quelques heures.
METRICS_FENETRE = os.environ.get("METRICS_FENETRE", "6h")

# Tarifs du modèle, en USD par million de tokens. Valeurs publiées pour
# deepseek-v4-flash (relevées le 2026-07-29) :
#     entrée cache miss 0,14 · entrée cache hit 0,0028 · sortie 0,28
#
# APPROXIMATIF, et il faut le dire : ces tarifs sont relevés sur la grille
# publique, pas sur une facture. Recoupement fait sur la consommation réelle du
# compte — 671 593 tokens facturés 0,09 USD, soit 0,134 USD/M tous tokens
# confondus, cohérent avec 0,14 en entrée pour un trafic très majoritairement
# entrant. L'ordre de grandeur est bon ; ne pas s'en servir pour de la
# refacturation.
#
# Le cache hit est 50x moins cher que le cache miss : sur ce pipeline, le prompt
# système est constant d'un incident à l'autre, donc une part croissante de
# l'entrée est mise en cache. On lit la ventilation renvoyée par l'API quand
# elle est disponible ; sinon on compte TOUT en cache miss, ce qui majore le
# coût (une estimation haute vaut mieux qu'une basse).
LLM_COUT_USD_PAR_MTOKEN_IN = float(
    os.environ.get("LLM_COUT_USD_PAR_MTOKEN_IN", "0.14"))
LLM_COUT_USD_PAR_MTOKEN_IN_CACHE = float(
    os.environ.get("LLM_COUT_USD_PAR_MTOKEN_IN_CACHE", "0.0028"))
LLM_COUT_USD_PAR_MTOKEN_OUT = float(
    os.environ.get("LLM_COUT_USD_PAR_MTOKEN_OUT", "0.28"))

# --- VOC : gestion des vulnérabilités (vulns.py) ----------------------------
#
# Le module Vulnerability Detection de Wazuh écrit dans un index d'ÉTAT
# (`wazuh-states-vulnerabilities-*`) : le document d'une vulnérabilité corrigée
# est SUPPRIMÉ, pas archivé. On y voit donc toujours « où on en est », jamais
# « est-ce qu'on progresse ». Un VOC a besoin de la seconde question — burn-down,
# MTTR de remédiation, respect des SLA — et elle ne se répond qu'avec un
# historique qu'il faut construire soi-même. C'est tout l'objet de vulns.py.
VULN_INDICES = os.environ.get("VULN_INDICES", "wazuh-states-vulnerabilities-*")

# Index d'export du VOC, distinct de `wazuh-ai-*` : ce ne sont ni des alertes ni
# des métriques d'IA, et les mélanger fausserait les compteurs des deux.
VOC_INDEX_PREFIX = os.environ.get("VOC_INDEX_PREFIX", "wazuh-voc")

# Poids d'une vulnérabilité selon sa sévérité, pour l'agrégat de risque. Échelle
# volontairement TRÈS non linéaire : il faut dix Medium, ou cinquante Low, pour
# peser une seule Critical. Un score qui les additionnerait à poids égal serait
# dominé par le bruit de fond des distributions (2 500 CVE ouvertes sur un Debian
# à jour, en écrasante majorité Low/Medium sans exploit connu) et classerait les
# machines par nombre de paquets installés.
VULN_POIDS_SEVERITE = {
    "critical": 10.0, "high": 4.0, "medium": 1.0, "low": 0.2,
    # Sévérité absente du feed (334 par hôte Debian mesurées le 2026-08-12) :
    # ni ignorée — c'est une CVE réelle — ni traitée comme grave.
    "": 0.5, "untriaged": 0.5, "unknown": 0.5,
}

# Multiplicateur de risque par priorité CMDB (P1..P4). Même logique que
# `SEVERITE_BONUS_PRIORITE` sur les incidents : une CVE critique sur le
# contrôleur de domaine et la même sur un poste de lab ne sont pas le même
# problème, et un VOC qui les compte pareil fait patcher dans le désordre.
VOC_FACTEUR_PRIORITE = {
    p + 1: float(v) for p, v in enumerate(
        os.environ.get("VOC_FACTEUR_PRIORITE", "4,2,1,0.5").split(","))}

# Délai de correction attendu, EN JOURS, par sévérité puis par priorité (P1..P4).
# Ce sont des objectifs de service, pas une norme : ils viennent du bon sens
# (« une critical sur le DC se traite dans la semaine ») et se règlent par
# déploiement. Leur seule fonction est de rendre le retard MESURABLE — sans
# échéance, « vulnérabilité ouverte depuis 210 jours » n'est qu'un nombre.
VOC_SLA_JOURS = {
    "critical": [7, 14, 30, 60],
    "high": [15, 30, 60, 90],
    "medium": [30, 60, 90, 180],
    "low": [90, 180, 365, 365],
}
for _ligne in os.environ.get("VOC_SLA_JOURS", "").split(";"):
    if ":" in _ligne:
        _sev, _jours = _ligne.split(":", 1)
        try:
            _v = [int(j) for j in _jours.split(",")]
        except ValueError:
            sys.exit(f"VOC_SLA_JOURS : valeur non entière dans « {_ligne} »")
        if len(_v) != 4:
            sys.exit(f"VOC_SLA_JOURS : 4 valeurs (P1..P4) attendues dans « {_ligne} »")
        VOC_SLA_JOURS[_sev.strip().lower()] = _v

# Charge pondérée qui vaut 100/100 dans le score d'exposition. Le score est
# log-compressé : la charge va de quelques unités (serveur tenu à jour) à
# plusieurs dizaines de milliers (un Debian dont le méta-paquet noyau traîne
# 2 500 CVE), et une échelle linéaire écraserait tout le parc en bas. À relever
# si l'essentiel des machines sature à 100 — auquel cas le score ne trie plus
# rien et il faut lire les compteurs bruts, exportés à côté.
VOC_CHARGE_MAX = float(os.environ.get("VOC_CHARGE_MAX", "20000"))

# Sévérité minimale à partir de laquelle une vulnérabilité hors SLA est exportée
# document par document dans l'index VOC. Les Low/Medium ouvertes se comptent par
# milliers et n'ont pas de valeur d'action individuelle : elles restent dans les
# agrégats, pas dans la table « à traiter ».
VOC_SEVERITES_DETAIL = {
    s.strip().lower() for s in
    os.environ.get("VOC_SEVERITES_DETAIL", "critical,high").split(",")
    if s.strip()}

# Nombre de CVE listées nommément dans la section « Exposition aux
# vulnérabilités » d'un case IRIS. Au-delà, la note devient un catalogue que
# personne ne lit et le rapport généré déborde.
VOC_MAX_CVE_RAPPORT = int(os.environ.get("VOC_MAX_CVE_RAPPORT", "10"))

# --- Réglage automatique des règles Wazuh (rule_tuning.py) ------------------
#
# Second étage de la whitelist : au lieu d'écarter l'alerte APRÈS coup dans le
# soc-agent, on génère une règle fille Wazuh qui la neutralise dans le moteur
# lui-même. Le bruit ne coûte alors plus ni indexation ni corrélation.

# Répertoire de règles du manager, monté dans le conteneur. Même répertoire que
# les règles écrites à la main : un fichier par règle, ordre alphabétique.
RULE_TUNING_DIR = os.environ.get(
    "RULE_TUNING_DIR", "/wazuh-rules")

# Plage d'identifiants réservée aux règles générées. Séparée de 1006xx-1009xx
# (règles écrites à la main) pour qu'un coup d'œil au numéro dise l'origine.
RULE_TUNING_ID_MIN = int(os.environ.get("RULE_TUNING_ID_MIN", "101000"))
RULE_TUNING_ID_MAX = int(os.environ.get("RULE_TUNING_ID_MAX", "101999"))

# Niveau appliqué par l'exception. Par DÉFAUT on abaisse (5) au lieu de
# supprimer (0) : l'alerte reste consultable et auditable, elle passe seulement
# sous MIN_LEVEL, donc n'ouvre plus d'incident. C'est ce qui distingue
# « calmer une règle » de « l'invalider ».
RULE_TUNING_NIVEAU = int(os.environ.get("RULE_TUNING_NIVEAU", "5"))

# La suppression totale (niveau 0) fait disparaître l'évènement des alertes :
# plus rien à relire le jour où la signature exonérée s'avère être une vraie
# attaque. Verrouillée derrière un drapeau explicite.
RULE_TUNING_AUTORISE_NIVEAU_0 = os.environ.get(
    "RULE_TUNING_AUTORISE_NIVEAU_0", "false").lower() == "true"

# Plafond de règles générées. Au-delà, ce n'est plus du réglage fin : c'est un
# ruleset qui ne correspond pas à l'environnement, et ça se traite à la main.
RULE_TUNING_MAX_REGLES = int(os.environ.get("RULE_TUNING_MAX_REGLES", "50"))

# Alertes examinées pour trouver un contre-exemple (un évènement de la même
# règle parente NON couvert par l'exception). Sans contre-exemple, la règle
# n'est pas déployée : on ne peut pas prouver qu'elle n'invalide pas la parente.
RULE_TUNING_CANDIDATS_CONTRE_EXEMPLE = int(
    os.environ.get("RULE_TUNING_CANDIDATS_CONTRE_EXEMPLE", "200"))

# Redémarrage du manager (seule façon de charger un changement de règle) :
# nombre de sondages de 5 s avant de conclure à l'échec et de tout retirer.
RULE_TUNING_ATTENTE_ESSAIS = int(os.environ.get("RULE_TUNING_ATTENTE_ESSAIS", "24"))

# Niveau Wazuh à partir duquel on ne whitelist JAMAIS automatiquement, même sur
# des FP répétés. Même logique que le garde-fou de clôture : une règle qui tire
# à 14+ mérite un humain avant d'être neutralisée. Un attaquant qui provoque
# des FP répétés pour se faire whitelister s'arrête à ce mur.
WHITELIST_MAX_LEVEL = int(os.environ.get("WHITELIST_MAX_LEVEL", "14"))

# --- Mode training (apprentissage du bruit ambiant, cf. training.py) --------
#
# Fenêtre de mise en service : le SOC branché sur un SI déjà en production
# apprend d'abord son bruit, pipeline d'analyse suspendu, avant de juger et de
# remédier quoi que ce soit. Piloté depuis le .env racine par l'administrateur
# (lu directement par docker compose up -d).
#
# TRAINING_ENABLED n'ouvre une fenêtre qu'au TOUT PREMIER lancement (aucune
# fenêtre en base) : le training est une phase de mise en service, pas un mode
# récurrent. En rouvrir une plus tard est une décision explicite
# (`python -m soc_agent.training --demarrer`).
TRAINING_ENABLED = os.environ.get("TRAINING_ENABLED", "false").lower() == "true"
TRAINING_DAYS = int(os.environ.get("TRAINING_DAYS", "7"))

# Niveau à partir duquel une alerte observée pendant la fenêtre est apprise
# comme bruit. Aligné sur MIN_LEVEL (12 = HIGH) : en dessous, l'alerte n'ouvre
# de toute façon pas d'incident, la whitelister n'apporterait rien.
TRAINING_MIN_LEVEL = int(os.environ.get("TRAINING_MIN_LEVEL", "12"))

# Plafond PROPRE au training, distinct de WHITELIST_MAX_LEVEL (14) qui borne la
# whitelist automatique en exploitation. Défaut 15 : le training doit pouvoir
# apprendre le bruit CRITICAL, sinon il ne calme pas ce qui fait le plus de
# dégâts (remédiation autonome sur du trafic métier). C'est assumé — la fenêtre
# est une confiance déclarée par l'administrateur, bornée dans le temps, et
# chaque exception reste révocable depuis le case IRIS TRAINING.
TRAINING_MAX_LEVEL = int(os.environ.get("TRAINING_MAX_LEVEL", "15"))

# --- UEBA (analyse comportementale des alertes LOW/MEDIUM) ------------------
#
# Troisième étage de réduction, entre le filtre VT et le LLM (cf. ueba.py). Il
# construit une baseline du comportement normal par machine et par compte, score
# la RARETÉ de ce qui arrive en bits d'information, et promeut en graine
# d'incident les concentrations les mieux notées. Objectif : voir l'intrusion
# discrète qui n'émet que du niveau 3-11, sans envoyer le bruit au LLM.
UEBA_ENABLED = os.environ.get("UEBA_ENABLED", "true").lower() == "true"

# Maturité d'un profil. Un scope trop jeune n'est PAS scoré : le premier jour,
# tout y est inédit — scorer enverrait l'intégralité du parc au LLM. On observe
# d'abord, on juge ensuite. Même philosophie que le mode training, et les deux
# se cumulent bien : la fenêtre de training amorce gratuitement la baseline.
UEBA_MATURITE_JOURS = int(os.environ.get("UEBA_MATURITE_JOURS", "7"))
UEBA_MATURITE_MIN_OBS = int(os.environ.get("UEBA_MATURITE_MIN_OBS", "200"))

# Bits attribués à une valeur JAMAIS vue dans un profil mûr. 12 bits = « une
# chance sur 4096 », l'ordre de grandeur d'un événement réellement inédit.
UEBA_FIRSTSEEN_BITS = float(os.environ.get("UEBA_FIRSTSEEN_BITS", "12"))

# Nombre d'hôtes à partir duquel une valeur inédite ICI est jugée banale
# AILLEURS (déploiement d'admin, mise à jour, outil métier) : son score est
# alors écrasé. Principal anti-faux-positif du module — sans lui, chaque
# nouveau binaire poussé sur le parc ouvrirait un incident par machine.
UEBA_FLOTTE_BANAL = int(os.environ.get("UEBA_FLOTTE_BANAL", "3"))

# Nombre de jours DISTINCTS au-delà duquel une valeur est une habitude et cesse
# d'être scorée. En jours et non en occurrences : 500 exécutions en un seul jour
# est un incident, 5 exécutions sur 5 jours est une routine.
UEBA_JOURS_HABITUEL = int(os.environ.get("UEBA_JOURS_HABITUEL", "5"))

# Garde-fou de CARDINALITÉ. Un trait dont presque chaque observation apporte une
# valeur neuve (chemins horodatés, archives LVM rotatives, GUID, identifiants de
# session) est inédit par construction : « jamais vu » n'y signifie rien, et il
# sature le score en permanence. Mesuré à la mise en service : les archives LVM
# de l'hôte Proxmox donnaient à elles seules un signal à 1434 points, quarante
# fois le plancher.
#
# On juge sur le RATIO distincts/observations plutôt que sur une liste de
# motifs : aucune liste noire n'anticipe ce qu'un parc produit, la statistique
# se corrige seule. En dessous de MIN_OBS on ne conclut pas (on n'exclut pas un
# trait faute de recul).
#
# Le seuil de 0,25 n'est pas choisi au jugé : mesuré sur le parc réel, le trait
# pathologique (archives LVM) est à 0,481 et le suivant à 0,056 — un ordre de
# grandeur d'écart. 0,25 tombe au milieu du fossé, donc loin des deux.
UEBA_CARDINALITE_MAX = float(os.environ.get("UEBA_CARDINALITE_MAX", "0.25"))
UEBA_CARDINALITE_MIN_OBS = int(os.environ.get("UEBA_CARDINALITE_MIN_OBS", "200"))

# Plancher de rareté : en dessous, le trait n'est pas retenu comme motif. Évite
# d'empiler des dixièmes de bit qui finiraient par franchir le seuil sans qu'un
# seul élément soit anormal.
UEBA_BITS_MIN_RARETE = float(os.environ.get("UEBA_BITS_MIN_RARETE", "4"))

# Plafonds de saturation. Sans eux, une seule valeur répétée mille fois écrase
# tout le reste et le score cesse de décrire l'incident.
UEBA_CAP_TRAIT = float(os.environ.get("UEBA_CAP_TRAIT", "14"))
UEBA_CAP_ALERTE = float(os.environ.get("UEBA_CAP_ALERTE", "20"))

# Fenêtre de regroupement des alertes basses d'un même agent en un « signal ».
# Plus large que CORRELATION_GAP_MINUTES : une intrusion discrète est lente, et
# ici on ne cherche pas un point commun nommable mais une CONCENTRATION.
UEBA_FENETRE_MINUTES = int(os.environ.get("UEBA_FENETRE_MINUTES", "60"))

# Durée totale maximale d'un signal. Le chaînage est de proche en proche : sans
# ce plafond, un hôte qui émet une alerte toutes les 50 minutes agglomère sa
# journée entière en un seul signal — le score enfle par accumulation et non par
# anomalie. Équivalent de MAX_INCIDENT_HOURS pour la corrélation.
UEBA_SIGNAL_MAX_HEURES = int(os.environ.get("UEBA_SIGNAL_MAX_HEURES", "6"))

# Chaîne MITRE. Le simple « 3 tactiques distinctes » remonte surtout Discovery
# x3 (un admin qui inventorie sa machine) : les tactiques sont donc PONDÉRÉES
# (credential-access = 5, discovery = 1) et un bonus s'ajoute quand elles
# PROGRESSENT dans l'ordre de la kill chain.
UEBA_MIN_TACTIQUES = int(os.environ.get("UEBA_MIN_TACTIQUES", "3"))
UEBA_BONUS_ORDRE = float(os.environ.get("UEBA_BONUS_ORDRE", "3"))

# Score minimal pour qu'un signal puisse être promu. Se calibre sur des données
# réelles SANS consommer de token : `python -m soc_agent.ueba --simulation`
# enregistre les signaux et leurs scores sans rien promouvoir.
UEBA_SCORE_PLANCHER = float(os.environ.get("UEBA_SCORE_PLANCHER", "35"))

# LE garde-fou de coût. Un seuil de score seul ne borne rien : le volume varie
# d'un facteur dix entre une journée calme et une campagne. Le budget, lui, est
# un nombre qu'on décide. Un signal non promu n'est pas perdu — il est réévalué
# au cycle suivant, et son score aura grossi s'il continue.
# 20 promotions/jour ~ 20 triages LLM/jour ajoutés au coût existant.
UEBA_BUDGET_JOUR = int(os.environ.get("UEBA_BUDGET_JOUR", "20"))
UEBA_BUDGET_PAR_CYCLE = int(os.environ.get("UEBA_BUDGET_PAR_CYCLE", "2"))

# Âge au-delà duquel une alerte basse n'est plus candidate à un signal : elle a
# eu ses chances, la reprendre indéfiniment ferait grossir le lot sans fin.
UEBA_RETENTION_HOURS = int(os.environ.get("UEBA_RETENTION_HOURS", "24"))

# Taille du lot d'observation par passage. Le tout premier passage doit avaler
# l'historique déjà en base ; les suivants ne voient que le delta du cycle.
UEBA_LOT = int(os.environ.get("UEBA_LOT", "20000"))

# Mémoire de la baseline. Un profil qui ne vieillit jamais fige le comportement
# d'il y a six mois : un serveur réinstallé resterait « normal » sur ses anciens
# binaires. Les observations plus vieilles sont supprimées et les profils
# recalculés sur ce qui reste.
UEBA_MEMOIRE_JOURS = int(os.environ.get("UEBA_MEMOIRE_JOURS", "90"))

# Remédiation autonome sur un incident issu d'un signal UEBA.
#
# FALSE par défaut, et c'est délibéré. Le reste du pipeline agit sans validation
# humaine parce qu'il part d'une graine de niveau >= 12 — une règle Wazuh qui a
# déjà exigé plusieurs corrélations. Un incident UEBA part, lui, d'un score
# statistique dont la justesse n'est PAS encore mesurée : le laisser isoler un
# hôte reviendrait à confier la production à un seuil non calibré. Le LLM rend
# donc son verdict VP/FP, le case IRIS est créé avec toutes les actions
# proposées, mais rien n'est exécuté tant que ce drapeau est à false.
UEBA_MITIGATE = os.environ.get("UEBA_MITIGATE", "false").lower() == "true"


# --- Infrastructure du SOC lui-même ----------------------------------------
#
# Défini en fin de fichier : dépend des URL déclarées plus haut.

def _hote_url(url: str) -> str | None:
    """Hôte d'une URL de configuration, uniquement si c'est une IP littérale.

    Un nom DNS ne sert à rien ici : la comparaison se fera contre l'IP telle
    qu'elle apparaît dans une alerte.
    """
    try:
        hote = urlparse(url or "").hostname
    except ValueError:
        return None
    if not hote:
        return None
    try:
        ipaddress.ip_address(hote)
    except ValueError:
        return None
    return hote


# IP de l'infrastructure du SOC : manager Wazuh, indexer, IRIS, Shuffle.
# JAMAIS un IOC, jamais une cible de blocage.
#
# Le SIEM parle à toutes les machines qu'il surveille — il pousse ses
# active-responses, ses agents lui répondent — donc son IP apparaît en `srcip`
# ou en cible de connexion sur des alertes parfaitement normales. Publiée comme
# indicateur, elle salit la threat intel ; traitée au premier degré par un
# analyste ou un automatisme de blocage, elle coupe le SOC de son propre parc.
# Constaté sur le case #207 : l'IP du manager y figurait en « cible interne —
# connexion /dev/tcp », à côté du vrai rootkit.
#
# Trois sources, cumulées :
#
#  - MITIGATE_ISOLATE_ALLOW : par définition « l'IP du manager telle que
#    l'AGENT la joint », c'est-à-dire exactement celle qui apparaît dans les
#    alertes. La source la plus juste des trois.
#  - les URL du soc-agent : utiles en déploiement à plat, mais en conteneur
#    elles pointent vers des noms de service Docker et ne donnent rien.
#  - SOC_INFRA_IPS, pour le reste : VIP, seconde interface du manager,
#    collecteur tiers.
SOC_INFRA_IPS = {
    ip for ip in (_hote_url(INDEXER_URL), _hote_url(IRIS_URL),
                  _hote_url(SHUFFLE_URL), _hote_url(WAZUH_API_URL)) if ip
} | set(MITIGATE_ISOLATE_ALLOW) | {
    ip.strip() for ip in os.environ.get("SOC_INFRA_IPS", "").split(",")
    if ip.strip()}
