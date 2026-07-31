"""Configuration du soc-agent, lue depuis l'environnement.

Aucune valeur par défaut pour les secrets : une absence doit faire échouer le
démarrage, pas passer silencieusement sur une valeur de repli.
"""

import os
import sys


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

# --- Filtrage ---------------------------------------------------------------
#
# Niveau Wazuh minimal pour OUVRIR un incident (graine). 12 = seuil HIGH de
# l'échelle 0-15 (12-14 high, 15 critical) : un case IRIS + analyse IA ne se
# déclenchent QUE sur une alerte HIGH/CRITICAL. En dessous, une alerte n'ouvre
# jamais d'incident mais peut être RATTACHÉE à un incident déjà confirmé pour
# l'enrichir (cf. ATTACH_MIN_LEVEL) — l'analyse voit tout, l'ouverture reste
# réservée au signal fort.
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "12"))

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
REPORT_MAX_TOKENS = int(os.environ.get("REPORT_MAX_TOKENS", "6000"))
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
# Défaut volontairement NON-loopback : les liens sont ouverts depuis le
# navigateur de l'analyste, jamais depuis cet hôte — « localhost » y pointait
# sur la machine de l'analyste et cassait le lien. Surcharger par l'env avec
# l'URL réellement joignable du dashboard (ex. https://192.168.10.5).
WAZUH_DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "https://192.168.10.5")
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
# RFC1918 » à « interne » : le C2 du lab est lui-même en RFC1918 (10.0.0.6,
# 192.168.60.1) — le classer « interne » l'aurait blanchi. On liste donc
# explicitement les subnets du parc, tout le reste (dont ces C2) est externe.
RESEAUX_INTERNES = [
    r.strip() for r in os.environ.get(
        "RESEAUX_INTERNES",
        "192.168.20.0/24,192.168.10.0/24,192.168.40.0/24").split(",")
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
# machine, on n'agit pas. Vide par défaut ; en prod, l'agent hôte Proxmox (009).
AGENTS_CAPTEURS = {
    a.strip() for a in os.environ.get("AGENTS_CAPTEURS", "").split(",")
    if a.strip()}

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
# Silence toléré avant de crier. 90 min : au-delà, ce n'est plus un creux de
# trafic normal (Suricata/sshd émettent en continu sur ces hôtes).
WATCHDOG_SILENCE_MINUTES = int(os.environ.get("WATCHDOG_SILENCE_MINUTES", "90"))

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
