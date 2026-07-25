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

# Indices interrogés pour l'ingestion. Un pipeline d'ingest indexer route les
# alertes par type vers wazuh-linux-* / wazuh-web-* (et le reste dans
# wazuh-alerts-*) : ne lire que wazuh-alerts-* rendait l'IA aveugle à la
# quasi-totalité des alertes. On couvre donc les trois familles. Ajuster ici
# si de nouveaux préfixes d'index apparaissent (ex. wazuh-windows-*).
INDEXER_ALERT_INDICES = os.environ.get(
    "INDEXER_ALERT_INDICES", "wazuh-alerts-*,wazuh-linux-*,wazuh-web-*")

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

# --- Modèle : DeepSeek (API cloud, compatible OpenAI) -----------------------
#
# Bascule depuis l'IA locale (llama.cpp) : cette machine n'a pas les ressources
# pour un modèle local en continu. DeepSeek expose une API compatible OpenAI
# (/chat/completions, Bearer token). Conséquence de sécurité MAJEURE : les
# données SOC quittent l'hôte. Elles DOIVENT être anonymisées avant tout appel
# (cf. sanitize.py — anonymisation à implémenter). Aucune donnée sensible en
# clair vers le cloud tant que ce n'est pas fait.
#
# Perte par rapport au local : plus de GBNF (grammaire). DeepSeek garantit un
# JSON valide (response_format), pas le respect du schéma ni de l'enum. La
# barrière est donc dans le code : coercition/validation dans triage.py, en
# plus des garde-fous déterministes d'actions.py.
DEEPSEEK_API_KEY = _requis("DEEPSEEK_API_KEY")
# Les modèles v4 raisonnent : les tokens de raisonnement (reasoning_content)
# sont décomptés de max_tokens AVANT le content. Un budget trop court (l'ancien
# 400, calé sur le chat non raisonnant) est intégralement consommé par le
# raisonnement → finish_reason=length et content VIDE. Il faut de la marge pour
# le raisonnement + le JSON de verdict.
TRIAGE_MAX_TOKENS = int(os.environ.get("TRIAGE_MAX_TOKENS", "3000"))
# Le rapport TP est un récit markdown multi-sections, plus long que le verdict ;
# avec le raisonnement en plus, il lui faut davantage de marge encore.
REPORT_MAX_TOKENS = int(os.environ.get("REPORT_MAX_TOKENS", "4000"))
# Nom de case : sortie minuscule (nom de code + titre court) mais le modèle
# raisonne quand même — il lui faut de quoi ne pas tronquer avant le JSON.
CASE_NAME_MAX_TOKENS = int(os.environ.get("CASE_NAME_MAX_TOKENS", "1500"))
DEEPSEEK_URL = os.environ.get("DEEPSEEK_URL", "https://api.deepseek.com")
# deepseek-chat déprécié (l'API ne l'accepte plus, 400). Tiers actuels :
# deepseek-v4-flash (rapide/économique, équivalent le plus proche du chat sur
# lequel le pipeline a été calé) et deepseek-v4-pro (verdict plus robuste).
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")

# Conservé pour compat (tokenize éventuel) — plus utilisé pour l'inférence.
LLM_URL = os.environ.get("LLM_URL", "http://127.0.0.1:8081")

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
WAZUH_DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "https://localhost")
WAZUH_DASHBOARD_DISCOVER_PATH = os.environ.get(
    "WAZUH_DASHBOARD_DISCOVER_PATH", "/app/data-explorer/discover")
# Index-pattern couvrant les indices réellement alimentés (cf. le routage
# wazuh-linux/web). « soc-ai-all-alerts » existe déjà côté dashboard.
WAZUH_DASHBOARD_INDEX_PATTERN = os.environ.get(
    "WAZUH_DASHBOARD_INDEX_PATTERN", "soc-ai-all-alerts")

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

# Niveau Wazuh à partir duquel on ne whitelist JAMAIS automatiquement, même sur
# des FP répétés. Même logique que le garde-fou de clôture : une règle qui tire
# à 14+ mérite un humain avant d'être neutralisée. Un attaquant qui provoque
# des FP répétés pour se faire whitelister s'arrête à ce mur.
WHITELIST_MAX_LEVEL = int(os.environ.get("WHITELIST_MAX_LEVEL", "14"))
