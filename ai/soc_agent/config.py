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
# Niveau Wazuh minimal traité. 12 = début du « high » dans l'échelle 0-15
# (12-14 high, 15 critical). En dessous, l'alerte est stockée pour les
# statistiques mais ne partira jamais au triage.
#
# Ce seuil est ce qui rend le système possible sur CPU : à ~20 s par triage,
# traiter le niveau 3 (359 alertes sur 5 jours dans notre lab) n'a pas de sens.
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "12"))

# Niveau en dessous duquel on n'ingère même pas. 0 = tout stocker, ce qui donne
# les statistiques complètes ; monter à MIN_LEVEL une fois la mesure faite.
INGEST_MIN_LEVEL = int(os.environ.get("INGEST_MIN_LEVEL", "0"))

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
