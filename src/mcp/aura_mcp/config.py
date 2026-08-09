"""Configuration du serveur MCP AURA.

Tout vient du `.env` racine, comme le reste du stack — un seul fichier de
secrets sur l'hôte. Ce module ne configure QUE le serveur : les seuils du
pipeline (MIN_LEVEL, UEBA_*, MITIGATE_EXECUTE…) restent dans
`soc_agent.config`, qui est importé tel quel. Dupliquer une valeur ici la
ferait diverger de ce que le pipeline applique réellement.
"""

import os
import sys

# --- Écoute ---------------------------------------------------------------
# Le conteneur tourne en network_mode: host, donc pas de `ports:` possible
# dans le compose : c'est au code de ne pas s'exposer. Défaut loopback, et
# c'est volontaire — exposer le MCP sur le LAN donnerait à qui l'atteint les
# droits d'isolation d'hôte du SOC.
HOST = os.environ.get("AURA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("AURA_MCP_PORT", "3100"))
PATH = os.environ.get("AURA_MCP_PATH", "/mcp")

# --- Authentification -----------------------------------------------------
# JWT HS256, même schéma que le MCP Wazuh amont (secret partagé, jetons émis
# hors ligne par scripts/aura-mcp-token.py). Pas d'OAuth : il n'y a pas
# d'utilisateurs, seulement des clients IA déclarés.
SECRET = os.environ.get("AURA_MCP_SECRET", "")
ISSUER = os.environ.get("AURA_MCP_ISSUER", "aura")
AUDIENCE = os.environ.get("AURA_MCP_AUDIENCE", "aura-mcp")

# Sans secret, on refuse de démarrer plutôt que de servir en clair : un serveur
# ouvert donne isolate/kill à quiconque atteint le port.
if not SECRET:
    print("AURA_MCP_SECRET manquant — le serveur MCP refuse de démarrer sans "
          "authentification.", file=sys.stderr)
    sys.exit(1)

# --- Scopes ---------------------------------------------------------------
# Fail-closed : un jeton sans claim `scope` n'obtient rien du tout (le MCP
# Wazuh amont accorde la lecture par défaut ; ici même la lecture expose des
# journaux d'incidents, donc on n'accorde rien implicitement).
LECTURE = "aura:read"
ECRITURE = "aura:write"
ADMIN = "aura:admin"

# Ordre d'inclusion : admin implique write, write implique read. Un jeton
# d'admin n'a donc pas à lister les trois.
IMPLIQUE = {
    ADMIN: {ADMIN, ECRITURE, LECTURE},
    ECRITURE: {ECRITURE, LECTURE},
    LECTURE: {LECTURE},
}

# --- Anti-rebinding DNS ---------------------------------------------------
# La comparaison du SDK porte sur l'en-tête `Host` BRUT, port compris : un
# client qui appelle http://127.0.0.1:3100/mcp envoie `127.0.0.1:3100`, que
# « 127.0.0.1 » seul ne couvre pas (421 Misdirected Request, sans indice côté
# client). On génère donc les deux formes pour chaque nom.
def _avec_port(noms: list[str]) -> list[str]:
    return [f"{n}:{PORT}" for n in noms]


_NOMS = [n.strip() for n in os.environ.get(
    "AURA_MCP_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if n.strip()]
HOTES = _NOMS + _avec_port(_NOMS)

_ORIGINES = [o.strip() for o in os.environ.get(
    "AURA_MCP_ALLOWED_ORIGINS",
    "http://localhost,http://127.0.0.1").split(",") if o.strip()]
ORIGINES = _ORIGINES + [f"{o}:{PORT}" for o in _ORIGINES]

# --- Limitation de débit --------------------------------------------------
# Par IP source, fenêtre glissante d'une minute. Ne protège pas d'un client
# légitime bavard : protège du bouclage d'un agent IA qui rappelle le même
# outil en rafale (vu sur d'autres MCP : 200 appels/min sur un timeout).
DEBIT_MAX = int(os.environ.get("AURA_MCP_RATE_LIMIT", "120"))

# --- Plafonds de réponse --------------------------------------------------
# Une réponse d'outil part dans le contexte d'un LLM. Un `full_log` de 200 Ko
# ou 5 000 alertes ne l'aident pas, ils l'étouffent. Ces bornes sont dures :
# un outil qui doit rendre plus rend une page et le dit.
PAGE_MAX = int(os.environ.get("AURA_MCP_PAGE_MAX", "100"))
PAGE_DEFAUT = int(os.environ.get("AURA_MCP_PAGE_DEFAUT", "25"))
TEXTE_MAX = int(os.environ.get("AURA_MCP_TEXTE_MAX", "4000"))
