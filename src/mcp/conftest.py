"""Environnement minimal pour la suite de tests du serveur MCP.

Même problème, même remède que `src/ai/conftest.py` : `aura_mcp/config.py`
appelle `sys.exit(1)` à l'import quand `AURA_MCP_SECRET` manque — c'est voulu en
exploitation (un MCP sans authentification donne isolate/kill à qui atteint le
port), mais à la collecte pytest ce `SystemExit` remonte en INTERNALERROR et la
suite s'arrête **sans avoir exécuté un seul test**, y compris ceux qui ne
touchent ni au réseau ni à la base.

Le bouchon est posé en `setdefault` : un environnement réellement configuré
garde toujours la main. Il ne vaut évidemment que pour les tests — aucun de ceux
qui l'utilisent ne signe ni ne vérifie un jeton contre un secret réel.

`soc_agent` est importé par `aura_mcp.db` et `aura_mcp.outils` : ses propres
variables requises sont bouchonnées ici aussi, pour la même raison.
"""

import os
import pathlib
import sys

# aura_mcp importe soc_agent (config de la base, garde-fous). Les deux paquets
# vivent dans des répertoires frères, non installés.
RACINE = pathlib.Path(__file__).resolve().parent
for chemin in (RACINE, RACINE.parent / "ai"):
    if str(chemin) not in sys.path:
        sys.path.insert(0, str(chemin))

for nom, bouchon in (
    ("AURA_MCP_SECRET", "bouchon-de-test"),
    ("INDEXER_PASSWORD", "bouchon-de-test"),
    ("PGPASSWORD", "bouchon-de-test"),
    ("DEEPSEEK_API_KEY", "bouchon-de-test"),
):
    os.environ.setdefault(nom, bouchon)
