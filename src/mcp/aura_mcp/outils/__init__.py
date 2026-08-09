"""Enregistrement des outils du serveur MCP AURA.

Importer ce paquet suffit à peupler le serveur : chaque module y déclare ses
outils puis appelle `serveur.enregistrer`. L'ordre d'import fixe l'ordre du
`tools/list`, donc celui dans lequel un client découvre les outils — lecture
d'abord, action ensuite, délibérément.
"""

from . import lecture  # noqa: F401
from . import simulation  # noqa: F401
from . import action  # noqa: F401
from . import enrolement  # noqa: F401
from . import relais  # noqa: F401
