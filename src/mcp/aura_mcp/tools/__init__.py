"""Registration of the AURA MCP server tools.

Importing this package is enough to populate the server: each module
declares its tools here and then calls `server.register`. Import order fixes
the order of `tools/list`, and therefore the order in which a client
discovers the tools — read first, action next, deliberately.
"""

from . import read  # noqa: F401
from . import cmdb  # noqa: F401
from . import archiving  # noqa: F401
from . import hunting  # noqa: F401
from . import simulation  # noqa: F401
from . import action  # noqa: F401
from . import enrollment  # noqa: F401
from . import relay  # noqa: F401
