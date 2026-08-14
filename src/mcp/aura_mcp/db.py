"""Postgres access for the MCP tools.

One connection per call, no pool: an MCP tool is a one-off triggered by a
human via their AI, not a hot loop. A persistent connection would mostly
hold a transaction open while the model thinks.

The DSN comes from `soc_agent.config`: a single source of truth for the
database, shared with the pipeline.
"""

from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from soc_agent import config as soc_config


@contextmanager
def read():
    """Read-only connection — the transaction can't write anything.

    Backstop guardrail: most exposed tools are read tools, and a typo in a
    SQL query must not be able to mutate the incident database. Action tools
    go through `soc_agent`, not here.
    """
    with psycopg.connect(soc_config.PG_DSN, row_factory=dict_row) as conn:
        conn.read_only = True
        yield conn
