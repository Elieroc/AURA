"""Accès Postgres pour les outils MCP.

Connexion par appel, pas de pool : un outil MCP est un coup ponctuel déclenché
par un humain via son IA, pas une boucle chaude. Une connexion persistante
tiendrait surtout une transaction ouverte pendant que le modèle réfléchit.

Le DSN vient de `soc_agent.config` : une seule source de vérité pour la base,
partagée avec le pipeline.
"""

from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from soc_agent import config as soc_config


@contextmanager
def read():
    """Connexion en lecture seule — la transaction ne peut rien écrire.

    Garde-fou de fond : la majorité des outils exposés sont des outils de
    lecture, et une faute de frappe dans un SQL ne doit pas pouvoir muter la
    base d'incidents. Les outils d'action passent par `soc_agent`, pas ici.
    """
    with psycopg.connect(soc_config.PG_DSN, row_factory=dict_row) as conn:
        conn.read_only = True
        yield conn
