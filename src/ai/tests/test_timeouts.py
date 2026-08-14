"""Garde-fous de durée : personne ne doit pouvoir immobiliser le pipeline.

Le cycle tient un verrou consultatif Postgres pendant tout son déroulé (cf.
cycle.VERROU). Tout ce qui bloque à l'intérieur bloque donc l'ingestion, et les
transactions restées ouvertes bloquent en plus les migrations de schéma.
Constaté le 2026-08-11 : ingestion arrêtée 19 min, `ALTER TABLE` en attente.
"""

from soc_agent import config
from soc_agent.config import _with_statement_timeout


def test_dsn_porte_le_statement_timeout():
    """Le plafond est posé sur le DSN et pas par un SET après connexion : chaque
    module ouvre sa propre connexion, la chaîne est le seul point commun."""
    assert "statement_timeout" in config.PG_DSN


def test_statement_timeout_ajoute_sur_url_et_sur_kv():
    url = _with_statement_timeout("postgresql://u:p@h:5433/db", 300000)
    assert url.endswith("?options=-c%20statement_timeout%3D300000")
    with_query = _with_statement_timeout("postgresql://u@h/db?sslmode=require",
                                         1000)
    assert "&options=" in with_query
    kv = _with_statement_timeout("host=h dbname=db", 1000)
    assert kv == "host=h dbname=db options='-c statement_timeout=1000'"


def test_statement_timeout_n_ecrase_jamais_une_option_existante():
    """Un déploiement qui passe déjà des options garde les siennes."""
    dsn = "postgresql://u@h/db?options=-c%20search_path%3Dsoc"
    assert _with_statement_timeout(dsn, 300000) == dsn
    assert _with_statement_timeout("host=h options='-c foo=1'", 5) \
        == "host=h options='-c foo=1'"


def test_statement_timeout_desactivable():
    assert _with_statement_timeout("postgresql://u@h/db", 0) \
        == "postgresql://u@h/db"


def test_pas_de_idle_in_transaction_timeout():
    """Interdit ici, et c'est un choix : le verrou consultatif du cycle vit dans
    une transaction ouverte pendant toute son exécution. Le tuer sur inactivité
    libérerait le verrou et autoriserait deux cycles concurrents."""
    assert "idle_in_transaction" not in config.PG_DSN


def test_timeout_llm_est_un_couple_connexion_lecture():
    """Un seul nombre passé à `requests` s'applique aux deux phases sans les
    distinguer : la connexion doit échouer vite, la lecture doit être patiente."""
    assert config.LLM_TIMEOUT_CONNECT_S < config.LLM_TIMEOUT_READ_S
    assert 0 < config.LLM_TIMEOUT_CONNECT_S <= 30
