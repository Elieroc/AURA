"""Tests du noise filter — les deux étages et le piège du composite vide.

`NoiseFilter` décide ce qui n'atteint jamais la base (query_level) et ce qui
est ingéré puis marqué (post-retrieval). Une erreur ici supprime du signal en
silence : testable sans base ni indexer, ça doit l'être.
"""

from soc_agent.noise import NoiseFilter


def _filtre(**sections) -> NoiseFilter:
    return NoiseFilter({"filters": sections})


def test_query_level_produit_une_clause_must_not():
    f = _filtre(actors={"ignore_src_users": [
        {"user": "_apt", "query_level": True, "reason": "APT"}]})
    assert {"term": {"data.srcuser": "_apt"}} in f.clauses_must_not()
    # Une entrée query_level ne doit pas AUSSI se retrouver dans les post-rules
    # (elle n'arrivera jamais jusque-là), mais reste évaluable au rejeu.
    assert f.raison_suppression({"data": {"srcuser": "_apt"}}) == "APT"


def test_post_retrieval_ne_touche_pas_le_must_not():
    f = _filtre(actors={"ignore_src_users": [
        {"user": "colord", "query_level": False, "reason": "color daemon"}]})
    assert f.clauses_must_not() == []
    assert f.raison_suppression({"data": {"srcuser": "colord"}}) == "color daemon"


def test_alerte_normale_non_supprimee():
    f = _filtre(actors={"ignore_src_users": [
        {"user": "_apt", "query_level": True}]})
    assert f.raison_suppression({"data": {"srcuser": "root"}}) is None


def test_composite_exige_toutes_les_conditions():
    f = _filtre(composite=[{
        "name": "apt_daily_root",
        "match_all": {"src_user": "root", "command": "/usr/lib/apt/apt.systemd.daily"},
    }])
    ok = {"data": {"srcuser": "root", "command": "/usr/lib/apt/apt.systemd.daily"}}
    partiel = {"data": {"srcuser": "root", "command": "/bin/bash"}}
    assert f.raison_suppression(ok) == "apt_daily_root"
    assert f.raison_suppression(partiel) is None


def test_composite_a_cle_inconnue_ne_supprime_rien():
    """Garde-fou : un all() sur générateur vide vaut True et supprimerait tout."""
    f = _filtre(composite=[{
        "name": "cle_inexistante",
        "match_all": {"champ_bidon": "valeur"},
    }])
    assert f.raison_suppression({"data": {"srcuser": "root"}}) is None


def test_agent_et_regle():
    f = _filtre(
        rules={"ignore_rule_ids": [{"id": "5715", "query_level": True}]},
        hosts={"ignore_agent_names": [{"name": "test-agent-01", "query_level": True}]},
    )
    clauses = f.clauses_must_not()
    assert {"term": {"rule.id": "5715"}} in clauses
    assert {"term": {"agent.name": "test-agent-01"}} in clauses
