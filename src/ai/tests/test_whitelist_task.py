"""Logique pure du traitement des tâches WHITELIST (sans IRIS ni LLM)."""

from soc_agent.whitelist import validate_signature
from soc_agent.whitelist_task import (_PREFIX_AI, _instructions,
                                      _tasks_to_process)


def test_taches_a_traiter_filtre_titre_et_statut():
    """Seules les tâches WHITELIST en 'To do' sont reprises — pas les tâches
    de remédiation, pas celles encore 'On hold' ou déjà 'Closed'."""
    tasks = [
        {"task_id": 1, "task_title": "WHITELIST — demande d'exception",
         "status_name": "On hold"},
        {"task_id": 2, "task_title": "WHITELIST — demande d'exception",
         "status_name": "To do"},
        {"task_id": 3, "task_title": "Remédiation — Isoler l'hôte (001)",
         "status_name": "To do"},
        {"task_id": 4, "task_title": "WHITELIST — demande d'exception",
         "status_name": "Closed"},
    ]
    assert [t["task_id"] for t in _tasks_to_process(tasks)] == [2]
    assert _tasks_to_process([]) == []
    assert _tasks_to_process(None) == []


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def is_success(self):
        return True

    def get_data(self):
        return self._data


class _FakeCase:
    """Simule juste ce que _instructions() consomme de dfir-iris-client."""

    def __init__(self, description="", comments=()):
        self._description = description
        self._comments = [{"comment_text": c} for c in comments]

    def get_task(self, task_id, cid=None):
        return _FakeResponse({"task_description": self._description})

    def list_task_comments(self, task_id, cid=None):
        return _FakeResponse(self._comments)


def test_instructions_dernier_commentaire_analyste_a_traiter():
    case = _FakeCase(description="whitelister la commande",
                     comments=["ping test", "en fait whitelister le compte svc"])
    instructions, pending = _instructions(case, case_id=1, task_id=2)
    assert not pending
    assert "whitelister la commande" in instructions
    assert "en fait whitelister le compte svc" in instructions


def test_instructions_dernier_commentaire_ia_on_ne_relance_pas():
    """Si le dernier mot est déjà celui de l'IA, on n'a rien de nouveau à
    traiter — évite de reposter la même question à chaque passage."""
    case = _FakeCase(description="whitelister ?",
                     comments=[_PREFIX_AI + "Peux-tu préciser le champ ?"])
    instructions, pending = _instructions(case, case_id=1, task_id=2)
    assert pending
    assert instructions == ""


def test_valider_signature_rejette_rule_id_seul():
    assert validate_signature({"rule_id": "5715"}, level=8, sig_tp=set()) is not None


def test_valider_signature_rejette_niveau_trop_haut():
    sig = {"rule_id": "1", "command": "/bin/x"}
    assert validate_signature(sig, level=14, sig_tp=set()) is not None
    assert validate_signature(sig, level=13, sig_tp=set()) is None


def test_valider_signature_rejette_signature_vue_en_tp():
    from soc_agent.whitelist import _canonical
    sig = {"rule_id": "1", "command": "/bin/x"}
    assert validate_signature(sig, level=8, sig_tp={_canonical(sig)}) is not None
    assert validate_signature(sig, level=8, sig_tp=set()) is None
