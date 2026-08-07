"""Robustesse du parsing de la réponse du modèle.

`response_format=json_object` était réputé garantir un JSON valide. Faux, et
mesuré en production : sur un incident Windows (chemins `C:\\...` partout dans
le contexte), DeepSeek recopie un chemin dans sa justification et rend
« Invalid \\escape ». Sans réparation, l'incident échoue à chaque cycle — le lot
étant trié de façon déterministe, il repasse en tête indéfiniment.
"""

import json

import pytest

from soc_agent.llm import _charger_json


def test_json_valide_inchange():
    assert _charger_json('{"verdict": "true_positive", "n": 1}') == {
        "verdict": "true_positive", "n": 1}


def test_chemin_windows_non_echappe_repare():
    brut = r'{"reason": "binaire C:\Windows\System32\cmd.exe lancé", "n": 2}'
    obj = _charger_json(brut)
    assert obj["reason"] == r"binaire C:\Windows\System32\cmd.exe lancé"
    assert obj["n"] == 2


def test_echappements_legaux_preserves():
    """La réparation ne doit pas casser un JSON correct qui contient \\n ou \\"."""
    brut = '{"reason": "ligne1\\nligne2 \\"citée\\" et \\\\ littéral"}'
    assert _charger_json(brut) == json.loads(brut)


def test_json_irreparable_remonte():
    """Une vraie panne d'API doit rester une erreur, pas être maquillée."""
    with pytest.raises(json.JSONDecodeError):
        _charger_json('{"reason": "tronqué au milieu')
