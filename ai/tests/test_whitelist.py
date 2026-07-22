"""Tests de la signature de whitelist et du champ virtuel « file ».

`_signature` décide ce qui devient une exception automatique. Une signature
trop large neutraliserait toute une règle de détection : c'est l'erreur à
rendre impossible, et elle se teste sans base ni LLM.
"""

from soc_agent.noise import NoiseFilter, _valeur_champ
from soc_agent.whitelist import _canonique, _signature


def _alerte(rule_id="87105", srcuser=None, command=None, file=None):
    data = {}
    if srcuser:
        data["srcuser"] = srcuser
    if command:
        data["command"] = command
    if file:
        data["virustotal"] = {"source": {"file": file}}
    return {"rule": {"id": rule_id}, "data": data}


def test_champ_virtuel_file_resout_plusieurs_chemins():
    assert _valeur_champ({"syscheck": {"path": "/etc/passwd"}}, "file") == "/etc/passwd"
    assert _valeur_champ(
        {"data": {"virustotal": {"source": {"file": "/tmp/x"}}}}, "file") == "/tmp/x"
    assert _valeur_champ({"data": {}}, "file") is None


def test_signature_precise_avec_fichier():
    """EICAR : rule + file, discriminant présent -> signature valide."""
    alertes = [_alerte(file="/tmp/eicar.com") for _ in range(3)]
    sig = _signature(alertes)
    assert sig == {"rule_id": "87105", "file": "/tmp/eicar.com"}


def test_rule_id_seul_refuse():
    """Sans discriminant, on neutraliserait toute la règle : refusé."""
    alertes = [_alerte(rule_id="5715") for _ in range(3)]
    assert _signature(alertes) is None


def test_champ_non_constant_exclu_de_la_signature():
    """Un compte qui varie entre alertes n'entre pas dans la signature."""
    alertes = [_alerte(rule_id="5402", srcuser="alice", command="/bin/x"),
               _alerte(rule_id="5402", srcuser="bob", command="/bin/x")]
    sig = _signature(alertes)
    # srcuser varie -> exclu ; command constant -> discriminant retenu.
    assert sig == {"rule_id": "5402", "command": "/bin/x"}


def test_signature_canonique_stable():
    a = _canonique({"rule_id": "1", "file": "/x"})
    b = _canonique({"file": "/x", "rule_id": "1"})
    assert a == b  # indépendant de l'ordre des clés


def test_exception_file_suppression_bout_en_bout():
    """Une exception composite sur file supprime l'alerte visée, pas les autres."""
    f = NoiseFilter({})
    f.ajouter_composite({"rule_id": "87105", "file": "/tmp/eicar.com"}, "EICAR")
    vise = {"rule": {"id": "87105"},
            "data": {"virustotal": {"source": {"file": "/tmp/eicar.com"}}}}
    autre = {"rule": {"id": "87105"},
             "data": {"virustotal": {"source": {"file": "/tmp/malware.bin"}}}}
    assert f.raison_suppression(vise) == "EICAR"
    assert f.raison_suppression(autre) is None
