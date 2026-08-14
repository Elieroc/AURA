"""Tests de la signature de whitelist et du champ virtuel « file ».

`_signature` décide ce qui devient une exception automatique. Une signature
trop large neutraliserait toute une règle de détection : c'est l'erreur à
rendre impossible, et elle se teste sans base ni LLM.
"""

from soc_agent.noise import NoiseFilter, _value_field
from soc_agent.whitelist import _canonical, _signature


def _alert(rule_id="87105", srcuser=None, command=None, file=None):
    data = {}
    if srcuser:
        data["srcuser"] = srcuser
    if command:
        data["command"] = command
    if file:
        data["virustotal"] = {"source": {"file": file}}
    return {"rule": {"id": rule_id}, "data": data}


def test_champ_virtuel_file_resout_plusieurs_chemins():
    assert _value_field({"syscheck": {"path": "/etc/passwd"}}, "file") == "/etc/passwd"
    assert _value_field(
        {"data": {"virustotal": {"source": {"file": "/tmp/x"}}}}, "file") == "/tmp/x"
    assert _value_field({"data": {}}, "file") is None


def test_signature_precise_avec_fichier():
    """EICAR : rule + file, discriminant présent -> signature valide."""
    alerts = [_alert(file="/tmp/eicar.com") for _ in range(3)]
    sig = _signature(alerts)
    assert sig == {"rule_id": "87105", "file": "/tmp/eicar.com"}


def test_rule_id_seul_refuse():
    """Sans discriminant, on neutraliserait toute la règle : refusé."""
    alerts = [_alert(rule_id="5715") for _ in range(3)]
    assert _signature(alerts) is None


def test_champ_non_constant_exclu_de_la_signature():
    """Un compte qui varie entre alertes n'entre pas dans la signature."""
    alerts = [_alert(rule_id="5402", srcuser="alice", command="/bin/x"),
               _alert(rule_id="5402", srcuser="bob", command="/bin/x")]
    sig = _signature(alerts)
    # srcuser varie -> exclu ; command constant -> discriminant retenu.
    assert sig == {"rule_id": "5402", "command": "/bin/x"}


def test_signature_canonique_stable():
    a = _canonical({"rule_id": "1", "file": "/x"})
    b = _canonical({"file": "/x", "rule_id": "1"})
    assert a == b  # indépendant de l'ordre des clés


def test_exception_file_suppression_bout_en_bout():
    """Une exception composite sur file supprime l'alerte visée, pas les autres."""
    f = NoiseFilter({})
    f.add_composite({"rule_id": "87105", "file": "/tmp/eicar.com"}, "EICAR")
    vise = {"rule": {"id": "87105"},
            "data": {"virustotal": {"source": {"file": "/tmp/eicar.com"}}}}
    other = {"rule": {"id": "87105"},
             "data": {"virustotal": {"source": {"file": "/tmp/malware.bin"}}}}
    assert f.deletion_reason(vise) == "EICAR"
    assert f.deletion_reason(other) is None


# --- parcours en flux (correctif OOM du 2026-08-14) --------------------------
#
# `_signature` reçoit désormais un itérable, pour que l'appelant puisse lui
# passer un curseur serveur : matérialiser les 126 508 `raw` d'un incident de
# flood coûtait 1 Go et a fait OOM-killer le cycle, donc arrêté l'ingestion.

def test_signature_accepte_un_generateur():
    """Un curseur serveur ne se parcourt qu'une fois : la fonction ne doit
    jamais relire son entrée."""
    alerts = [_alert(command="/usr/bin/borg", file="/etc/passwd"),
               _alert(command="/usr/bin/borg", file="/etc/passwd")]
    sig = _signature(a for a in alerts)
    assert sig is not None
    assert sig["command"] == "/usr/bin/borg"


def test_signature_voit_la_valeur_divergente_tardive():
    """Le champ qui varie à la DERNIÈRE alerte doit sortir de la signature.

    C'est le garde-fou contre la tentation d'échantillonner : une signature
    calculée sur les N premières alertes déclarerait `command` constant et
    produirait une exception plus large que l'incident réellement observé.
    """
    alerts = ([_alert(command="/usr/bin/borg", file="/etc/passwd")] * 5000
               + [_alert(command="/usr/bin/curl", file="/etc/passwd")])
    sig = _signature(a for a in alerts)
    assert "command" not in sig      # divergent, donc écarté
    assert sig["file"] == "/etc/passwd"
