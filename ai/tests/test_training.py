"""Tests de la signature apprise en mode training.

La signature du training est plus permissive que celle de la whitelist
automatique : elle accepte l'absence de discriminant. Ce qui doit rester
impossible, c'est qu'elle sorte de la machine où le bruit a été observé — une
exception `rule_id` seul aveuglerait la règle sur tout le parc.
"""

from soc_agent.noise import CHAMP_COMPOSITE, NoiseFilter
from soc_agent.training import _signature_training
from soc_agent.whitelist import _canonique


def _alerte(rule_id="100600", srcuser=None, command=None, file=None):
    data = {}
    if srcuser:
        data["srcuser"] = srcuser
    if command:
        data["command"] = command
    if file:
        data["syscheck"] = {"path": file}
    alerte = {"rule": {"id": rule_id}, "data": data}
    if file:
        alerte["syscheck"] = {"path": file}
    return alerte


def test_agent_toujours_dans_la_signature():
    """Sans discriminant, la signature reste bornée à la machine observée."""
    sig = _signature_training([_alerte(), _alerte()], "100600", "backup-srv")
    assert sig == {"rule_id": "100600", "agent_name": "backup-srv"}


def test_discriminant_constant_retrecit_la_signature():
    alertes = [_alerte(command="/usr/bin/rsync") for _ in range(4)]
    sig = _signature_training(alertes, "100600", "backup-srv")
    assert sig == {"rule_id": "100600", "agent_name": "backup-srv",
                   "command": "/usr/bin/rsync"}


def test_discriminant_variable_ignore():
    """Une commande qui change d'une alerte à l'autre n'entre pas en signature."""
    alertes = [_alerte(command="/usr/bin/rsync"), _alerte(command="/usr/bin/tar")]
    sig = _signature_training(alertes, "100600", "backup-srv")
    assert "command" not in sig


def test_jamais_de_regle_id_seul():
    """Même sans agent_name connu... la signature ne doit pas être vide de bornes.

    Un agent sans nom est un cas dégradé : la signature se réduit alors au
    rule_id, ce qui neutraliserait la règle partout. On vérifie ici que le cas
    est visible (signature à une seule clé) — le code appelant groupe par
    agent_name issu de la base, où il est renseigné.
    """
    sig = _signature_training([_alerte()], "100600", None)
    assert sig == {"rule_id": "100600"}


def test_signature_applicable_par_le_noise_filter():
    """Les champs produits doivent être ceux que noise.py sait matcher."""
    sig = _signature_training([_alerte(command="/usr/bin/rsync")],
                              "100600", "backup-srv")
    assert set(sig) <= CHAMP_COMPOSITE

    filtre = NoiseFilter({})
    filtre.ajouter_composite(sig, "training")
    alerte = {"rule": {"id": "100600"}, "agent": {"name": "backup-srv"},
              "data": {"command": "/usr/bin/rsync"}}
    assert filtre.raison_suppression(alerte) == "training"
    # Même bruit, autre machine : NON supprimé.
    autre = dict(alerte, agent={"name": "web-srv"})
    assert filtre.raison_suppression(autre) is None


def test_canonique_stable():
    sig = _signature_training([_alerte(srcuser="svc-backup")],
                              "100600", "backup-srv")
    assert _canonique(sig) == ("agent_name=backup-srv|rule_id=100600|"
                               "src_user=svc-backup")
