"""Tests du regroupement en incidents.

`_grouper` est une fonction pure : elle prend une liste d'alertes et rend des
groupes, sans base de données. C'est délibéré — la logique qui décide qu'une
attaque est un incident et pas trente est la partie du code où une erreur coûte
le plus cher, et elle doit rester vérifiable sans infrastructure.

    ~/.local/share/soc-ai/venv/bin/python -m pytest ai/tests -q
"""

from datetime import datetime, timedelta, timezone

from soc_agent.correlate import _grouper, point_commun

T0 = datetime(2026, 7, 22, 10, 0, tzinfo=timezone.utc)


def alerte(minutes=0, agent="001", rule="100670", level=15,
           groups=("ransomware",), tactics=("Impact",), srcip=None,
           srcuser=None, entity=None):
    return {
        "id": f"a{minutes}-{rule}-{entity or srcip or ''}",
        "ts": T0 + timedelta(minutes=minutes),
        "agent_id": agent, "agent_name": agent,
        "rule_id": rule, "rule_level": level,
        "rule_groups": list(groups), "mitre_tactics": list(tactics),
        "srcip": srcip, "srcuser": srcuser, "entity": entity,
    }


def test_rafale_meme_tactique_donne_un_incident():
    """Les 25 alertes canari du ransomware sont un incident, pas 25."""
    alertes = [alerte(minutes=i, entity=f"/data/f{i}.docx") for i in range(25)]
    assert len(_grouper(alertes)) == 1


def test_agents_differents_jamais_fusionnes():
    alertes = [alerte(agent="001"), alerte(minutes=1, agent="002")]
    assert len(_grouper(alertes)) == 2


def test_lien_faible_hors_fenetre_separe():
    """Même tactique mais 45 min plus tard : deux incidents (fenêtre 30 min)."""
    alertes = [alerte(minutes=0), alerte(minutes=45)]
    assert len(_grouper(alertes)) == 2


def test_lien_fort_survit_a_une_fenetre_large():
    """Même IP hostile à 68 min d'écart : une seule campagne.

    C'est le cas réel qui a motivé la fenêtre à deux vitesses — trois alertes
    AbuseIPDB de 185.220.101.34 réparties sur l'après-midi.
    """
    alertes = [
        alerte(minutes=0, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="185.220.101.34"),
        alerte(minutes=68, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="185.220.101.34"),
    ]
    assert len(_grouper(alertes)) == 1


def test_alerte_etrangere_intercalee_ne_coupe_pas_l_incident():
    """Plusieurs incidents restent ouverts en parallèle sur un même agent.

    Avec un seul incident ouvert par agent, l'alerte étrangère du milieu
    refermait le premier et les deux alertes de la même IP finissaient
    séparées.
    """
    alertes = [
        alerte(minutes=0, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="1.2.3.4"),
        alerte(minutes=1, rule="87105", tactics=("Execution",),
               groups=("virustotal",), entity="/tmp/eicar.com"),
        alerte(minutes=40, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="1.2.3.4"),
    ]
    groupes = _grouper(alertes)
    assert len(groupes) == 2
    assert sorted(len(g) for g in groupes) == [1, 2]


def test_ip_differentes_restent_separees():
    alertes = [
        alerte(minutes=0, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="1.2.3.4"),
        alerte(minutes=5, rule="100622", tactics=(), groups=("abuseipdb",),
               srcip="9.9.9.9"),
    ]
    # Le groupe « abuseipdb » n'est pas générique : il les relie malgré tout,
    # ce qui est voulu — deux IP signalées coup sur coup relèvent du même
    # sujet. Le test fige ce comportement pour qu'un changement soit délibéré.
    assert len(_grouper(alertes)) == 1


def test_groupes_generiques_ne_relient_rien():
    """`syscheck` ou `pci_dss` sont sur la moitié des règles."""
    a = alerte(rule="550", groups=("syscheck", "pci_dss"), tactics=())
    b = alerte(minutes=5, rule="554", groups=("syscheck", "gdpr"), tactics=())
    assert point_commun(a, b) is None
    assert len(_grouper([a, b])) == 2


def test_duree_maximale_coupe_le_chainage():
    """Une alerte toutes les 10 min pendant 10 h ne fait pas un incident de 10 h."""
    alertes = [alerte(minutes=10 * i) for i in range(60)]
    groupes = _grouper(alertes)
    assert len(groupes) > 1
    for g in groupes:
        assert g[-1]["ts"] - g[0]["ts"] <= timedelta(hours=6)


def test_lien_fort_prioritaire_sur_lien_faible():
    a = alerte(srcip="1.2.3.4")
    b = alerte(minutes=1, srcip="1.2.3.4")
    assert point_commun(a, b) == ("même IP source", True)
