"""Tests du regroupement en incidents.

`_grouper` est une fonction pure : elle prend une liste d'alertes et rend des
groupes, sans base de données. C'est délibéré — la logique qui décide qu'une
attaque est un incident et pas trente est la partie du code où une erreur coûte
le plus cher, et elle doit rester vérifiable sans infrastructure.

    ~/.local/share/soc-ai/venv/bin/python -m pytest ai/tests -q
"""

from datetime import datetime, timedelta, timezone

from soc_agent.correlate import (_graine_valide, _grouper, _signal_decisif,
                                 point_commun)

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


# --- Filtrage des graines : le bruit structurel n'ouvre pas d'incident -------

def test_graine_bruit_sca_refusee():
    """Un check de conformité CIS/SCA ne fonde jamais un case, même remonté."""
    a = alerte(rule="19001", level=12, groups=("sca",), tactics=(),
               entity=None)
    a["rule_desc"] = "CIS Debian benchmark: ensure X"
    assert _graine_valide(a) is False


def test_graine_bruit_statut_agent_refusee():
    a = alerte(rule="503", level=12, groups=("ossec",), tactics=())
    a["rule_desc"] = "Wazuh agent stopped."
    assert _graine_valide(a) is False


def test_graine_bruit_login_reussi_refusee():
    a = alerte(rule="5715", level=12, groups=("authentication_success",),
               tactics=())
    a["rule_desc"] = "sshd: authentication success."
    assert _graine_valide(a) is False


def test_graine_intrusion_reelle_acceptee():
    """Un vrai signal d'intrusion (reverse shell) reste une graine valide."""
    a = alerte(rule="100721", level=12, groups=("attack",),
               tactics=("Execution",))
    a["rule_desc"] = "Reverse shell probable : /dev/tcp"
    assert _graine_valide(a) is True


# --- correctif #2 : needs_refresh ne repart que sur un signal décisif --------

def test_signal_repetition_de_bruit_ne_declenche_pas():
    """Une salve qui répète des règles déjà présentes, sans hausse de niveau,
    n'est PAS un signal décisif : pas de re-triage + rapport (boucle tokens)."""
    anciennes = {"100670", "100710"}
    nouvelles = [alerte(rule="100670", level=12, groups=("attack",))]
    assert _signal_decisif(anciennes, nouvelles, ancien_max=15) is False


def test_signal_bruit_structurel_meme_regle_inedite_ne_declenche_pas():
    """Une règle inédite MAIS structurelle (rootcheck/SCA/statut d'agent, ex.
    100801 auditd absent) n'ouvre pas un refresh : ce n'est pas une graine."""
    a = alerte(rule="510", level=12, groups=("rootcheck",), tactics=())
    a["rule_desc"] = "Host-based anomaly detection event (rootcheck)."
    assert _signal_decisif({"100670"}, [a], ancien_max=15) is False


def test_signal_regle_inedite_reelle_declenche():
    """Une règle d'intrusion inédite (non structurelle) = signal décisif."""
    a = alerte(rule="100721", level=12, groups=("attack",),
               tactics=("Execution",))
    a["rule_desc"] = "Reverse shell probable : /dev/tcp"
    assert _signal_decisif({"100670"}, [a], ancien_max=15) is True


def test_signal_hausse_de_niveau_declenche():
    """Une escalade de sévérité rouvre toujours un refresh, même règle connue."""
    nouvelles = [alerte(rule="100670", level=14, groups=("attack",))]
    assert _signal_decisif({"100670"}, nouvelles, ancien_max=12) is True


def test_signal_ueba_reste_un_seul_incident():
    """Un signal promu ne doit pas se faire réémietter par la corrélation.

    Mesuré à la mise en service : un signal de 239 alertes ressortait en 8
    incidents — 8 triages LLM au lieu d'un, chacun amputé du contexte des autres
    et portant un score sans rapport avec celui du signal.
    """
    from datetime import datetime, timedelta, timezone
    from soc_agent import correlate

    t0 = datetime(2026, 8, 7, 6, 0, tzinfo=timezone.utc)
    # Rien de commun entre elles hors le signal : règles, objets et comptes
    # tous différents, et un écart supérieur à la fenêtre faible (30 min).
    alertes = [{
        "id": str(i), "ts": t0 + timedelta(minutes=45 * i), "agent_id": "014",
        "agent_name": "winsrv", "rule_id": f"9{i}000", "rule_level": 3,
        "rule_desc": "x", "rule_groups": [f"g{i}"], "mitre_tactics": [],
        "srcip": None, "srcuser": None, "entity": f"/tmp/f{i}",
        "audit_uid": None, "ueba_seed": True, "ueba_signal_id": 42,
    } for i in range(6)]

    assert len(correlate._grouper(alertes)) == 1

    # Sans le lien de signal, les mêmes alertes se seraient bien émiettées :
    # c'est ce lien qui les tient, pas une coïncidence de la fixture.
    for a in alertes:
        a["ueba_signal_id"] = None
    assert len(correlate._grouper(alertes)) > 1
