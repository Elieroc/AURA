"""CMDB : rôle -> priorité, sévérité effective, garde-fou de clôture.

Tout ce qui est testé ici est PUR (pas de base, pas d'API Wazuh) : c'est la
partie qui décide de l'ORDRE dans lequel les incidents sont analysés et de ce
que le modèle a le droit de refermer seul. La synchronisation depuis le manager
et la résolution en base sont couvertes en recette.
"""

from datetime import datetime, timezone

from soc_agent import actions, assets, config
from soc_agent.render import render

T0 = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)


# --- Rôle déduit des groupes Wazuh ------------------------------------------

def test_role_lu_sur_le_groupe_prefixe():
    assert assets.role_from_groups(["default", "role-dc"]) == "dc"


def test_groupe_sans_prefixe_ne_declare_rien():
    # `infrastructure` est un groupe de configuration existant (interdiction
    # d'isolation) : il ne doit pas être confondu avec une déclaration de rôle.
    assert assets.role_from_groups(["infrastructure", "default"]) is None


def test_role_inconnu_du_catalogue_ignore():
    # Un groupe `role-` inventé n'a pas de priorité : mieux vaut retomber sur le
    # défaut que d'inventer un classement.
    assert assets.role_from_groups(["role-tototo"]) is None
    assert assets.role_priority("tototo") == config.DEFAULT_PRIORITY


def test_asset_mixte_prend_le_role_le_plus_critique():
    # Un LAMP mutualisé qui est aussi le DNS interne : le traiter comme sa
    # moitié la moins importante serait le pire des deux mondes.
    assert assets.role_from_groups(["role-web", "role-dc"]) == "dc"


# --- Sévérité effective ------------------------------------------------------

def test_severite_majoree_sur_asset_critique():
    assert assets.severity(12, 1) == 14
    assert assets.severity(12, 2) == 13


def test_severite_minoree_sur_poste_jetable():
    assert assets.severity(12, 4) == 11


def test_severite_bornee_a_l_echelle_wazuh():
    # Un niveau 15 sur un DC reste 15 : au-delà, la valeur ne serait plus
    # comparable à `max_level` et ne voudrait plus rien dire.
    assert assets.severity(15, 1) == 15
    assert assets.severity(1, 4) == 1


def test_priorite_inconnue_ne_decale_rien():
    assert assets.severity(10, 99) == 10


# --- Garde-fou de clôture ----------------------------------------------------

def test_cloture_refusee_plus_tot_sur_un_asset_p1():
    final_actions, patterns = actions.apply_guardrails(
        "false_positive", ["close_false_positive"], 12,
        suspected_injection=False, priority=1)
    assert final_actions == ["escalate_human", "open_case"]
    assert patterns and "P1" in patterns[0]


def test_meme_incident_cloturable_sur_un_asset_p4():
    final_actions, patterns = actions.apply_guardrails(
        "false_positive", ["close_false_positive"], 12,
        suspected_injection=False, priority=4)
    assert final_actions == ["close_false_positive"]
    assert not patterns


def test_seuil_historique_conserve_sans_priorite():
    # Incidents antérieurs à la CMDB, et appelants qui ne passent pas de
    # priorité : le comportement ne doit pas changer sous leurs pieds.
    assert actions.closure_threshold(None) == actions.LEVEL_CLOSURE_FORBIDDEN
    _, patterns = actions.apply_guardrails(
        "false_positive", ["close_false_positive"], 13,
        suspected_injection=False)
    assert not patterns


def test_niveau_14_reste_incloturable_partout():
    for priority in (None, 1, 2, 3, 4):
        _, patterns = actions.apply_guardrails(
            "false_positive", ["close_false_positive"], 14,
            suspected_injection=False, priority=priority)
        assert patterns, f"P{priority} : un niveau 14 ne se referme jamais seul"


# --- Rendu pour le modèle ----------------------------------------------------

def _incident(**kw):
    base = {"id": 1, "agent_id": "004", "agent_name": "win-dc",
            "first_seen": T0, "last_seen": T0, "alert_count": 3,
            "max_level": 12, "mitre_tactics": []}
    base.update(kw)
    return base


def test_le_prompt_explicite_la_criticite():
    text = render(_incident(priority=1, asset_role="dc"), [])
    assert "P1" in text
    # Le chiffre seul n'apprend rien au modèle : la conséquence doit être écrite.
    assert "domaine" in text


def test_le_prompt_reste_muet_sans_priorite():
    # Incident antérieur à la CMDB : pas de ligne inventée, pas de « P None ».
    assert "criticité" not in render(_incident(), [])


def test_role_non_declare_dit_comme_tel():
    text = render(_incident(priority=4), [])
    assert "rôle non déclaré" in text


def test_capteur_n_affiche_pas_le_role_de_la_machine():
    # Priorité rabattue : afficher « P3 — firewall » à côté de « serveur interne
    # sans exposition » est contradictoire, et fait analyser le mauvais hôte.
    text = render(_incident(priority=3, asset_role="sensor"), [])
    assert "firewall" not in text
    assert "agent capteur" in text
    assert "autres machines" in text
