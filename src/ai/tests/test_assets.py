"""CMDB : rôle -> priorité, sévérité effective, garde-fou de clôture.

Tout ce qui est testé ici est PUR (pas de base, pas d'API Wazuh) : c'est la
partie qui décide de l'ORDRE dans lequel les incidents sont analysés et de ce
que le modèle a le droit de refermer seul. La synchronisation depuis le manager
et la résolution en base sont couvertes en recette.
"""

from datetime import datetime, timezone

from soc_agent import actions, assets, config
from soc_agent.render import rendre

T0 = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)


# --- Rôle déduit des groupes Wazuh ------------------------------------------

def test_role_lu_sur_le_groupe_prefixe():
    assert assets.role_depuis_groupes(["default", "role-dc"]) == "dc"


def test_groupe_sans_prefixe_ne_declare_rien():
    # `infrastructure` est un groupe de configuration existant (interdiction
    # d'isolation) : il ne doit pas être confondu avec une déclaration de rôle.
    assert assets.role_depuis_groupes(["infrastructure", "default"]) is None


def test_role_inconnu_du_catalogue_ignore():
    # Un groupe `role-` inventé n'a pas de priorité : mieux vaut retomber sur le
    # défaut que d'inventer un classement.
    assert assets.role_depuis_groupes(["role-tototo"]) is None
    assert assets.priorite_du_role("tototo") == config.PRIORITE_DEFAUT


def test_asset_mixte_prend_le_role_le_plus_critique():
    # Un LAMP mutualisé qui est aussi le DNS interne : le traiter comme sa
    # moitié la moins importante serait le pire des deux mondes.
    assert assets.role_depuis_groupes(["role-web", "role-dc"]) == "dc"


# --- Sévérité effective ------------------------------------------------------

def test_severite_majoree_sur_asset_critique():
    assert assets.severite(12, 1) == 14
    assert assets.severite(12, 2) == 13


def test_severite_minoree_sur_poste_jetable():
    assert assets.severite(12, 4) == 11


def test_severite_bornee_a_l_echelle_wazuh():
    # Un niveau 15 sur un DC reste 15 : au-delà, la valeur ne serait plus
    # comparable à `max_level` et ne voudrait plus rien dire.
    assert assets.severite(15, 1) == 15
    assert assets.severite(1, 4) == 1


def test_priorite_inconnue_ne_decale_rien():
    assert assets.severite(10, 99) == 10


# --- Garde-fou de clôture ----------------------------------------------------

def test_cloture_refusee_plus_tot_sur_un_asset_p1():
    actions_finales, motifs = actions.appliquer_garde_fous(
        "false_positive", ["close_false_positive"], 12,
        injection_suspectee=False, priorite=1)
    assert actions_finales == ["escalate_human", "open_case"]
    assert motifs and "P1" in motifs[0]


def test_meme_incident_cloturable_sur_un_asset_p4():
    actions_finales, motifs = actions.appliquer_garde_fous(
        "false_positive", ["close_false_positive"], 12,
        injection_suspectee=False, priorite=4)
    assert actions_finales == ["close_false_positive"]
    assert not motifs


def test_seuil_historique_conserve_sans_priorite():
    # Incidents antérieurs à la CMDB, et appelants qui ne passent pas de
    # priorité : le comportement ne doit pas changer sous leurs pieds.
    assert actions.seuil_cloture(None) == actions.NIVEAU_CLOTURE_INTERDITE
    _, motifs = actions.appliquer_garde_fous(
        "false_positive", ["close_false_positive"], 13,
        injection_suspectee=False)
    assert not motifs


def test_niveau_14_reste_incloturable_partout():
    for priorite in (None, 1, 2, 3, 4):
        _, motifs = actions.appliquer_garde_fous(
            "false_positive", ["close_false_positive"], 14,
            injection_suspectee=False, priorite=priorite)
        assert motifs, f"P{priorite} : un niveau 14 ne se referme jamais seul"


# --- Rendu pour le modèle ----------------------------------------------------

def _incident(**kw):
    base = {"id": 1, "agent_id": "004", "agent_name": "win-dc",
            "first_seen": T0, "last_seen": T0, "alert_count": 3,
            "max_level": 12, "mitre_tactics": []}
    base.update(kw)
    return base


def test_le_prompt_explicite_la_criticite():
    texte = rendre(_incident(priorite=1, asset_role="dc"), [])
    assert "P1" in texte
    # Le chiffre seul n'apprend rien au modèle : la conséquence doit être écrite.
    assert "domaine" in texte


def test_le_prompt_reste_muet_sans_priorite():
    # Incident antérieur à la CMDB : pas de ligne inventée, pas de « P None ».
    assert "criticité" not in rendre(_incident(), [])


def test_role_non_declare_dit_comme_tel():
    texte = rendre(_incident(priorite=4), [])
    assert "rôle non déclaré" in texte
