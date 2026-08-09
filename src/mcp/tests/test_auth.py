"""Ce que le serveur MCP ne doit jamais laisser passer.

Ces tests portent sur les invariants d'autorisation, pas sur le comportement
des outils : un outil qui rend une mauvaise donnée est un bug, un outil
accessible au mauvais jeton est une porte ouverte sur la production.
"""

import pytest

from aura_mcp import auth, gateway


def _scopes(*valeurs):
    """Installe des scopes pour la durée d'un test."""
    return auth.SCOPES.set(frozenset(valeurs))


def test_defaut_est_le_refus():
    """Un appel sans jeton n'a aucun droit — pas même la lecture.

    Le serveur MCP Wazuh amont accorde la lecture par défaut. Ici même la
    lecture expose des journaux d'incidents : rien n'est implicite.
    """
    assert auth.SCOPES.get() == frozenset()

    @auth.exige("aura:read")
    def outil():
        return "atteint"

    with pytest.raises(auth.Refus):
        outil()


def test_admin_implique_write_et_read():
    """Un jeton d'admin n'a pas à lister les trois scopes."""
    jeton = _scopes(*auth.config.IMPLIQUE["aura:admin"])
    try:
        @auth.exige("aura:read")
        def lire():
            return "ok"

        @auth.exige("aura:admin")
        def agir():
            return "ok"

        assert lire() == "ok"
        assert agir() == "ok"
    finally:
        auth.SCOPES.reset(jeton)


def test_lecture_ne_donne_pas_action():
    """Le cas qui compte : un jeton de lecture ne doit pas pouvoir isoler."""
    jeton = _scopes("aura:read")
    try:
        @auth.exige("aura:admin")
        def isoler():
            return "isolé"

        with pytest.raises(auth.Refus) as e:
            isoler()
        # Le message doit nommer le scope manquant : le client est un agent IA
        # qui doit pouvoir dire à son utilisateur quel jeton demander.
        assert "aura:admin" in str(e.value)
    finally:
        auth.SCOPES.reset(jeton)


def test_outil_sans_scope_refuse_a_l_enregistrement():
    """Un outil qui oublie @auth.exige ne doit pas pouvoir être servi."""
    from aura_mcp import serveur

    def outil_negligent():
        return "accessible à tout jeton valide"

    with pytest.raises(RuntimeError, match="auth.exige"):
        serveur.enregistrer(outil_negligent)


def test_scopes_du_jeton_developpe_les_implications():
    import datetime as dt

    import jwt

    maintenant = dt.datetime.now(dt.timezone.utc)
    brut = jwt.encode(
        {"sub": "test", "scope": "aura:admin", "iss": auth.config.ISSUER,
         "aud": auth.config.AUDIENCE, "iat": maintenant,
         "exp": maintenant + dt.timedelta(minutes=5)},
        auth.config.SECRET, algorithm="HS256")

    sujet, scopes = auth.scopes_du_jeton(brut)
    assert sujet == "test"
    assert scopes == frozenset({"aura:admin", "aura:write", "aura:read"})


def test_jeton_expire_est_refuse():
    import datetime as dt

    import jwt

    passe = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    brut = jwt.encode(
        {"sub": "test", "scope": "aura:read", "iss": auth.config.ISSUER,
         "aud": auth.config.AUDIENCE, "iat": passe,
         "exp": passe + dt.timedelta(minutes=5)},
        auth.config.SECRET, algorithm="HS256")

    with pytest.raises(jwt.PyJWTError):
        auth.scopes_du_jeton(brut)


# --- Relais ---------------------------------------------------------------

def test_active_response_wazuh_toujours_masquee():
    """Le point non négociable du relais.

    Ces outils parlent à l'API du manager sans rien connaître des agents
    protégés ni des groupes d'infrastructure. Un client qui les voit peut
    isoler le pare-feu — et couper le SOC avec.
    """
    amont = gateway.Amont("wazuh", "http://x/mcp", "", "wazuh_")
    for outil in gateway.WAZUH_MASQUES:
        assert not gateway.autorise(amont, outil), outil


def test_liste_autorisation_et_non_interdiction():
    """Un outil inconnu n'est pas relayé.

    C'est ce qui fait qu'une montée de version de l'amont ne peut pas exposer
    d'elle-même un nouvel outil d'action.
    """
    amont = gateway.Amont("wazuh", "http://x/mcp", "", "wazuh_")
    assert not gateway.autorise(amont, "outil_ajoute_par_une_maj")
    assert gateway.autorise(amont, "get_wazuh_agents")


def test_aucun_outil_masque_dans_la_liste_autorisee():
    """Garde-fou contre une contradiction introduite par distraction."""
    assert not (gateway.WAZUH_AUTORISES & gateway.WAZUH_MASQUES)
