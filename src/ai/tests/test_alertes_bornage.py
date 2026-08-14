"""Bornage du chargement des alertes d'un incident (`soc_agent.alertes`).

Ce qui est testé : que la borne s'applique, qu'elle prenne bien les DEUX bouts
de l'incident, et qu'elle se taise quand l'incident tient sous le plafond. La
panne que ce module empêche n'est pas une erreur mais un OOM-kill silencieux —
il n'y a donc aucun test qui « échoue » naturellement si le bornage disparaît,
d'où ces vérifications sur la requête elle-même.
"""

import pytest

from soc_agent import alertes, config


class FauxCurseur:
    """Connexion minimale : mémorise les requêtes, rend un compte fixé."""

    def __init__(self, total):
        self.total = total
        self.requetes = []

    def execute(self, sql, params=None):
        self.requetes.append((" ".join(sql.split()), params))
        self._derniere = sql
        return self

    def fetchone(self):
        return {"c": self.total}

    def fetchall(self):
        return [{"id": "a"}]


def test_sous_le_plafond_une_seule_requete_sans_limit():
    """Le cas normal ne doit rien payer : pas d'UNION, pas de LIMIT."""
    conn = FauxCurseur(total=10)
    alertes.charger_bornees(conn, 1, alertes.COLONNES_TRIAGE)
    sql = conn.requetes[-1][0]
    assert "UNION ALL" not in sql and "LIMIT" not in sql


def test_au_dela_du_plafond_les_deux_bouts_sont_pris():
    """Prendre « les N dernières » perdrait le début de l'attaque — c'est-à-dire
    exactement ce qu'un analyste cherche, et d'où sortent les cibles de la
    remédiation."""
    conn = FauxCurseur(total=102869)
    alertes.charger_bornees(conn, 2555, alertes.COLONNES_CIBLAGE)
    sql, params = conn.requetes[-1]
    assert "UNION ALL" in sql
    assert "ORDER BY ts ASC LIMIT" in sql and "ORDER BY ts DESC LIMIT" in sql
    assert params["debut"] + params["fin"] == config.INCIDENT_MAX_ALERTES
    assert params["i"] == 2555


def test_ts_non_duplique_quand_les_colonnes_le_portent_deja():
    """Régression du 2026-08-14 : `ts` ajouté en aveugle aux colonnes le
    projetait deux fois, et Postgres refusait la requête entière (« ORDER BY
    "ts" is ambiguous »). Trois des quatre jeux de colonnes contiennent déjà
    `ts` — c'était donc le cas NOMINAL qui était cassé, et il l'est resté
    jusqu'à la prod parce que les tests tournaient sur une fausse connexion,
    qui ne valide aucun SQL."""
    conn = FauxCurseur(total=99999)
    alertes.charger_bornees(conn, 7, alertes.COLONNES_TRIAGE)
    sql = conn.requetes[-1][0]
    assert ", ts, ts" not in sql and "raw, ts" not in sql
    assert sql.count("ORDER BY ts") == 3      # ASC, DESC, et le tri final


def test_porte_ts_ne_confond_pas_une_sous_chaine():
    """« rule_groups, mitre_tactics » contient « ts » sans porter la colonne."""
    assert alertes._porte_ts("id, ts, raw")
    assert not alertes._porte_ts("rule_groups, mitre_tactics, raw")
    assert not alertes._porte_ts(alertes.COLONNES_CIBLAGE)


def test_ts_est_projete_dans_les_deux_branches():
    """L'ORDER BY final porte sur `ts` : absent du SELECT des deux branches de
    l'UNION, la requête est une erreur SQL — et le bornage ne servirait qu'à
    faire échouer le cycle autrement."""
    conn = FauxCurseur(total=99999)
    alertes.charger_bornees(conn, 7, "agent_id, raw")
    sql = conn.requetes[-1][0]
    assert sql.count("agent_id, raw, ts FROM alerts") == 2


def test_troncature_journalisee(caplog):
    """Jamais silencieuse : ce qui est au milieu de la salve n'est pas examiné,
    et un analyste doit pouvoir le lire dans les logs."""
    conn = FauxCurseur(total=50000)
    with caplog.at_level("WARNING"):
        alertes.charger_bornees(conn, 42, alertes.COLONNES_UEBA, "remédiation")
    msg = caplog.text
    assert "#42" in msg and "remédiation" in msg
    assert "50000" in msg and "non examinée" in msg


def test_pas_de_bruit_sous_le_plafond(caplog):
    conn = FauxCurseur(total=5)
    with caplog.at_level("WARNING"):
        alertes.charger_bornees(conn, 42, alertes.COLONNES_UEBA)
    assert caplog.text == ""


@pytest.mark.parametrize("colonnes", [
    alertes.COLONNES_RAPPORT, alertes.COLONNES_TRIAGE,
    alertes.COLONNES_CIBLAGE, alertes.COLONNES_UEBA,
])
def test_tous_les_jeux_de_colonnes_portent_le_raw(colonnes):
    """`raw` est le poids lourd (186 Mo pour un incident de flood) : c'est
    précisément parce que chaque appelant en a besoin que le bornage doit être
    commun, et non refait au cas par cas — il a été oublié quatre fois."""
    assert "raw" in colonnes


def test_les_appelants_passent_par_le_module_commun():
    """Garde-fou de non-régression : la panne s'est reproduite quatre fois en
    étant corrigée localement à chaque fois. Si un module recharge un incident
    entier à la main, ce test doit le voir."""
    import inspect
    import re

    from soc_agent import iris, mitigate, triage, ueba

    # Ce qu'on traque, c'est la projection de `raw` sur tout un incident. Deux
    # précautions apprises en écrivant ce test :
    #   - les guillemets sont RETIRÉS avant l'analyse : la requête fautive était
    #     écrite en deux littéraux concaténés (« SELECT ... raw " "FROM alerts »),
    #     et un motif qui s'arrête au guillemet ne l'aurait jamais vue ;
    #   - une agrégation (`count(*)`, `array_agg`) sur les mêmes lignes se
    #     calcule côté Postgres et ne ramène qu'une ligne : légitime.
    interdit = re.compile(
        r"SELECT(?!.{0,80}count\().{0,200}?\braw\b.{0,200}?FROM alerts"
        r".{0,80}?WHERE incident_id", re.DOTALL)
    for module in (iris, mitigate, triage, ueba):
        brut = inspect.getsource(module)
        src = re.sub(r"[\"']", "", brut)
        # Une requête « toutes les alertes de l'incident, raw compris » ne doit
        # plus exister en dur ; elle passe par charger_bornees ou parcourir.
        m = interdit.search(src)
        if m:
            raise AssertionError(
                f"{module.__name__} recharge un incident entier — utiliser "
                f"soc_agent.alertes.charger_bornees/parcourir. Vu : "
                f"{' '.join(m.group(0).split())[:120]}")


# ---------------------------------------------------------------------------
# Validation SQL réelle
# ---------------------------------------------------------------------------
#
# Les tests ci-dessus tournent sur une fausse connexion : ils vérifient la
# FORME de la requête, jamais sa validité. C'est exactement ce qui a laissé
# passer en prod un `ORDER BY "ts" is ambiguous` — la requête était bien
# construite, et refusée par Postgres. Celui-ci l'exécute pour de vrai quand une
# base est joignable, et se saute proprement sinon.
@pytest.mark.parametrize("nom", ["COLONNES_RAPPORT", "COLONNES_TRIAGE",
                                 "COLONNES_CIBLAGE", "COLONNES_UEBA"])
def test_sql_accepte_par_postgres(nom):
    psycopg = pytest.importorskip("psycopg")
    try:
        conn = psycopg.connect(config.PG_DSN, row_factory=psycopg.rows.dict_row,
                               connect_timeout=3)
    except Exception:                                          # noqa: BLE001
        pytest.skip("pas de Postgres joignable")
    with conn:
        # Branche NON bornée : incident inexistant, le compte vaut 0.
        alertes.charger_bornees(conn, -1, getattr(alertes, nom))
        # Branche BORNÉE : il faut un incident réel dont le compte dépasse le
        # plafond, sinon c'est encore la première branche qui est exercée — et
        # c'est justement l'UNION qui était invalide.
        vrai = conn.execute(
            "SELECT incident_id FROM alerts WHERE incident_id IS NOT NULL "
            "GROUP BY incident_id HAVING count(*) >= 2 LIMIT 1").fetchone()
        if not vrai:
            pytest.skip("aucun incident de 2 alertes ou plus en base")
        plafond = config.INCIDENT_MAX_ALERTES
        try:
            config.INCIDENT_MAX_ALERTES = 1
            alertes.charger_bornees(conn, vrai["incident_id"],
                                    getattr(alertes, nom))
        finally:
            config.INCIDENT_MAX_ALERTES = plafond
