"""VOC : score d'exposition, SLA, clôture, rapprochement avec un incident.

Ce qui est testé ici est PUR (pas d'indexer, pas de base) sauf la partie
clôture, couverte par un faux curseur. Deux propriétés valent tout le reste et
justifient à elles seules ce fichier :

- une machine qui a cessé de répondre ne doit JAMAIS produire de remédiation
  (`test_cloture_ne_touche_que_les_agents_vus`) — c'est le seul mensonge que ce
  module peut raconter, et il serait invisible : un burn-down parfait ;
- une CVE n'est « liée à l'incident » que si elle y est CITÉE, jamais parce
  qu'elle est grave et que la machine est attaquée.
"""

from datetime import datetime, timedelta, timezone

import pytest

from soc_agent import config, vulns

T0 = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)


# --- Sévérité effective -----------------------------------------------------

def test_severite_du_feed_prioritaire_sur_le_score():
    assert vulns.severite_effective("High", 2.0) == "high"


def test_severite_vide_deduite_du_score_cvss():
    # 334 CVE par hôte Debian arrivent sans sévérité mais avec un score : les
    # jeter au poids « inconnu » serait perdre une information qu'on a.
    assert vulns.severite_effective("", 9.8) == "critical"
    assert vulns.severite_effective(None, 7.5) == "high"
    assert vulns.severite_effective("untriaged", 5.0) == "medium"
    assert vulns.severite_effective("", 1.0) == "low"


def test_severite_absente_et_score_absent_reste_indeterminee():
    assert vulns.severite_effective("", None) == ""
    assert vulns.poids("") == pytest.approx(0.5)


# --- Score d'exposition -----------------------------------------------------

def test_score_nul_sans_vulnerabilite():
    assert vulns.score_risque(0) == 0


def test_score_croit_avec_la_charge():
    scores = [vulns.score_risque(c) for c in (10, 100, 1000, 10000)]
    assert scores == sorted(scores)
    assert all(0 <= s <= 100 for s in scores)


def test_score_sature_au_plafond():
    # Propriété assumée, écrite partout où le score s'affiche : deux machines à
    # 100 ne sont plus comparables entre elles.
    assert vulns.score_risque(config.VOC_CHARGE_MAX) == 100
    assert vulns.score_risque(config.VOC_CHARGE_MAX * 10) == 100


def test_echelle_de_poids_tres_non_lineaire():
    # Sinon le score serait dominé par le bruit de fond des distributions et
    # classerait les machines par nombre de paquets installés.
    assert vulns.poids("critical") >= 10 * vulns.poids("medium")
    assert vulns.poids("critical") >= 50 * vulns.poids("low")
    assert vulns.poids("high") > vulns.poids("medium") > vulns.poids("low")


def test_niveau_lisible_borne():
    assert vulns.niveau_risque(0) == "nulle"
    assert vulns.niveau_risque(90) == "critique"
    assert vulns.niveau_risque(65) == "élevée"


# --- SLA --------------------------------------------------------------------

def test_sla_plus_court_sur_asset_critique():
    assert vulns.sla_jours("critical", 1) < vulns.sla_jours("critical", 4)


def test_sla_plus_court_pour_une_severite_plus_grave():
    assert vulns.sla_jours("critical", 2) < vulns.sla_jours("low", 2)


def test_pas_de_sla_sur_severite_non_classee():
    # On ne réclame pas le respect d'une échéance qu'on n'a pas su fixer.
    assert vulns.sla_jours("", 1) is None


def test_priorite_hors_echelle_bornee():
    # Une priorité aberrante (0, 9) ne doit pas lever un IndexError en plein
    # calcul d'exposition : elle est rabattue dans P1..P4.
    assert vulns.sla_jours("high", 0) == vulns.sla_jours("high", 1)
    assert vulns.sla_jours("high", 9) == vulns.sla_jours("high", 4)


# --- Rapprochement avec un incident -----------------------------------------

def _alerte(desc="", raw=None, mitre=None):
    return {"rule_desc": desc, "raw": raw or {},
            "mitre_ids": mitre or []}


def test_cve_citee_dans_la_description_reperee():
    assert vulns.cves_citees([_alerte("Exploit CVE-2021-4034 detected")]) == {
        "CVE-2021-4034"}


def test_cve_citee_dans_le_log_brut_reperee_et_normalisee():
    a = _alerte(raw={"full_log": "curl -O poc-cve-2024-3094.sh"})
    assert vulns.cves_citees([a]) == {"CVE-2024-3094"}


def test_texte_sans_cve_ne_produit_rien():
    assert vulns.cves_citees([_alerte("ssh brute force"),
                             _alerte(raw={"full_log": "CVE- incomplet"})]) == set()


class _FauxCurseur:
    """Connexion Postgres réduite à ce que `lien_incident` en fait : une seule
    requête, celle des vulnérabilités ouvertes de l'agent."""

    def __init__(self, ouvertes):
        self._ouvertes = ouvertes

    def execute(self, sql, params=None):
        return list(self._ouvertes)


def _vuln(cve, severite="critical", score=9.8, age=10.0):
    return {"cve": cve, "paquet": "openssl", "version": "1.1", "age_jours": age,
            "severite": severite, "score_base": score, "publiee_a": None,
            "vue_a": T0 - timedelta(days=age)}


_EXPO_VIDE = {"pires": [], "couverte": True}


def test_cve_citee_et_ouverte_est_confirmee():
    conn = _FauxCurseur([_vuln("CVE-2021-4034")])
    lien = vulns.lien_incident(conn, "013",
                               [_alerte("exploit CVE-2021-4034")], _EXPO_VIDE)
    assert [v["cve"] for v in lien["confirmees"]] == ["CVE-2021-4034"]
    assert lien["citees_non_ouvertes"] == []


def test_cve_citee_mais_non_ouverte_reste_a_part():
    # Tentative contre une version non vulnérable : information sur la MÉTHODE
    # de l'attaquant, pas sur l'exposition de l'hôte. Ne doit pas remonter dans
    # `confirmees`, sur quoi le rapport écrit « le même accès reste
    # reproductible ».
    conn = _FauxCurseur([_vuln("CVE-2021-4034")])
    lien = vulns.lien_incident(conn, "013",
                               [_alerte("scan CVE-2017-0144")], _EXPO_VIDE)
    assert lien["confirmees"] == []
    assert lien["citees_non_ouvertes"] == ["CVE-2017-0144"]


def test_pas_de_vecteur_propose_sans_technique_d_exploitation():
    # Le piège que cette règle évite : lister les pires CVE de la machine à côté
    # d'un incident qui n'a rien à voir. L'analyste ferait le lien à notre place.
    expo = {"pires": [_vuln("CVE-2024-0001")], "couverte": True}
    lien = vulns.lien_incident(_FauxCurseur([]), "013",
                               [_alerte("ssh brute force", mitre=["T1110"])],
                               expo)
    assert lien["vecteurs_possibles"] == []
    assert lien["techniques_exploit"] == []


def test_vecteurs_proposes_sur_technique_d_exploitation():
    expo = {"pires": [_vuln("CVE-2024-0001"),
                      _vuln("CVE-2024-0002", "medium", 5.0)],
            "couverte": True}
    lien = vulns.lien_incident(
        _FauxCurseur([]), "013",
        [_alerte("privilege escalation", mitre=["T1068"])], expo)
    assert lien["techniques_exploit"] == ["T1068"]
    # Seules les graves : proposer une medium comme vecteur d'une privesc
    # noierait la piste.
    assert [v["cve"] for v in lien["vecteurs_possibles"]] == ["CVE-2024-0001"]


# --- Clôture : le garde-fou qui compte --------------------------------------

def test_cloture_ne_touche_que_les_agents_vus():
    """La requête de clôture DOIT être bornée aux agents ayant répondu.

    Sans cette borne, un agent arrêté (ou dont syscollector est cassé) sort de
    l'index d'état avec toutes ses vulnérabilités, et le diff conclut à une
    remédiation massive : burn-down parfait, MTTR magnifique, parc invisible.
    Test sur le texte du SQL faute de base : c'est la clause dont l'absence ne
    produirait aucune erreur, seulement un mensonge.
    """
    assert "agent_id = ANY(%(agents)s)" in vulns.CLOTURE
    assert "statut = 'corrigee'" in vulns.CLOTURE


def test_upsert_ne_reecrit_pas_la_date_de_premiere_vue():
    """`vue_a` fait courir le SLA : la réécrire à chaque scan remettrait tous
    les compteurs de retard à zéro à chaque passage, et le VOC se féliciterait
    tout seul. Seule une vulnérabilité qui RÉAPPARAÎT après correction
    redémarre."""
    assert "vue_a        = CASE WHEN vulnerabilites.statut = 'corrigee'" \
        in vulns.UPSERT


# --- Aplatissement d'un document Wazuh --------------------------------------

_DOC = {
    "agent": {"id": "013", "name": "debian2"},
    "package": {"name": "linux-image-amd64", "version": "6.1.174-1"},
    "vulnerability": {"id": "CVE-2026-43105", "severity": "Medium",
                      "score": {"base": 5.5},
                      "published_at": "2026-05-06T10:16:24Z"},
    "host": {"os": {"full": "Debian GNU/Linux 12 (bookworm)"}},
}


def test_aplatir_document_complet():
    v = vulns._aplatir(_DOC)
    assert v["agent_id"] == "013"
    assert v["cve"] == "CVE-2026-43105"
    assert v["paquet"] == "linux-image-amd64"
    assert v["severite"] == "medium"
    assert v["score_base"] == pytest.approx(5.5)


def test_paquet_absent_remplace_par_un_libelle_stable():
    # Vulnérabilité de l'OS lui-même (Windows, corrigée par un hotfix) : NULL
    # casserait la clé d'unicité (agent, cve, paquet).
    doc = {**_DOC, "package": {}}
    assert vulns._aplatir(doc)["paquet"] == "(système)"


def test_document_sans_cve_ignore():
    assert vulns._aplatir({**_DOC, "vulnerability": {}}) is None
