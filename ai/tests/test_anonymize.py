"""Pseudonymisation avant envoi au LLM cloud.

Trois invariants : (1) les actifs internes ne sortent jamais en clair ;
(2) les IOC externes et les attributs analytiques, eux, restent — c'est le
signal du verdict ; (3) la transformation est réversible (réhydratation).
"""

import json

import pytest

from soc_agent.anonymize import (Anonymiseur, FuiteError, anonymiser,
                                 rehydrater, verifier_fuite)
from soc_agent.render import rendre


def _incident():
    from datetime import datetime, timezone
    t = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
    incident = {
        "id": 1, "agent_id": "001", "agent_name": "debian-vm",
        "first_seen": t, "last_seen": t, "alert_count": 2, "max_level": 15,
        "mitre_tactics": ["Impact"], "entities": [],
    }
    alertes = [
        {"id": "a", "ts": t, "rule_id": "100670", "rule_level": 15,
         "rule_desc": "Ransomware sur debian-vm, compte jdupont",
         "srcip": "45.134.26.87", "srcuser": "jdupont",
         "entity": "/home/jdupont/rapport.docx.lockbit",
         "raw": json.dumps({"data": {"abuseipdb": {
             "srcip": "45.134.26.87", "abuse_confidence_score": "98",
             "total_reports": "2100", "country_code": "RU"}},
             "GeoLocation": {"country_name": "Russia", "city_name": "Moscow"}})},
        {"id": "b", "ts": t, "rule_id": "5710", "rule_level": 5,
         "rule_desc": "Connexion depuis 192.168.50.50",
         "srcip": "192.168.50.50", "srcuser": "root", "entity": None,
         "raw": json.dumps({})},
    ]
    return incident, alertes


def test_actifs_internes_pseudonymises():
    inc, alertes = _incident()
    anon = Anonymiseur()
    inc_a, alertes_a, interdits = anonymiser(anon, inc, alertes)

    assert inc_a["agent_name"].startswith("<HOTE_")
    assert alertes_a[0]["srcuser"].startswith("<COMPTE_")
    # IP privée -> jeton ; IP publique attaquant -> clair (IOC externe).
    assert alertes_a[1]["srcip"].startswith("<IP_")
    assert alertes_a[0]["srcip"] == "45.134.26.87"
    # « root » est générique : gardé (signal de privilège).
    assert alertes_a[1]["srcuser"] == "root"
    # Chemin : catégorie + extension gardées, milieu (dont le compte) masqué.
    assert alertes_a[0]["entity"].startswith("/home/<FICHIER_")
    assert alertes_a[0]["entity"].endswith(".lockbit")
    assert "jdupont" not in alertes_a[0]["entity"]


def test_attributs_et_ioc_externes_preserves():
    inc, alertes = _incident()
    anon = Anonymiseur()
    inc_a, alertes_a, _ = anonymiser(anon, inc, alertes)
    texte = rendre(inc_a, alertes_a)

    # Le signal du verdict survit.
    assert "98" in texte and "RU" in texte and "2100" in texte
    assert "45.134.26.87" in texte           # IOC externe gardé
    # Aucun actif interne en clair.
    for interdit in ("debian-vm", "jdupont", "192.168.50.50", "Moscow"):
        assert interdit not in texte, interdit


def test_texte_libre_nettoye():
    inc, alertes = _incident()
    anon = Anonymiseur()
    _, alertes_a, _ = anonymiser(anon, inc, alertes)
    # rule_desc contenait hostname, compte, IP privée.
    d0, d1 = alertes_a[0]["rule_desc"], alertes_a[1]["rule_desc"]
    assert "debian-vm" not in d0 and "jdupont" not in d0
    assert "192.168.50.50" not in d1


def test_chemin_dans_texte_libre_masque():
    """Un chemin noyé dans rule_desc (compte + nom de fichier) ne fuit pas."""
    anon = Anonymiseur()
    out = anon.texte_libre(
        "Canari altéré (/home/elie/000_CANARY_NE_PAS_TOUCHER.xlsx)", [])
    assert "elie" not in out
    assert "000_CANARY" not in out
    assert out.endswith(".xlsx)")           # extension = signal, gardée


def test_verifier_fuite_bloque_chemin_residuel():
    with pytest.raises(FuiteError):
        verifier_fuite("note dans /home/elie/secret.txt", [])
    # Un chemin déjà pseudonymisé ne déclenche pas le garde-fou.
    verifier_fuite("note dans /home/<FICHIER_1>.txt", [])


def test_verifier_fuite_scanne_les_donnees_pas_le_prompt_systeme():
    """Le scan ne porte que sur les données incident, pas le prompt système.

    Le prompt système du triage est un template dev constant qui contient des
    chemins d'exemple (/var/tmp, /dev/shm) : les scanner déclenchait un faux
    positif de fuite qui bloquait tout triage (régression). Les appelants
    passent donc `utilisateur` seul à verifier_fuite ; on documente ici que ces
    chemins d'exemple SONT bien des motifs que le garde-fou refuserait dans les
    données incident, d'où la nécessité de ne pas les lui soumettre.
    """
    from soc_agent.triage import PROMPTS
    systeme = (PROMPTS / "system.md").read_text()
    # Le prompt système contient bien un chemin qui piégerait le garde-fou…
    with pytest.raises(FuiteError):
        verifier_fuite(systeme, [])
    # …mais les données incident pseudonymisées, elles, passent.
    verifier_fuite("=== DEBUT INCIDENT ===\nNiveau 12/15, verdict attendu.\n"
                   "Objet : /home/<FICHIER_1>.sh\n=== FIN INCIDENT ===", [])


def test_reversible():
    inc, alertes = _incident()
    anon = Anonymiseur()
    inc_a, alertes_a, _ = anonymiser(anon, inc, alertes)
    texte = rendre(inc_a, alertes_a)
    clair = rehydrater(texte, anon.mapping)
    assert "debian-vm" in clair and "jdupont" in clair


def test_jetons_stables_entre_passages():
    inc, alertes = _incident()
    a1 = Anonymiseur()
    inc1, _, _ = anonymiser(a1, inc, alertes)
    # Re-triage : on repart de la map persistée -> mêmes jetons.
    a2 = Anonymiseur(a1.mapping)
    inc2, _, _ = anonymiser(a2, inc, alertes)
    assert inc1["agent_name"] == inc2["agent_name"]
    assert a1.mapping == a2.mapping


def test_verifier_fuite_bloque_identifiant_residuel():
    with pytest.raises(FuiteError):
        verifier_fuite("hôte debian-vm compromis", ["debian-vm"])
    with pytest.raises(FuiteError):
        verifier_fuite("contact admin@corp.local", [])
    with pytest.raises(FuiteError):
        verifier_fuite("depuis 10.0.0.5", [])
    # IP publique tolérée (IOC externe).
    verifier_fuite("depuis 45.134.26.87", [])
