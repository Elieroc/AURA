"""CTI : normalisation, cache d'IOC, et extraction côté Wazuh.

Trois propriétés valent tout le reste de ce fichier, parce qu'elles portent
chacune une panne SILENCIEUSE — celles qui ne lèvent aucune erreur et laissent
croire à une CTI qui fonctionne :

- `test_normalisation_identique_cote_wazuh` : le cache est écrit par le
  soc-agent et lu par un script du manager qui réimplémente la normalisation
  (interpréteur différent, pas de code partagé possible). Une divergence entre
  les deux ne casse rien, elle fait juste que plus rien ne matche, jamais ;
- `test_pas_de_boucle_sur_nos_propres_alertes` : l'intégration réinjecte des
  événements dans l'analyseur. Sans garde-fou, une alerte CTI porte les mêmes
  IOC que celle qui l'a produite et se réalimente en boucle ;
- `test_ioc_retire_du_feed_disparait_du_cache` : la révocation. Un IOC qui ne
  disparaît pas d'un cache reconstruit alerte indéfiniment sur une IP
  réhabilitée.
"""

import importlib.util
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_agent import cti

# Le script d'intégration vit hors du paquet (il tourne sur le manager, avec
# l'interpréteur embarqué de Wazuh). Chargé par son chemin, comme le fait
# wazuh-integratord.
CHEMIN_INTEGRATION = (Path(__file__).resolve().parents[2]
                      / "wazuh" / "integrations" / "custom-misp.py")


def _charger_integration():
    spec = importlib.util.spec_from_file_location("custom_misp", CHEMIN_INTEGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


integration = _charger_integration()


# --- Normalisation ----------------------------------------------------------

CAS = [
    ("ip", "185.220.101.1", "185.220.101.1"),
    ("ip", " 185.220.101.1 ", "185.220.101.1"),
    ("ip", "185.220.101.1|443", "185.220.101.1"),
    ("ip", "[2001:0db8::0001]", "2001:db8::1"),
    ("ip", "pas-une-ip", None),
    ("domaine", "Evil.Example.COM.", "evil.example.com"),
    ("domaine", "localhost", None),          # sans point : nom interne
    ("domaine", "deux mots", None),
    ("url", "HTTP://Evil.example.com/Payload/", "http://evil.example.com/payload"),
    ("url", "/wp-login.php", None),          # chemin nu : matcherait n'importe quel hôte
    ("hash", "  D41D8CD98F00B204E9800998ECF8427E  ", "d41d8cd98f00b204e9800998ecf8427e"),
    ("hash", "malware.exe|d41d8cd98f00b204e9800998ecf8427e",
     "d41d8cd98f00b204e9800998ecf8427e"),
    ("hash", "zzzz", None),
    ("hash", "d41d8cd98f00b204e9800998ecf8427", None),   # 31 caractères
]


@pytest.mark.parametrize("type_cache,brut,attendu", CAS)
def test_normalisation(type_cache, brut, attendu):
    assert cti.normaliser(type_cache, brut) == attendu


@pytest.mark.parametrize("type_cache,brut,attendu", CAS)
def test_normalisation_identique_cote_wazuh(type_cache, brut, attendu):
    # Deux implémentations, un seul comportement attendu. Si ce test tombe,
    # le cache est écrit dans une forme que la détection ne cherche pas : elle
    # ne matchera plus rien, sans la moindre erreur.
    assert integration.normaliser(type_cache, brut) == attendu


def test_url_sans_schema_jamais_indexee():
    # Une URL réduite à son chemin est le piège classique : les logs Apache
    # décodés par Wazuh ne portent que ça, et tous les hôtes du monde
    # partagent /index.php.
    assert cti.normaliser("url", "evil.example.com/payload") is None


# --- Cache ------------------------------------------------------------------

def _ioc(valeur, type_="ip", source="ThreatFox", confiance=cti.CONFIANCE_CUREE,
         menace=2, tags=""):
    return {"valeur": valeur, "type": type_, "source": source,
            "categorie": "Network activity", "evenement": "Campagne X",
            "event_id": "42", "tags": tags, "niveau_menace": menace,
            "confiance": confiance}


def test_ecriture_et_lecture_du_cache(tmp_path):
    chemin = str(tmp_path / "ioc.db")
    compte = cti.ecrire_cache([_ioc("1.2.3.4"),
                               _ioc("5.6.7.8", confiance=cti.CONFIANCE_MASSE)],
                              chemin)
    assert compte == {cti.CONFIANCE_CUREE: 1, cti.CONFIANCE_MASSE: 1}
    trouve = cti.interroger("1.2.3.4", chemin)
    assert trouve and trouve[0]["source"] == "ThreatFox"
    assert cti.interroger("9.9.9.9", chemin) == []


def test_meme_ioc_de_deux_sources_le_cure_dabord(tmp_path):
    chemin = str(tmp_path / "ioc.db")
    cti.ecrire_cache([
        _ioc("1.2.3.4", source="data-shield", confiance=cti.CONFIANCE_MASSE, menace=4),
        _ioc("1.2.3.4", source="CERT-FR", confiance=cti.CONFIANCE_CUREE, menace=1),
    ], chemin)
    resultats = cti.interroger("1.2.3.4", chemin)
    # Les deux sont conservées — l'analyste veut savoir que l'IP est aussi sur
    # une liste de masse — mais c'est le renseignement curé qui décide du
    # niveau de l'alerte, donc il doit sortir en tête.
    assert [r["source"] for r in resultats] == ["CERT-FR", "data-shield"]


def test_ioc_retire_du_feed_disparait_du_cache(tmp_path):
    chemin = str(tmp_path / "ioc.db")
    cti.ecrire_cache([_ioc("1.2.3.4"), _ioc("5.6.7.8")], chemin)
    cti.ecrire_cache([_ioc("1.2.3.4")], chemin)
    assert cti.interroger("5.6.7.8", chemin) == []


def test_echec_de_synchronisation_laisse_le_cache_precedent(tmp_path):
    chemin = str(tmp_path / "ioc.db")
    cti.ecrire_cache([_ioc("1.2.3.4")], chemin)

    def source_qui_casse():
        yield _ioc("5.6.7.8")
        raise RuntimeError("feed interrompu")

    with pytest.raises(RuntimeError):
        cti.ecrire_cache(source_qui_casse(), chemin)

    # Le remplacement est atomique : une synchronisation ratée ne doit ni
    # vider le cache, ni le laisser à moitié écrit. Mieux vaut un
    # renseignement d'hier que pas de renseignement du tout.
    assert cti.interroger("1.2.3.4", chemin)
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".ioc-")]


def test_etat_signale_la_peremption(tmp_path, monkeypatch):
    chemin = str(tmp_path / "ioc.db")
    cti.ecrire_cache([_ioc("1.2.3.4")], chemin)
    assert cti.etat(chemin)["perime"] is False

    vieux = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    conn = sqlite3.connect(chemin)
    conn.execute("UPDATE meta SET valeur = ? WHERE cle = 'synchronise_a'", (vieux,))
    conn.commit()
    conn.close()
    assert cti.etat(chemin)["perime"] is True


# --- Extraction MISP --------------------------------------------------------

def _fausse_reponse(attributs):
    """Deux pages : le lot demandé, puis vide (fin de pagination)."""
    pages = [{"response": {"Attribute": attributs}}, {"response": {"Attribute": []}}]

    def _misp(methode, chemin, corps=None):
        return pages.pop(0) if pages else {"response": {"Attribute": []}}
    return _misp


def test_attributs_misp_ignore_les_types_sans_equivalent(monkeypatch):
    monkeypatch.setattr(cti, "_misp", _fausse_reponse([
        {"type": "ip-dst", "value": "1.2.3.4", "category": "Network activity",
         "event_id": "7", "Event": {"info": "Campagne", "threat_level_id": "1",
                                    "Orgc": {"name": "CERT-FR"}}},
        # Aucun champ d'alerte Wazuh ne porte de clé de registre : l'ingérer
        # gonflerait le cache sans jamais matcher.
        {"type": "regkey", "value": "HKLM\\Run\\evil", "Event": {}},
    ]))
    iocs = list(cti.attributs_misp())
    assert [(i["valeur"], i["type"], i["source"]) for i in iocs] == [
        ("1.2.3.4", "ip", "CERT-FR")]
    assert iocs[0]["confiance"] == cti.CONFIANCE_CUREE


def test_extraction_misp_demande_bien_les_indicateurs_de_detection(monkeypatch):
    vus = {}

    def _misp(methode, chemin, corps=None):
        vus.update(corps or {})
        return {"response": {"Attribute": []}}

    monkeypatch.setattr(cti, "_misp", _misp)
    list(cti.attributs_misp())
    # to_ids : MISP contient beaucoup d'attributs de CONTEXTE (sinkholes, IP
    # citées en exemple) que leurs auteurs marquent explicitement comme non
    # destinés à la détection. Les ingérer fabrique des faux positifs signés
    # « CERT-FR », les plus coûteux à réfuter.
    assert vus["to_ids"] == 1
    assert vus["published"] == 1
    assert vus["enforceWarninglist"] == 1


# --- Blocklists -------------------------------------------------------------

class _Reponse:
    def __init__(self, texte):
        self.text = texte

    def raise_for_status(self):
        pass


def test_blocklist_ignore_commentaires_et_lignes_vides(monkeypatch):
    monkeypatch.setattr(cti.requests, "get", lambda *a, **k: _Reponse(
        "# entête du fournisseur\n\n1.2.3.4\n5.6.7.8 # commentaire en fin\n"
        "; autre style\npas-une-ip\n"))
    catalogue = {"misp_feeds": [], "blocklists": [
        {"nom": "test", "type": "ip", "urls": ["https://exemple/liste.txt"],
         "tags": ["cti:test"]}]}
    iocs = list(cti.blocklists(catalogue))
    assert [i["valeur"] for i in iocs] == ["1.2.3.4", "5.6.7.8"]
    # Une liste de masse ne qualifie rien : elle ne doit jamais faire d'incident.
    assert all(i["confiance"] == cti.CONFIANCE_MASSE for i in iocs)


def test_blocklist_injoignable_ne_fait_pas_echouer_les_autres(monkeypatch):
    def _get(url, **kwargs):
        if "morte" in url:
            raise cti.requests.ConnectionError("injoignable")
        return _Reponse("1.2.3.4\n")

    monkeypatch.setattr(cti.requests, "get", _get)
    catalogue = {"misp_feeds": [], "blocklists": [
        {"nom": "morte", "type": "ip", "urls": ["https://morte/liste.txt"]},
        {"nom": "vivante", "type": "ip", "urls": ["https://vivante/liste.txt"]}]}
    # Le cache est reconstruit en entier à chaque passe : laisser une source
    # morte tout interrompre reviendrait à perdre TOUTE la CTI pour un feed.
    assert [i["source"] for i in cti.blocklists(catalogue)] == ["vivante"]


def test_bootstrap_reconnait_un_feed_preinstalle_par_misp(monkeypatch):
    # MISP livre le feed CIRCL sous `.../feed-osint`, le catalogue l'écrit avec
    # un slash final. Sans normalisation, le bootstrap crée un DOUBLON : les
    # deux exemplaires activés, MISP tire le même feed deux fois et double les
    # événements. Constaté en prod le 2026-08-12.
    appels = []

    def _misp(methode, chemin, corps=None):
        appels.append((methode, chemin))
        if chemin == "/feeds/index":
            return [{"Feed": {"id": "1", "url": "https://www.circl.lu/doc/misp/feed-osint",
                              "enabled": True, "caching_enabled": True}}]
        return {}

    monkeypatch.setattr(cti, "_misp", _misp)
    catalogue = {"misp_feeds": [{"nom": "CIRCL OSINT Feed", "format": "misp",
                                 "url": "https://www.circl.lu/doc/misp/feed-osint/"}],
                 "blocklists": []}
    resume = cti.bootstrap_feeds(catalogue=catalogue)
    assert resume["crees"] == []
    assert not any(chemin == "/feeds/add" for _, chemin in appels)


def test_rafraichissement_utilise_le_bon_endpoint(monkeypatch):
    # /feeds/fetchFromFeed/{id} attend un identifiant numérique et répond 404
    # sur « all » — mesuré en prod. Seul cacheFeeds accepte une portée nommée.
    appels = []
    monkeypatch.setattr(cti, "_misp",
                        lambda m, c, corps=None: appels.append(c))
    cti.rafraichir_feeds()
    assert appels == ["/feeds/fetchFromAllFeeds", "/feeds/cacheFeeds/all"]


def test_catalogue_livre_est_coherent():
    catalogue = cti.charger_catalogue()
    assert catalogue["misp_feeds"] and catalogue["blocklists"]
    for feed in catalogue["misp_feeds"]:
        assert feed["url"].startswith("https://")
    for bl in catalogue["blocklists"]:
        assert bl["urls"] and bl.get("type") in ("ip", "url", "domaine")
    # Le feed demandé nommément, et celui qui justifie la moitié du dispositif.
    urls = [f["url"] for f in catalogue["misp_feeds"]]
    assert any("cert.ssi.gouv.fr" in u for u in urls)
    assert any("duggytuxy" in u
               for bl in catalogue["blocklists"] for u in bl["urls"])


# --- Intégration Wazuh ------------------------------------------------------

def _alerte(**donnees):
    base = {"rule": {"id": "5710", "description": "sshd: failed login"},
            "agent": {"id": "003", "name": "web01"}, "data": {}}
    base["data"].update(donnees.pop("data", {}))
    base.update(donnees)
    return base


def test_extraction_des_candidats_par_direction():
    trouves = integration.candidats(_alerte(data={
        "srcip": "185.220.101.1", "dstip": "23.45.67.89"}))
    par_valeur = {v: (t, champ, direction) for t, v, champ, direction in trouves}
    assert par_valeur["185.220.101.1"][2] == "entrant"
    assert par_valeur["23.45.67.89"][2] == "sortant"


def test_ip_privee_jamais_cherchee():
    # Une IP privée ne peut pas être un IOC public. La chercher, c'est risquer
    # de matcher une de nos machines parce qu'un feed a publié du 192.168.x —
    # ça arrive.
    trouves = integration.candidats(_alerte(data={
        "srcip": "192.168.1.10", "dstip": "172.20.0.5"}))
    assert trouves == []


def test_url_recollee_depuis_hote_et_chemin():
    trouves = integration.candidats(_alerte(data={
        "http": {"hostname": "evil.example.com", "url": "/payload.bin"}}))
    urls = {v for t, v, _, _ in trouves if t == "url"}
    assert "http://evil.example.com/payload.bin" in urls
    assert "https://evil.example.com/payload.bin" in urls


def test_empreintes_sysmon_extraites_du_champ_agrege():
    trouves = integration.candidats({"rule": {"id": "61603"}, "data": {"win": {
        "eventdata": {"hashes": "SHA1=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,"
                                "MD5=D41D8CD98F00B204E9800998ECF8427E"}}}})
    hashes = {v for t, v, _, _ in trouves if t == "hash"}
    assert hashes == {"da39a3ee5e6b4b0d3255bfef95601890afd80709",
                      "d41d8cd98f00b204e9800998ecf8427e"}


def test_hash_du_fim_extrait():
    trouves = integration.candidats({
        "rule": {"id": "550"},
        "syscheck": {"sha256_after": "a" * 64}})
    assert ("hash", "a" * 64, "syscheck.sha256_after", "artefact") in trouves


def _lancer(monkeypatch, tmp_path, alerte, iocs=(), age_heures=1.0):
    """Exécute l'intégration sur une alerte, rend les événements réinjectés."""
    chemin = str(tmp_path / "ioc.db")
    cti.ecrire_cache(list(iocs), chemin)
    if age_heures != 1.0:
        conn = sqlite3.connect(chemin)
        conn.execute("UPDATE meta SET valeur = ? WHERE cle = 'synchronise_a'",
                     ((datetime.now(timezone.utc)
                       - timedelta(hours=age_heures)).isoformat(),))
        conn.commit()
        conn.close()
    monkeypatch.setattr(integration, "CACHE", chemin)
    monkeypatch.setattr(integration, "TEMOIN_PEREMPTION",
                        str(tmp_path / "temoin"))

    envoyes = []
    monkeypatch.setattr(integration, "envoyer", envoyes.append)

    fichier = tmp_path / "alerte.json"
    fichier.write_text(json.dumps(alerte))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(fichier)])
    integration.main()
    return envoyes


def test_pas_de_boucle_sur_nos_propres_alertes(monkeypatch, tmp_path):
    # Une alerte 100952 porte le même IOC que celle qui l'a produite : la
    # retraiter réinjecterait un événement, qui rematcherait, indéfiniment — et
    # la boucle serait alimentée par le trafic normal du parc.
    alerte = _alerte(rule={"id": "100952", "description": "CTI - outbound"},
                     data={"srcip": "185.220.101.1"})
    assert _lancer(monkeypatch, tmp_path, alerte,
                   [_ioc("185.220.101.1")]) == []


def test_pas_de_retraitement_dune_alerte_denrichissement(monkeypatch, tmp_path):
    alerte = _alerte(rule={"id": "100622", "description": "AbuseIPDB"},
                     data={"integration": "custom-abuseipdb",
                           "srcip": "185.220.101.1"})
    assert _lancer(monkeypatch, tmp_path, alerte,
                   [_ioc("185.220.101.1")]) == []


def test_evenement_enrichi_sur_correspondance(monkeypatch, tmp_path):
    alerte = _alerte(data={"srcip": "185.220.101.1"})
    envoyes = _lancer(monkeypatch, tmp_path, alerte, [_ioc("185.220.101.1")])
    assert len(envoyes) == 1
    misp = envoyes[0]["misp"]
    assert envoyes[0]["integration"] == "custom-misp"
    assert (misp["ioc"], misp["direction"], misp["confiance"]) == (
        "185.220.101.1", "entrant", "curated")
    assert misp["source_alert_rule_id"] == "5710"
    assert misp["agent"] == "web01"
    # srcip à la racine : c'est ce qui fait géolocaliser l'IOC par le pipeline
    # d'ingest de l'indexer, comme pour custom-abuseipdb.
    assert envoyes[0]["srcip"] == "185.220.101.1"


def test_sans_correspondance_aucun_evenement(monkeypatch, tmp_path):
    alerte = _alerte(data={"srcip": "185.220.101.1"})
    assert _lancer(monkeypatch, tmp_path, alerte, [_ioc("9.9.9.9")]) == []


def test_le_sortant_cure_prime_sur_lentrant_de_masse(monkeypatch, tmp_path):
    # Une même alerte porte souvent les deux : une IP source de scanner (bruit)
    # et une IP destination de C2 (incident). Un seul événement est réinjecté,
    # il doit porter le second.
    alerte = _alerte(data={"srcip": "1.1.1.2", "dstip": "23.45.67.89"})
    envoyes = _lancer(monkeypatch, tmp_path, alerte, [
        _ioc("1.1.1.2", source="data-shield", confiance=cti.CONFIANCE_MASSE),
        _ioc("23.45.67.89", source="ThreatFox", confiance=cti.CONFIANCE_CUREE),
    ])
    assert envoyes[0]["misp"]["ioc"] == "23.45.67.89"
    assert envoyes[0]["misp"]["direction"] == "sortant"
    assert envoyes[0]["misp"]["correspondances"] == "2"


def test_cache_perime_signale_une_seule_fois(monkeypatch, tmp_path):
    alerte = _alerte(data={"srcip": "185.220.101.1"})
    envoyes = _lancer(monkeypatch, tmp_path, alerte, [_ioc("9.9.9.9")],
                      age_heures=72)
    assert len(envoyes) == 1 and "erreur" in envoyes[0]["misp"]

    # Second passage immédiat : le témoin doit museler le rappel, sinon le SOC
    # se noie sous son propre voyant de panne — une alerte par alerte traitée.
    envoyes = _lancer(monkeypatch, tmp_path, alerte, [_ioc("9.9.9.9")],
                      age_heures=72)
    assert envoyes == []


def test_cache_absent_signale_sans_planter(monkeypatch, tmp_path):
    monkeypatch.setattr(integration, "CACHE", str(tmp_path / "absent.db"))
    monkeypatch.setattr(integration, "TEMOIN_PEREMPTION", str(tmp_path / "temoin"))
    envoyes = []
    monkeypatch.setattr(integration, "envoyer", envoyes.append)
    fichier = tmp_path / "alerte.json"
    fichier.write_text(json.dumps(_alerte(data={"srcip": "185.220.101.1"})))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(fichier)])
    integration.main()
    assert len(envoyes) == 1 and "erreur" in envoyes[0]["misp"]
