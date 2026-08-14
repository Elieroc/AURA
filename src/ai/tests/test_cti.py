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
PATH_INTEGRATION = (Path(__file__).resolve().parents[2]
                      / "wazuh" / "integrations" / "custom-misp.py")


def _load_integration():
    spec = importlib.util.spec_from_file_location("custom_misp", PATH_INTEGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


integration = _load_integration()


# --- Normalisation ----------------------------------------------------------

CAS = [
    ("ip", "185.220.101.1", "185.220.101.1"),
    ("ip", " 185.220.101.1 ", "185.220.101.1"),
    ("ip", "185.220.101.1|443", "185.220.101.1"),
    ("ip", "[2001:0db8::0001]", "2001:db8::1"),
    ("ip", "pas-une-ip", None),
    ("domain", "Evil.Example.COM.", "evil.example.com"),
    ("domain", "localhost", None),          # sans point : nom interne
    ("domain", "deux mots", None),
    ("url", "HTTP://Evil.example.com/Payload/", "http://evil.example.com/payload"),
    ("url", "/wp-login.php", None),          # chemin nu : matcherait n'importe quel hôte
    ("hash", "  D41D8CD98F00B204E9800998ECF8427E  ", "d41d8cd98f00b204e9800998ecf8427e"),
    ("hash", "malware.exe|d41d8cd98f00b204e9800998ecf8427e",
     "d41d8cd98f00b204e9800998ecf8427e"),
    ("hash", "zzzz", None),
    ("hash", "d41d8cd98f00b204e9800998ecf8427", None),   # 31 caractères
]


@pytest.mark.parametrize("type_cache,raw,expected", CAS)
def test_normalisation(type_cache, raw, expected):
    assert cti.normalize(type_cache, raw) == expected


@pytest.mark.parametrize("type_cache,raw,expected", CAS)
def test_normalisation_identique_cote_wazuh(type_cache, raw, expected):
    # Deux implémentations, un seul comportement attendu. Si ce test tombe,
    # le cache est écrit dans une forme que la détection ne cherche pas : elle
    # ne matchera plus rien, sans la moindre erreur.
    assert integration.normalize(type_cache, raw) == expected


def test_url_sans_schema_jamais_indexee():
    # Une URL réduite à son chemin est le piège classique : les logs Apache
    # décodés par Wazuh ne portent que ça, et tous les hôtes du monde
    # partagent /index.php.
    assert cti.normalize("url", "evil.example.com/payload") is None


# --- Cache ------------------------------------------------------------------

def _ioc(value, type_="ip", source="ThreatFox", confidence=cti.CONFIDENCE_CURATED,
         threat=2, tags=""):
    return {"value": value, "type": type_, "source": source,
            "categorie": "Network activity", "evenement": "Campagne X",
            "event_id": "42", "tags": tags, "niveau_menace": threat,
            "confiance": confidence}


def test_ecriture_et_lecture_du_cache(tmp_path):
    path = str(tmp_path / "ioc.db")
    account = cti.write_cache([_ioc("1.2.3.4"),
                               _ioc("5.6.7.8", confidence=cti.CONFIDENCE_BULK)],
                              path)
    assert account == {cti.CONFIDENCE_CURATED: 1, cti.CONFIDENCE_BULK: 1}
    found = cti.query("1.2.3.4", path)
    assert found and found[0]["source"] == "ThreatFox"
    assert cti.query("9.9.9.9", path) == []


def test_meme_ioc_de_deux_sources_le_cure_dabord(tmp_path):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([
        _ioc("1.2.3.4", source="data-shield", confidence=cti.CONFIDENCE_BULK, threat=4),
        _ioc("1.2.3.4", source="CERT-FR", confidence=cti.CONFIDENCE_CURATED, threat=1),
    ], path)
    results = cti.query("1.2.3.4", path)
    # Les deux sont conservées — l'analyste veut savoir que l'IP est aussi sur
    # une liste de masse — mais c'est le renseignement curé qui décide du
    # niveau de l'alerte, donc il doit sortir en tête.
    assert [r["source"] for r in results] == ["CERT-FR", "data-shield"]


def test_ioc_retire_du_feed_disparait_du_cache(tmp_path):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("1.2.3.4"), _ioc("5.6.7.8")], path)
    cti.write_cache([_ioc("1.2.3.4")], path)
    assert cti.query("5.6.7.8", path) == []


def test_echec_de_synchronisation_laisse_le_cache_precedent(tmp_path):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("1.2.3.4")], path)

    def source_qui_casse():
        yield _ioc("5.6.7.8")
        raise RuntimeError("feed interrompu")

    with pytest.raises(RuntimeError):
        cti.write_cache(source_qui_casse(), path)

    # Le remplacement est atomique : une synchronisation ratée ne doit ni
    # vider le cache, ni le laisser à moitié écrit. Mieux vaut un
    # renseignement d'hier que pas de renseignement du tout.
    assert cti.query("1.2.3.4", path)
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".ioc-")]


def test_etat_signale_la_peremption(tmp_path, monkeypatch):
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("1.2.3.4")], path)
    assert cti.state(path)["perime"] is False

    old = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE meta SET value = ? WHERE key = 'synchronise_a'", (old,))
    conn.commit()
    conn.close()
    assert cti.state(path)["perime"] is True


# --- Extraction MISP --------------------------------------------------------

def _fake_response(attributes):
    """Deux pages : le lot demandé, puis vide (fin de pagination)."""
    pages = [{"response": {"Attribute": attributes}}, {"response": {"Attribute": []}}]

    def _misp(method, path, body=None):
        return pages.pop(0) if pages else {"response": {"Attribute": []}}
    return _misp


def test_attributs_misp_ignore_les_types_sans_equivalent(monkeypatch):
    monkeypatch.setattr(cti, "_misp", _fake_response([
        {"type": "ip-dst", "value": "1.2.3.4", "category": "Network activity",
         "event_id": "7", "Event": {"info": "Campagne", "threat_level_id": "1",
                                    "Orgc": {"name": "CERT-FR"}}},
        # Aucun champ d'alerte Wazuh ne porte de clé de registre : l'ingérer
        # gonflerait le cache sans jamais matcher.
        {"type": "regkey", "value": "HKLM\\Run\\evil", "Event": {}},
    ]))
    iocs = list(cti.misp_attributes())
    assert [(i["value"], i["type"], i["source"]) for i in iocs] == [
        ("1.2.3.4", "ip", "CERT-FR")]
    assert iocs[0]["confiance"] == cti.CONFIDENCE_CURATED


def _attribute(type_misp, value, event_date):
    return {"type": type_misp, "value": value, "category": "Network activity",
            "event_id": "7", "Event": {"info": "Rapport", "threat_level_id": "2",
                                       "date": event_date,
                                       "Orgc": {"name": "CIRCL"}}}


def test_ip_dun_vieux_rapport_ecartee_mais_pas_son_hash(monkeypatch):
    # `CTI_WINDOW` porte sur la date de MODIFICATION de l'attribut : tout ce
    # qu'un feed vient d'importer passe, y compris des IP de rapports de 2015.
    # Les garder, c'est alerter au niveau 12-14 sur l'hébergeur mutualisé qui a
    # récupéré l'adresse depuis. Un hash, lui, ne périme jamais.
    monkeypatch.setattr(cti, "_misp", _fake_response([
        _attribute("ip-dst", "107.6.172.54", "2015-09-01"),
        _attribute("md5", "d41d8cd98f00b204e9800998ecf8427e", "2015-09-01"),
        _attribute("domain", "evil.example.com", "2015-09-01"),
        _attribute("ip-dst", "23.45.67.89", "2026-08-01"),
    ]))
    values = {i["value"] for i in cti.misp_attributes()}
    assert values == {"d41d8cd98f00b204e9800998ecf8427e", "evil.example.com",
                       "23.45.67.89"}


def test_ip_sans_date_devenement_conservee(monkeypatch):
    # Sans date, on ne sait pas : jeter serait perdre du renseignement valide
    # sur une simple lacune de métadonnée.
    monkeypatch.setattr(cti, "_misp", _fake_response([
        _attribute("ip-dst", "23.45.67.89", "")]))
    assert [i["value"] for i in cti.misp_attributes()] == ["23.45.67.89"]


def test_peremption_ip_desactivable(monkeypatch):
    monkeypatch.setattr(cti.config, "CTI_IP_MAX_DAYS", 0)
    monkeypatch.setattr(cti, "_misp", _fake_response([
        _attribute("ip-dst", "107.6.172.54", "2015-09-01")]))
    assert [i["value"] for i in cti.misp_attributes()] == ["107.6.172.54"]


def test_extraction_misp_demande_bien_les_indicateurs_de_detection(monkeypatch):
    seen = {}

    def _misp(method, path, body=None):
        seen.update(body or {})
        return {"response": {"Attribute": []}}

    monkeypatch.setattr(cti, "_misp", _misp)
    list(cti.misp_attributes())
    # to_ids : MISP contient beaucoup d'attributs de CONTEXTE (sinkholes, IP
    # citées en exemple) que leurs auteurs marquent explicitement comme non
    # destinés à la détection. Les ingérer fabrique des faux positifs signés
    # « CERT-FR », les plus coûteux à réfuter.
    assert seen["to_ids"] == 1
    assert seen["published"] == 1
    assert seen["enforceWarninglist"] == 1


# --- Blocklists -------------------------------------------------------------

class _Response:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_blocklist_ignore_commentaires_et_lignes_vides(monkeypatch):
    monkeypatch.setattr(cti.requests, "get", lambda *a, **k: _Response(
        "# entête du fournisseur\n\n1.2.3.4\n5.6.7.8 # commentaire en fin\n"
        "; autre style\npas-une-ip\n"))
    catalogue = {"misp_feeds": [], "blocklists": [
        {"name": "test", "type": "ip", "urls": ["https://exemple/liste.txt"],
         "tags": ["cti:test"]}]}
    iocs = list(cti.blocklists(catalogue))
    assert [i["value"] for i in iocs] == ["1.2.3.4", "5.6.7.8"]
    # Une liste de masse ne qualifie rien : elle ne doit jamais faire d'incident.
    assert all(i["confiance"] == cti.CONFIDENCE_BULK for i in iocs)


def test_blocklist_injoignable_ne_fait_pas_echouer_les_autres(monkeypatch):
    def _get(url, **kwargs):
        if "morte" in url:
            raise cti.requests.ConnectionError("injoignable")
        return _Response("1.2.3.4\n")

    monkeypatch.setattr(cti.requests, "get", _get)
    catalogue = {"misp_feeds": [], "blocklists": [
        {"name": "morte", "type": "ip", "urls": ["https://morte/liste.txt"]},
        {"name": "vivante", "type": "ip", "urls": ["https://vivante/liste.txt"]}]}
    # Le cache est reconstruit en entier à chaque passe : laisser une source
    # morte tout interrompre reviendrait à perdre TOUTE la CTI pour un feed.
    assert [i["source"] for i in cti.blocklists(catalogue)] == ["vivante"]


def test_bootstrap_reconnait_un_feed_preinstalle_par_misp(monkeypatch):
    # MISP livre le feed CIRCL sous `.../feed-osint`, le catalogue l'écrit avec
    # un slash final. Sans normalisation, le bootstrap crée un DOUBLON : les
    # deux exemplaires activés, MISP tire le même feed deux fois et double les
    # événements. Constaté en prod le 2026-08-12.
    calls = []

    def _misp(method, path, body=None):
        calls.append((method, path))
        if path == "/feeds/index":
            return [{"Feed": {"id": "1", "url": "https://www.circl.lu/doc/misp/feed-osint",
                              "enabled": True, "caching_enabled": True}}]
        return {}

    monkeypatch.setattr(cti, "_misp", _misp)
    catalogue = {"misp_feeds": [{"name": "CIRCL OSINT Feed", "format": "misp",
                                 "url": "https://www.circl.lu/doc/misp/feed-osint/"}],
                 "blocklists": []}
    resume = cti.bootstrap_feeds(catalogue=catalogue)
    assert resume["crees"] == []
    assert not any(path == "/feeds/add" for _, path in calls)


def test_rafraichissement_utilise_le_bon_endpoint(monkeypatch):
    # /feeds/fetchFromFeed/{id} attend un identifiant numérique et répond 404
    # sur « all » — mesuré en prod. Seul cacheFeeds accepte une portée nommée.
    calls = []
    monkeypatch.setattr(cti, "_misp",
                        lambda m, c, body=None: calls.append(c))
    cti.refresh_feeds()
    assert calls == ["/feeds/fetchFromAllFeeds", "/feeds/cacheFeeds/all"]


def test_catalogue_livre_est_coherent():
    catalogue = cti.load_catalog()
    assert catalogue["misp_feeds"] and catalogue["blocklists"]
    for feed in catalogue["misp_feeds"]:
        assert feed["url"].startswith("https://")
    for bl in catalogue["blocklists"]:
        assert bl["urls"] and bl.get("type") in ("ip", "url", "domain")
    # Le feed demandé nommément, et celui qui justifie la moitié du dispositif.
    urls = [f["url"] for f in catalogue["misp_feeds"]]
    assert any("cert.ssi.gouv.fr" in u for u in urls)
    assert any("duggytuxy" in u
               for bl in catalogue["blocklists"] for u in bl["urls"])


# --- Intégration Wazuh ------------------------------------------------------

def _alert(**data):
    base = {"rule": {"id": "5710", "description": "sshd: failed login"},
            "agent": {"id": "003", "name": "web01"}, "data": {}}
    base["data"].update(data.pop("data", {}))
    base.update(data)
    return base


def test_extraction_des_candidats_par_direction():
    found = integration.candidates(_alert(data={
        "srcip": "185.220.101.1", "dstip": "23.45.67.89"}))
    by_value = {v: (t, field, direction) for t, v, field, direction in found}
    assert by_value["185.220.101.1"][2] == "inbound"
    assert by_value["23.45.67.89"][2] == "outbound"


def test_ip_privee_jamais_cherchee():
    # Une IP privée ne peut pas être un IOC public. La chercher, c'est risquer
    # de matcher une de nos machines parce qu'un feed a publié du 192.168.x —
    # ça arrive.
    found = integration.candidates(_alert(data={
        "srcip": "192.168.1.10", "dstip": "172.20.0.5"}))
    assert found == []


def test_url_recollee_depuis_hote_et_chemin():
    found = integration.candidates(_alert(data={
        "http": {"hostname": "evil.example.com", "url": "/payload.bin"}}))
    urls = {v for t, v, _, _ in found if t == "url"}
    assert "http://evil.example.com/payload.bin" in urls
    assert "https://evil.example.com/payload.bin" in urls


def test_empreintes_sysmon_extraites_du_champ_agrege():
    found = integration.candidates({"rule": {"id": "61603"}, "data": {"win": {
        "eventdata": {"hashes": "SHA1=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,"
                                "MD5=D41D8CD98F00B204E9800998ECF8427E"}}}})
    hashes = {v for t, v, _, _ in found if t == "hash"}
    assert hashes == {"da39a3ee5e6b4b0d3255bfef95601890afd80709",
                      "d41d8cd98f00b204e9800998ecf8427e"}


def test_hash_du_fim_extrait():
    found = integration.candidates({
        "rule": {"id": "550"},
        "syscheck": {"sha256_after": "a" * 64}})
    assert ("hash", "a" * 64, "syscheck.sha256_after", "artifact") in found


def _launch(monkeypatch, tmp_path, alert, iocs=(), age_hours=1.0):
    """Exécute l'intégration sur une alerte, rend les événements réinjectés."""
    path = str(tmp_path / "ioc.db")
    cti.write_cache(list(iocs), path)
    if age_hours != 1.0:
        conn = sqlite3.connect(path)
        conn.execute("UPDATE meta SET value = ? WHERE key = 'synchronise_a'",
                     ((datetime.now(timezone.utc)
                       - timedelta(hours=age_hours)).isoformat(),))
        conn.commit()
        conn.close()
    monkeypatch.setattr(integration, "CACHE", path)
    monkeypatch.setattr(integration, "EXPIRY_WITNESS",
                        str(tmp_path / "witness"))

    sent = []
    monkeypatch.setattr(integration, "send", sent.append)

    file = tmp_path / "alerte.json"
    file.write_text(json.dumps(alert))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(file)])
    integration.main()
    return sent


def test_pas_de_boucle_sur_nos_propres_alertes(monkeypatch, tmp_path):
    # Une alerte 100952 porte le même IOC que celle qui l'a produite : la
    # retraiter réinjecterait un événement, qui rematcherait, indéfiniment — et
    # la boucle serait alimentée par le trafic normal du parc.
    alert = _alert(rule={"id": "100952", "description": "CTI - outbound"},
                     data={"srcip": "185.220.101.1"})
    assert _launch(monkeypatch, tmp_path, alert,
                   [_ioc("185.220.101.1")]) == []


def test_pas_de_retraitement_dune_alerte_denrichissement(monkeypatch, tmp_path):
    alert = _alert(rule={"id": "100622", "description": "AbuseIPDB"},
                     data={"integration": "custom-abuseipdb",
                           "srcip": "185.220.101.1"})
    assert _launch(monkeypatch, tmp_path, alert,
                   [_ioc("185.220.101.1")]) == []


def test_evenement_enrichi_sur_correspondance(monkeypatch, tmp_path):
    alert = _alert(data={"srcip": "185.220.101.1"})
    sent = _launch(monkeypatch, tmp_path, alert, [_ioc("185.220.101.1")])
    assert len(sent) == 1
    misp = sent[0]["misp"]
    assert sent[0]["integration"] == "custom-misp"
    assert (misp["ioc"], misp["direction"], misp["confidence"]) == (
        "185.220.101.1", "inbound", "curated")
    assert misp["source_alert_rule_id"] == "5710"
    assert misp["agent"] == "web01"
    # srcip à la racine : c'est ce qui fait géolocaliser l'IOC par le pipeline
    # d'ingest de l'indexer, comme pour custom-abuseipdb.
    assert sent[0]["srcip"] == "185.220.101.1"


def test_liens_misp_poses_dans_levenement(monkeypatch, tmp_path):
    monkeypatch.setattr(cti.config, "MISP_BASE_URL", "https://misp.example.fr")
    sent = _launch(monkeypatch, tmp_path, _alert(data={"srcip": "185.220.101.1"}),
                      [_ioc("185.220.101.1")])
    misp = sent[0]["misp"]
    # Le lien vient de l'URL PUBLIQUE, pas de l'adresse d'appel du client : un
    # lien vers la loopback n'est cliquable que depuis le manager.
    assert misp["event_url"] == "https://misp.example.fr/events/view/42"
    assert misp["search_url"] == (
        "https://misp.example.fr/events/index/searchall:185.220.101.1")


def test_ioc_de_masse_na_pas_devenement_mais_garde_un_lien(monkeypatch, tmp_path):
    monkeypatch.setattr(cti.config, "MISP_BASE_URL", "https://misp.example.fr")
    ioc = _ioc("1.1.1.2", source="data-shield", confidence=cti.CONFIDENCE_BULK)
    ioc["event_id"] = ""     # les blocklists vivent en cache Redis, sans événement
    sent = _launch(monkeypatch, tmp_path,
                      _alert(data={"srcip": "1.1.1.2"}), [ioc])
    misp = sent[0]["misp"]
    assert misp["event_url"] == ""
    # Sans ce lien de recherche, l'analyste n'aurait aucun point d'entrée dans
    # MISP pour la moitié la plus volumineuse du renseignement.
    assert misp["search_url"].endswith("searchall:1.1.1.2")


def test_cache_sans_url_publique_ne_casse_pas_lenrichissement(monkeypatch, tmp_path):
    # Cache écrit par une version antérieure : pas de meta base_url. La
    # détection doit continuer, sans liens — pas planter.
    path = str(tmp_path / "ioc.db")
    cti.write_cache([_ioc("185.220.101.1")], path)
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM meta WHERE key = 'base_url'")
    conn.commit()
    conn.close()
    monkeypatch.setattr(integration, "CACHE", path)
    monkeypatch.setattr(integration, "EXPIRY_WITNESS", str(tmp_path / "witness"))
    sent = []
    monkeypatch.setattr(integration, "send", sent.append)
    file = tmp_path / "alerte.json"
    file.write_text(json.dumps(_alert(data={"srcip": "185.220.101.1"})))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(file)])
    integration.main()
    assert sent[0]["misp"]["ioc"] == "185.220.101.1"
    assert sent[0]["misp"]["event_url"] == ""


def test_tous_les_champs_enrichis_sont_en_anglais(monkeypatch, tmp_path):
    # Ces noms partent dans les alertes, les dashboards et les cases IRIS, à
    # côté des champs natifs de Wazuh. Ce test fige le contrat : les règles
    # 100951-100956 matchent dessus, les renommer sans les suivre rend les
    # règles muettes sans la moindre erreur.
    sent = _launch(monkeypatch, tmp_path, _alert(data={"srcip": "185.220.101.1"}),
                      [_ioc("185.220.101.1")])
    assert set(sent[0]["misp"]) == {
        "ioc", "ioc_type", "field", "direction", "source", "confidence",
        "category", "event_info", "event_id", "event_url", "search_url",
        "tags", "threat_level", "match_count", "source_alert_rule_id",
        "source_alert_description", "agent", "agent_id"}


def test_sans_correspondance_aucun_evenement(monkeypatch, tmp_path):
    alert = _alert(data={"srcip": "185.220.101.1"})
    assert _launch(monkeypatch, tmp_path, alert, [_ioc("9.9.9.9")]) == []


def test_le_sortant_cure_prime_sur_lentrant_de_masse(monkeypatch, tmp_path):
    # Une même alerte porte souvent les deux : une IP source de scanner (bruit)
    # et une IP destination de C2 (incident). Un seul événement est réinjecté,
    # il doit porter le second.
    alert = _alert(data={"srcip": "1.1.1.2", "dstip": "23.45.67.89"})
    sent = _launch(monkeypatch, tmp_path, alert, [
        _ioc("1.1.1.2", source="data-shield", confidence=cti.CONFIDENCE_BULK),
        _ioc("23.45.67.89", source="ThreatFox", confidence=cti.CONFIDENCE_CURATED),
    ])
    assert sent[0]["misp"]["ioc"] == "23.45.67.89"
    assert sent[0]["misp"]["direction"] == "outbound"
    assert sent[0]["misp"]["match_count"] == "2"


def test_cache_perime_signale_une_seule_fois(monkeypatch, tmp_path):
    alert = _alert(data={"srcip": "185.220.101.1"})
    sent = _launch(monkeypatch, tmp_path, alert, [_ioc("9.9.9.9")],
                      age_hours=72)
    assert len(sent) == 1 and "error" in sent[0]["misp"]

    # Second passage immédiat : le témoin doit museler le rappel, sinon le SOC
    # se noie sous son propre voyant de panne — une alerte par alerte traitée.
    sent = _launch(monkeypatch, tmp_path, alert, [_ioc("9.9.9.9")],
                      age_hours=72)
    assert sent == []


def test_cache_absent_signale_sans_planter(monkeypatch, tmp_path):
    monkeypatch.setattr(integration, "CACHE", str(tmp_path / "absent.db"))
    monkeypatch.setattr(integration, "EXPIRY_WITNESS", str(tmp_path / "witness"))
    sent = []
    monkeypatch.setattr(integration, "send", sent.append)
    file = tmp_path / "alerte.json"
    file.write_text(json.dumps(_alert(data={"srcip": "185.220.101.1"})))
    monkeypatch.setattr(integration.sys, "argv", ["custom-misp", str(file)])
    integration.main()
    assert len(sent) == 1 and "error" in sent[0]["misp"]


# --- Confiance d'après les tags ---------------------------------------------

def test_automate_non_supervise_traite_comme_de_la_masse():
    # Mesuré le 2026-08-12 : le feed OSINT du CIRCL relaie les publications
    # quotidiennes de Maltrail, soit 255 361 des 692 543 IOC « curés » du cache,
    # tous avec to_ids=1. En `curated`, ils matchaient aux niveaux 12 à 14 —
    # donc un incident et un triage LLM par match, sur ce qui est par
    # construction une blocklist. La taxonomie MISP l'annonce elle-même.
    assert cti._confidence([cti.TAG_NON_SUPERVISED, "tlp:clear"]) == cti.CONFIDENCE_BULK


def test_extraction_aura_reste_distincte_du_cure():
    assert cti._confidence([cti.TAG_EXTRACTION]) == cti.CONFIDENCE_EXTRACTED
    assert cti._confidence(["tlp:clear", "type:OSINT"]) == cti.CONFIDENCE_CURATED


def test_le_plus_prudent_gagne_si_les_deux_tags_sont_presents():
    assert cti._confidence([cti.TAG_EXTRACTION,
                           cti.TAG_NON_SUPERVISED]) == cti.CONFIDENCE_BULK
