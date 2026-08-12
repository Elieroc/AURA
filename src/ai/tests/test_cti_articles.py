"""CTI : extraction d'IOC depuis des articles publics.

Le LLM n'est pas testé ici (il est appelé pour de vrai, ou pas du tout) : ce
qui est couvert est tout ce qui l'ENCADRE, et c'est là que se joue la qualité du
renseignement produit :

- `test_ioc_invente_par_le_modele_est_rejete` : le seul mode de défaillance qui
  fabriquerait des indicateurs de toutes pièces. Un IOC absent du texte source
  doit être jeté, pas discuté ;
- `test_defanging_*` : sans réécriture des IOC neutralisés (hxxp, [.]), la
  quasi-totalité de ce que publient ces sources reste invisible — l'extraction
  paraîtrait fonctionner en ne trouvant jamais rien ;
- `test_domaine_du_media_jamais_retenu` et les exclusions d'IP : un faux IOC à
  niveau 12 fait alerter sur du trafic normal, et l'IP du SOC en IOC ferait
  agir le SOC contre lui-même.
"""

import json
from datetime import datetime, timezone

import pytest

from soc_agent import cti, cti_articles as ca


# --- Défanging et candidats -------------------------------------------------

@pytest.mark.parametrize("brut,attendu", [
    ("hxxp://evil.example/payload", "http://evil.example/payload"),
    ("hxxps://evil.example", "https://evil.example"),
    ("evil[.]com", "evil.com"),
    ("evil(.)com", "evil.com"),
    ("evil[dot]com", "evil.com"),
    ("192.0.2.1[:]8080", "192.0.2.1:8080"),
    ("contact[at]evil.com", "contact@evil.com"),
])
def test_defanging(brut, attendu):
    assert ca.defanger(brut) == attendu


def test_candidats_trouve_les_ioc_defanges():
    texte = ("The loader contacts hxxp://malicious-c2[.]top/gate.php and "
             "resolves second-stage[.]xyz from 203.0.113.9, dropping a file "
             "with SHA256 " + "ab" * 32 + ".")
    trouves = ca.candidats(texte)
    assert "http://malicious-c2.top/gate.php" in trouves["url"]
    assert "second-stage.xyz" in trouves["domain"]
    assert "ab" * 32 in trouves["hash"]
    # 203.0.113.0/24 est le réseau de DOCUMENTATION (RFC 5737) : les rapports
    # s'en servent pour illustrer sans exposer une vraie cible.
    assert "203.0.113.9" not in trouves["ip"]


def test_domaine_du_media_jamais_retenu():
    texte = ("As reported by bleepingcomputer.com and confirmed on github.com, "
             "the group used real-c2-server.top for command and control.")
    trouves = ca.candidats(texte)
    assert "real-c2-server.top" in trouves["domain"]
    assert not {"bleepingcomputer.com", "github.com"} & set(trouves["domain"])


def test_sous_domaine_dun_media_exclu_aussi():
    # L'exclusion se fait par SUFFIXE : sans ça, elle ne tient que sur le
    # domaine nu et tout CDN de la source repasse.
    trouves = ca.candidats("see cdn.bleepingcomputer.com and unit42.paloaltonetworks.com")
    assert trouves["domain"] == []


def test_ip_privee_et_infra_soc_exclues(monkeypatch):
    monkeypatch.setattr(cti_config := ca.config, "SOC_INFRA_IPS", {"51.15.1.2"})
    assert cti_config.SOC_INFRA_IPS  # garde-fou du test lui-même
    trouves = ca.candidats("hosts 10.0.0.5, 127.0.0.1, 51.15.1.2 and 45.77.1.9")
    assert trouves["ip"] == ["45.77.1.9"]


def test_texte_brut_retire_scripts_et_balises():
    html_source = ("<html><head><script>var c2='fake-c2.top';</script></head>"
                   "<body><p>Real IOC: bad-domain.xyz</p>"
                   "<nav><a href='https://twitter.com/x'>x</a></nav></body></html>")
    texte = ca.texte_brut(html_source)
    # Le contenu des <script> est du code, pas du texte d'article : les
    # domaines qui y figurent sont des artefacts de la page.
    assert "fake-c2.top" not in texte
    assert "bad-domain.xyz" in texte


def test_tronquer_garde_le_debut_et_la_fin():
    # La section « Indicators of Compromise » est presque toujours en FIN de
    # corps : une troncature qui ne garderait que le début la perdrait
    # systématiquement.
    texte = "DEBUT" + "x" * 50000 + "FIN"
    coupe = ca.tronquer(texte, 1000)
    assert coupe.startswith("DEBUT") and coupe.endswith("FIN")
    assert len(coupe) < 1200


# --- Validation de la sortie du modèle --------------------------------------

TROUVES = {"ip": ["45.77.1.9"], "domain": ["bad-domain.xyz"], "url": [], "hash": []}


def test_ioc_invente_par_le_modele_est_rejete():
    reponse = {"iocs": [
        {"valeur": "bad-domain.xyz", "type": "domain", "role": "C2"},
        # Jamais vu dans le texte : le modèle l'a fabriqué.
        {"valeur": "invente-par-le-modele.com", "type": "domain", "role": "C2"},
    ]}
    retenus = ca.valider(reponse, TROUVES)
    assert [i["valeur"] for i in retenus] == ["bad-domain.xyz"]


def test_type_annonce_faux_est_corrige_par_la_valeur():
    # On ne fait pas confiance au type annoncé : c'est la valeur qui décide.
    retenus = ca.valider(
        {"iocs": [{"valeur": "45.77.1.9", "type": "domain", "role": "C2"}]}, TROUVES)
    assert retenus[0]["type"] == "ip"


def test_doublons_ecartes():
    reponse = {"iocs": [{"valeur": "45.77.1.9", "type": "ip", "role": "C2"},
                        {"valeur": "45.77.1.9", "type": "ip", "role": "C2 again"}]}
    assert len(ca.valider(reponse, TROUVES)) == 1


def test_sortie_vide_ou_malformee_ne_casse_rien():
    assert ca.valider({}, TROUVES) == []
    assert ca.valider({"iocs": None}, TROUVES) == []
    assert ca.valider({"iocs": ["pas un objet"]}, TROUVES) == []


# --- Découpage en lots ------------------------------------------------------

def test_lots_bornes_par_max_lots():
    trouves = {"ip": [f"45.77.1.{n}" for n in range(1, 255)],
               "domain": [], "url": [], "hash": []}
    lots = ca._lots(trouves)
    assert len(lots) <= ca.MAX_LOTS
    assert all(len(lot) <= ca.LOT_CANDIDATS for lot in lots)


def test_arbitrage_survit_a_un_lot_en_echec(monkeypatch, tmp_path):
    # Mesuré en vrai : sur un digest de 403 candidats, plusieurs lots ont
    # échoué (budget épuisé par le raisonnement, coupure réseau) et 148 IOC
    # valides ont quand même été récupérés. Sans cette tolérance : zéro.
    appels = {"n": 0}

    def _completion(systeme, utilisateur, usage, max_tokens=0):
        appels["n"] += 1
        if appels["n"] == 1:
            raise RuntimeError("timeout de l'API")
        return {"iocs": [{"valeur": "bad-domain.xyz", "type": "domain",
                          "role": "C2"}], "menace": "TestCampaign",
                "resume": "r", "confiance": "haute"}, {}

    monkeypatch.setattr(ca.llm, "completion", _completion)
    monkeypatch.setattr(ca, "LOT_CANDIDATS", 1)
    article = {"url": "https://exemple/rapport", "titre": "T", "texte": "texte",
               "contexte": ""}
    fusion = ca.arbitrer(article, {"ip": ["45.77.1.9"],
                                   "domain": ["bad-domain.xyz"],
                                   "url": [], "hash": []})
    assert [i["valeur"] for i in fusion["iocs"]] == ["bad-domain.xyz"]
    assert fusion["menace"] == "TestCampaign"


def test_lot_trop_lourd_est_redecoupe(monkeypatch):
    # Le budget épuisé n'est pas un échec définitif : le lot est rejoué en deux
    # moitiés. Surdimensionner le budget de TOUS les appels pour les rares qui
    # débordent coûterait beaucoup plus cher.
    vus = []

    def _completion(systeme, utilisateur, usage, max_tokens=0):
        candidats_du_lot = utilisateur.split("CANDIDATS")[1]
        n = candidats_du_lot.count(".")
        vus.append(n)
        if n > 3:
            raise RuntimeError("réponse sans content (finish_reason=length, ...)")
        return {"iocs": [], "menace": "", "resume": "", "confiance": ""}, {}

    monkeypatch.setattr(ca.llm, "completion", _completion)
    monkeypatch.setattr(ca, "LOT_CANDIDATS", 8)
    ca.arbitrer({"url": "u", "titre": "t", "texte": "x", "contexte": ""},
                {"ip": [f"45.77.1.{n}" for n in range(1, 9)],
                 "domain": [], "url": [], "hash": []})
    # Le premier appel (lot entier) échoue, puis deux appels sur des moitiés.
    assert len(vus) >= 3


# --- Publication MISP -------------------------------------------------------

def test_evenement_porte_le_tag_qui_degrade_la_confiance(monkeypatch):
    envoye = {}

    def _misp(methode, chemin, corps=None):
        envoye.update({"methode": methode, "chemin": chemin, "corps": corps})
        return {"Event": {"id": "77"}}

    monkeypatch.setattr(cti, "_misp", _misp)
    article = {"url": "https://exemple/rapport", "titre": "Rapport",
               "publie": datetime(2026, 8, 12, tzinfo=timezone.utc), "contexte": ""}
    iocs = [{"valeur": "bad-domain.xyz", "type": "domain", "role": "C2 server"},
            {"valeur": "ab" * 32, "type": "hash", "role": "payload"}]
    event_id = ca.creer_evenement(article, iocs, {"menace": "TestCampaign",
                                                  "resume": "r",
                                                  "confiance": "haute"},
                                  {"nom": "thehackernews"})
    assert event_id == 77
    event = envoye["corps"]["Event"]
    tags = {t["name"] for t in event["Tag"]}
    # SANS ce tag, cti.py classerait l'IOC en `curated` : une extraction
    # automatique d'article déclencherait au même niveau qu'un IOC du CERT-FR.
    assert cti.TAG_EXTRACTION in tags
    assert "aura:feed:thehackernews" in tags
    # Le lien vers l'article est le premier attribut : c'est ce qui permet de
    # juger si l'extraction était fondée.
    assert event["Attribute"][0]["type"] == "link"
    assert event["Attribute"][0]["value"] == "https://exemple/rapport"
    assert event["published"] is True
    types = {a["type"] for a in event["Attribute"][1:]}
    assert types == {"domain", "sha256"}
    assert all(a["to_ids"] for a in event["Attribute"][1:])


def test_tag_extraction_degrade_bien_la_confiance_au_relecture(monkeypatch):
    """Boucle complète : le tag posé ici doit être relu par cti.py."""
    attributs = [{
        "type": "domain", "value": "bad-domain.xyz", "category": "Network activity",
        "event_id": "77", "to_ids": True,
        "Event": {"info": "[AURA/thehackernews] TestCampaign",
                  "threat_level_id": "2", "date": "2026-08-12",
                  "Orgc": {"name": "AURA"}},
        "Tag": [{"name": cti.TAG_EXTRACTION}, {"name": "tlp:clear"}],
    }]
    pages = [{"response": {"Attribute": attributs}}, {"response": {"Attribute": []}}]
    monkeypatch.setattr(cti, "_misp",
                        lambda m, c, corps=None: pages.pop(0) if pages else
                        {"response": {"Attribute": []}})
    iocs = list(cti.attributs_misp())
    assert iocs[0]["confiance"] == cti.CONFIANCE_EXTRAITE


def test_warninglists_injoignables_ne_jettent_rien(monkeypatch):
    def _misp(*a, **k):
        raise RuntimeError("MISP indisponible")
    monkeypatch.setattr(cti, "_misp", _misp)
    # Ne rien filtrer plutôt que tout jeter : la perte serait invisible.
    assert ca.filtrer_warninglists(["bad-domain.xyz"]) == set()


def test_warninglists_ecartent_ce_que_misp_connait(monkeypatch):
    monkeypatch.setattr(cti, "_misp", lambda m, c, corps=None: {
        "1.1.1.1": ["List of known public DNS resolvers"], "bad-domain.xyz": []})
    assert ca.filtrer_warninglists(["1.1.1.1", "bad-domain.xyz"]) == {"1.1.1.1"}


# --- Sources ----------------------------------------------------------------

def test_catalogue_articles_declare_les_quatre_sources():
    noms = {s["nom"] for s in ca.sources()}
    assert noms == {"thehackernews", "bleepingcomputer", "rst-cloud", "malpedia"}


def test_malpedia_ne_rend_que_les_urls_nouvelles(monkeypatch):
    reponse = {"references": {
        "https://rapport-connu/a.pdf": [{"type": "family", "common_name": "Emotet"}],
        "https://rapport-neuf/b.html": [{"type": "family", "common_name": "Qakbot"},
                                        {"type": "actor", "common_name": "TA577"}],
    }}

    class R:
        def json(self):
            return reponse

    monkeypatch.setattr(ca, "_http", lambda url: R())
    entrees = ca.entrees_malpedia({"nom": "malpedia", "url": "u"},
                                  {"https://rapport-connu/a.pdf"})
    assert [e["url"] for e in entrees] == ["https://rapport-neuf/b.html"]
    # L'attribution est la valeur propre de Malpedia : elle part au modèle
    # comme contexte, aucun article ne la donne de lui-même.
    assert entrees[0]["contexte"] == "Qakbot, TA577"


def test_date_rss_formats_reels():
    assert ca._date_rss("Tue, 12 Aug 2026 10:30:00 +0000").year == 2026
    assert ca._date_rss("2026-08-12T10:30:00Z").month == 8
    assert ca._date_rss("n'importe quoi") is None
