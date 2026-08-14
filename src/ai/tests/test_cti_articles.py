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

@pytest.mark.parametrize("raw,expected", [
    ("hxxp://evil.example/payload", "http://evil.example/payload"),
    ("hxxps://evil.example", "https://evil.example"),
    ("evil[.]com", "evil.com"),
    ("evil(.)com", "evil.com"),
    ("evil[dot]com", "evil.com"),
    ("192.0.2.1[:]8080", "192.0.2.1:8080"),
    ("contact[at]evil.com", "contact@evil.com"),
])
def test_defanging(raw, expected):
    assert ca.defanger(raw) == expected


def test_candidats_trouve_les_ioc_defanges():
    text = ("The loader contacts hxxp://malicious-c2[.]top/gate.php and "
             "resolves second-stage[.]xyz from 203.0.113.9, dropping a file "
             "with SHA256 " + "ab" * 32 + ".")
    found = ca.candidates(text)
    assert "http://malicious-c2.top/gate.php" in found["url"]
    assert "second-stage.xyz" in found["domain"]
    assert "ab" * 32 in found["hash"]
    # 203.0.113.0/24 est le réseau de DOCUMENTATION (RFC 5737) : les rapports
    # s'en servent pour illustrer sans exposer une vraie cible.
    assert "203.0.113.9" not in found["ip"]


def test_domaine_du_media_jamais_retenu():
    text = ("As reported by bleepingcomputer.com and confirmed on github.com, "
             "the group used real-c2-server.top for command and control.")
    found = ca.candidates(text)
    assert "real-c2-server.top" in found["domain"]
    assert not {"bleepingcomputer.com", "github.com"} & set(found["domain"])


def test_sous_domaine_dun_media_exclu_aussi():
    # L'exclusion se fait par SUFFIXE : sans ça, elle ne tient que sur le
    # domaine nu et tout CDN de la source repasse.
    found = ca.candidates("see cdn.bleepingcomputer.com and unit42.paloaltonetworks.com")
    assert found["domain"] == []


def test_ip_privee_et_infra_soc_exclues(monkeypatch):
    monkeypatch.setattr(cti_config := ca.config, "SOC_INFRA_IPS", {"51.15.1.2"})
    assert cti_config.SOC_INFRA_IPS  # garde-fou du test lui-même
    found = ca.candidates("hosts 10.0.0.5, 127.0.0.1, 51.15.1.2 and 45.77.1.9")
    assert found["ip"] == ["45.77.1.9"]


def test_texte_brut_retire_scripts_et_balises():
    html_source = ("<html><head><script>var c2='fake-c2.top';</script></head>"
                   "<body><p>Real IOC: bad-domain.xyz</p>"
                   "<nav><a href='https://twitter.com/x'>x</a></nav></body></html>")
    text = ca.plain_text(html_source)
    # Le contenu des <script> est du code, pas du texte d'article : les
    # domaines qui y figurent sont des artefacts de la page.
    assert "fake-c2.top" not in text
    assert "bad-domain.xyz" in text


def test_tronquer_garde_le_debut_et_la_fin():
    # La section « Indicators of Compromise » est presque toujours en FIN de
    # corps : une troncature qui ne garderait que le début la perdrait
    # systématiquement.
    text = "DEBUT" + "x" * 50000 + "FIN"
    cut = ca.truncate(text, 1000)
    assert cut.startswith("DEBUT") and cut.endswith("FIN")
    assert len(cut) < 1200


# --- Validation de la sortie du modèle --------------------------------------

FOUND = {"ip": ["45.77.1.9"], "domain": ["bad-domain.xyz"], "url": [], "hash": []}


def test_ioc_invente_par_le_modele_est_rejete():
    response = {"iocs": [
        {"value": "bad-domain.xyz", "type": "domain", "role": "C2"},
        # Jamais vu dans le texte : le modèle l'a fabriqué.
        {"value": "invente-par-le-modele.com", "type": "domain", "role": "C2"},
    ]}
    kept = ca.validate(response, FOUND)
    assert [i["value"] for i in kept] == ["bad-domain.xyz"]


def test_type_annonce_faux_est_corrige_par_la_valeur():
    # On ne fait pas confiance au type annoncé : c'est la valeur qui décide.
    kept = ca.validate(
        {"iocs": [{"value": "45.77.1.9", "type": "domain", "role": "C2"}]}, FOUND)
    assert kept[0]["type"] == "ip"


def test_doublons_ecartes():
    response = {"iocs": [{"value": "45.77.1.9", "type": "ip", "role": "C2"},
                        {"value": "45.77.1.9", "type": "ip", "role": "C2 again"}]}
    assert len(ca.validate(response, FOUND)) == 1


def test_sortie_vide_ou_malformee_ne_casse_rien():
    assert ca.validate({}, FOUND) == []
    assert ca.validate({"iocs": None}, FOUND) == []
    assert ca.validate({"iocs": ["pas un objet"]}, FOUND) == []


# --- Découpage en lots ------------------------------------------------------

def test_lots_bornes_par_max_lots():
    found = {"ip": [f"45.77.1.{n}" for n in range(1, 255)],
               "domain": [], "url": [], "hash": []}
    batches = ca._batches(found)
    assert len(batches) <= ca.MAX_BATCHES
    assert all(len(batch) <= ca.BATCH_CANDIDATES for batch in batches)


def test_arbitrage_survit_a_un_lot_en_echec(monkeypatch, tmp_path):
    # Mesuré en vrai : sur un digest de 403 candidats, plusieurs lots ont
    # échoué (budget épuisé par le raisonnement, coupure réseau) et 148 IOC
    # valides ont quand même été récupérés. Sans cette tolérance : zéro.
    calls = {"n": 0}

    def _completion(system, user, usage, max_tokens=0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("timeout de l'API")
        return {"iocs": [{"value": "bad-domain.xyz", "type": "domain",
                          "role": "C2"}], "threat": "TestCampaign",
                "resume": "r", "confiance": "haute"}, {}

    monkeypatch.setattr(ca.llm, "completion", _completion)
    monkeypatch.setattr(ca, "BATCH_CANDIDATES", 1)
    article = {"url": "https://exemple/rapport", "titre": "T", "texte": "texte",
               "contexte": ""}
    merge = ca.arbitrate(article, {"ip": ["45.77.1.9"],
                                   "domain": ["bad-domain.xyz"],
                                   "url": [], "hash": []})
    assert [i["value"] for i in merge["iocs"]] == ["bad-domain.xyz"]
    assert merge["threat"] == "TestCampaign"


def test_lot_trop_lourd_est_redecoupe(monkeypatch):
    # Le budget épuisé n'est pas un échec définitif : le lot est rejoué en deux
    # moitiés. Surdimensionner le budget de TOUS les appels pour les rares qui
    # débordent coûterait beaucoup plus cher.
    seen = []

    def _completion(system, user, usage, max_tokens=0):
        batch_candidates = user.split("CANDIDATS")[1]
        n = batch_candidates.count(".")
        seen.append(n)
        if n > 3:
            raise RuntimeError("réponse sans content (finish_reason=length, ...)")
        return {"iocs": [], "threat": "", "resume": "", "confiance": ""}, {}

    monkeypatch.setattr(ca.llm, "completion", _completion)
    monkeypatch.setattr(ca, "BATCH_CANDIDATES", 8)
    ca.arbitrate({"url": "u", "titre": "t", "texte": "x", "contexte": ""},
                {"ip": [f"45.77.1.{n}" for n in range(1, 9)],
                 "domain": [], "url": [], "hash": []})
    # Le premier appel (lot entier) échoue, puis deux appels sur des moitiés.
    assert len(seen) >= 3


# --- Publication MISP -------------------------------------------------------

def test_evenement_porte_le_tag_qui_degrade_la_confiance(monkeypatch):
    sent = {}

    def _misp(method, path, body=None):
        sent.update({"methode": method, "chemin": path, "corps": body})
        return {"Event": {"id": "77"}}

    monkeypatch.setattr(cti, "_misp", _misp)
    article = {"url": "https://exemple/rapport", "titre": "Rapport",
               "publie": datetime(2026, 8, 12, tzinfo=timezone.utc), "contexte": ""}
    iocs = [{"value": "bad-domain.xyz", "type": "domain", "role": "C2 server"},
            {"value": "ab" * 32, "type": "hash", "role": "payload"}]
    event_id = ca.create_event(article, iocs, {"threat": "TestCampaign",
                                                  "resume": "r",
                                                  "confiance": "haute"},
                                  {"name": "thehackernews"})
    assert event_id == 77
    event = sent["corps"]["Event"]
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
    attributes = [{
        "type": "domain", "value": "bad-domain.xyz", "category": "Network activity",
        "event_id": "77", "to_ids": True,
        "Event": {"info": "[AURA/thehackernews] TestCampaign",
                  "threat_level_id": "2", "date": "2026-08-12",
                  "Orgc": {"name": "AURA"}},
        "Tag": [{"name": cti.TAG_EXTRACTION}, {"name": "tlp:clear"}],
    }]
    pages = [{"response": {"Attribute": attributes}}, {"response": {"Attribute": []}}]
    monkeypatch.setattr(cti, "_misp",
                        lambda m, c, body=None: pages.pop(0) if pages else
                        {"response": {"Attribute": []}})
    iocs = list(cti.misp_attributes())
    assert iocs[0]["confiance"] == cti.CONFIDENCE_EXTRACTED


def test_warninglists_injoignables_ne_jettent_rien(monkeypatch):
    def _misp(*a, **k):
        raise RuntimeError("MISP indisponible")
    monkeypatch.setattr(cti, "_misp", _misp)
    # Ne rien filtrer plutôt que tout jeter : la perte serait invisible.
    assert ca.filter_warninglists(["bad-domain.xyz"]) == set()


def test_warninglists_ecartent_ce_que_misp_connait(monkeypatch):
    monkeypatch.setattr(cti, "_misp", lambda m, c, body=None: {
        "1.1.1.1": ["List of known public DNS resolvers"], "bad-domain.xyz": []})
    assert ca.filter_warninglists(["1.1.1.1", "bad-domain.xyz"]) == {"1.1.1.1"}


# --- Sources ----------------------------------------------------------------

def test_catalogue_articles_declare_les_quatre_sources():
    names = {s["name"] for s in ca.sources()}
    assert names == {"thehackernews", "bleepingcomputer", "rst-cloud", "malpedia"}


def test_malpedia_ne_rend_que_les_urls_nouvelles(monkeypatch):
    response = {"references": {
        "https://rapport-connu/a.pdf": [{"type": "family", "common_name": "Emotet"}],
        "https://rapport-neuf/b.html": [{"type": "family", "common_name": "Qakbot"},
                                        {"type": "actor", "common_name": "TA577"}],
    }}

    class R:
        def json(self):
            return response

    monkeypatch.setattr(ca, "_http", lambda url: R())
    entries = ca.malpedia_entries({"name": "malpedia", "url": "u"},
                                  {"https://rapport-connu/a.pdf"})
    assert [e["url"] for e in entries] == ["https://rapport-neuf/b.html"]
    # L'attribution est la valeur propre de Malpedia : elle part au modèle
    # comme contexte, aucun article ne la donne de lui-même.
    assert entries[0]["contexte"] == "Qakbot, TA577"


def test_date_rss_formats_reels():
    assert ca._rss_date("Tue, 12 Aug 2026 10:30:00 +0000").year == 2026
    assert ca._rss_date("2026-08-12T10:30:00Z").month == 8
    assert ca._rss_date("n'importe quoi") is None


def test_amorcage_ne_grille_pas_les_flux_rss(monkeypatch):
    # L'amorçage n'existe que pour les sources SANS date (Malpedia). Marquer un
    # flux RSS au passage reviendrait à condamner ses articles récents — ceux
    # qu'on veut justement traiter à la première vraie passe. Constaté en prod
    # le 2026-08-12 : 40 articles perdus au premier amorçage.
    monkeypatch.setattr(ca, "rss_entries",
                        lambda source, since: [{"url": "https://neuf", "title": "t",
                                                 "published": None, "content": "",
                                                 "context": ""}])
    rss = ca.collect({"name": "thehackernews", "type": "rss"}, set(),
                       datetime.now(timezone.utc), 10, True, True)
    assert rss == []

    monkeypatch.setattr(ca, "malpedia_entries",
                        lambda source, already: [{"url": "https://rapport", "title": "",
                                               "published": None, "content": "",
                                               "context": "Emotet"}])
    malpedia = ca.collect({"name": "malpedia", "type": "malpedia_references"},
                            set(), datetime.now(timezone.utc), 10, True, True)
    assert [r["pattern"] for r in malpedia] == ["amorçage"]
