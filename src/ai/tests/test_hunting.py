"""Garde-fous de l'espace de threat hunting (soc_agent.hunting).

Deux familles de tests, et la première compte plus que la seconde :

1. **Le cloisonnement.** `wazuh-hunting-*` ne doit JAMAIS être lu par
   l'ingestion ni observé par le routage. Si cette exclusion casse, restaurer un
   vieux mois fait rejouer à AURA une attaque passée — corrélation, triage, puis
   remédiation autonome sur des faits vieux d'un an. C'est le seul test de ce
   fichier dont l'échec est un incident de production.
2. **Les plafonds.** Cet espace est accessible par un agent IA via MCP :
   « restaure-moi tout » doit être refusé par le code.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("ARCHIVAGE_ENABLED", "false")

from soc_agent import config, hunting  # noqa: E402


# --------------------------------------------------------------------------
# Cloisonnement — le test qui compte
# --------------------------------------------------------------------------

def test_hunting_exclu_de_ce_que_lit_l_ingestion(monkeypatch):
    """La négation `-wazuh-hunting-*` doit être présente dans les indices lus.

    Sans elle, `ingest.py` ramasse les alertes restaurées, `correlate` en fait
    des incidents, `triage` les juge et `mitigate` agit — sur des faits vieux de
    dix mois, avec l'isolation d'hôte au bout.
    """
    from soc_agent import routage
    monkeypatch.setattr(routage, "_INDICES_CACHE",
                        {"valeur": "", "expire": None})
    monkeypatch.setattr(routage, "patterns_appliques", lambda conn: [])
    monkeypatch.setattr("psycopg.connect",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("pas de base")))
    lus = routage.indices_lus()
    assert f"-{config.HUNTING_INDEX_BASE}-*" in lus.split(",")
    # Et la négation doit être en DERNIER : la syntaxe multi-index d'OpenSearch
    # applique les exclusions dans l'ordre, une négation suivie d'un `wazuh-*`
    # serait annulée.
    assert lus.split(",")[-1] == f"-{config.HUNTING_INDEX_BASE}-*"


def test_negation_tient_meme_avec_wazuh_etoile(monkeypatch):
    """Le pire cas de configuration : quelqu'un met `wazuh-*` dans la liste.

    La protection ne doit pas dépendre de la discipline de configuration.
    """
    from soc_agent import routage
    monkeypatch.setattr(config, "INDEXER_ALERT_INDICES", "wazuh-*")
    monkeypatch.setattr(routage, "_INDICES_CACHE",
                        {"valeur": "", "expire": None})
    monkeypatch.setattr(routage, "patterns_appliques", lambda conn: [])
    monkeypatch.setattr("psycopg.connect",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("pas de base")))
    lus = routage.indices_lus().split(",")
    assert "wazuh-*" in lus
    assert lus[-1] == f"-{config.HUNTING_INDEX_BASE}-*"


def test_hunting_exclu_de_l_archivage():
    """Réarchiver une archive restaurée reviendrait à payer deux fois la même
    donnée pendant douze mois, sous Object Lock qui interdit d'annuler."""
    from soc_agent import archive
    assert f"{config.HUNTING_INDEX_BASE}-*" in config.ARCHIVE_INDEX_EXCLUS
    assert archive._exclu("wazuh-hunting-firewall-2026-03")
    # Deuxième barrière : le nom n'est pas daté au jour, donc la forme l'exclut
    # déjà, indépendamment de la liste.
    assert archive._DATE_INDEX.match("wazuh-hunting-firewall-2026-03") is None


def test_politiques_ism_ne_se_recoupent_pas():
    """Un index ne porte qu'UNE politique ISM. Deux `ism_template` qui matchent
    le même index à la même priorité donneraient un rattachement arbitraire."""
    from soc_agent import retention
    motifs_alertes = retention.ism_patterns()
    hunting_motif = f"{config.HUNTING_INDEX_BASE}-*"
    assert hunting_motif not in motifs_alertes
    import fnmatch
    exemple = "wazuh-hunting-firewall-2026-03"
    assert not any(fnmatch.fnmatch(exemple, m) for m in motifs_alertes)
    assert fnmatch.fnmatch(exemple, hunting_motif)
    assert retention.ISM_HUNTING_ID != retention.ISM_POLICY_ID


def test_retention_hunting_plus_courte_que_les_alertes():
    """C'est une copie : la garder aussi longtemps que l'original doublerait
    l'occupation disque sans rien apporter."""
    from soc_agent import retention
    p = retention.politique_ism_hunting()["policy"]
    assert p["states"][0]["transitions"][0]["conditions"]["min_index_age"] == \
        f"{config.HUNTING_RETENTION_JOURS}d"
    assert config.HUNTING_RETENTION_JOURS < config.RETENTION_INDEX_JOURS


# --------------------------------------------------------------------------
# Nommage
# --------------------------------------------------------------------------

@pytest.mark.parametrize("base, periode, attendu", [
    ("wazuh-firewall", "2026-03", "wazuh-hunting-firewall-2026-03"),
    ("wazuh-alerts-4.x", "2026-01", "wazuh-hunting-alerts-4.x-2026-01"),
    ("wazuh-web", "2027-12", "wazuh-hunting-web-2027-12"),
])
def test_nom_index(base, periode, attendu):
    assert hunting.nom_index(base, periode) == attendu


# --------------------------------------------------------------------------
# Plafonds
# --------------------------------------------------------------------------

def _etat(indices=0, octets=0, disque=40):
    return {"total_indices": indices, "total_documents": 0,
            "total_octets": octets, "disque_pct": disque,
            "plafonds": {}}


def test_disque_sature_refuse_avant_tout(monkeypatch):
    """Le premier garde-fou, et le plus important : le hunting est du confort,
    un disque plein bascule l'indexer en lecture seule et arrête l'ingestion de
    tout le parc."""
    monkeypatch.setattr(config, "DISQUE_SEUIL_ALERTE", 80)
    with pytest.raises(RuntimeError, match="disque à 85 %"):
        hunting.verifier_place({"documents": 1, "octets_clair": 1},
                               _etat(disque=85))


def test_archive_trop_grosse_refusee(monkeypatch):
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 1000)
    with pytest.raises(RuntimeError, match="HUNTING_MAX_DOCS"):
        hunting.verifier_place({"documents": 5000, "octets_clair": 1}, _etat())


def test_plafond_d_index_refuse(monkeypatch):
    monkeypatch.setattr(config, "HUNTING_MAX_INDICES", 3)
    with pytest.raises(RuntimeError, match="HUNTING_MAX_INDICES"):
        hunting.verifier_place({"documents": 1, "octets_clair": 1},
                               _etat(indices=3))


def test_plafond_d_octets_refuse_sur_le_PROJETE(monkeypatch):
    """Le plafond porte sur l'occupation APRÈS restauration, pas avant : refuser
    seulement quand c'est déjà plein laisserait toujours passer un dépassement."""
    monkeypatch.setattr(config, "HUNTING_MAX_OCTETS", 1000)
    monkeypatch.setattr(config, "HUNTING_MAX_INDICES", 10)
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 10**9)
    hunting.verifier_place({"documents": 1, "octets_clair": 400}, _etat(octets=500))
    with pytest.raises(RuntimeError, match="HUNTING_MAX_GO"):
        hunting.verifier_place({"documents": 1, "octets_clair": 600},
                               _etat(octets=500))


# --------------------------------------------------------------------------
# Purge : bornée au préfixe de hunting
# --------------------------------------------------------------------------

@pytest.mark.parametrize("index", [
    "wazuh-firewall-2026.08.14",   # de la PRODUCTION
    "wazuh-alerts-4.x-2026.08.14",
    "wazuh-voc-vulns",
    ".opendistro-ism-config",
    "wazuh-huntingXfirewall",      # préfixe approchant, pas le bon
])
def test_purge_refuse_hors_hunting(index):
    """Cet outil est exposé par MCP, donc appelable par un agent IA. Il ne doit
    pas pouvoir supprimer un index d'alertes de production."""
    with pytest.raises(RuntimeError, match="n'est pas un index de hunting"):
        hunting.purger(index, confirmer=True)


@pytest.mark.parametrize("index", [
    "wazuh-hunting-*",
    "wazuh-hunting-a,wazuh-hunting-b",
])
def test_purge_refuse_les_jokers(index):
    """Une suppression par motif est exactement le geste dont on ne mesure pas
    la portée."""
    with pytest.raises(RuntimeError, match="un index à la fois"):
        hunting.purger(index, confirmer=True)


def test_purge_sans_confirmation_ne_supprime_rien():
    r = hunting.purger("wazuh-hunting-firewall-2026-03")
    assert r["supprime"] is False and "confirmer=true" in r["note"]


# --------------------------------------------------------------------------
# Le MCP expose bien ces outils, avec leurs scopes
# --------------------------------------------------------------------------

def test_outils_mcp_declares_avec_leur_scope():
    """Un outil sans `@auth.exige` est accessible à tout jeton valide, y compris
    en lecture seule. Le serveur refuse de l'enregistrer, mais autant vérifier
    ici que les scopes sont ceux qu'on croit."""
    import importlib.util
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("SDK mcp absent de cet environnement")
    from aura_mcp.outils import hunting as outils
    attendus = {
        "aura_archives_list": "aura:read",
        "aura_hunting_state": "aura:read",
        "aura_hunting_restore": "aura:write",
        "aura_hunting_purge": "aura:write",
    }
    for nom, scope in attendus.items():
        fn = getattr(outils, nom)
        assert getattr(fn, "scope_requis", None) == scope, nom


# --------------------------------------------------------------------------
# Réinjection _bulk
# --------------------------------------------------------------------------

class _IndexerBouchon:
    """Capture les appels à l'indexer, sans en avoir un."""

    def __init__(self, echecs: int = 0):
        self.appels: list[tuple] = []
        self.corps: list[bytes] = []
        self.echecs = echecs

    def __call__(self, methode, chemin, corps=None, timeout=120, brut=None,
                 content_type=None):
        self.appels.append((methode, chemin, content_type))
        if brut:
            self.corps.append(brut)

        class R:
            ok = True
            status_code = 200

            @staticmethod
            def json():
                lignes = (brut or b"").count(b"\n") // 2
                items = []
                for i in range(lignes):
                    if i < self.echecs:
                        items.append({"index": {"error": {"type": "mapper_parsing"}}})
                    else:
                        items.append({"index": {"result": "created"}})
                return {"items": items}
        return R()


def test_injection_conserve_les_id_et_le_content_type(tmp_path, monkeypatch):
    """Deux exigences dans le même test parce qu'elles échouent ensemble :

    - `_id` conservé => rejouer une restauration ÉCRASE les mêmes documents au
      lieu d'en créer des doublons. C'est ce qui rend l'opération idempotente
      sans repère à tenir ;
    - `application/x-ndjson` => sans lui l'indexer refuse le `_bulk`, et le
      diagnostic (« Content-Type header … is not supported ») n'a rien à voir
      avec la cause apparente.
    """
    import json as js
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_text("".join(
        js.dumps({"_index": "wazuh-web-2026.03.01", "_id": f"id{n}",
                  "_source": {"rule": {"level": 7}}}) + "\n" for n in range(5)))
    bouchon = _IndexerBouchon()
    monkeypatch.setattr(hunting, "_indexer", bouchon)
    monkeypatch.setattr(config, "HUNTING_BULK_TAILLE", 1000)

    r = hunting._injecter("wazuh-hunting-web-2026-03", ndjson)
    assert r == {"injectes": 5, "erreurs": 0, "exemples_erreurs": []}
    assert bouchon.appels[0] == ("POST", "/_bulk", "application/x-ndjson")

    lignes = bouchon.corps[0].decode().strip().split("\n")
    entetes = [js.loads(l) for l in lignes[0::2]]
    assert all(e["index"]["_index"] == "wazuh-hunting-web-2026-03" for e in entetes)
    assert [e["index"]["_id"] for e in entetes] == [f"id{n}" for n in range(5)]
    # `_source` réinjecté SEUL : ni `_index` ni `_id` ne doivent polluer le
    # document, sinon on altère la pièce à conviction.
    docs = [js.loads(l) for l in lignes[1::2]]
    assert docs[0] == {"rule": {"level": 7}}


def test_injection_par_lots(tmp_path, monkeypatch):
    """Un `_bulk` unique sur 200 000 documents ferait une requête de plusieurs
    centaines de Mo, refusée par l'indexer."""
    import json as js
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_text("".join(
        js.dumps({"_id": f"id{n}", "_source": {"n": n}}) + "\n"
        for n in range(10)))
    bouchon = _IndexerBouchon()
    monkeypatch.setattr(hunting, "_indexer", bouchon)
    monkeypatch.setattr(config, "HUNTING_BULK_TAILLE", 3)
    r = hunting._injecter("wazuh-hunting-x-2026-03", ndjson)
    assert r["injectes"] == 10
    # 10 documents par lots de 3 -> 4 requêtes.
    assert len([c for c in bouchon.corps]) == 4


def test_injection_compte_les_erreurs_sans_les_taire(tmp_path, monkeypatch):
    """Un `_bulk` répond 200 même quand des documents sont rejetés. Compter les
    succès sans lire `items[].error` ferait conclure à une restauration complète
    sur une copie partielle."""
    import json as js
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_text("".join(
        js.dumps({"_id": f"id{n}", "_source": {"n": n}}) + "\n"
        for n in range(4)))
    monkeypatch.setattr(hunting, "_indexer", _IndexerBouchon(echecs=2))
    monkeypatch.setattr(config, "HUNTING_BULK_TAILLE", 1000)
    r = hunting._injecter("wazuh-hunting-x-2026-03", ndjson)
    assert r["injectes"] == 2 and r["erreurs"] == 2
    assert r["exemples_erreurs"] and "mapper_parsing" in r["exemples_erreurs"][0]


def test_injection_ignore_les_lignes_illisibles(tmp_path, monkeypatch):
    """Une archive tronquée ne doit pas faire échouer toute la restauration :
    ce qui est lisible est remis en ligne, et le reste est compté."""
    ndjson = tmp_path / "a.ndjson"
    ndjson.write_bytes(b'{"_id":"a","_source":{}}\n\n{tronque\n')
    monkeypatch.setattr(hunting, "_indexer", _IndexerBouchon())
    monkeypatch.setattr(config, "HUNTING_BULK_TAILLE", 1000)
    r = hunting._injecter("wazuh-hunting-x-2026-03", ndjson)
    assert r["injectes"] == 1 and r["erreurs"] == 1


# --------------------------------------------------------------------------
# Dry-run
# --------------------------------------------------------------------------

def test_dry_run_ne_telecharge_rien_et_rend_le_verdict(monkeypatch):
    """Le dry-run doit répondre « ça passerait » ou « ça serait refusé, et
    pourquoi » sans télécharger 40 Mo pour l'apprendre."""
    ligne = {"cle": "v1/wazuh-web/2026/x.age", "documents": 10,
             "octets_clair": 1000, "indices": ["wazuh-web-2026.03.01"],
             "verif_etat": None, "index_base": "wazuh-web", "periode": "2026-03",
             "sha256_clair": "a" * 64}
    monkeypatch.setattr(hunting, "archive_disponible", lambda c, b, p: ligne)
    monkeypatch.setattr(hunting, "etat", lambda: _etat() | {"plafonds": {}})
    monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Ctx())
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 10**9)
    monkeypatch.setattr(config, "HUNTING_MAX_INDICES", 10)
    monkeypatch.setattr(config, "HUNTING_MAX_OCTETS", 10**12)
    monkeypatch.setattr(config, "DISQUE_SEUIL_ALERTE", 80)

    def _interdit(*a, **k):
        raise AssertionError("le dry-run a touché l'indexer ou S3")
    monkeypatch.setattr(hunting, "_indexer", _interdit)
    monkeypatch.setattr(hunting, "preparer", _interdit)

    r = hunting.restaurer("wazuh-web", "2026-03")
    assert r["applique"] is False
    assert r["garde_fous"] == "ok"
    assert r["index_cible"] == "wazuh-hunting-web-2026-03"
    # Le rappel du cloisonnement doit être dans la réponse : c'est un client IA
    # qui la lit, et c'est l'information qui l'empêche de croire qu'il vient de
    # réinjecter des alertes dans le pipeline.
    assert "corrélées" in r["note"] or "corrél" in r["note"]


def test_dry_run_annonce_le_refus_sans_lever(monkeypatch):
    """En dry-run, un garde-fou qui refuserait doit être RENDU, pas levé : le
    client demande un plan, on lui donne le plan et le verdict."""
    ligne = {"cle": "k", "documents": 10**9, "octets_clair": 1,
             "indices": [], "verif_etat": None, "index_base": "wazuh-web",
             "periode": "2026-03", "sha256_clair": "a" * 64}
    monkeypatch.setattr(hunting, "archive_disponible", lambda c, b, p: ligne)
    monkeypatch.setattr(hunting, "etat", lambda: _etat() | {"plafonds": {}})
    monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Ctx())
    monkeypatch.setattr(config, "HUNTING_MAX_DOCS", 1000)
    r = hunting.restaurer("wazuh-web", "2026-03")
    assert r["applique"] is False
    assert r["garde_fous"].startswith("REFUS")
    assert "HUNTING_MAX_DOCS" in r["garde_fous"]


class _Ctx:
    """Contexte de connexion Postgres bouchonné."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
