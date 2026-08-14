"""Tests du contrôle de routage (sans indexer, sans base, sans LLM).

Ce qui est testé ici est ce qui DÉCIDE : la validation d'un nom d'index, le
rendu du script painless (dont la stabilité octet pour octet, sans laquelle le
pipeline serait réécrit toutes les deux minutes), le point d'insertion dans le
pipeline et la lecture d'une simulation. Les appels réseau, eux, n'ont pas de
branche à couvrir.
"""

import json

import pytest

from soc_agent import config, routing


# --------------------------------------------------------------------------
# Nommage
# --------------------------------------------------------------------------

def test_generique_hors_vocabulaire_est_refuse():
    """Le cœur de la convention : un pare-feu ne s'appelle pas « pfsense ».

    Sans vocabulaire fermé, chaque produit ouvre son index et la même question
    (« qu'a bloqué le pare-feu ? ») demande d'interroger autant d'index que de
    marques présentes dans le SI.
    """
    assert routing._validate("generique", "pfsense", {"pfsense"}) is not None
    assert routing._validate("generique", "fortinet", {"fortinet"}) is not None
    assert routing._validate("generique", "firewall", set()) is None


def test_application_doit_etre_attestee_par_les_donnees():
    """Un nom d'application que rien n'atteste est une hallucination coûteuse :
    l'index créé ne se renomme pas, il se double."""
    assert routing._validate("applicative", "jellyfin", {"jellyfin", "media"}) is None
    assert routing._validate("applicative", "grafana", {"jellyfin"}) is not None


def test_nom_de_metier_refuse_comme_application():
    """« web » est une famille, pas un produit : l'accepter comme applicative
    contournerait le vocabulaire fermé par la porte de service."""
    assert routing._validate("applicative", "web", {"web"}) is not None


def test_formes_invalides():
    for suffix in ("", "a", "Web", "web-proxy", "proxy2", "x" * 21):
        assert routing._validate("generique", suffix, set()) is not None


def test_suffixes_reserves_par_la_stack():
    """`wazuh-alerts-*` ou `wazuh-monitoring-*` existent déjà : un index set
    homonyme en avalerait le contenu."""
    for suffix in ("alerts", "monitoring", "statistics", "ai", "voc"):
        assert routing._validate("generique", suffix, set()) is not None


def test_inconnu_nest_pas_un_nom():
    assert routing._validate("inconnu", "", set()) is not None


def test_repli_reste_deterministe_et_conforme():
    r = routing._fallback({"criterion_value": "npm-access"}, "pattern")
    assert r["index_base"] == "wazuh-npmaccess"
    assert r["named_by"] == "fallback"      # -> jamais auto-appliqué


# --------------------------------------------------------------------------
# Rendu du pipeline
# --------------------------------------------------------------------------

ROUTES = [
    {"criterion_type": "decoder", "criterion_value": "npm-access",
     "index_base": "wazuh-proxy"},
    {"criterion_type": "groups", "criterion_value": "adguard",
     "index_base": "wazuh-dns"},
]


def test_script_appris_teste_le_decodeur_avant_les_groupes():
    """Le décodeur identifie la source, le groupe ne fait que la caractériser.
    Une alerte Suricata portant le groupe `dns` doit partir chez le pare-feu —
    c'est le piège que documente déjà le routage statique."""
    src = routing._learned_script(ROUTES)["script"]["source"]
    assert src.index("dn == 'npm-access'") < src.index("g.contains('adguard')")


def test_rendu_stable_octet_pour_octet():
    """Deux rendus identiques ne doivent produire AUCUNE différence : la
    réconciliation compare le pipeline attendu à celui qui tourne, et la
    moindre instabilité (ordre, espace) déclencherait un PUT toutes les deux
    minutes, sur le pipeline qui porte toutes les alertes du SOC."""
    a = json.dumps(routing._learned_script(ROUTES), sort_keys=True)
    b = json.dumps(routing._learned_script(list(ROUTES)), sort_keys=True)
    assert a == b


def test_valeurs_non_conformes_refusees_avant_de_generer_du_painless():
    """Ces valeurs viennent des données indexées et finissent dans une chaîne
    entre quotes au milieu d'un script exécuté par l'indexer."""
    for bad in ("npm'access", "a b", "x" * 65, "év", ""):
        with pytest.raises(ValueError):
            routing._learned_script([{"criterion_type": "decoder",
                                     "criterion_value": bad,
                                     "index_base": "wazuh-proxy"}])


def test_index_base_non_conforme_refuse():
    with pytest.raises(ValueError):
        routing._learned_script([{"criterion_type": "decoder",
                                 "criterion_value": "npm-access",
                                 "index_base": "autre-chose"}])


PIPELINE = {
    "description": "Wazuh alerts pipeline",
    "processors": [
        {"json": {"field": "message", "add_to_root": True}},
        {"script": {"tag": "routage-statique", "source": "..."}},
        {"script": {"description": "YARITRUST", "source": "..."}},
    ],
    "on_failure": [{"drop": {}}],
}


def test_insertion_apres_le_routage_statique():
    """Contre-intuitif, et vérifié sur le pipeline de prod : le `return` du
    painless ne sort que du script courant, pas du pipeline. Une branche
    apprise placée AVANT le routage statique écrit bien `ctx._index`, puis le
    script statique le réécrit derrière elle — sans la moindre erreur. Mesuré
    le 2026-08-14 : `pam -> wazuh-endpoint` repartait dans wazuh-linux."""
    rendered = routing.render(PIPELINE, ROUTES)
    tags = [next(iter(p.values())).get("tag") for p in rendered["processors"]]
    assert tags.index(routing.TAG_LEARNED) > tags.index(routing.TAG_STATIC)
    assert len(rendered["processors"]) == len(PIPELINE["processors"]) + 1


def test_le_script_yara_garde_le_dernier_mot():
    """Il est volontairement le dernier processor du pipeline : les matches YARA
    sortent dans wazuh-yara-* quelle que soit la source qui les a produits."""
    rendered = routing.render(PIPELINE, ROUTES)
    last = next(iter(rendered["processors"][-1].values()))
    assert "YARITRUST" in last["description"]


def test_insertion_par_defaut_sur_la_description():
    """La prod tourne peut-être encore avec un pipeline antérieur au tag."""
    sans_tag = {**PIPELINE, "processors": [
        {"json": {}},
        {"script": {"description": "Aura-SOC: route les alertes des agents ..."}},
    ]}
    assert routing._insert_position(sans_tag["processors"]) == 2


def test_refus_d_inserer_a_l_aveugle():
    """Aucun repère trouvé = aucune écriture. Insérer au hasard dans le
    pipeline qui porte toutes les alertes du SOC n'est pas rattrapable."""
    with pytest.raises(RuntimeError):
        routing.render({"processors": [{"json": {}}]}, ROUTES)


def test_le_processor_appris_est_retirable():
    """La base, c'est le pipeline vivant MOINS notre processor : c'est ce qui
    permet de repartir de ce que filebeat a réellement poussé, sans jamais lire
    le fichier sur disque."""
    rendered = routing.render(PIPELINE, ROUTES)
    assert routing._without_learned(rendered)["processors"] == PIPELINE["processors"]
    assert routing._without_learned(PIPELINE)["processors"] == PIPELINE["processors"]


# --------------------------------------------------------------------------
# Simulation
# --------------------------------------------------------------------------

def test_message_repose_le_prefixe_efface_a_l_indexation():
    """`date_index_name` lit `fields.index_prefix` et c'est le SEUL processor du
    pipeline en `ignore_failure: false` : sans ce champ, tout document simulé
    part dans le `drop` du `on_failure` et chaque témoin ressort « perdu ». Le
    champ est effacé par un `remove` avant l'écriture, donc il n'est dans aucun
    document indexé et ne peut pas venir du témoin."""
    m = routing._message({"timestamp": "2026-08-14T10:00:00.000+0000"})
    assert m["fields"]["index_prefix"] == routing.DEFAULT_PREFIX
    already = {"fields": {"index_prefix": "autre-"}}
    assert routing._message(already)["fields"]["index_prefix"] == "autre-"


def test_simulation_sans_temoin_ne_bloque_rien():
    assert routing.simulate({}, []) == []


def test_lecture_d_une_simulation(monkeypatch):
    """Trois verdicts à distinguer : routé comme attendu, routé ailleurs (la
    régression qu'on cherche), et document perdu (painless invalide)."""
    response = {
        "docs": [
            {"doc": {"_index": "wazuh-proxy-2026.08.14"}},
            {"doc": {"_index": "wazuh-alerts-4.x-2026.08.14"}},
            {"error": {"reason": "compile error"}},
        ]
    }

    class Fake:
        ok = True

        @staticmethod
        def json():
            return response

    monkeypatch.setattr(routing, "_indexer", lambda *a, **k: Fake())
    cases = [{"source_key": "decoder:npm-access", "index_base": "wazuh-proxy",
            "example": {}},
           {"source_key": "decoder:jellyfin", "index_base": "wazuh-jellyfin",
            "example": {}},
           {"source_key": "groups:adguard", "index_base": "wazuh-dns",
            "example": {}}]
    failures = routing.simulate({}, cases)
    assert len(failures) == 2
    assert "attendu wazuh-jellyfin, obtenu wazuh-alerts-4.x" in failures[0]
    assert "PERDU" in failures[1]


def test_base_index_retire_la_date():
    assert routing._base_index("wazuh-linux-2026.08.14") == "wazuh-linux"
    assert routing._base_index("wazuh-voc-vulns") == "wazuh-voc-vulns"


# --------------------------------------------------------------------------
# Ce qui n'est pas une source de log
# --------------------------------------------------------------------------

def test_le_bruit_transverse_nest_pas_une_source():
    """FIM, SCA, rootcheck et l'état des agents produisent ~1 800 alertes par
    jour dans l'index par défaut, sur TOUS les agents. Sans cette liste
    blanche, le module proposerait de leur créer un index dès le premier
    passage."""
    for d in ("ossec", "rootcheck", "sca", "wazuh"):
        assert d in routing.DECODERS_CROSS_CUTTING
    for g in ("syscheck", "sca", "virustotal", "vulnerability-detector"):
        assert g in routing.GROUPS_CROSS_CUTTING


def test_windows_eventchannel_nest_pas_traite_comme_ambigu():
    """Ses alertes portent des dizaines de groupes qui deviendraient autant de
    fausses sources pour un seul index — elles sont déjà routées par OS."""
    assert "windows_eventchannel" not in routing.DECODERS_AMBIGUOUS
    assert "json" in routing.DECODERS_AMBIGUOUS


# --------------------------------------------------------------------------
# Garde-fous de configuration
# --------------------------------------------------------------------------

def test_plafond_de_creation_est_bas():
    """Dix index sets créés le même jour, ce n'est pas dix index sets qu'il
    faut : c'est un humain qui regarde ce qui vient de changer dans le SI."""
    assert 1 <= config.ROUTING_MAX_NEW_PER_DAY <= 3


def test_seuil_de_silence_est_en_jours_pas_en_minutes():
    """Une source de log n'est pas un capteur continu : un proxy peut ne rien
    logger d'alertable d'une nuit entière."""
    assert config.ROUTING_SILENCE_HOURS >= 24
