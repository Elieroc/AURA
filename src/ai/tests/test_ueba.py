"""Moteur UEBA : extraction des traits, rareté, chaîne MITRE, regroupement.

Tout ce qui est testé ici est PUR (pas de base) : c'est justement la partie qui
décide ce qui part au LLM, donc celle qui doit rester vérifiable sans monter une
infra. Les accès Postgres (`observer`, `evaluer`, `purger`) sont couverts en
recette sur le serveur, pas ici.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from soc_agent import config, ueba
from soc_agent.anonymize import Anonymiseur, anonymiser, verifier_fuite
from soc_agent.render import rendre

T0 = datetime(2026, 8, 5, 10, 0, tzinfo=timezone.utc)   # mercredi, ouvré


def alerte(**kw):
    base = {
        "id": "1.1", "ts": T0, "agent_id": "002", "agent_name": "debian-vm",
        "rule_id": "80792", "rule_level": 3, "rule_desc": "Command executed",
        "rule_groups": ["audit"], "mitre_tactics": [], "srcip": None,
        "srcuser": None, "entity": None, "raw": {},
    }
    base.update(kw)
    return base


# --- Extraction des traits ---------------------------------------------------

def test_traits_exe_et_scope_utilisateur():
    a = alerte(srcuser="jdupont",
               raw={"data": {"audit": {"exe": "/usr/bin/nc"}}})
    t = ueba.traits(a)
    assert ("host", "002", "exe", "/usr/bin/nc") in t
    # Le même trait est observé DEUX fois : une fois pour la machine, une fois
    # pour le couple compte/machine. C'est ce second scope qui voit la
    # latéralisation (un compte légitime sur un hôte où il n'a jamais servi).
    assert ("user@host", "jdupont@002", "exe", "/usr/bin/nc") in t


def test_traits_sans_compte_pas_de_scope_fourre_tout():
    """Un « inconnu@hôte » créerait un profil où tout finit par sembler normal."""
    a = alerte(raw={"data": {"audit": {"exe": "/usr/bin/nc"}}})
    assert all(s == "host" for s, _, _, _ in ueba.traits(a))


def test_traits_shell_generique_ignore():
    """Le premier `bash` d'une machine ne doit pas valoir 12 bits."""
    a = alerte(raw={"data": {"audit": {"exe": "/bin/bash"}}})
    assert not [t for t in ueba.traits(a) if t[2] == "exe"]


def test_traits_parent_child_windows():
    a = alerte(agent_id="010", raw={"data": {"win": {"eventdata": {
        "parentImage": r"C:\Program Files\nginx\nginx.exe",
        "image": r"C:\Windows\System32\cmd.exe"}}}})
    t = ueba.traits(a)
    assert ("host", "010", "parent_child", "nginx.exe>cmd.exe") in t


def test_traits_heure_tranche_ouvre_ou_non():
    ouvre = ueba.traits(alerte(ts=T0))
    nuit = ueba.traits(alerte(ts=T0.replace(hour=3)))
    assert ("host", "002", "heure", "ouvre") in ouvre
    assert ("host", "002", "heure", "hors_ouvre") in nuit


def test_traits_raw_json_serialise():
    """`alerts.raw` revient tantôt en dict, tantôt en texte selon l'appelant."""
    a = alerte(raw=json.dumps({"data": {"audit": {"exe": "/opt/x/impl"}}}))
    assert ("host", "002", "exe", "/opt/x/impl") in ueba.traits(a)


# --- Rareté ------------------------------------------------------------------

def test_surprisal_decroit_avec_la_frequence():
    rare = ueba.surprisal(1, 10_000, 50)
    courant = ueba.surprisal(5_000, 10_000, 50)
    assert rare > courant
    assert courant < 2.0


def test_surprisal_jamais_infinie():
    """Le lissage de Laplace borne le score d'un profil encore maigre."""
    assert ueba.surprisal(0, 0, 0) < 2.0
    assert ueba.surprisal(0, 100, 3) < 10.0


def test_profil_immature_ne_score_pas():
    """Le premier jour, tout est inédit : scorer enverrait le parc entier au LLM."""
    bits, _ = ueba._bits_trait(None, None, 0, mature=False)
    assert bits == 0.0


def test_first_seen_module_par_la_flotte():
    """Inédit ici mais banal ailleurs = déploiement d'admin, pas intrusion."""
    seul, note_seul = ueba._bits_trait(None, None, 0, mature=True)
    partout, _ = ueba._bits_trait(None, None, 12, mature=True)
    assert seul == config.UEBA_FIRSTSEEN_BITS
    assert "flotte" in note_seul
    assert partout < seul / 4


def test_habitude_ne_score_plus():
    """Vu sur assez de jours DISTINCTS : c'est une routine."""
    profil = {"total": 40, "days_seen": config.UEBA_JOURS_HABITUEL + 1,
              "seen_in_tp": False}
    bits, _ = ueba._bits_trait(profil, {"total": 100, "distincts": 5}, 0, True)
    assert bits == 0.0


def test_vu_en_vrai_positif_ne_devient_jamais_une_habitude():
    """Sinon un attaquant normalise son outillage en le lançant tous les jours."""
    profil = {"total": 5_000, "days_seen": 300, "seen_in_tp": True}
    bits, note = ueba._bits_trait(profil, {"total": 5_000, "distincts": 2},
                                  40, True)
    assert bits == config.UEBA_FIRSTSEEN_BITS
    assert "vrai positif" in note


# --- Chaîne MITRE ------------------------------------------------------------

def test_chaine_sous_le_minimum_ne_bonifie_pas():
    assert ueba.bonus_chaine(["Discovery", "Discovery"]) == (0.0, None)


def test_trois_discovery_valent_moins_qu_une_vraie_chaine():
    """Le brut « 3 tactiques » remonte surtout l'admin qui inventorie sa machine."""
    faible, _ = ueba.bonus_chaine(["Discovery", "Execution", "Reconnaissance"])
    fort, phrase = ueba.bonus_chaine(
        ["Initial Access", "Persistence", "Credential Access", "Exfiltration"])
    assert fort > faible * 2
    assert "progression kill-chain" in phrase


def test_bonus_ordre_recompense_la_progression():
    ordonnee, _ = ueba.bonus_chaine(
        ["Initial Access", "Execution", "Persistence", "Exfiltration"])
    desordre, _ = ueba.bonus_chaine(
        ["Exfiltration", "Persistence", "Execution", "Initial Access"])
    assert ordonnee > desordre


# --- Regroupement et score d'un signal ---------------------------------------

def test_groupement_coupe_sur_l_agent_et_sur_la_fenetre():
    loin = T0 + timedelta(minutes=config.UEBA_FENETRE_MINUTES + 10)
    alertes = [
        alerte(id="a", ts=T0),
        alerte(id="b", ts=T0 + timedelta(minutes=5)),
        alerte(id="c", ts=loin),                 # trop loin -> nouveau groupe
        alerte(id="d", ts=loin, agent_id="003"),  # autre agent -> nouveau groupe
    ]
    groupes = ueba._grouper_signaux(alertes)
    assert [len(g) for g in groupes] == [2, 1, 1]


def test_groupement_borne_la_duree_totale():
    """Le chaînage est de proche en proche : sans plafond, un hôte qui émet une
    alerte toutes les 50 min agglomère sa journée entière en un seul signal."""
    pas = timedelta(minutes=config.UEBA_FENETRE_MINUTES - 1)
    n = int(config.UEBA_SIGNAL_MAX_HEURES * 60 / (pas.seconds / 60)) + 3
    alertes = [alerte(id=str(i), ts=T0 + pas * i) for i in range(n)]
    groupes = ueba._grouper_signaux(alertes)
    assert len(groupes) > 1
    for g in groupes:
        span = g[-1]["ts"] - g[0]["ts"]
        assert span <= timedelta(hours=config.UEBA_SIGNAL_MAX_HEURES)


def test_score_signal_sature_les_repetitions():
    """Quarante fois le même binaire rare ne valent pas quarante fois le score."""
    trait = {"trait": "exe", "valeur": "/opt/impl", "scope": "host",
             "bits": 12.0, "note": "jamais vu"}
    un = ueba.scorer_groupe([alerte(ueba_traits=[trait])])[0]
    quarante = ueba.scorer_groupe(
        [alerte(id=str(i), ueba_traits=[trait]) for i in range(40)])[0]
    assert un == quarante


def test_score_signal_cumule_des_traits_distincts():
    a = alerte(ueba_traits=[{"trait": "exe", "valeur": "/opt/impl",
                             "scope": "host", "bits": 12.0, "note": ""}])
    b = alerte(id="2", ueba_traits=[{"trait": "pays", "valeur": "Russia",
                                     "scope": "host", "bits": 9.0, "note": ""}])
    score, motifs = ueba.scorer_groupe([a, b])
    assert score == pytest.approx(21.0)
    assert {m["trait"] for m in motifs} == {"exe", "pays"}


def test_score_signal_ajoute_le_bonus_de_chaine():
    traits = [{"trait": "exe", "valeur": "/opt/impl", "scope": "host",
               "bits": 12.0, "note": ""}]
    sans = ueba.scorer_groupe([alerte(ueba_traits=traits)])[0]
    avec, motifs = ueba.scorer_groupe([
        alerte(ueba_traits=traits, mitre_tactics=["Initial Access"]),
        alerte(id="2", mitre_tactics=["Persistence"], ueba_traits=[]),
        alerte(id="3", mitre_tactics=["Exfiltration"], ueba_traits=[]),
    ])
    assert avec > sans
    assert any(m["trait"] == "chaine_mitre" for m in motifs)


# --- Intégration prompt : rendu, pseudonymisation, garde-fou de fuite --------

def _incident_ueba():
    return {
        "id": 1, "agent_id": "002", "agent_name": "debian-vm",
        "first_seen": T0, "last_seen": T0 + timedelta(minutes=10),
        "alert_count": 6, "max_level": 5, "mitre_tactics": ["Execution"],
        "entities": [], "ueba": True, "ueba_score": 41.5,
        "ueba_motifs": [
            {"trait": "exe", "valeur": "/home/jdupont/.cache/impl",
             "scope": "host", "bits": 12.0,
             "note": "jamais vu ici ni ailleurs sur la flotte"},
            {"trait": "compte", "valeur": "jdupont", "scope": "host",
             "bits": 7.2, "note": "rare : 2x sur 4000 observations"},
            {"trait": "srcip", "valeur": "192.168.10.12", "scope": "host",
             "bits": 6.0, "note": "inédit ici"},
            {"trait": "pays", "valeur": "Russia", "scope": "host",
             "bits": 9.0, "note": "jamais vu ici ni ailleurs sur la flotte"},
        ],
    }


def test_rendu_explique_pourquoi_un_incident_de_niveau_5_est_ouvert():
    """Sans ça, le modèle voit du niveau 5 et conclut mécaniquement au FP."""
    texte = rendre(_incident_ueba(), [alerte(id="a")])
    assert "UEBA" in texte
    assert "41.5" in texte
    assert "jamais vu ici ni ailleurs" in texte


def test_motifs_ueba_pseudonymises_avant_envoi_cloud():
    """Les motifs portent des valeurs BRUTES de logs : chemins, comptes, IP.

    Sans pseudonymisation, `verifier_fuite` (fail-closed) refuserait l'incident
    et TOUT ce que le moteur remonte serait silencieusement écarté du triage.
    """
    anon = Anonymiseur()
    alertes = [alerte(id="a", srcuser="jdupont", srcip="192.168.10.12",
                      entity="/home/jdupont/.cache/impl")]
    inc, alertes_a, interdits = anonymiser(anon, _incident_ueba(), alertes)

    texte = rendre(inc, alertes_a)
    verifier_fuite(texte, interdits)   # ne doit pas lever

    assert "jdupont" not in texte
    assert "192.168.10.12" not in texte
    # L'ATTRIBUT reste : c'est lui qui porte le signal, et il n'identifie personne.
    assert "Russia" in texte


def test_pays_et_attributs_non_tokenises():
    anon = Anonymiseur()
    inc, _, _ = anonymiser(anon, _incident_ueba(), [])
    par_trait = {m["trait"]: m["valeur"] for m in inc["ueba_motifs"]}
    assert par_trait["pays"] == "Russia"
    assert par_trait["compte"].startswith("<COMPTE_")
    assert par_trait["srcip"].startswith("<IP_")


# --- Garde-fou de remédiation ------------------------------------------------

def test_incident_ueba_ne_declenche_pas_de_remediation_autonome(monkeypatch):
    """Le pipeline agit seul parce qu'il part d'une règle Wazuh de niveau >= 12.

    Un incident UEBA part d'un score statistique NON calibré : le laisser isoler
    un hôte reviendrait à confier la production à un seuil qu'on n'a pas mesuré.
    """
    from soc_agent import iris

    monkeypatch.setattr(config, "UEBA_MITIGATE", False)
    assert iris._remediation_autorisee(
        {"id": 1, "ueba": True, "ueba_score": 41}) is False
    # Le pipeline normal (graine de niveau >= 12) n'est PAS affecté : il continue
    # d'agir de façon autonome, c'est le but du projet.
    assert iris._remediation_autorisee({"id": 1, "ueba": False}) is True


def test_remediation_ueba_reactivable_par_configuration(monkeypatch):
    from soc_agent import iris

    monkeypatch.setattr(config, "UEBA_MITIGATE", True)
    assert iris._remediation_autorisee({"id": 1, "ueba": True}) is True


# --- Garde-fou de cardinalité ------------------------------------------------

def test_trait_a_cardinalite_explosive_est_mute():
    """Archives LVM, chemins horodatés, GUID : inédits PAR CONSTRUCTION.

    Mesuré à la mise en service : les archives LVM de l'hôte Proxmox donnaient à
    elles seules un signal à 1434 points, quarante fois le plancher.
    """
    explosif = {"total": 5_000, "distincts": 4_900}
    assert ueba.cardinalite_exploitable(explosif) is False
    bits, _ = ueba._bits_trait(None, explosif, 0, mature=True)
    assert bits == 0.0


def test_trait_normal_reste_scorable():
    normal = {"total": 5_000, "distincts": 60}
    assert ueba.cardinalite_exploitable(normal) is True
    bits, _ = ueba._bits_trait(None, normal, 0, mature=True)
    assert bits == config.UEBA_FIRSTSEEN_BITS


def test_cardinalite_ne_conclut_pas_sans_recul():
    """Peu d'observations : on n'exclut pas un trait faute de données."""
    assert ueba.cardinalite_exploitable({"total": 10, "distincts": 10}) is True
    assert ueba.cardinalite_exploitable(None) is True


def test_exe_ne_prend_pas_les_chemins_fim():
    """`entity` vaut syscheck.path : clé de registre sur Windows, archive LVM
    sur Proxmox. Ni l'un ni l'autre n'est un exécutable."""
    a = alerte(entity=r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Run")
    traits_ = ueba.traits(a)
    assert not [t for t in traits_ if t[2] == "exe"]
    # Conservé, mais comme trait `fichier`, moins pesant et soumis au garde-fou
    # de cardinalité.
    assert [t for t in traits_ if t[2] == "fichier"]
