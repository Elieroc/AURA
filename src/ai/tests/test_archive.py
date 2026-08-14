"""Garde-fous de l'archivage à froid (soc_agent.archive).

Ce qui est testé ici est ce dont l'échec est SILENCIEUX en exploitation : une
archive qui se croit complète, un mois figé trop tôt, un index d'état avalé par
un motif trop large, une chaîne de compression qui rend un fichier tronqué. Le
reste (S3, indexer) appartient au préflight `--verifier`, pas à une suite unitaire.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import date

import pytest

os.environ.setdefault("ARCHIVAGE_ENABLED", "false")

from soc_agent import archive, config  # noqa: E402


# --------------------------------------------------------------------------
# Périmètre : ce qui est archivable, et surtout ce qui ne l'est pas
# --------------------------------------------------------------------------

@pytest.mark.parametrize("nom, base, mois", [
    ("wazuh-firewall-2026.08.14", "wazuh-firewall", "2026-08"),
    ("wazuh-alerts-4.x-2026.01.01", "wazuh-alerts-4.x", "2026-01"),
    ("wazuh-voc-2026.12.31", "wazuh-voc", "2026-12"),
])
def test_index_date_reconnu(nom, base, mois):
    m = archive._DATE_INDEX.match(nom)
    assert m and m.group("base") == base
    assert f"{m.group('a')}-{m.group('m')}" == mois


@pytest.mark.parametrize("nom", [
    # Index d'ÉTAT, non daté : il porte le cycle de vie des vulnérabilités donc
    # le MTTR. L'archiver par date effacerait la notion même d'historique de
    # dette. Exclu par la FORME du nom, sans liste à tenir à jour.
    "wazuh-voc-vulns",
    # Datés à la SEMAINE par Wazuh, et ce n'est pas de l'alerte.
    "wazuh-monitoring-2026.33w",
    "wazuh-statistics-2026.33w",
    # Ni date, ni jour.
    "wazuh-firewall",
    "wazuh-firewall-2026.08",
    ".opendistro-ism-config",
])
def test_index_non_archivable(nom):
    assert archive._DATE_INDEX.match(nom) is None


# --------------------------------------------------------------------------
# Clôture du mois : le délai de grâce n'est pas décoratif
# --------------------------------------------------------------------------

def test_mois_en_cours_jamais_archive(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DELAI_JOURS", 2)
    assert not archive._mois_clos("2026-08", date(2026, 8, 31))


def test_mois_clos_attend_le_delai_de_grace(monkeypatch):
    """Le rattrapage des alertes indexées en retard écrit encore dans les index
    de la veille : archiver le 1er au matin fige une copie incomplète, et une
    archive incomplète ne se répare pas — elle se croit complète."""
    monkeypatch.setattr(config, "ARCHIVE_DELAI_JOURS", 2)
    assert not archive._mois_clos("2026-08", date(2026, 9, 1))
    assert not archive._mois_clos("2026-08", date(2026, 9, 2))
    assert archive._mois_clos("2026-08", date(2026, 9, 3))


def test_bascule_de_decembre():
    assert archive._premier_du_mois_suivant("2026-12") == date(2027, 1, 1)


def test_mois_entre_traverse_l_annee():
    assert archive._mois_entre("2026-11", "2027-02") == [
        "2026-11", "2026-12", "2027-01", "2027-02"]


# --------------------------------------------------------------------------
# Disposition des clés S3
# --------------------------------------------------------------------------

def test_cle_index_set_avant_annee(monkeypatch):
    """Index set d'abord : restaurer une source sur une fenêtre à cheval sur le
    nouvel an doit tenir dans un seul préfixe, et une règle de cycle de vie doit
    pouvoir cibler un index set."""
    monkeypatch.setattr(config, "ARCHIVE_S3_PREFIX", "")
    monkeypatch.setattr(config, "ARCHIVE_FORMAT_VERSION", "v1")
    assert archive.cle_objet("wazuh-firewall", "2026-03", "ndjson.zst.age") == (
        "v1/wazuh-firewall/2026/wazuh-firewall.2026-03.ndjson.zst.age")


def test_cle_prefixee_et_versionnee(monkeypatch):
    """`v2` doit pouvoir cohabiter avec `v1` sur le même mois : changer de format
    ne doit ni écraser l'ancien objet ni exiger de le supprimer."""
    monkeypatch.setattr(config, "ARCHIVE_S3_PREFIX", "soc")
    monkeypatch.setattr(config, "ARCHIVE_FORMAT_VERSION", "v2")
    assert archive.cle_objet("wazuh-web", "2027-01", "manifest.json") == (
        "soc/v2/wazuh-web/2027/wazuh-web.2027-01.manifest.json")


# --------------------------------------------------------------------------
# Chaîne compression + chiffrement, pour de vrai
# --------------------------------------------------------------------------

_OUTILS = shutil.which("zstd") and shutil.which("age") and shutil.which("age-keygen")


def _keyfile(tmp_path, monkeypatch):
    """Génère la clé du SOC et la déclare, comme en exploitation."""
    cle = tmp_path / "aura-archive-age.key"
    subprocess.run(["age-keygen", "-o", str(cle)], check=True,
                   capture_output=True)
    monkeypatch.setattr(config, "ARCHIVE_AGE_KEYFILE", str(cle))
    monkeypatch.setattr(config, "ARCHIVE_AGE_RECIPIENTS_EXTRA", [])
    return cle


@pytest.mark.skipif(not _OUTILS, reason="zstd/age absents de cet environnement")
def test_cle_publique_derivee_du_keyfile(tmp_path, monkeypatch):
    """La clé publique est DÉRIVÉE du fichier de clé, jamais recopiée dans le
    .env. Ça supprime une classe entière de pannes : un destinataire mal recopié
    produirait des archives que le SOC ne peut pas relire, et personne ne s'en
    apercevrait avant le premier drill."""
    cle = _keyfile(tmp_path, monkeypatch)
    attendu = next(l.split(": ")[1].strip() for l in cle.read_text().splitlines()
                   if l.startswith("# public key:"))
    assert archive.cle_publique() == attendu
    assert archive.destinataires() == [attendu]
    # Sans le commentaire, on retombe sur `age-keygen -y` plutôt que d'échouer.
    cle.write_text(next(l for l in cle.read_text().splitlines()
                        if l.startswith("AGE-SECRET-KEY-1")) + "\n")
    assert archive.cle_publique() == attendu


@pytest.mark.skipif(not _OUTILS, reason="zstd/age absents de cet environnement")
def test_secours_ajoute_aux_destinataires(tmp_path, monkeypatch):
    """Une clé de secours doit s'ajouter, jamais remplacer : le SOC doit rester
    capable de relire ses propres archives."""
    _keyfile(tmp_path, monkeypatch)
    secours = tmp_path / "secours.key"
    subprocess.run(["age-keygen", "-o", str(secours)], check=True,
                   capture_output=True)
    pub_secours = next(l.split(": ")[1].strip()
                       for l in secours.read_text().splitlines()
                       if l.startswith("# public key:"))
    monkeypatch.setattr(config, "ARCHIVE_AGE_RECIPIENTS_EXTRA", [pub_secours])
    d = archive.destinataires()
    assert len(d) == 2 and d[0] == archive.cle_publique() and d[1] == pub_secours


@pytest.mark.skipif(not _OUTILS, reason="zstd/age absents de cet environnement")
def test_verifier_cle_fait_un_aller_retour_reel(tmp_path, monkeypatch):
    """Le préflight doit REFUSER une clé qui ne redéchiffre pas ce qu'elle
    chiffre — sinon on ne l'apprend qu'à la première restauration."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    assert archive.verifier_cle()["aller_retour"] == "ok"
    # Clé d'un AUTRE porteur en destinataire exclusif : le SOC ne peut plus lire.
    autre = tmp_path / "autre.key"
    subprocess.run(["age-keygen", "-o", str(autre)], check=True,
                   capture_output=True)
    monkeypatch.setattr(archive, "destinataires", lambda: [
        next(l.split(": ")[1].strip() for l in autre.read_text().splitlines()
             if l.startswith("# public key:"))])
    with pytest.raises(RuntimeError, match="ne redéchiffre PAS"):
        archive.verifier_cle()


@pytest.mark.skipif(not _OUTILS, reason="zstd/age absents de cet environnement")
def test_export_chiffre_puis_relu(tmp_path, monkeypatch):
    """Le test qui prouve la propriété centrale : ce qui sort de la chaîne se
    redéchiffre à l'identique AVEC LA CLÉ DU SOC, et le SHA-256 annoncé est celui
    du clair.

    Sans ça, on ne saurait qu'à la première restauration réelle — donc trop tard.
    """
    cle = _keyfile(tmp_path, monkeypatch)

    docs = [{"_index": "wazuh-firewall-2026.08.14", "_id": f"i{n}",
             "_source": {"rule": {"level": 12}, "agent": {"id": "001"},
                         "full_log": "accès refusé " * 20}}
            for n in range(500)]
    attendu = b"".join(
        (json.dumps(d, ensure_ascii=False, separators=(",", ":"),
                    sort_keys=True) + "\n").encode() for d in docs)

    monkeypatch.setattr(config, "ARCHIVE_ZSTD_NIVEAU", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    monkeypatch.setattr(archive, "pages", lambda idx, taille=None: iter([docs]))

    objet = tmp_path / "archive.ndjson.zst.age"
    m = archive.exporter({"indices": ["wazuh-firewall-2026.08.14"],
                          "octets": 1024}, objet)

    assert m["documents"] == 500
    assert m["sha256_clair"] == hashlib.sha256(attendu).hexdigest()
    assert m["octets_objet"] == objet.stat().st_size
    assert m["sha256_chiffre"] == archive._sha256_fichier(objet)
    # L'archive doit être nettement plus petite que le clair : si la compression
    # ne mordait pas, c'est que la chaîne ne fait pas ce qu'on croit.
    assert m["octets_objet"] < m["octets_clair"] / 5

    relu = subprocess.run(f"age -d -i {str(cle)!r} {str(objet)!r} | zstd -d -c",
                          shell=True, capture_output=True, check=True)
    assert relu.stdout == attendu


@pytest.mark.skipif(not _OUTILS, reason="zstd/age absents de cet environnement")
def test_destinataire_invalide_ne_laisse_pas_de_fichier(tmp_path, monkeypatch):
    """Une chaîne en échec ne doit JAMAIS laisser son fichier derrière elle : un
    fichier tronqué qui monte dans S3 se fait passer pour une archive valide
    jusqu'au jour où on en a besoin."""
    monkeypatch.setattr(archive, "destinataires", lambda: ["age1pasunecle"])
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    monkeypatch.setattr(archive, "pages", lambda idx, taille=None: iter(
        [[{"_index": "i", "_id": "1", "_source": {}}]]))
    objet = tmp_path / "archive.ndjson.zst.age"
    with pytest.raises(RuntimeError):
        archive.exporter({"indices": ["i"], "octets": 1}, objet)
    assert not objet.exists()


def test_export_refuse_sans_place(tmp_path, monkeypatch):
    """Un disque plein arrête l'ingestion sans qu'aucune alerte ne le dise. Ce
    job de ménage ne doit pas en être la cause."""
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    libre = shutil.disk_usage(tmp_path).free
    with pytest.raises(RuntimeError, match="place insuffisante"):
        archive._place_disponible(libre * 4)


# --------------------------------------------------------------------------
# Manifeste
# --------------------------------------------------------------------------

def test_manifeste_porte_de_quoi_relire_sans_le_code(monkeypatch):
    """Le manifeste doit suffire à un humain dans trois ans : la chaîne exacte,
    les destinataires, et l'empreinte du clair qui fait la différence entre une
    sauvegarde et une preuve."""
    monkeypatch.setattr(archive, "destinataires", lambda: ["age1abc"])
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_NIVEAU", 19)
    man = archive.manifeste(
        {"index_base": "wazuh-web", "periode": "2026-05",
         "indices": ["wazuh-web-2026.05.01"]},
        {"documents": 3, "octets_clair": 30, "octets_objet": 10,
         "sha256_clair": "a" * 64, "sha256_chiffre": "b" * 64},
        "v1/wazuh-web/2026/wazuh-web.2026-05.ndjson.zst.age")
    assert man["sha256_clair"] == "a" * 64
    assert man["destinataires_age"] == ["age1abc"]
    assert "zstd -19" in man["chaine"] and "age -r age1abc" in man["chaine"]
    assert man["indices"] == ["wazuh-web-2026.05.01"]
    # Sérialisable : il part dans S3 tel quel.
    json.dumps(man)


# --------------------------------------------------------------------------
# Object Lock
# --------------------------------------------------------------------------

def test_object_lock_absent_par_defaut(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK", False)
    assert archive._args_lock() == {}


def test_object_lock_pose_une_echeance(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK", True)
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK_MODE", "COMPLIANCE")
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK_JOURS", 365)
    a = archive._args_lock()
    assert a["ObjectLockMode"] == "COMPLIANCE"
    assert (a["ObjectLockRetainUntilDate"].date()
            - date.today()).days in (364, 365, 366)


# --------------------------------------------------------------------------
# Désactivé = inerte
# --------------------------------------------------------------------------

def test_desactive_ne_touche_a_rien(monkeypatch):
    """ARCHIVAGE_ENABLED=false doit être inerte SANS toucher Postgres : le
    module est importé par le watchdog, qui tourne toutes les deux minutes chez
    tout le monde, y compris chez qui n'archive pas."""
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", False)
    assert archive.tourner() == {"etat": "désactivé"}
    assert archive.indices_en_peril(None) == []
    assert archive.anomalies(None) == []


# --------------------------------------------------------------------------
# Anomalies remontées au watchdog
# --------------------------------------------------------------------------

class _Conn:
    """Bouchon minimal : `execute(...).fetchall()`."""

    def __init__(self, lignes):
        self._lignes = lignes

    def execute(self, sql, params=None):
        self._sql = sql
        return self

    def fetchall(self):
        return self._lignes


def test_trou_de_couverture_detecte(monkeypatch):
    """Un mois absent ENTRE deux mois archivés : les index d'origine sont purgés
    depuis longtemps, la donnée n'existe plus nulle part, et rien ne l'avait dit
    au moment où elle partait."""
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)
    monkeypatch.setattr(archive, "indices_en_peril", lambda conn: [])
    conn = _Conn([
        {"index_base": "wazuh-web", "periode": "2026-01",
         "verifie_a": None, "verif_etat": "ok"},
        {"index_base": "wazuh-web", "periode": "2026-03",
         "verifie_a": None, "verif_etat": "ok"},
    ])
    trous = [a for a in archive.anomalies(conn)
             if a["capteur"].endswith("trou")]
    assert len(trous) == 1
    assert "2026-02" in trous[0]["note"]
    assert trous[0]["severite"] == "Medium"


def test_serie_recente_sans_passe_n_est_pas_un_trou(monkeypatch):
    """Un index set créé le mois dernier n'a pas de trou : il a un passé qui
    n'existe pas. Confondre les deux ouvrirait un dossier à chaque création
    d'index set — et routage.py en crée jusqu'à deux par jour."""
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)
    monkeypatch.setattr(archive, "indices_en_peril", lambda conn: [])
    conn = _Conn([{"index_base": "wazuh-jellyfin", "periode": "2026-07",
                   "verifie_a": None, "verif_etat": "ok"}])
    assert not [a for a in archive.anomalies(conn)
                if a["capteur"].endswith("trou")]


def test_drill_en_echec_remonte_en_high(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)
    monkeypatch.setattr(archive, "indices_en_peril", lambda conn: [])
    conn = _Conn([{"index_base": "wazuh-web", "periode": "2026-01",
                   "verifie_a": None, "verif_etat": "sha256-divergent"}])
    echecs = [a for a in archive.anomalies(conn)
              if a["capteur"].endswith("drill")]
    assert len(echecs) == 1 and echecs[0]["severite"] == "High"


def test_peril_remonte_en_high_avec_le_delai_restant(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)
    monkeypatch.setattr(archive, "indices_en_peril", lambda conn: [
        {"index": "wazuh-web-2026.05.02", "documents": 12,
         "age_jours": 85, "supprime_dans": 5}])
    conn = _Conn([])
    peril = [a for a in archive.anomalies(conn)
             if a["capteur"].endswith("peril")]
    assert len(peril) == 1
    assert peril[0]["severite"] == "High"
    assert "wazuh-web-2026.05.02" in peril[0]["note"]
    assert "5 j" in peril[0]["note"]


def test_capteurs_prefixes_pour_le_watchdog(monkeypatch):
    """Le watchdog reconnaît ces pseudo-capteurs par leur PRÉFIXE pour les
    mesurer contre l'horloge et non contre l'horizon d'ingestion."""
    from soc_agent import watchdog
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)
    monkeypatch.setattr(archive, "indices_en_peril", lambda conn: [
        {"index": "i-2026.05.02", "documents": 1, "age_jours": 85,
         "supprime_dans": 5}])
    for a in archive.anomalies(_Conn([])):
        assert a["capteur"].startswith(archive.PREFIXE_CAPTEUR)
        assert watchdog._est_archivage(a["capteur"])
        assert watchdog._hors_pipeline(a["capteur"])
        # `titre`, `note` et `severite` sont ce que le watchdog consomme sans
        # cas particulier (cf. watchdog._rendu / _titre / _severite_panne).
        assert a["titre"] and a["note"] and a["severite"]
        assert watchdog._titre(a) == a["titre"]
        assert watchdog._rendu(a, 0, markdown=False) == a["note"]
        assert watchdog._severite_panne(a["capteur"], a) == a["severite"]


# --------------------------------------------------------------------------
# Sélection des lots et péril de purge
# --------------------------------------------------------------------------

def _faux_indices(*specs):
    """(index_base, 'AAAA-MM', nb_jours, docs_par_jour) -> liste d'index datés."""
    out = []
    for base, mois, n, docs in specs:
        a, m = mois.split("-")
        for j in range(1, n + 1):
            out.append({"index": f"{base}-{a}.{m}.{j:02d}", "base": base,
                        "jour": date(int(a), int(m), j), "mois": mois,
                        "documents": docs, "octets": docs * 1000})
    return out


def test_lots_ignorent_le_mois_en_cours(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DELAI_JOURS", 2)
    monkeypatch.setattr(archive, "indices_dates", lambda: _faux_indices(
        ("wazuh-firewall", "2026-05", 3, 100),
        ("wazuh-firewall", "2026-08", 2, 50),   # mois en cours
        ("wazuh-web", "2026-05", 1, 7)))
    lots = archive.lots_a_archiver(_Conn([]), date(2026, 8, 14))
    assert [(l["index_base"], l["periode"]) for l in lots] == [
        ("wazuh-firewall", "2026-05"), ("wazuh-web", "2026-05")]
    # Les jours du mois sont regroupés en UN lot, documents cumulés.
    assert lots[0]["documents"] == 300 and len(lots[0]["indices"]) == 3


def test_lot_deja_archive_ne_revient_pas(monkeypatch):
    """Sans ça, chaque passage réexporterait et repaierait tout l'historique —
    le bug des pièces Evidence d'IRIS, transposé à S3."""
    monkeypatch.setattr(config, "ARCHIVE_DELAI_JOURS", 2)
    monkeypatch.setattr(archive, "indices_dates", lambda: _faux_indices(
        ("wazuh-firewall", "2026-05", 3, 100),
        ("wazuh-web", "2026-05", 1, 7)))
    conn = _Conn([{"index_base": "wazuh-firewall", "periode": "2026-05"}])
    lots = archive.lots_a_archiver(conn, date(2026, 8, 14))
    assert [(l["index_base"], l["periode"]) for l in lots] == [
        ("wazuh-web", "2026-05")]


def test_peril_borne_a_la_marge_avant_suppression(monkeypatch):
    """Un index jeune sans archive n'est pas en péril — il a le temps. Confondre
    les deux ouvrirait un dossier High tous les jours, pour rien."""
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)
    monkeypatch.setattr(config, "RETENTION_INDEX_JOURS", 90)
    monkeypatch.setattr(config, "ARCHIVE_MARGE_JOURS", 7)
    monkeypatch.setattr(archive, "indices_dates", lambda: _faux_indices(
        ("wazuh-web", "2026-05", 1, 7),      # 105 j -> en péril
        ("wazuh-web", "2026-08", 1, 7)))     # 13 j  -> tranquille
    peril = archive.indices_en_peril(_Conn([]), date(2026, 8, 14))
    assert [i["index"] for i in peril] == ["wazuh-web-2026.05.01"]
    assert peril[0]["age_jours"] == 105


def test_peril_tombe_quand_l_archive_existe(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)
    monkeypatch.setattr(config, "RETENTION_INDEX_JOURS", 90)
    monkeypatch.setattr(config, "ARCHIVE_MARGE_JOURS", 7)
    monkeypatch.setattr(archive, "indices_dates", lambda: _faux_indices(
        ("wazuh-web", "2026-05", 1, 7)))
    conn = _Conn([{"index_base": "wazuh-web", "periode": "2026-05"}])
    assert archive.indices_en_peril(conn, date(2026, 8, 14)) == []


# --------------------------------------------------------------------------
# Le verrou ne doit pas masquer l'erreur qui a interrompu le passage
# --------------------------------------------------------------------------

class _ConnAvortee:
    """Connexion dont la transaction est avortée : tout `execute` échoue.

    Reproduit l'état réel de Postgres après une requête en erreur — c'est ce que
    la prod a rencontré au premier passage, table `archives_s3` absente.
    """

    def __init__(self):
        self.rollback_appele = False

    def execute(self, sql, params=None):
        if not self.rollback_appele:
            raise RuntimeError("current transaction is aborted")

        class R:
            @staticmethod
            def fetchone():
                return {"pg_advisory_unlock": True}
        return R()

    def rollback(self):
        self.rollback_appele = True


def test_deverrouillage_ne_masque_pas_la_cause():
    """Sans rollback préalable, l'UNLOCK lève `InFailedSqlTransaction` et cette
    seconde exception REMPLACE la première : la trace ne dit plus ce qui
    n'allait pas. Arrivé en prod, où le diagnostic utile (« il manque une
    table ») était devenu invisible sous une erreur de transaction."""
    conn = _ConnAvortee()
    archive._deverrouiller(conn)          # ne doit RIEN lever
    assert conn.rollback_appele, "rollback non tenté avant l'unlock"


def test_deverrouillage_survit_a_une_connexion_morte():
    """Un verrou de session est rendu à la fermeture de la connexion : échouer
    ici est sans conséquence, alors que propager l'échec masquerait la cause."""
    class _Morte:
        def rollback(self):
            raise OSError("connexion fermée")

        def execute(self, *a):
            raise OSError("connexion fermée")

    archive._deverrouiller(_Morte())      # ne doit RIEN lever


def test_erreur_de_table_absente_remonte_telle_quelle(monkeypatch):
    """Le bout à bout du scénario de prod : ce qui doit sortir de `tourner`,
    c'est la cause réelle, pas l'erreur de transaction du nettoyage."""
    monkeypatch.setattr(config, "ARCHIVAGE_ENABLED", True)

    class _Conn(_ConnAvortee):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=None):
            if "pg_try_advisory_lock" in sql:
                class R:
                    @staticmethod
                    def fetchone():
                        return {"pg_try_advisory_lock": True}
                return R()
            return super().execute(sql, params)

    monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(archive, "lots_a_archiver", lambda conn: (_ for _ in ()).throw(
        RuntimeError('relation "archives_s3" does not exist')))
    with pytest.raises(RuntimeError, match="archives_s3"):
        archive.tourner()
