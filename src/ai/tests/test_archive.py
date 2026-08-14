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
from datetime import date, datetime, timezone

import pytest

os.environ.setdefault("ARCHIVAGE_ENABLED", "false")

from soc_agent import archive, config  # noqa: E402


# --------------------------------------------------------------------------
# Périmètre : ce qui est archivable, et surtout ce qui ne l'est pas
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name, base, month", [
    ("wazuh-firewall-2026.08.14", "wazuh-firewall", "2026-08"),
    ("wazuh-alerts-4.x-2026.01.01", "wazuh-alerts-4.x", "2026-01"),
    ("wazuh-voc-2026.12.31", "wazuh-voc", "2026-12"),
])
def test_index_date_reconnu(name, base, month):
    m = archive._DATE_INDEX.match(name)
    assert m and m.group("base") == base
    assert f"{m.group('a')}-{m.group('m')}" == month


@pytest.mark.parametrize("name", [
    # Index d'ÉTAT, non daté : il porte le cycle de vie des vulnérabilités donc
    # le MTTR. L'archive by date effacerait la notion même d'historique de
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
def test_index_non_archivable(name):
    assert archive._DATE_INDEX.match(name) is None


# --------------------------------------------------------------------------
# Clôture du mois : le délai de grâce n'est pas décoratif
# --------------------------------------------------------------------------

def test_mois_en_cours_jamais_archive(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    assert not archive._closed_months("2026-08", date(2026, 8, 31))


def test_mois_clos_attend_le_delai_de_grace(monkeypatch):
    """Le rattrapage des alertes indexées en retard écrit encore dans les index
    de la veille : archiver le 1er au matin fige une copie incomplète, et une
    archive incomplète ne se répare pas — elle se croit complète."""
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    assert not archive._closed_months("2026-08", date(2026, 9, 1))
    assert not archive._closed_months("2026-08", date(2026, 9, 2))
    assert archive._closed_months("2026-08", date(2026, 9, 3))


def test_bascule_de_decembre():
    assert archive._first_of_next_month("2026-12") == date(2027, 1, 1)


def test_mois_entre_traverse_l_annee():
    assert archive._months_between("2026-11", "2027-02") == [
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
    assert archive.object_key("wazuh-firewall", "2026-03", "ndjson.zst.age") == (
        "v1/wazuh-firewall/2026/wazuh-firewall.2026-03.ndjson.zst.age")


def test_cle_prefixee_et_versionnee(monkeypatch):
    """`v2` doit pouvoir cohabiter avec `v1` sur le même mois : changer de format
    ne doit ni écraser l'ancien objet ni exiger de le supprimer."""
    monkeypatch.setattr(config, "ARCHIVE_S3_PREFIX", "soc")
    monkeypatch.setattr(config, "ARCHIVE_FORMAT_VERSION", "v2")
    assert archive.object_key("wazuh-web", "2027-01", "manifest.json") == (
        "soc/v2/wazuh-web/2027/wazuh-web.2027-01.manifest.json")


# --------------------------------------------------------------------------
# Chaîne compression + chiffrement, pour de vrai
# --------------------------------------------------------------------------

_TOOLS = shutil.which("zstd") and shutil.which("age") and shutil.which("age-keygen")


def _keyfile(tmp_path, monkeypatch):
    """Génère la clé du SOC et la déclare, comme en exploitation."""
    key = tmp_path / "aura-archive-age.key"
    subprocess.run(["age-keygen", "-o", str(key)], check=True,
                   capture_output=True)
    monkeypatch.setattr(config, "ARCHIVE_AGE_KEYFILE", str(key))
    monkeypatch.setattr(config, "ARCHIVE_AGE_RECIPIENTS_EXTRA", [])
    return key


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_cle_publique_derivee_du_keyfile(tmp_path, monkeypatch):
    """La clé publique est DÉRIVÉE du fichier de clé, jamais recopiée dans le
    .env. Ça supprime une classe entière de pannes : un destinataire mal recopié
    produirait des archives que le SOC ne peut pas relire, et personne ne s'en
    apercevrait avant le premier drill."""
    key = _keyfile(tmp_path, monkeypatch)
    expected = next(l.split(": ")[1].strip() for l in key.read_text().splitlines()
                   if l.startswith("# public key:"))
    assert archive.public_key() == expected
    assert archive.recipients() == [expected]
    # Sans le commentaire, on retombe sur `age-keygen -y` plutôt que d'échouer.
    key.write_text(next(l for l in key.read_text().splitlines()
                        if l.startswith("AGE-SECRET-KEY-1")) + "\n")
    assert archive.public_key() == expected


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_secours_ajoute_aux_destinataires(tmp_path, monkeypatch):
    """Une clé de secours doit s'ajouter, jamais remplacer : le SOC doit rester
    capable de relire ses propres archives."""
    _keyfile(tmp_path, monkeypatch)
    backup = tmp_path / "secours.key"
    subprocess.run(["age-keygen", "-o", str(backup)], check=True,
                   capture_output=True)
    backup_pub = next(l.split(": ")[1].strip()
                       for l in backup.read_text().splitlines()
                       if l.startswith("# public key:"))
    monkeypatch.setattr(config, "ARCHIVE_AGE_RECIPIENTS_EXTRA", [backup_pub])
    d = archive.recipients()
    assert len(d) == 2 and d[0] == archive.public_key() and d[1] == backup_pub


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_verifier_cle_fait_un_aller_retour_reel(tmp_path, monkeypatch):
    """Le préflight doit REFUSER une clé qui ne redéchiffre pas ce qu'elle
    chiffre — sinon on ne l'apprend qu'à la première restauration."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    assert archive.check_key()["aller_retour"] == "ok"
    # Clé d'un AUTRE porteur en destinataire exclusif : le SOC ne peut plus lire.
    other = tmp_path / "autre.key"
    subprocess.run(["age-keygen", "-o", str(other)], check=True,
                   capture_output=True)
    monkeypatch.setattr(archive, "recipients", lambda: [
        next(l.split(": ")[1].strip() for l in other.read_text().splitlines()
             if l.startswith("# public key:"))])
    with pytest.raises(RuntimeError, match="ne redéchiffre PAS"):
        archive.check_key()


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_export_chiffre_puis_relu(tmp_path, monkeypatch):
    """Le test qui prouve la propriété centrale : ce qui sort de la chaîne se
    redéchiffre à l'identique AVEC LA CLÉ DU SOC, et le SHA-256 annoncé est celui
    du clair.

    Sans ça, on ne saurait qu'à la première restauration réelle — donc trop tard.
    """
    key = _keyfile(tmp_path, monkeypatch)

    docs = [{"_index": "wazuh-firewall-2026.08.14", "_id": f"i{n}",
             "_source": {"rule": {"level": 12}, "agent": {"id": "001"},
                         "full_log": "accès refusé " * 20}}
            for n in range(500)]
    expected = b"".join(
        (json.dumps(d, ensure_ascii=False, separators=(",", ":"),
                    sort_keys=True) + "\n").encode() for d in docs)

    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    # `controle` accepté et RENSEIGNÉ : c'est ce que fait le vrai `pages`, et
    # l'export vérifie désormais le compte annoncé contre le compte écrit.
    monkeypatch.setattr(archive, "pages",
                        lambda idx, size=None, control=None: (
                            control.update(expected=len(docs))
                            if control is not None else None,
                            iter([docs]))[1])

    object_path = tmp_path / "archive.ndjson.zst.age"
    m = archive.export({"indices": ["wazuh-firewall-2026.08.14"],
                          "octets": 1024}, object_path)

    assert m["documents"] == 500
    assert m["sha256_plain"] == hashlib.sha256(expected).hexdigest()
    assert m["object_bytes"] == object_path.stat().st_size
    assert m["sha256_encrypted"] == archive._sha256_file(object_path)
    # L'archive doit être nettement plus petite que le clair : si la compression
    # ne mordait pas, c'est que la chaîne ne fait pas ce qu'on croit.
    assert m["object_bytes"] < m["plain_bytes"] / 5

    reread = subprocess.run(f"age -d -i {str(key)!r} {str(object_path)!r} | zstd -d -c",
                          shell=True, capture_output=True, check=True)
    assert reread.stdout == expected


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_destinataire_invalide_ne_laisse_pas_de_fichier(tmp_path, monkeypatch):
    """Une chaîne en échec ne doit JAMAIS laisser son fichier derrière elle : un
    fichier tronqué qui monte dans S3 se fait passer pour une archive valide
    jusqu'au jour où on en a besoin."""
    monkeypatch.setattr(archive, "recipients", lambda: ["age1pasunecle"])
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    monkeypatch.setattr(archive, "pages",
                        lambda idx, size=None, control=None: iter(
                            [[{"_index": "i", "_id": "1", "_source": {}}]]))
    object_path = tmp_path / "archive.ndjson.zst.age"
    with pytest.raises(RuntimeError):
        archive.export({"indices": ["i"], "octets": 1}, object_path)
    assert not object_path.exists()


def test_export_refuse_sans_place(tmp_path, monkeypatch):
    """Un disque plein arrête l'ingestion sans qu'aucune alerte ne le dise. Ce
    job de ménage ne doit pas en être la cause."""
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    free = shutil.disk_usage(tmp_path).free
    with pytest.raises(RuntimeError, match="place insuffisante"):
        archive._free_space(free * 4)


# --------------------------------------------------------------------------
# Manifeste
# --------------------------------------------------------------------------

def test_manifeste_porte_de_quoi_relire_sans_le_code(monkeypatch):
    """Le manifeste doit suffire à un humain dans trois ans : la chaîne exacte,
    les destinataires, et l'empreinte du clair qui fait la différence entre une
    sauvegarde et une preuve."""
    monkeypatch.setattr(archive, "recipients", lambda: ["age1abc"])
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 19)
    man = archive.manifest(
        {"index_base": "wazuh-web", "period": "2026-05",
         "indices": ["wazuh-web-2026.05.01"]},
        {"documents": 3, "plain_bytes": 30, "object_bytes": 10,
         "sha256_plain": "a" * 64, "sha256_encrypted": "b" * 64},
        "v1/wazuh-web/2026/wazuh-web.2026-05.ndjson.zst.age")
    assert man["sha256_plain"] == "a" * 64
    assert man["destinataires_age"] == ["age1abc"]
    assert "zstd -19" in man["chain"] and "age -r age1abc" in man["chain"]
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
    monkeypatch.setattr(config, "ARCHIVE_OBJECT_LOCK_DAYS", 365)
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
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", False)
    assert archive.run() == {"etat": "désactivé"}
    assert archive.indices_at_risk(None) == []
    assert archive.anomalies(None) == []


# --------------------------------------------------------------------------
# Anomalies remontées au watchdog
# --------------------------------------------------------------------------

class _Conn:
    """Bouchon minimal : `execute(...).fetchall()`."""

    def __init__(self, lines):
        self._lines = lines

    def execute(self, sql, params=None):
        self._sql = sql
        return self

    def fetchall(self):
        return self._lines


def test_trou_de_couverture_detecte(monkeypatch):
    """Un mois absent ENTRE deux mois archivés : les index d'origine sont purgés
    depuis longtemps, la donnée n'existe plus nulle part, et rien ne l'avait dit
    au moment où elle partait."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [])
    conn = _Conn([
        {"index_base": "wazuh-web", "period": "2026-01",
         "verified_at": None, "verify_state": "ok"},
        {"index_base": "wazuh-web", "period": "2026-03",
         "verified_at": None, "verify_state": "ok"},
    ])
    gaps = [a for a in archive.anomalies(conn)
             if a["sensor"].endswith("trou")]
    assert len(gaps) == 1
    assert "2026-02" in gaps[0]["note"]
    assert gaps[0]["severity"] == "Medium"


def test_serie_recente_sans_passe_n_est_pas_un_trou(monkeypatch):
    """Un index set créé le mois dernier n'a pas de trou : il a un passé qui
    n'existe pas. Confondre les deux ouvrirait un dossier à chaque création
    d'index set — et routage.py en crée jusqu'à deux par jour."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [])
    conn = _Conn([{"index_base": "wazuh-jellyfin", "period": "2026-07",
                   "verified_at": None, "verify_state": "ok"}])
    assert not [a for a in archive.anomalies(conn)
                if a["sensor"].endswith("trou")]


def test_drill_en_echec_remonte_en_high(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [])
    conn = _Conn([{"index_base": "wazuh-web", "period": "2026-01",
                   "verified_at": None, "verify_state": "sha256-divergent"}])
    failures = [a for a in archive.anomalies(conn)
              if a["sensor"].endswith("drill")]
    assert len(failures) == 1 and failures[0]["severity"] == "High"


def test_peril_remonte_en_high_avec_le_delai_restant(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [
        {"index": "wazuh-web-2026.05.02", "documents": 12,
         "age_jours": 85, "supprime_dans": 5}])
    conn = _Conn([])
    risk = [a for a in archive.anomalies(conn)
             if a["sensor"].endswith("peril")]
    assert len(risk) == 1
    assert risk[0]["severity"] == "High"
    assert "wazuh-web-2026.05.02" in risk[0]["note"]
    assert "5 j" in risk[0]["note"]


def test_capteurs_prefixes_pour_le_watchdog(monkeypatch):
    """Le watchdog reconnaît ces pseudo-capteurs par leur PRÉFIXE pour les
    mesurer contre l'horloge et non contre l'horizon d'ingestion."""
    from soc_agent import watchdog
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(archive, "indices_at_risk", lambda conn: [
        {"index": "i-2026.05.02", "documents": 1, "age_jours": 85,
         "supprime_dans": 5}])
    for a in archive.anomalies(_Conn([])):
        assert a["sensor"].startswith(archive.PREFIX_SENSOR)
        assert watchdog._is_archiving(a["sensor"])
        assert watchdog._outside_pipeline(a["sensor"])
        # `titre`, `note` et `severite` sont ce que le watchdog consomme sans
        # cas particulier (cf. watchdog._rendu / _titre / _severite_panne).
        assert a["titre"] and a["note"] and a["severity"]
        assert watchdog._title(a) == a["titre"]
        assert watchdog._rendered(a, 0, markdown=False) == a["note"]
        assert watchdog._outage_severity(a["sensor"], a) == a["severity"]


# --------------------------------------------------------------------------
# Sélection des lots et péril de purge
# --------------------------------------------------------------------------

def _fake_indices(*specs):
    """(index_base, 'AAAA-MM', nb_jours, docs_par_jour) -> liste d'index datés."""
    out = []
    for base, month, n, docs in specs:
        a, m = month.split("-")
        for j in range(1, n + 1):
            out.append({"index": f"{base}-{a}.{m}.{j:02d}", "base": base,
                        "day": date(int(a), int(m), j), "mois": month,
                        "documents": docs, "octets": docs * 1000})
    return out


def test_lots_ignorent_le_mois_en_cours(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-firewall", "2026-05", 3, 100),
        ("wazuh-firewall", "2026-08", 2, 50),   # mois en cours
        ("wazuh-web", "2026-05", 1, 7)))
    batches = archive.batches_to_archive(_Conn([]), date(2026, 8, 14))
    assert [(l["index_base"], l["period"]) for l in batches] == [
        ("wazuh-firewall", "2026-05"), ("wazuh-web", "2026-05")]
    # Les jours du mois sont regroupés en UN lot, documents cumulés.
    assert batches[0]["documents"] == 300 and len(batches[0]["indices"]) == 3


def test_lot_deja_archive_ne_revient_pas(monkeypatch):
    """Sans ça, chaque passage réexporterait et repaierait tout l'historique —
    le bug des pièces Evidence d'IRIS, transposé à S3."""
    monkeypatch.setattr(config, "ARCHIVE_DELAY_DAYS", 2)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-firewall", "2026-05", 3, 100),
        ("wazuh-web", "2026-05", 1, 7)))
    conn = _Conn([{"index_base": "wazuh-firewall", "period": "2026-05"}])
    batches = archive.batches_to_archive(conn, date(2026, 8, 14))
    assert [(l["index_base"], l["period"]) for l in batches] == [
        ("wazuh-web", "2026-05")]


def test_peril_borne_a_la_marge_avant_suppression(monkeypatch):
    """Un index jeune sans archive n'est pas en péril — il a le temps. Confondre
    les deux ouvrirait un dossier High tous les jours, pour rien."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(config, "RETENTION_INDEX_DAYS", 90)
    monkeypatch.setattr(config, "ARCHIVE_MARGIN_DAYS", 7)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-web", "2026-05", 1, 7),      # 105 j -> en péril
        ("wazuh-web", "2026-08", 1, 7)))     # 13 j  -> tranquille
    risk = archive.indices_at_risk(_Conn([]), date(2026, 8, 14))
    assert [i["index"] for i in risk] == ["wazuh-web-2026.05.01"]
    assert risk[0]["age_jours"] == 105


def test_peril_tombe_quand_l_archive_existe(monkeypatch):
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)
    monkeypatch.setattr(config, "RETENTION_INDEX_DAYS", 90)
    monkeypatch.setattr(config, "ARCHIVE_MARGIN_DAYS", 7)
    monkeypatch.setattr(archive, "dated_indices", lambda: _fake_indices(
        ("wazuh-web", "2026-05", 1, 7)))
    conn = _Conn([{"index_base": "wazuh-web", "period": "2026-05"}])
    assert archive.indices_at_risk(conn, date(2026, 8, 14)) == []


# --------------------------------------------------------------------------
# Le verrou ne doit pas masquer l'erreur qui a interrompu le passage
# --------------------------------------------------------------------------

class _AbortedConn:
    """Connexion dont la transaction est avortée : tout `execute` échoue.

    Reproduit l'état réel de Postgres après une requête en erreur — c'est ce que
    la prod a rencontré au premier passage, table `archives_s3` absente.
    """

    def __init__(self):
        self.rollback_called = False

    def execute(self, sql, params=None):
        if not self.rollback_called:
            raise RuntimeError("current transaction is aborted")

        class R:
            @staticmethod
            def fetchone():
                return {"pg_advisory_unlock": True}
        return R()

    def rollback(self):
        self.rollback_called = True


def test_deverrouillage_ne_masque_pas_la_cause():
    """Sans rollback préalable, l'UNLOCK lève `InFailedSqlTransaction` et cette
    seconde exception REMPLACE la première : la trace ne dit plus ce qui
    n'allait pas. Arrivé en prod, où le diagnostic utile (« il manque une
    table ») était devenu invisible sous une erreur de transaction."""
    conn = _AbortedConn()
    archive._unlock(conn)          # ne doit RIEN lever
    assert conn.rollback_called, "rollback non tenté avant l'unlock"


def test_deverrouillage_survit_a_une_connexion_morte():
    """Un verrou de session est rendu à la fermeture de la connexion : échouer
    ici est sans conséquence, alors que propager l'échec masquerait la cause."""
    class _Dead:
        def rollback(self):
            raise OSError("connexion fermée")

        def execute(self, *a):
            raise OSError("connexion fermée")

    archive._unlock(_Dead())      # ne doit RIEN lever


def test_erreur_de_table_absente_remonte_telle_quelle(monkeypatch):
    """Le bout à bout du scénario de prod : ce qui doit sortir de `tourner`,
    c'est la cause réelle, pas l'erreur de transaction du nettoyage."""
    monkeypatch.setattr(config, "ARCHIVING_ENABLED", True)

    class _Conn(_AbortedConn):
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
    monkeypatch.setattr(archive, "batches_to_archive", lambda conn: (_ for _ in ()).throw(
        RuntimeError('relation "archives_s3" does not exist')))
    with pytest.raises(RuntimeError, match="archives_s3"):
        archive.run()


# --------------------------------------------------------------------------
# Intégrité : un export partiel ne doit JAMAIS devenir une archive
# --------------------------------------------------------------------------

class _Response:
    def __init__(self, body, ok=True, status=200):
        self._body, self.ok, self.status_code = body, ok, status
        self.text = json.dumps(body)

    def json(self):
        return self._body


def _page(hits, failed=0, total_shards=3, timed_out=False, total=None,
          scroll="s1"):
    return {
        "_scroll_id": scroll,
        "timed_out": timed_out,
        "_shards": {"total": total_shards, "successful": total_shards - failed,
                    "skipped": 0, "failed": failed,
                    "failures": [{"index": "wazuh-web-2026.03.01",
                                  "reason": {"reason": "shard indisponible"}}]
                    if failed else []},
        "hits": {"total": {"value": total if total is not None else len(hits),
                           "relation": "eq"},
                 "hits": hits},
    }


def _hit(n):
    return {"_index": "wazuh-web-2026.03.01", "_id": f"i{n}", "_source": {"n": n}}


def test_shard_en_echec_refuse_des_la_premiere_page(monkeypatch):
    """OpenSearch répond HTTP 200 avec des résultats PARTIELS quand un shard
    tombe : l'échec est dans `_shards.failed`, pas dans le code HTTP. Sans ce
    contrôle, l'archive enregistre son propre compte tronqué comme référence et
    tout le reste (manifeste, SHA-256, drill, adoption) est d'accord avec elle."""
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: _Response(_page([_hit(0)], failed=1)))
    with pytest.raises(RuntimeError, match="export partiel refusé"):
        list(archive.pages(["wazuh-web-2026.03.01"]))


def test_shard_en_echec_refuse_en_COURS_de_scroll(monkeypatch):
    """Un scroll dure plusieurs minutes : un shard peut tomber APRÈS la première
    page, et la page concernée revient simplement plus courte."""
    responses = [_Response(_page([_hit(0)], total=2)),
                _Response(_page([_hit(1)], failed=1, total=2))]
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: responses.pop(0) if responses
                        else _Response(_page([])))
    with pytest.raises(RuntimeError, match="export partiel refusé"):
        list(archive.pages(["wazuh-web-2026.03.01"]))


def test_recherche_expiree_refusee(monkeypatch):
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: _Response(_page([_hit(0)], timed_out=True)))
    with pytest.raises(RuntimeError, match="recherche expirée"):
        list(archive.pages(["wazuh-web-2026.03.01"]))


def test_total_exact_demande_a_l_indexer(monkeypatch):
    """Sans `track_total_hits`, OpenSearch plafonne le total à 10 000 et rend
    `relation: gte` : on prendrait un plafond pour un total, et la vérification
    de complétude validerait n'importe quel export de plus de 10 000 documents."""
    assert archive._body_search(500)["track_total_hits"] is True
    control = {}
    responses = [_Response(_page([_hit(0)], total=4200)), _Response(_page([]))]
    monkeypatch.setattr(archive, "_indexer",
                        lambda *a, **k: responses.pop(0) if responses
                        else _Response(_page([])))
    list(archive.pages(["wazuh-web-2026.03.01"], control=control))
    assert control == {"attendu": 4200, "relation": "eq"}


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_export_tronque_refuse_et_fichier_supprime(tmp_path, monkeypatch):
    """Le scroll s'arrête avant la fin : moins de documents écrits qu'annoncés.
    L'archive doit être REFUSÉE et le fichier supprimé — c'est exactement le cas
    qui produisait une copie tronquée se croyant complète."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))

    def _pages(indices, size=None, control=None):
        if control is not None:
            control["attendu"] = 1000      # l'indexer en annonce 1000...
        yield [_hit(n) for n in range(10)]  # ...on n'en reçoit que 10
    monkeypatch.setattr(archive, "pages", _pages)

    object_path = tmp_path / "a.ndjson.zst.age"
    with pytest.raises(RuntimeError, match="export INCOMPLET refusé"):
        archive.export({"indices": ["i"], "octets": 1,
                          "index_base": "wazuh-web", "period": "2026-03"}, object_path)
    assert not object_path.exists(), "le fichier tronqué a été conservé"


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_export_complet_accepte(tmp_path, monkeypatch):
    """Le cas nominal doit continuer de passer : autant de documents qu'annoncé."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))

    def _pages(indices, size=None, control=None):
        if control is not None:
            control["attendu"] = 10
        yield [_hit(n) for n in range(10)]
    monkeypatch.setattr(archive, "pages", _pages)

    m = archive.export({"indices": ["i"], "octets": 1,
                          "index_base": "wazuh-web", "period": "2026-03"},
                         tmp_path / "a.age")
    assert m["documents"] == 10


@pytest.mark.skipif(not _TOOLS, reason="zstd/age absents de cet environnement")
def test_surplus_accepte_car_sans_perte(tmp_path, monkeypatch):
    """Écrit en PLUS qu'annoncé n'est pas une perte : au pire un doublon. On
    conserve et on journalise, plutôt que de jeter une archive valide."""
    _keyfile(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ARCHIVE_ZSTD_LEVEL", 3)
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))

    def _pages(indices, size=None, control=None):
        if control is not None:
            control["attendu"] = 5
        yield [_hit(n) for n in range(10)]
    monkeypatch.setattr(archive, "pages", _pages)

    m = archive.export({"indices": ["i"], "octets": 1,
                          "index_base": "wazuh-web", "period": "2026-03"},
                         tmp_path / "a.age")
    assert m["documents"] == 10


# --------------------------------------------------------------------------
# Ménage des résidus d'un passage tué (SIGKILL : aucun `finally` ne tourne)
# --------------------------------------------------------------------------

def test_balayage_supprime_les_residus_vieux_pas_les_recents(tmp_path, monkeypatch):
    import os as _os
    monkeypatch.setattr(config, "ARCHIVE_TMP_DIR", str(tmp_path))
    old = tmp_path / "aura-archive-abandonne"
    old.mkdir()
    (old / "objet").write_bytes(b"x" * 4096)
    _os.utime(old, (0, 0))                       # laissé il y a longtemps
    recent = tmp_path / "aura-drill-en-cours"      # peut appartenir à un drill
    recent.mkdir()
    foreign = tmp_path / "autre-chose"            # pas à nous
    foreign.mkdir()

    r = archive.sweep_temporary(age_hours=2)
    assert r["repertoires"] == 1 and r["octets"] >= 4096
    assert not old.exists()
    assert recent.exists() and foreign.exists()


def test_multiparts_inacheves_avortes_sauf_les_recents():
    """Les parties d'un multipart interrompu sont FACTURÉES et n'apparaissent
    dans aucun list_objects. Mais un upload récent peut être en cours."""
    from datetime import timedelta as _td
    maintenant = datetime.now(timezone.utc)
    aborted = []

    class _S3:
        @staticmethod
        def list_multipart_uploads(Bucket):
            return {"Uploads": [
                {"Key": "v1/a.age", "UploadId": "u1",
                 "Initiated": maintenant - _td(days=3)},
                {"Key": "v1/b.age", "UploadId": "u2",
                 "Initiated": maintenant - _td(minutes=5)},
            ]}

        @staticmethod
        def abort_multipart_upload(Bucket, Key, UploadId):
            aborted.append(Key)

    r = archive.abort_multiparts(_S3(), age_hours=24)
    assert r["avortes"] == ["v1/a.age"] and r["en_cours_ignores"] == 1
    assert aborted == ["v1/a.age"]


def test_multiparts_non_listables_ne_bloquent_pas():
    """Une clé applicative sans le droit de lister ne doit pas empêcher
    d'archiver : ne pas archiver du tout est une bien pire réponse."""
    class _S3:
        @staticmethod
        def list_multipart_uploads(Bucket):
            raise Exception("AccessDenied")

    assert "indéterminé" in archive.abort_multiparts(_S3())["etat"]
