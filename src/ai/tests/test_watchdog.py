"""Tests du watchdog « capteur muet » (sans base ni IRIS).

Ce qui est testé ici est la partie qui décide : le seuil retenu par capteur, la
mise en forme de la durée et le contenu du dossier. La requête SQL, elle, est
couverte par son usage réel — elle n'a pas de branche.
"""

from datetime import datetime, timedelta, timezone

from soc_agent import config
from soc_agent import watchdog
from soc_agent.watchdog import _duration, _minutes, _outage_note


def _silent(sensor="suricata", minutes=42, agent="008", name="home-r-pf01"):
    return {
        "agent_id": agent, "agent_name": name, "sensor": sensor,
        "volume": 2134,
        "dernier": datetime.now(timezone.utc) - timedelta(minutes=minutes),
        "seuil": config.WATCHDOG_SILENCE_PER_SENSOR.get(
            sensor, config.WATCHDOG_SILENCE_MINUTES),
    }


def test_seuil_par_defaut_est_dix_minutes():
    """Réglage opérateur du 2026-08-11 : une panne, c'est 10 minutes de silence.
    Vaut pour les capteurs CONTINUS, dont l'écart p95 mesuré est de 5,4 min
    (audit) et 0 min (suricata)."""
    assert config.WATCHDOG_SILENCE_MINUTES == 10


def test_capteurs_evenementiels_ont_un_seuil_propre():
    """sshd et syscheck n'émettent que sur évènement : leur silence est normal.
    Au seuil de 10 min, toute machine au repos serait déclarée en panne."""
    by = config.WATCHDOG_SILENCE_PER_SENSOR
    assert by["sshd"] > config.WATCHDOG_SILENCE_MINUTES * 100
    assert by["syscheck"] > config.WATCHDOG_SILENCE_MINUTES * 300
    # Les capteurs continus, eux, ne doivent PAS avoir de dérogation.
    assert "suricata" not in by and "audit" not in by


def test_duree_lisible():
    assert _duration(12) == "12 min"
    assert _duration(89) == "89 min"
    assert _duration(150) == "2 h 30"
    assert _duration(60 * 50) == "2 j 2 h"


def test_minutes_depuis_un_horodatage():
    assert _minutes(datetime.now(timezone.utc) - timedelta(minutes=30)) == 30


def test_note_porte_le_diagnostic_et_la_portee():
    """Le dossier doit dire CE QUI N'EST PLUS DÉTECTÉ : un analyste qui lit
    « suricata muet » ne connaît pas par cœur le ruleset adossé."""
    note = _outage_note(_silent(), 42)
    assert "42 min" in note
    assert "home-r-pf01" in note
    assert "détection réseau" in note
    assert "plusieurs" in note          # le piège des logcollector empilés
    assert "isolé" in note              # la fausse panne d'un hôte confiné


def test_note_couvre_chaque_capteur_surveille():
    """Tout capteur surveillé doit avoir une portée rédigée, sinon le dossier
    sort avec un texte générique inutilisable."""
    from soc_agent.watchdog import _SCOPE
    for sensor in config.WATCHDOG_SENSORS:
        assert sensor in _SCOPE, sensor


def test_silence_mesure_contre_l_horizon_pas_l_horloge():
    """La base est alimentée par cycles de 5 min : mesurer contre l'horloge
    fabrique une panne à chaque intervalle. Mesuré le 2026-08-11 — `audit` et
    `suricata` déclarés en panne pour « 15 min » quatre minutes après un
    redémarrage des conteneurs, alors que les deux émettaient."""
    horizon = datetime.now(timezone.utc) - timedelta(minutes=14)
    last = horizon - timedelta(minutes=2)
    # Contre l'horloge : 16 min -> au-dessus du seuil, fausse panne.
    assert _minutes(last) > config.WATCHDOG_SILENCE_MINUTES
    # Contre l'horizon : 2 min -> rien à signaler.
    assert _minutes(last, horizon) < config.WATCHDOG_SILENCE_MINUTES


def test_seuil_retard_ingestion_couvre_plusieurs_cycles():
    """Le garde-fou anti-aveuglement ne doit pas se déclencher sur un cycle en
    retard : 300 s de cadence, il faut plusieurs cycles manqués."""
    assert config.WATCHDOG_INGEST_LAG_MAX >= 25


# ---------------------------------------------------------------------------
# Canal ALERTE (onglet Alerts d'IRIS)
# ---------------------------------------------------------------------------


class _Response:
    def __init__(self, data, ok=True, msg=""):
        self._data, self._ok, self._msg = data, ok, msg

    def is_success(self):
        return self._ok

    def get_data(self):
        return self._data

    def get_msg(self):
        return self._msg


class _FakeAlert:
    """Le strict nécessaire de `dfir_iris_client.alert.Alert` : ce qui est
    testé ici est le PAYLOAD qu'on envoie et la décision de refermer, pas le
    client IRIS."""

    def __init__(self, status="New", description="# Panne de capteur"):
        self.added, self.updates = [], []
        self._status, self._description = status, description

    def add_alert(self, data):
        self.added.append(data)
        return _Response({"alert_id": 77})

    def get_alert(self, alert_id):
        return _Response({"alert_description": self._description,
                         "status": {"status_name": self._status}})

    def update_alert(self, alert_id, data):
        self.updates.append((alert_id, data))
        return _Response({"alert_id": alert_id})


def _outage(sensor="suricata", status="open"):
    return {"id": 3, "agent_id": "008", "agent_name": "home-r-pf01",
            "sensor": sensor, "status": status,
            "detected_at": datetime.now(timezone.utc) - timedelta(hours=2),
            "last_event": datetime.now(timezone.utc) - timedelta(hours=3)}


def test_canal_par_defaut_est_l_alerte():
    """Une panne de capteur est un état à acquitter, pas une investigation :
    elle vit dans l'onglet Alerts, où l'analyste garde le choix d'escalader."""
    assert config.WATCHDOG_IRIS_CHANNEL == "alert"


def test_statuts_alerte_resolus_par_nom(monkeypatch):
    """Les ids de statut IRIS ne suivent aucun ordre logique (New=2 mais
    Unspecified=1, Closed=6) : les écrire en dur serait juste par hasard."""
    from soc_agent import watchdog
    monkeypatch.setattr(watchdog, "_STATUSES_ID", None)

    class _Session:
        def pi_get(self, uri):
            assert uri == "/manage/alert-status/list"
            return _Response([{"status_id": 42, "status_name": "Closed"},
                             {"status_id": 2, "status_name": "New"}])

    class _Alert:
        _s = _Session()

    # L'id vient du SERVEUR, pas de la table de repli (qui dit 6).
    assert watchdog._status_id(_Alert(), "Closed") == 42


def test_statuts_alerte_replient_si_iris_muet(monkeypatch):
    from soc_agent import watchdog
    monkeypatch.setattr(watchdog, "_STATUSES_ID", None)

    class _Alert:
        class _s:
            @staticmethod
            def pi_get(uri):
                raise RuntimeError("IRIS injoignable")

    assert watchdog._status_id(_Alert(), "New") == 2


def test_alerte_porte_source_reference_et_asset(monkeypatch):
    """La source filtre l'onglet, la référence identifie le couple
    (agent, capteur), l'asset regroupe les alertes d'une même machine et la
    suit si l'analyste escalade en case."""
    from soc_agent import watchdog
    fake = _FakeAlert()
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 2)
    monkeypatch.setattr(watchdog, "_alert_severity_id", lambda a, n: 5)

    assert watchdog._open_alert({**_silent(), "os": "pfSense 2.7"}, 42) == 77
    sent = fake.added[0]
    assert sent["alert_source"] == watchdog.SOURCE_ALERT
    assert sent["alert_source_ref"] == "capteur-008-suricata"
    assert sent["alert_classification_id"] == watchdog.CLASSIF_OUTAGE
    assert "détection réseau" in sent["alert_description"]
    assert (sent["alert_assets"][0]["asset_type_id"]
            == watchdog.ASSET_FIREWALL)


def test_severite_distingue_capteur_continu_et_evenementiel():
    """Un capteur continu muet est une perte de visibilité certaine ; un
    capteur événementiel sort sur un seuil de plusieurs heures et se trompe
    plus souvent."""
    from soc_agent.watchdog import _outage_severity
    assert _outage_severity("suricata") == "High"
    assert _outage_severity("syscheck") == "Medium"


def test_type_asset_par_defaut_ne_bloque_pas():
    from soc_agent.watchdog import (ASSET_LINUX_SERVER, ASSET_WIN_SERVER,
                                    _type_asset)
    assert _type_asset(None) == ASSET_LINUX_SERVER
    assert _type_asset("Microsoft Windows Server 2022") == ASSET_WIN_SERVER


def test_retablissement_referme_l_alerte(monkeypatch):
    from soc_agent import watchdog
    fake = _FakeAlert(status="New")
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 6)

    watchdog._close_alert(77, _outage(), 180)
    _, update = fake.updates[0]
    assert update["alert_status_id"] == 6
    assert "CAPTEUR RÉTABLI" in update["alert_description"]
    # La description d'origine est conservée : le diagnostic ne doit pas
    # disparaître au rétablissement.
    assert "# Panne de capteur" in update["alert_description"]


def test_alerte_escaladee_par_un_humain_nest_pas_refermee(monkeypatch):
    """L'analyste a jugé que la panne méritait un dossier : le watchdog
    l'informe du rétablissement, il ne referme pas à sa place. C'est ce que le
    canal `case` faisait mal."""
    from soc_agent import watchdog
    fake = _FakeAlert(status="Escalated")
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 6)

    watchdog._close_alert(77, _outage(), 180)
    _, update = fake.updates[0]
    assert "alert_status_id" not in update
    assert "CAPTEUR RÉTABLI" in update["alert_description"]


def test_echec_de_cloture_remonte(monkeypatch):
    """La panne doit rester OUVERTE en base pour être retentée : la marquer
    rétablie laisserait une alerte fantôme que plus rien ne referme."""
    import pytest

    from soc_agent import watchdog
    fake = _FakeAlert()
    fake.update_alert = lambda i, d: _Response(None, ok=False, msg="boom")
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 6)

    with pytest.raises(RuntimeError):
        watchdog._close_alert(77, _outage(), 180)


def test_description_d_alerte_est_en_texte_brut(monkeypatch):
    """L'onglet Alerts d'IRIS ne rend PAS le markdown (vérifié le 2026-08-13 :
    dièses, astérisques, backticks et tuyaux affichés littéralement). Un
    tableau markdown y devient six lignes de ferraille là où l'analyste
    cherche l'heure du dernier événement."""
    from soc_agent import watchdog
    fake = _FakeAlert()
    monkeypatch.setattr(watchdog, "_alert", lambda: fake)
    monkeypatch.setattr(watchdog, "_status_id", lambda a, n: 2)
    monkeypatch.setattr(watchdog, "_alert_severity_id", lambda a, n: 5)

    watchdog._open_alert({**_silent(), "os": "Debian 12"}, 42)
    desc = fake.added[0]["alert_description"]
    for scorie in ("**", "|---|", "`", "# "):
        assert scorie not in desc, scorie
    # Le contenu, lui, ne change pas d'un rendu à l'autre.
    assert "Dernier événement" in desc and "42 min" in desc
    assert "détection réseau" in desc


def test_note_de_case_reste_en_markdown():
    """Les NOTES de case, elles, sont bien rendues : on ne dégrade pas le
    dossier d'investigation pour aligner sur la limite de l'onglet Alerts."""
    note = _outage_note(_silent(), 42)
    assert note.startswith("# Panne de capteur")
    assert "|---|---|" in note


def test_rendu_brut_aligne_les_faits():
    """Sans tableau, l'alignement est la seule chose qui rend ces six lignes
    lisibles en un coup d'œil."""
    raw = _outage_note(_silent(), 42, markdown=False)
    columns = {line.index(":") for line in raw.splitlines()
                if line.startswith("  ") and ":" in line}
    assert len(columns) == 1


# --- garde-fou disque --------------------------------------------------------
#
# Le 2026-08-14, 6 Go/jour partaient sans que rien ne le signale. Le disque est
# traité comme un capteur : même état, même canal d'alerte, même clôture.

def _usage(total_go, pct):
    """Retour de shutil.disk_usage pour une occupation donnée."""
    total = int(total_go * 1073741824)
    used = int(total * pct / 100)
    return _NamedUsage(total=total, used=used, free=total - used)


class _NamedUsage:
    def __init__(self, total, used, free):
        self.total, self.used, self.free = total, used, free


def test_disque_sous_le_seuil_ne_dit_rien(monkeypatch):
    monkeypatch.setattr(watchdog.shutil, "disk_usage",
                        lambda p: _usage(148, 45))
    assert watchdog.disk_saturated() == []


def test_disque_au_dessus_du_seuil_sort_une_entree(monkeypatch):
    monkeypatch.setattr(watchdog.shutil, "disk_usage",
                        lambda p: _usage(148, 84))
    d = watchdog.disk_saturated()
    assert len(d) == 1
    assert d[0]["sensor"] == watchdog.SENSOR_DISK
    assert d[0]["pct"] == 84
    # Format d'un capteur muet : c'est ce qui lui permet de traverser la boucle
    # d'ouverture/clôture de `surveiller` sans cas particulier.
    assert {"agent_id", "agent_name", "sensor", "dernier", "horizon",
            "volume", "seuil"} <= set(d[0])


def test_severite_disque_suit_le_seuil_critique(monkeypatch):
    """Au seuil d'alerte il reste du temps pour agir, au seuil critique non."""
    monkeypatch.setattr(config, "DISK_THRESHOLD_CRITICAL", 90)
    assert watchdog._outage_severity(watchdog.SENSOR_DISK, {"pct": 84}) == "Medium"
    assert watchdog._outage_severity(watchdog.SENSOR_DISK, {"pct": 93}) == "High"


def test_note_disque_en_texte_brut_sans_markdown(monkeypatch):
    """L'onglet Alerts d'IRIS ne rend pas le markdown : la description ne doit
    porter ni dièse de titre, ni gras, ni backtick (cf. _note_panne)."""
    monkeypatch.setattr(watchdog.shutil, "disk_usage",
                        lambda p: _usage(148, 93))
    txt = watchdog._disk_note(watchdog.disk_saturated()[0], markdown=False)
    assert "DISQUE DU SOC SATURÉ" in txt
    assert "93 %" in txt
    assert "CRITIQUE" in txt
    for forbidden in ("# ", "**", "`"):
        assert forbidden not in txt


def test_duree_disque_mesuree_contre_l_horloge():
    """La saturation disque se mesure contre l'horloge, pas contre l'horizon
    d'ingestion : celui-ci est en retard par construction et produisait une
    durée NÉGATIVE dans l'alerte de rétablissement (« -2 min » en prod)."""
    start = datetime.now(timezone.utc) - timedelta(minutes=17)
    assert _minutes(start) == 17
    horizon_lagging = datetime.now(timezone.utc) - timedelta(minutes=19)
    assert _minutes(start, horizon_lagging) < 0
