"""Tests du watchdog « capteur muet » (sans base ni IRIS).

Ce qui est testé ici est la partie qui décide : le seuil retenu par capteur, la
mise en forme de la durée et le contenu du dossier. La requête SQL, elle, est
couverte par son usage réel — elle n'a pas de branche.
"""

from datetime import datetime, timedelta, timezone

from soc_agent import config
from soc_agent.watchdog import _duree, _minutes, _note_panne


def _muet(capteur="suricata", minutes=42, agent="008", nom="home-r-pf01"):
    return {
        "agent_id": agent, "agent_name": nom, "capteur": capteur,
        "volume": 2134,
        "dernier": datetime.now(timezone.utc) - timedelta(minutes=minutes),
        "seuil": config.WATCHDOG_SILENCE_PAR_CAPTEUR.get(
            capteur, config.WATCHDOG_SILENCE_MINUTES),
    }


def test_seuil_par_defaut_est_dix_minutes():
    """Réglage opérateur du 2026-08-11 : une panne, c'est 10 minutes de silence.
    Vaut pour les capteurs CONTINUS, dont l'écart p95 mesuré est de 5,4 min
    (audit) et 0 min (suricata)."""
    assert config.WATCHDOG_SILENCE_MINUTES == 10


def test_capteurs_evenementiels_ont_un_seuil_propre():
    """sshd et syscheck n'émettent que sur évènement : leur silence est normal.
    Au seuil de 10 min, toute machine au repos serait déclarée en panne."""
    par = config.WATCHDOG_SILENCE_PAR_CAPTEUR
    assert par["sshd"] > config.WATCHDOG_SILENCE_MINUTES * 100
    assert par["syscheck"] > config.WATCHDOG_SILENCE_MINUTES * 50
    # Les capteurs continus, eux, ne doivent PAS avoir de dérogation.
    assert "suricata" not in par and "audit" not in par


def test_duree_lisible():
    assert _duree(12) == "12 min"
    assert _duree(89) == "89 min"
    assert _duree(150) == "2 h 30"
    assert _duree(60 * 50) == "2 j 2 h"


def test_minutes_depuis_un_horodatage():
    assert _minutes(datetime.now(timezone.utc) - timedelta(minutes=30)) == 30


def test_note_porte_le_diagnostic_et_la_portee():
    """Le dossier doit dire CE QUI N'EST PLUS DÉTECTÉ : un analyste qui lit
    « suricata muet » ne connaît pas par cœur le ruleset adossé."""
    note = _note_panne(_muet(), 42)
    assert "42 min" in note
    assert "home-r-pf01" in note
    assert "détection réseau" in note
    assert "plusieurs" in note          # le piège des logcollector empilés
    assert "isolé" in note              # la fausse panne d'un hôte confiné


def test_note_couvre_chaque_capteur_surveille():
    """Tout capteur surveillé doit avoir une portée rédigée, sinon le dossier
    sort avec un texte générique inutilisable."""
    from soc_agent.watchdog import _PORTEE
    for capteur in config.WATCHDOG_CAPTEURS:
        assert capteur in _PORTEE, capteur
