#!/usr/bin/env python3
"""Inserts the Windows/AD active-response commands into wazuh_manager.conf.

This file is gitignored (it carries the VirusTotal / AbuseIPDB API keys): it
cannot be deployed via `git pull` and must be edited in place. So we insert
the missing blocks at anchors, without rewriting the rest - the production
copy contains settings absent elsewhere (allowed-ips of the YARITRUST scanner).

Idempotent: does nothing if `win-kill-process` is already declared.
"""
import shutil
import sys
import time

PATH = sys.argv[1] if len(sys.argv) > 1 else \
    "/opt/AURA/src/wazuh/config/wazuh_cluster/wazuh_manager.conf"

ACTIONS = [
    "win-host-isolate", "win-host-unisolate", "win-kill-process",
    "win-quarantine-file", "win-restore-file", "win-block-ip", "win-allow-ip",
    "ad-disable-account", "ad-enable-account", "ad-remove-group-member",
    "ad-add-group-member",
]

HEADER = """
  <!--
    ===== Windows / Active Directory active response =====

    These eleven commands were missing, and that is what made ALL Windows
    remediation inoperative. The manager generates `shared\\ar.conf` from the
    <command> + <active-response> blocks below and pushes it to the agents;
    the agent's execd refuses any command absent from this file, without
    logging anything. The API still replies 200 (it only forwards) so
    soc-agent recorded the remediation as having run.

    Consequence measured during a purple-team exercise: dozens of Windows
    actions on the same day - including disabling an account created by the
    attacker and quarantining mimikatz - executed strictly nothing. Checked
    afterward on the domain controller: the account still active,
    `active-responses.log` without a single line from our scripts. The
    initial diagnosis ("rejected by the script's safelist") was wrong: they
    never reached the script.

    The blocks lived in src/wazuh/active-response/windows/register-commands.xml,
    which already documented this trap, but had never been carried over here.
    Since this file is gitignored (API keys), they are placed here by
    scripts/patch-manager-ar-windows.py.
  -->
"""

CMD = """  <command>
    <name>{n}</name>
    <executable>{n}.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

"""

AR = """  <active-response>
    <disabled>no</disabled>
    <command>{n}</command>
    <location>local</location>
    <rules_id>999999</rules_id>
  </active-response>

"""

src = open(PATH, encoding="utf-8").read()
if "win-kill-process" in src:
    print("already present, nothing to do")
    sys.exit(0)

# Anchor 1: right after the <command> block of host-allow.
cmd_anchor = """  <command>
    <name>host-allow</name>
    <executable>host-allow.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
"""
if cmd_anchor not in src:
    sys.exit("host-allow <command> anchor not found - unexpected file")
src = src.replace(
    cmd_anchor,
    cmd_anchor + HEADER + "".join(CMD.format(n=n) for n in ACTIONS), 1)

# Anchor 2: right after the <active-response> block of host-allow.
ar_anchor = """  <active-response>
    <disabled>no</disabled>
    <command>host-allow</command>
    <location>local</location>
    <rules_id>999999</rules_id>
  </active-response>
"""
if ar_anchor not in src:
    sys.exit("host-allow <active-response> anchor not found - unexpected file")
src = src.replace(
    ar_anchor,
    ar_anchor + "\n  <!-- Windows / AD. Same nonexistent rule 999999: no "
    "automatic\n       trigger, only the API call (soc-agent, MCP) "
    "executes the action. -->\n"
    + "".join(AR.format(n=n) for n in ACTIONS), 1)

# Validate BEFORE writing: a broken file here prevents the manager from
# starting. Comments are stripped before parsing, because the production
# conf contains one with "--remote": illegal in strict XML, tolerated by
# Wazuh's parser. We validate the tag structure, not comment typography.
import re
import xml.etree.ElementTree as ET

without_comments = re.sub(r"<!--.*?-->", "", src, flags=re.DOTALL)
try:
    ET.fromstring("<root>" + without_comments + "</root>")
except ET.ParseError as e:
    sys.exit(f"invalid XML after insertion, nothing written: {e}")

shutil.copy2(PATH, f"{PATH}.bak.{int(time.time())}")
open(PATH, "w", encoding="utf-8").write(src)
print(f"{len(ACTIONS)} commands + {len(ACTIONS)} active-response inserted, "
      "XML structure validated")
