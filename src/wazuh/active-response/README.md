# Aura-SOC active response

Remediation scripts executed **on the agent**, called by the Wazuh API, the
MCP server, or `src/ai/soc_agent/mitigate.py`.

## Why custom scripts

The native binaries shipped with the package (`firewall-drop`, `disable-account`, …)
read the target **from the alert** (`alert.data.srcip`, `alert.data.dstuser`) and
fail on any driven call, which passes the target via `extra_args`
("Cannot read 'srcip' from data"). These scripts read `extra_args[0]` instead.

Each action has its inverse, in pairs: `firewall-drop.sh` / `firewall-allow.sh`,
`disable-account.sh` / `enable-account.sh`, `host-isolate.sh` /
`host-unisolate.sh`. `kill-process.sh` has none (no "unkill").

## Deployment — mandatory, and fails silently

The scripts must be present in `/var/ossec/active-response/bin/` on
**every agent** (root:wazuh, 750). `install-agent.sh` handles this at
install time; for an agent already in place:

```sh
./scripts/deploy-active-response.sh <agent-ip> [<agent-ip> ...]
```

Without these files, **every remediation fails without reporting anything**:
the `ar.conf` pushed by the manager does declare `firewall-drop.sh`, the Wazuh
API responds `200` (it only forwards the command to the agent), and nothing
runs. The only clue is the absence of a line in the agent's
`/var/ossec/logs/active-responses.log`. This is what can make IP blocking
silently inoperative if deploying the scripts was forgotten.

## Calling

The `!` prefix is **mandatory**: it designates the literal **file** name and
bypasses resolution through `ossec.conf`'s `<command>`.

```sh
curl -sk -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -X PUT "https://127.0.0.1:55000/active-response?agents_list=003" \
  -d '{"command":"!firewall-drop.sh","arguments":["198.51.100.77"]}'
```

Without the `!`, the API looks for a `<command>` in `ossec.conf` and may respond
`1652 The command used is not defined in the configuration`.

## Firewall: iptables or nftables

`firewall-drop.sh` / `firewall-allow.sh` use `iptables` when present, otherwise
**nftables** (dedicated table `inet soc_ai_block`, chain `input`
priority -10). The fallback is necessary: some recent Debian 12 hosts only
ship `nft`, without the iptables shim.

The table is **distinct** from `wazuh_isolation` (`host-isolate.sh`): a
de-isolation removes its entire table and must not take the separately-set IP
blocks down with it.

## End-to-end verification

Never trust the `mitigations` table nor the API's return code. Read the
actual state of the host:

```sh
tail /var/ossec/logs/active-responses.log
iptables -S INPUT           # or: nft list table inet soc_ai_block
chage -l <user>             # disable-account
nft list table inet wazuh_isolation   # isolation
```
