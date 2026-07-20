# Shuffle SOAR — remédiation

Orchestration des remédiations SOC via [Shuffle](https://shuffler.io). Remédiations implémentées : **isolation réseau d'un hôte** (nftables) et **kill d'un process** (pkill), toutes deux via active response Wazuh.

## Setup

```bash
cd shuffle
cp .env.example .env     # remplir (mots de passe / clé API aléatoires)
docker compose up -d
```

- UI : http://localhost:3001 — API : http://localhost:5001
- Premier compte admin : `POST /api/v1/users/register` avec `{"username": ..., "password": ...}` (retourne l'apikey), ou via l'UI.

## Workflow « Wazuh - Host Isolation »

```
Webhook ──► auth_wazuh (POST /security/user/authenticate?raw=true)
                 │ token
                 ▼
        run_active_response (PUT /active-response?agents_list=<agent_id>)
```

Workflow id `a1697bc2-596d-4f87-ac9b-4b3fa1ab6c9c`, webhook `webhook_00000000-0000-0000-0000-00000000a001`.

Déclenchement (décision humaine — jamais automatique, cf. CLAUDE.md) :

```bash
# Isoler l'agent 001
curl -X POST http://localhost:5001/api/v1/hooks/webhook_00000000-0000-0000-0000-00000000a001 \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!host-isolate.sh", "reason": "compromission suspectée"}'

# Dé-isoler
curl -X POST http://localhost:5001/api/v1/hooks/webhook_00000000-0000-0000-0000-00000000a001 \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!host-unisolate.sh", "reason": "incident clos"}'
```

## Workflow « Wazuh - Kill Process »

Même schéma que l'isolation (webhook → auth_wazuh → run_active_response), mais l'AR command passe le nom **exact** du process (comm, `pkill -x` — pas un pattern substring) en `extra_args`.

Workflow id `f66a08ef-dfbc-496f-a3fe-8f5f2b30572b`, webhook `webhook_00000000-0000-0000-0000-00000000a002`.

```bash
# Tuer le process "malware_bin" sur l'agent 001
curl -X POST http://localhost:5001/api/v1/hooks/webhook_00000000-0000-0000-0000-00000000a002 \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!kill-process.sh", "extra_args": "malware_bin", "reason": "process suspect détecté"}'
```

`extra_args` est une chaîne simple (pas un tableau) — le body Shuffle (`"arguments": ["$exec.extra_args"]`) l'encapsule déjà dans le tableau attendu par l'API Wazuh.

Action irréversible (pas d'« unkill ») — le script refuse de tuer les process de la safelist (`sshd`, `wazuh-agentd`, `systemd`, etc., voir `kill-process.sh`) pour ne pas se couper de l'agent.

## Côté agent (prérequis)

Scripts active response déployés sur l'agent Linux (voir `wazuh/active-response/`) :

```bash
scp wazuh/active-response/host-*.sh wazuh/active-response/kill-process.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g wazuh -m 750 /tmp/host-*.sh /tmp/kill-process.sh /var/ossec/active-response/bin/'
```

`host-isolate.sh` pose une table nftables `wazuh_isolation` (priorité -50, policy drop) qui coupe tout le trafic **sauf** :

- loopback
- connexions établies + agent → manager (1514/1515) — l'agent reste pilotable
- SSH entrant depuis le serveur Wazuh — administration / dé-isolation garanties

`host-unisolate.sh` supprime la table. Les deux loggent dans `/var/ossec/logs/active-responses.log` (remonté au manager via localfile).

Les commandes `host-isolate` / `host-unisolate` sont déclarées dans `wazuh_manager.conf` ; l'appel API utilise la forme directe `!host-isolate.sh`.

## Testé

**2026-07-19** — Bout-en-bout sur agent `001 debian-vm` (Debian 12, libvirt) : webhook → Shuffle → API Wazuh → AR → isolation effective (ping et sortie internet bloqués, agent toujours Active, SSH admin conservé) → dé-isolation → réseau rétabli.

**2026-07-20** — Bout-en-bout kill-process sur agent `001 debian-vm` : webhook → Shuffle → API Wazuh → AR → `kill-process.sh` exécuté sur l'agent (log `active-responses.log` confirmé). Safelist validée (`sshd` refusé), `pkill -x` validé exact-match (process `testproc` tué, `testproc-decoy` au nom proche épargné).
