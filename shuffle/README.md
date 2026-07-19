# Shuffle SOAR — remédiation

Orchestration des remédiations SOC via [Shuffle](https://shuffler.io). Première remédiation implémentée : **isolation réseau d'un hôte** (active response Wazuh, nftables).

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

Déclenchement (décision humaine — jamais automatique, cf. CLAUDE.md) :

```bash
# Isoler l'agent 001
curl -X POST http://localhost:5001/api/v1/hooks/webhook_<WEBHOOK_ID> \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!host-isolate.sh", "reason": "compromission suspectée"}'

# Dé-isoler
curl -X POST http://localhost:5001/api/v1/hooks/webhook_<WEBHOOK_ID> \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!host-unisolate.sh", "reason": "incident clos"}'
```

## Côté agent (prérequis)

Scripts active response déployés sur l'agent Linux (voir `wazuh/active-response/`) :

```bash
scp wazuh/active-response/host-*.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g wazuh -m 750 /tmp/host-*.sh /var/ossec/active-response/bin/'
```

`host-isolate.sh` pose une table nftables `wazuh_isolation` (priorité -50, policy drop) qui coupe tout le trafic **sauf** :

- loopback
- connexions établies + agent → manager (1514/1515) — l'agent reste pilotable
- SSH entrant depuis le serveur Wazuh — administration / dé-isolation garanties

`host-unisolate.sh` supprime la table. Les deux loggent dans `/var/ossec/logs/active-responses.log` (remonté au manager via localfile).

Les commandes `host-isolate` / `host-unisolate` sont déclarées dans `wazuh_manager.conf` ; l'appel API utilise la forme directe `!host-isolate.sh`.

## Testé (2026-07-19)

Bout-en-bout sur agent `001 debian-vm` (Debian 12, libvirt) : webhook → Shuffle → API Wazuh → AR → isolation effective (ping et sortie internet bloqués, agent toujours Active, SSH admin conservé) → dé-isolation → réseau rétabli.
