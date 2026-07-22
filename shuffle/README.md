# Shuffle SOAR — remédiation

Orchestration des remédiations SOC via [Shuffle](https://shuffler.io). Remédiations implémentées : **isolation réseau d'un hôte** (nftables), **kill d'un process** (pkill) et **collecte forensique** (RAM + image disque), toutes via active response Wazuh.

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

Workflow id `a1697bc2-596d-4f87-ac9b-4b3fa1ab6c9c`, webhook `webhook_b755bdec-241d-47fd-9703-4405d9052066`.

Déclenchement (décision humaine — jamais automatique, cf. CLAUDE.md) :

```bash
# Isoler l'agent 001
curl -X POST http://localhost:5001/api/v1/hooks/webhook_b755bdec-241d-47fd-9703-4405d9052066 \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!host-isolate.sh", "reason": "compromission suspectée"}'

# Dé-isoler
curl -X POST http://localhost:5001/api/v1/hooks/webhook_b755bdec-241d-47fd-9703-4405d9052066 \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!host-unisolate.sh", "reason": "incident clos"}'
```

## Workflow « Wazuh - Kill Process »

Même schéma que l'isolation (webhook → auth_wazuh → run_active_response), mais l'AR command passe le nom **exact** du process (comm, `pkill -x` — pas un pattern substring) en `extra_args`.

Workflow id `f66a08ef-dfbc-496f-a3fe-8f5f2b30572b`, webhook `webhook_8c9c473e-e6cd-44b9-ba2f-60a864cdda3e`.

```bash
# Tuer le process "malware_bin" sur l'agent 001
curl -X POST http://localhost:5001/api/v1/hooks/webhook_8c9c473e-e6cd-44b9-ba2f-60a864cdda3e \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!kill-process.sh", "extra_args": "malware_bin", "reason": "process suspect détecté"}'
```

`extra_args` est une chaîne simple (pas un tableau) — le body Shuffle (`"arguments": ["$exec.extra_args"]`) l'encapsule déjà dans le tableau attendu par l'API Wazuh.

Action irréversible (pas d'« unkill ») — le script refuse de tuer les process de la safelist (`sshd`, `wazuh-agentd`, `systemd`, etc., voir `kill-process.sh`) pour ne pas se couper de l'agent.

## Workflow « Wazuh - Forensic Collection »

Collecte de preuves sur un agent : **capture RAM puis image disque**, streamées vers un serveur de preuves. Même schéma que les précédents (webhook → auth_wazuh → run_active_response), l'AR appelée est `!forensic-collect.sh` et `scope` porte le périmètre.

Workflow id `9660788f-f4e4-496e-ac24-52d754236a6a`, webhook `webhook_2d9698dd-02c3-5441-999a-77d481105e49`.

```bash
# Collecte complète (RAM + disque) sur l'agent 001
curl -X POST http://localhost:5001/api/v1/hooks/webhook_2d9698dd-02c3-5441-999a-77d481105e49 \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!forensic-collect.sh", "scope": "full", "reason": "brute force SSH réussi (règle 100690)"}'

# RAM seule (rapide, à faire en premier si le temps manque)
curl -X POST http://localhost:5001/api/v1/hooks/webhook_2d9698dd-02c3-5441-999a-77d481105e49 \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "001", "ar_command": "!forensic-collect.sh", "scope": "ram", "reason": "..."}'
```

`scope` : `ram`, `disk` ou `full` (défaut `full`). Toute autre valeur est refusée par le script.

### Ce que fait la collecte

1. **RAM d'abord** (ordre de volatilité, RFC 3227) via AVML → `memory.lime.gz`. Une image disque prend assez de temps pour que la mémoire recherchée soit partiellement écrasée entre-temps.
2. **Disque entier** (pas seulement la partition racine : table de partitions, secteur d'amorçage et espace inter-partitions sont des caches classiques) via `dd` → `disk.raw.gz`.
3. `manifest.json` (hostname, noyau, boot_id, uptime, date UTC) + un `.sha256` par image, calculé **sur le flux émis**.

Rien n'est écrit sur le disque de la machine analysée : tout est streamé en SSH. Écrire une image de plusieurs Go localement écraserait l'espace non alloué, donc les fichiers supprimés récupérables.

L'AR rend la main immédiatement et détache un worker (`setsid`) : `wazuh-execd` attend la fin du script AR, or une image disque dure des minutes à des heures. **Le suivi se fait dans `/var/ossec/logs/active-responses.log` de l'agent**, remonté au manager.

### Interaction avec l'isolation réseau

Un hôte isolé par `host-isolate.sh` n'a plus de sortie que vers le manager — le stream SSH serait droppé. Le cas est la norme (on isole d'abord, on collecte ensuite) : le worker détecte la table `wazuh_isolation`, ajoute une exception ciblée (serveur de preuves, tcp/22 uniquement) et **la retire en sortant**, remettant l'isolation dans l'état trouvé.

### Limites (à connaître avant de s'appuyer sur ces preuves)

- **Image disque prise à chaud** : système monté, image incohérente (« smear »). Inhérent à l'acquisition live. Pour une image cohérente sur une VM libvirt, il faut passer par l'hyperviseur (snapshot qcow2 + `virsh dump`) — hors périmètre de cette AR.
- **La collecte tourne sur la machine suspecte**, avec son noyau et ses binaires : un rootkit noyau peut mentir aux deux captures. Une collecte qui ne trouve rien ne prouve pas l'absence de compromission.
- **Le hash atteste le transfert, pas un état figé** du support : re-hasher un disque live donne une valeur différente à chaque passe.
- Pas de repli si AVML est absent : la collecte RAM échoue bruyamment plutôt que de produire une capture partielle (`/proc/kcore`) passée pour complète.

### Prérequis d'installation

**1. Serveur de preuves** (hôte séparé de la machine analysée) :

```bash
sudo useradd -r -m -d /var/lib/forensics -s /bin/sh forensics
sudo install -d -o forensics -g forensics -m 750 /var/lib/forensics
# déposer la clé publique de l'agent dans /var/lib/forensics/.ssh/authorized_keys
```

**2. Clé SSH dédiée sur l'agent** (jamais la clé d'admin — cf. CLAUDE.md) :

```bash
sudo install -d -o root -g wazuh -m 750 /var/ossec/active-response/.ssh
sudo ssh-keygen -t ed25519 -N '' -f /var/ossec/active-response/.ssh/forensic_ed25519
sudo ssh-keyscan -H <evidence-host> | sudo tee /var/ossec/active-response/.ssh/known_hosts
```

`StrictHostKeyChecking=yes` avec un `known_hosts` épinglé : sans ça, un MITM sur le réseau de l'agent compromis récupérerait les preuves.

**3. AVML sur l'agent** (binaire statique Microsoft, pas de module noyau à compiler — contrairement à LiME, qui échoue dès que les headers ne correspondent pas au noyau courant, c'est-à-dire précisément en incident) :

```bash
curl -sL https://github.com/microsoft/avml/releases/latest/download/avml -o /tmp/avml
sudo install -o root -g wazuh -m 750 /tmp/avml /var/ossec/active-response/bin/avml
```

**4. Script AR** : voir « Côté agent » ci-dessous.

## Côté agent (prérequis)

Scripts active response déployés sur l'agent Linux (voir `wazuh/active-response/`) :

```bash
scp wazuh/active-response/host-*.sh wazuh/active-response/kill-process.sh wazuh/active-response/forensic-collect.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g wazuh -m 750 /tmp/host-*.sh /tmp/kill-process.sh /tmp/forensic-collect.sh /var/ossec/active-response/bin/'
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
