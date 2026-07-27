# Shuffle SOAR — remédiation

Orchestration des remédiations SOC via [Shuffle](https://shuffler.io). Remédiations implémentées : **isolation réseau d'un hôte** (nftables) et **kill d'un process** (pkill) via active response Wazuh, plus une **collecte forensique** (RAM + image disque) tirée par le manager en SSH.

## Setup

```bash
cd shuffle
cp .env.example .env     # remplir (mots de passe / clé API aléatoires)
docker compose up -d
```

- UI : http://localhost:3001 — API : http://localhost:5001
- Premier compte admin : `POST /api/v1/users/register` avec `{"username": ..., "password": ...}` (retourne l'apikey), ou via l'UI.

## Import des workflows

Pas d'export upstream de ces workflows (ils n'ont jamais existé qu'en tant
qu'objets vivants dans une instance Shuffle donnée) : `workflows/build_workflows.py`
les recrée par l'API en fixant l'id des triggers webhook sur les valeurs
attendues par `ai/.env` (`SHUFFLE_WEBHOOK_ISOLATE` / `_KILL`), pour que
`mitigate.py` retrouve la même URL quelle que soit l'instance Shuffle.

```bash
SHUFFLE_DEFAULT_APIKEY=$(grep SHUFFLE_DEFAULT_APIKEY .env | cut -d= -f2) \
WAZUH_API_USER=wazuh-wui \
WAZUH_API_PASSWORD=$(grep API_PASSWORD ../wazuh/.env | cut -d= -f2) \
WAZUH_HOST=<IP LAN de l'hôte, PAS 127.0.0.1> \
SHUFFLE_WEBHOOK_ISOLATE=webhook_b755bdec-241d-47fd-9703-4405d9052066 \
SHUFFLE_WEBHOOK_KILL=webhook_8c9c473e-e6cd-44b9-ba2f-60a864cdda3e \
python3 workflows/build_workflows.py
```

`WAZUH_HOST` doit être une IP joignable depuis le réseau docker `shuffle` : le
worker qui exécute l'action HTTP n'est **pas** en `network_mode: host` comme
soc-agent, donc `127.0.0.1`/`localhost` ne pointe pas vers le manager Wazuh
depuis là — utiliser l'IP LAN réelle de la machine.

Pas idempotent au sens strict : relancer crée de nouveaux workflows si les
précédents n'ont pas été supprimés (`DELETE /api/v1/workflows/<id>`).

Forensic Collection n'est pas couvert par ce script (infra SSH K1/K2/K3 à
provisionner à part, voir plus bas) — se crée à la main dans l'UI.

## Workflow « Wazuh - Host Isolation »

```
Webhook ──► auth_wazuh (POST /security/user/authenticate?raw=true)
                 │ token
                 ▼
        run_active_response (PUT /active-response?agents_list=<agent_id>)
```

Workflow id `a1697bc2-596d-4f87-ac9b-4b3fa1ab6c9c`, webhook `webhook_b755bdec-241d-47fd-9703-4405d9052066`.

Déclenchement : **automatique** par le soc-agent (`mitigate.py`) sur verdict vrai positif (XDR autonome, cf. CLAUDE.md), ou manuellement par un opérateur pour test/urgence :

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

Collecte de preuves sur un agent : **capture RAM puis image disque**. Contrairement aux deux workflows précédents, il ne passe **pas** par une active response Wazuh.

```
Webhook ──► run_ssh_command (Shuffle Tools)
                 │  K1, forced command
                 ▼
           hôte manager : forensic-pull.sh <agent> <scope>
                 │                                  │
        K2, forced command                    K3, dépôt
                 ▼                                  ▼
          agent suspect ──── flux de preuves ──► evidence host
```

Workflow id `9660788f-f4e4-496e-ac24-52d754236a6a`, webhook `webhook_2d9698dd-02c3-5441-999a-77d481105e49`.

```bash
# Collecte complète (RAM + disque) sur l'agent 192.168.122.155
curl -X POST http://localhost:5001/api/v1/hooks/webhook_2d9698dd-02c3-5441-999a-77d481105e49 \
  -H "Content-Type: application/json" \
  -d '{"manager_host": "192.168.122.1", "manager_user": "soc-forensic",
       "manager_key_file_id": "<file id Shuffle de K1>",
       "agent_host": "192.168.122.155", "scope": "full",
       "reason": "brute force SSH réussi (règle 100690)"}'
```

`scope` : `ram`, `disk` ou `full` (défaut `full`). Toute autre valeur est refusée.

### Pourquoi le manager tire, et ne se fait pas pousser

La première version faisait pousser les preuves **par l'agent** vers le dépôt. Ça imposait de déposer une **clé privée sur la machine suspecte** : un attaquant root la lisait et gagnait un accès en écriture au dépôt de preuves — de quoi altérer les preuves d'autres incidents ou s'en servir comme rebond.

Le flux est donc inversé. Les trois clés vivent hors de la machine analysée :

| Clé | Trajet | Restriction |
|---|---|---|
| K1 | Shuffle → manager | forced command `forensic-pull.sh` |
| K2 | manager → agent | forced command `forensic-source.sh` (3 mots-clés) |
| K3 | manager → dépôt | compte dédié, écriture seule |

L'agent ne détient qu'une **clé publique** dans `authorized_keys` et n'a aucun accès sortant.

**Contrepartie assumée** : le manager détient une clé *vers* l'agent. C'est le sens d'administration habituel et la forced command la borne à trois mots-clés qui ne produisent que des octets — mais lire un disque brut, c'est lire tout le disque. K2 est à traiter comme une clé root.

**Conséquence** : la collecte exige un accès SSH manager → agent. Les agents sans SSH (Windows, réseau restreint) ne sont pas couverts par ce workflow.

### Ce que fait la collecte

1. `meta` sur l'agent → `manifest.json` (hostname, noyau, boot_id, uptime, device et taille disque) déposé **en premier** : si la suite échoue, la trace de la tentative reste.
2. **RAM d'abord** (ordre de volatilité, RFC 3227) via AVML → `memory.lime.gz`. Une image disque fait tourner la machine assez longtemps pour écraser une partie de la mémoire recherchée.
3. **Disque entier** (pas la seule partition racine : table de partitions, secteur d'amorçage et espace inter-partitions sont des caches classiques) via `dd` → `disk.raw.gz`.
4. Un `.sha256` par image, calculé au vol sur le flux.

Les octets transitent par la mémoire du manager, **jamais par son disque** : le manager est un relais, pas un lieu de stockage de preuves. Rien n'est écrit non plus sur l'agent — une image de plusieurs Go écrite localement écraserait l'espace non alloué, donc les fichiers supprimés récupérables.

`forensic-pull.sh` rend la main immédiatement (il détache un worker et retourne `case_id=…`) : une image disque dure des minutes à des heures, alors que l'appel SSH de Shuffle attend la fin de la commande. **Suivi dans `/var/log/soc-ai-forensic.log` sur le manager.**

### Interaction avec l'isolation réseau

**Rien à faire.** `host-isolate.sh` laisse déjà passer le SSH entrant depuis le manager (`ip saddr $MANAGER_IP tcp dport 22 accept`) et les réponses sortantes (`ct state established,related accept`) : le flux de preuves emprunte cette connexion établie. La version « push » devait au contraire percer un trou dans l'isolation pour sortir — ce bricolage a disparu avec l'inversion du flux.

### Limites (à connaître avant de s'appuyer sur ces preuves)

- **Image disque prise à chaud** : système monté, image incohérente (« smear »). Inhérent à l'acquisition live. Pour une image cohérente sur une VM libvirt, passer par l'hyperviseur (snapshot qcow2 + `virsh dump`) — hors périmètre.
- **La capture s'exécute sur la machine suspecte**, avec son noyau et ses binaires : un rootkit noyau peut mentir aux deux captures. Une collecte qui ne trouve rien ne prouve pas l'absence de compromission.
- **Le hash atteste le transfert, pas un état figé** du support : une seconde lecture d'un disque live donnerait une valeur différente.
- Pas de repli si AVML est absent : la capture RAM échoue bruyamment plutôt que de produire une capture partielle (`/proc/kcore`) passée pour complète.
- **AVML vers un FIFO n'est pas vérifié en conditions réelles** (testé avec un stub). Si le binaire exige une cible seekable, la capture RAM échouera et il faudra revoir ce point — écrire dans un fichier local est exclu (sur disque ça écrase l'espace non alloué, en tmpfs ça consomme la RAM qu'on capture).

### Prérequis d'installation

**1. Fichier de conf** (cf. `config/soc-ai.conf.example`) :

```bash
cp config/soc-ai.conf.example config/soc-ai.conf   # gitignored, remplir
sudo install -d -m 750 /etc/soc-ai
sudo install -o root -g root -m 640 config/soc-ai.conf /etc/soc-ai/soc-ai.conf   # manager
ssh <agent> 'sudo install -o root -g wazuh -m 640 /tmp/soc-ai.conf /var/ossec/etc/soc-ai.conf'
```

Sourcé en root : mode `640` obligatoire (inscriptible par un autre compte = escalade de privilèges directe), et uniquement des affectations `KEY="valeur"` littérales.

**2. Sur l'agent** — source de collecte + AVML, aucune clé privée :

```bash
scp scripts/forensic-source.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g root -m 700 /tmp/forensic-source.sh /usr/local/sbin/'
ssh <agent> 'curl -sL https://github.com/microsoft/avml/releases/latest/download/avml -o /tmp/avml \
             && sudo install -o root -g root -m 700 /tmp/avml /usr/local/sbin/avml'
sudo useradd -r -m -s /bin/sh forensic        # sur l'agent
# sudoers, commande exacte, sans joker :
echo 'forensic ALL=(root) NOPASSWD: /usr/local/sbin/forensic-source.sh' | sudo tee /etc/sudoers.d/forensic
```

`authorized_keys` de `forensic` sur l'agent — la forced command est ce qui borne K2 :

```
command="sudo /usr/local/sbin/forensic-source.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... manager-forensic
```

**3. Sur le manager** — les trois clés et le collecteur :

```bash
sudo install -o root -g root -m 700 scripts/forensic-pull.sh /usr/local/sbin/
sudo ssh-keygen -t ed25519 -N '' -f /etc/soc-ai/forensic_agent_ed25519      # K2
sudo ssh-keygen -t ed25519 -N '' -f /etc/soc-ai/forensic_evidence_ed25519   # K3
sudo ssh-keyscan -H <agent> | sudo tee /etc/soc-ai/known_hosts_agents
sudo ssh-keyscan -H <evidence-host> | sudo tee /etc/soc-ai/known_hosts_evidence
```

`StrictHostKeyChecking=yes` avec `known_hosts` épinglés des deux côtés : sans ça, un MITM sur le réseau d'un agent compromis se ferait passer pour l'agent (et fabriquerait les preuves) ou pour le dépôt (et les récupérerait).

Compte de service pour K1 (Shuffle → manager), lui aussi en forced command :

```
command="/usr/local/sbin/forensic-pull.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... shuffle
```

La clé privée K1 s'upload dans Shuffle (Files) ; son file id va dans `manager_key_file_id`.

**4. Serveur de preuves** :

```bash
sudo useradd -r -m -d /var/lib/forensics -s /bin/sh forensics
sudo install -d -o forensics -g forensics -m 750 /var/lib/forensics
# clé publique K3 dans /var/lib/forensics/.ssh/authorized_keys
```

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
