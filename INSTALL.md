# Installation

Prérequis : Docker, Docker Compose, Python 3.12+, `vm.max_map_count=262144`.

## 1. Wazuh

```bash
cd wazuh
sysctl -w vm.max_map_count=262144
cp .env.example .env
cp config/wazuh_cluster/wazuh_manager.conf.example config/wazuh_cluster/wazuh_manager.conf
cp config/wazuh_dashboard/wazuh.yml.example config/wazuh_dashboard/wazuh.yml
$EDITOR .env
$EDITOR config/wazuh_cluster/wazuh_manager.conf
$EDITOR config/wazuh_dashboard/wazuh.yml
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

**Vérifier que la configuration partagée (agent.conf : FIM ransomware/webshell/SSH
keys, cron/sudoers/pam) part bien vers les agents** — piège vécu en prod : le
volume `wazuh_etc` neuf a `/var/ossec/etc/shared/default/` en `root:root`, alors
que `wazuh-remoted` tourne en user `wazuh` (uid 999) et ne peut pas y écrire
`merged.mg`. Symptôme : `wazuh-remoted: ERROR: Unable to open file:
'etc/shared/default/merged.mg' due to [(13)-(Permission denied)]` en boucle
dans les logs du manager, agents actifs mais **aucune des directives FIM
custom jamais appliquée** (silencieux : pas d'agent syscheckd en erreur, il
applique juste le strict minimum par défaut de l'image). Fix (une fois par
volume `wazuh_etc`, persiste ensuite) :

```bash
docker exec wazuh-wazuh.manager-1 chown -R wazuh:wazuh /var/ossec/etc/shared
docker restart wazuh-wazuh.manager-1
# vérifier :
docker exec wazuh-wazuh.manager-1 ls -la /var/ossec/etc/shared/default/   # merged.mg doit exister
docker exec wazuh-wazuh.manager-1 grep merged.mg /var/ossec/logs/ossec.log  # plus d'erreur après le restart
```

Dashboard : https://localhost — `admin` / `INDEXER_PASSWORD`.

Dashboards/visualisations custom (index patterns d'abord, sinon l'import
échoue silencieusement sur les références manquantes) :

```bash
INDEXER_PASSWORD=... python3 dashboards/create_index_patterns.py
curl -sk -u admin:$INDEXER_PASSWORD -X POST \
  "https://localhost/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' --form file=@dashboards/soc-ai-dashboards.ndjson
```

## 2. DFIR-IRIS

```bash
cd iris
cp .env.example .env
$EDITOR .env
./scripts/generate-certs.sh
docker compose up -d
docker compose logs app | grep "IRIS IS READY"
```

UI : https://localhost:8443

## 3. Shuffle (SOAR)

```bash
cd shuffle
cp .env.example .env
$EDITOR .env
docker compose up -d
```

UI : http://localhost:3001 — API : http://localhost:5001

Workflows Host Isolation / Kill Process — pas d'export upstream à importer,
recréés par l'API (webhook ids fixés sur ceux attendus par `ai/.env`) :

```bash
SHUFFLE_DEFAULT_APIKEY=$(grep SHUFFLE_DEFAULT_APIKEY .env | cut -d= -f2) \
WAZUH_API_USER=wazuh-wui \
WAZUH_API_PASSWORD=$(grep API_PASSWORD ../wazuh/.env | cut -d= -f2) \
WAZUH_HOST=<IP LAN de l'hôte, pas 127.0.0.1> \
SHUFFLE_WEBHOOK_ISOLATE=webhook_b755bdec-241d-47fd-9703-4405d9052066 \
SHUFFLE_WEBHOOK_KILL=webhook_8c9c473e-e6cd-44b9-ba2f-60a864cdda3e \
python3 workflows/build_workflows.py
```

Forensic Collection reste manuel (infra SSH K1/K2/K3 lourde à provisionner) —
cf. `shuffle/README.md`.

## 4. Active response Wazuh (agents)

```bash
scp wazuh/active-response/*.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g wazuh -m 750 /tmp/*-*.sh /var/ossec/active-response/bin/'
```

Déployer **tous** les scripts, pas seulement `host-*` et `kill-process` : un AR
déclaré dans `ossec.conf` du manager mais absent de l'agent échoue sans que rien
ne le signale côté manager (l'API répond 200, elle ne fait que transmettre). Les
comptes en particulier — `disable-account.sh` / `enable-account.sh` — vont par
paire : sans le second, une désactivation n'est pas défaisable.

**`soc-ai.conf` AVANT tout test d'isolation — sinon lockout.** `host-isolate.sh`
a une IP manager par défaut codée en dur (`192.168.122.1`, ancien lab) : c'est
la seule sortie laissée ouverte pendant l'isolation. Sans override, isoler un
agent le coupe de son vrai manager, sans retour possible par l'AR de
dé-isolation (le canal est mort) — vécu en prod, récupéré seulement via une
console hors-bande (hyperviseur).

```bash
cp config/soc-ai.conf.example config/soc-ai.conf
$EDITOR config/soc-ai.conf   # WAZUH_MANAGER_IP = IP du manager telle que l'agent la joint
scp config/soc-ai.conf <agent>:/tmp/soc-ai.conf
ssh <agent> 'sudo install -o root -g wazuh -m 640 /tmp/soc-ai.conf /var/ossec/etc/soc-ai.conf'
```

Après un test d'isolation/dé-isolation, si l'agent ne remonte pas de
keepalive : `wazuh-agentd` ne se reconnecte pas toujours seul après la coupure
brutale du firewall, `systemctl restart wazuh-agent` sur l'agent force la
reprise.

## 5. soc-agent (pipeline IA)

```bash
cd ai
cp .env.example .env
$EDITOR .env
docker compose up -d db
docker exec -i socagent-db psql -q -U socagent -d socagent < soc_agent/schema.sql
docker compose up -d --build soc-agent-cycle soc-agent-reconcile soc-agent-whitelist-task
```
