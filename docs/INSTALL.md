# Installation

Prérequis : Docker, Docker Compose, Python 3.12+, `vm.max_map_count=262144`.

Toutes les commandes se lancent depuis la **racine du dépôt** (ce fichier vit
dans `docs/`). Voir aussi [`TRAINING.md`](TRAINING.md) pour la mise en service
sur un SI déjà en production et [`REMEDIATION.md`](REMEDIATION.md) pour le
déploiement et le catalogue des active responses.

## 0. Un seul `.env`, un seul compose

Un unique `docker-compose.yml` et un unique `.env` à la racine du dépôt pilotent
les 4 stacks (Wazuh, soc-agent, DFIR-IRIS, Shuffle). Le serveur MCP Wazuh
(`mcp/`) reste hors dépôt et se déploie à part (voir `mcp/README.md`).

```bash
git clone <dépôt> AURA && cd AURA
sysctl -w vm.max_map_count=262144         # root, requis par l'indexer
cp .env.example .env
$EDITOR .env                              # creds/secrets/topologie — voir table plus bas
```

Variables à éditer au minimum (les autres ont des défauts raisonnables pour un
lab) : `INDEXER_PASSWORD`, `WAZUH_API_PASSWORD`, `WAZUH_VT_API_KEY`,
`WAZUH_ABUSEIPDB_API_KEY`, `PGPASSWORD`, `DEEPSEEK_API_KEY`,
`WAZUH_DASHBOARD_URL`, `RESEAUX_INTERNES`, `POSTGRES_PASSWORD`,
`POSTGRES_ADMIN_PASSWORD`, `IRIS_SECRET_KEY`, `IRIS_SECURITY_PASSWORD_SALT`,
`IRIS_API_KEY`, `SHUFFLE_DEFAULT_PASSWORD`, `SHUFFLE_DEFAULT_APIKEY`.

Configs annexes à copier depuis leur `.example` et éditer (secrets, gitignorées) :

```bash
cp src/wazuh/config/wazuh_cluster/wazuh_manager.conf.example src/wazuh/config/wazuh_cluster/wazuh_manager.conf
cp src/wazuh/config/wazuh_dashboard/wazuh.yml.example src/wazuh/config/wazuh_dashboard/wazuh.yml
$EDITOR src/wazuh/config/wazuh_cluster/wazuh_manager.conf   # CHANGEME_VT_API_KEY / CHANGEME_ABUSEIPDB_API_KEY
$EDITOR src/wazuh/config/wazuh_dashboard/wazuh.yml           # CHANGEME_API_PASSWORD = WAZUH_API_PASSWORD
```

Bases de données (bind mounts vers `db/`, gitignoré) et certificats à générer
une fois :

```bash
mkdir -p db/{socagent-postgres,iris-postgres,shuffle-opensearch,wazuh-indexer}
docker compose -f src/wazuh/generate-indexer-certs.yml run --rm generator
./src/iris/scripts/generate-certs.sh
```

Puis tout démarrer :

```bash
docker compose up -d
```

## 1. Wazuh

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
docker exec wazuh.manager chown -R wazuh:wazuh /var/ossec/etc/shared
docker restart wazuh.manager
# vérifier :
docker exec wazuh.manager ls -la /var/ossec/etc/shared/default/   # merged.mg doit exister
docker exec wazuh.manager grep merged.mg /var/ossec/logs/ossec.log  # plus d'erreur après le restart
```

Dashboard : https://localhost — `admin` / `INDEXER_PASSWORD`.

Dashboards/visualisations custom (index patterns d'abord, sinon l'import
échoue silencieusement sur les références manquantes) :

```bash
INDEXER_PASSWORD=... python3 src/wazuh/dashboards/create_index_patterns.py
curl -sk -u admin:$INDEXER_PASSWORD -X POST \
  "https://localhost/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' --form file=@src/wazuh/dashboards/soc-ai-dashboards.ndjson
```

## 2. DFIR-IRIS

Certificats déjà générés à l'étape 0 (`./src/iris/scripts/generate-certs.sh`).

```bash
docker compose logs iris-app | grep "IRIS IS READY"
```

UI : https://localhost:8443

## 3. Shuffle (SOAR)

UI : http://localhost:3001 — API : http://localhost:5001

Workflows Host Isolation / Kill Process — pas d'export upstream à importer,
recréés par l'API (webhook ids fixés sur ceux attendus par le `.env` racine) :

```bash
SHUFFLE_DEFAULT_APIKEY=$(grep SHUFFLE_DEFAULT_APIKEY .env | cut -d= -f2) \
WAZUH_API_USER=wazuh-wui \
WAZUH_API_PASSWORD=$(grep WAZUH_API_PASSWORD .env | cut -d= -f2) \
WAZUH_HOST=<IP LAN de l'hôte, pas 127.0.0.1> \
SHUFFLE_WEBHOOK_ISOLATE=webhook_00000000-0000-0000-0000-00000000a001 \
SHUFFLE_WEBHOOK_KILL=webhook_00000000-0000-0000-0000-00000000a002 \
python3 src/shuffle/workflows/build_workflows.py
```

Forensic Collection reste manuel (infra SSH K1/K2/K3 lourde à provisionner) —
cf. `src/shuffle/README.md`.

## 4. Active response Wazuh (agents)

```bash
scp src/wazuh/active-response/*.sh <agent>:/tmp/
ssh <agent> 'sudo install -o root -g wazuh -m 750 /tmp/*-*.sh /var/ossec/active-response/bin/'
```

Déployer **tous** les scripts, pas seulement `host-*` et `kill-process` : un AR
déclaré dans `ossec.conf` du manager mais absent de l'agent échoue sans que rien
ne le signale côté manager (l'API répond 200, elle ne fait que transmettre). Les
comptes en particulier — `disable-account.sh` / `enable-account.sh` — vont par
paire : sans le second, une désactivation n'est pas défaisable.

**`soc-ai.conf` AVANT tout test d'isolation — sinon lockout.** `host-isolate.sh`
a une IP manager par défaut codée en dur (`192.168.60.1`, ancien lab) : c'est
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

Schéma Postgres à charger une fois, après le premier `docker compose up -d` :

```bash
docker exec -i socagent-db psql -q -U socagent -d socagent < src/ai/soc_agent/schema.sql
```

Les jobs périodiques (`soc-agent-cycle`, `soc-agent-reconcile`,
`soc-agent-whitelist-task`, `soc-agent-metrics`, `soc-agent-rule-tuning`)
démarrent avec le reste de la stack (`docker compose up -d`). `soc-training`
démarre aussi, mais reste inactif tant que `TRAINING_ENABLED` n'est pas à
`true` (voir plus bas).

### Mise en service sur un SI déjà en production : le mode training

Sur un parc existant, activer le training AVANT le premier démarrage : le SOC
apprend le bruit ambiant pendant `TRAINING_DAYS` jours (pipeline d'analyse
suspendu, aucune remédiation) puis rend un case IRIS « TRAINING » listant
chaque exception créée. Détail complet : [`TRAINING.md`](TRAINING.md).

```bash
$EDITOR config/soc-ai.conf     # TRAINING_ENABLED="true", TRAINING_DAYS="7"
./scripts/soc-start.sh         # source la conf et (re)démarre les services soc-agent
```

La fenêtre ne s'ouvre qu'au tout premier démarrage. À la fin, relire le case
TRAINING : une intrusion déjà en cours au lancement aurait été apprise comme du
bruit ; passer la tâche en `Canceled` retire l'exception.
