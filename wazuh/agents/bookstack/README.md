# BookStack — agent Wazuh standard, décodeur natif

Agent Wazuh normal (Debian 12 + docker, comme `wazuh/agents/npm/`). Différence
avec NPM : BookStack (image `lscr.io/linuxserver/bookstack`) écrit un access
log nginx au **format combined log standard**, directement reconnu par le
décodeur natif Wazuh `web-accesslog` — **aucun décodeur/règle custom
nécessaire**, contrairement à NPM (format propriétaire) ou pfSense (pas
d'agent possible).

## 1. Installer et enrôler l'agent

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --batch --yes --no-tty --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=4.9.2-1

sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_IP</address>|" /var/ossec/etc/ossec.conf
/var/ossec/bin/agent-auth -m $MANAGER_IP -p 1515
```

`soc-ai.conf` avant tout test d'isolation — cf. `INSTALL.md` §4.

## 2. Permissions de lecture des logs

Même piège que NPM : `/root` en `0700`, illisible par l'utilisateur `wazuh`.

```bash
scp setup-acl.sh root@<bookstack>:/tmp/
ssh root@<bookstack> 'bash /tmp/setup-acl.sh [/root/bookstack]'
```

## 3. Localfile

Insérer `localfile-snippet.xml` dans `/var/ossec/etc/ossec.conf` (avant
`</ossec_config>`), puis `systemctl restart wazuh-agent`.

## 4. Vérification

```bash
docker exec wazuh-wazuh.manager-1 grep "nginx/access.log" /var/ossec/logs/alerts/alerts.json | tail -1
```

Doit montrer `"decoder":{"name":"web-accesslog"}` et atterrir dans
`wazuh-web-*` (routage existant sur `rule.groups` contient `web`/`accesslog` —
`agent.id` non nul ici, agent réel, donc le chemin normal de
`alerts-pipeline.json` s'applique directement).

## Pas de remédiation automatisée

Rien de branché ici — agent standard donc l'AR générique reste possible plus
tard si besoin, mais hors scope de ce déploiement (visibilité seule).
