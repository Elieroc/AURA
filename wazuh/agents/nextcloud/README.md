# Nextcloud — agent Wazuh standard, décodeur natif

Même schéma que `wazuh/agents/bookstack/` : image linuxserver.io, nginx
interne au format combined log standard, décodeur natif Wazuh
`web-accesslog` — aucun décodeur/règle custom.

## 1. Installer et enrôler l'agent

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --batch --yes --no-tty --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=4.9.2-1

sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_IP</address>|" /var/ossec/etc/ossec.conf
/var/ossec/bin/agent-auth -m $MANAGER_IP -p 1515
```

`soc-ai.conf` avant tout test d'isolation — cf. `docs/INSTALL.md` §4.

## 2. Permissions de lecture des logs

```bash
scp setup-acl.sh root@<nextcloud>:/tmp/
ssh root@<nextcloud> 'bash /tmp/setup-acl.sh [/root/nextcloud]'
```

## 3. Localfile

Insérer `localfile-snippet.xml` dans `/var/ossec/etc/ossec.conf` (avant
`</ossec_config>`), puis `systemctl restart wazuh-agent`.

## 4. Vérification

```bash
docker exec wazuh-wazuh.manager-1 grep "nginx/access.log" /var/ossec/logs/alerts/alerts.json | grep nextcloud | tail -1
```

Atterrit dans `wazuh-web-*` (routage existant sur `rule.groups` contient
`web`/`accesslog`).

## Pas de remédiation automatisée

Rien de branché ici — visibilité seule.
