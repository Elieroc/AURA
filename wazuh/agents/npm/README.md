# Nginx Proxy Manager — agent Wazuh standard

Contrairement à pfSense (FreeBSD, appliance, syslog direct — cf.
`wazuh/agents/pfsense/`), l'hôte NPM est un Linux classique (testé Debian 12 +
docker) : **agent Wazuh normal**, logs lus en local via `<localfile>`.

## 1. Installer et enrôler l'agent

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --batch --yes --no-tty --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=4.9.2-1

sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_IP</address>|" /var/ossec/etc/ossec.conf
/var/ossec/bin/agent-auth -m $MANAGER_IP -p 1515
```

**`soc-ai.conf` avant tout test d'isolation** — cf. `INSTALL.md` §4 et
`config/soc-ai.conf.example` (`WAZUH_MANAGER_IP` mal réglé = lockout réseau,
vécu en prod sur un autre agent). Même si NPM n'est pas une cible de
remédiation prévue, le fichier ne coûte rien à déployer par cohérence.

```bash
scp config/soc-ai.conf root@<npm>:/tmp/soc-ai.conf
ssh root@<npm> 'install -o root -g wazuh -m 640 /tmp/soc-ai.conf /var/ossec/etc/soc-ai.conf'
```

## 2. Permissions de lecture des logs

NPM (déploiement standard `jc21/nginx-proxy-manager`) écrit ses logs dans
`<install_dir>/data/logs/`, souvent sous `/root/nginx-proxy-manager` —
répertoire `/root` en `0700`, illisible par l'utilisateur `wazuh`. **ACL
minimale**, pas d'ouverture large de `/root` :

```bash
scp setup-acl.sh root@<npm>:/tmp/
ssh root@<npm> 'bash /tmp/setup-acl.sh [/root/nginx-proxy-manager]'
```

Le script pose une ACL par défaut sur le dossier `logs/` : les fichiers des
futurs proxy hosts (NPM en crée un par host, numéroté, à chaque ajout dans
l'UI) héritent automatiquement de la permission de lecture.

## 3. Localfile

Insérer `localfile-snippet.xml` dans `/var/ossec/etc/ossec.conf` (avant
`</ossec_config>`), puis `systemctl restart wazuh-agent`.

Wildcard plutôt que lister chaque `proxy-host-<id>_*.log` : NPM en crée un
nouveau à chaque host ajouté dans l'UI, une liste figée se périmerait.

## 4. Décodeur + règles (déjà dans le repo, rien à faire ici)

- `wazuh/config/wazuh_cluster/decoders/npm-proxy.xml`
- `wazuh/config/wazuh_cluster/rules/100820-npm-proxy-rules.xml`

Le format d'access log NPM (`[timestamp] - status upstream_status - METHOD
scheme host "uri" [Client ip] ...`) n'est pas le combined log format nginx
standard — décodeur custom. **Piège rencontré** : ce format coïncide avec le
prematch du décodeur natif `zeus` (`0390-zeus_decoders.xml`, pensé pour un
panel C2 historique), qui capture nos logs NPM en premier — chargé depuis
`ruleset/decoders` avant tout décodeur local, quel que soit l'ordre déclaré
des `<decoder_dir>` (testé). Résolu en désactivant zeus (decoder + rules,
les deux ensemble ou le chargement plante) via `<decoder_exclude>` /
`<rule_exclude>` dans `wazuh_manager.conf` — détail dans le commentaire de
`npm-proxy.xml`. Zeus n'a aucun usage réel dans cet environnement.

Index de destination : `wazuh-proxy-*` (routage dans `alerts-pipeline.json`
sur `rule.groups` contenant `npm-proxy`).

## Vérification

```bash
# côté manager : décodage correct sur un événement réel
docker exec wazuh-wazuh.manager-1 grep npm-proxy /var/ossec/logs/alerts/alerts.json | tail -1
```

## Pas de remédiation automatisée

Aucun script active response spécifique déployé pour ce flux — c'est un
agent standard (donc l'AR générique reste possible si besoin plus tard,
contrairement à pfSense), mais rien n'a été demandé/branché ici : ce agent
sert la visibilité (logs proxy), pas la mitigation.
