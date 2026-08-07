# Jellyfin — agent Wazuh, log applicatif (pas de format web)

Contrairement à NPM/BookStack/Nextcloud (nginx devant), Jellyfin sert le HTTP
directement via son serveur Kestrel embarqué (`network_mode: host`, pas de
port mappé) — **pas de log d'accès HTTP structuré à la verbosité par
défaut** (vérifié sur jellyfin.lab : 0 ligne `GET `/`POST ` dans le log du
jour). Ingéré tel quel, dans un index **dédié** `wazuh-jellyfin-*` — pas
`wazuh-web-*`, décision explicite (le contenu n'est pas comparable à un
access log).

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
scp setup-acl.sh root@<jellyfin>:/tmp/
ssh root@<jellyfin> 'bash /tmp/setup-acl.sh [/root/jellyfin]'
```

## 3. Localfile

Insérer `localfile-snippet.xml` dans `/var/ossec/etc/ossec.conf` (avant
`</ossec_config>`), puis `systemctl restart wazuh-agent`.

## 4. Décodeur + règles (déjà dans le repo)

- `src/wazuh/config/wazuh_cluster/decoders/jellyfin.xml` — format Serilog
  (`[timestamp] [LEVEL] [thread] Classe: message`), extrait `level`
  (VRB/DBG/INF/WRN/ERR/FTL) et `class`.
- `src/wazuh/config/wazuh_cluster/rules/100830-jellyfin-rules.xml` — grouped
  (level 0, INF/DBG/VRB ne remontent pas), WRN=5, ERR=7, FTL=12.

Index de destination : `wazuh-jellyfin-*` (routage dans
`alerts-pipeline.json` sur `decoder.name=='jellyfin'`).

## Vérification

```bash
docker exec wazuh-wazuh.manager-1 grep jellyfin.xml /var/ossec/logs/ossec.log  # pas d'erreur de config
docker exec -i wazuh-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# coller une ligne du log Jellyfin — doit décoder name='jellyfin'
```

L'index ne se peuple qu'à la première ligne `WRN`/`ERR`/`FTL` réelle (les
`INF` sont groupées à level 0, pas d'alerte donc pas d'indexation) —
normal à froid, les échecs de téléchargement de sous-titres ou d'auth en
génèrent régulièrement en usage normal.

## Pas de remédiation automatisée

Rien de branché ici — visibilité seule.
