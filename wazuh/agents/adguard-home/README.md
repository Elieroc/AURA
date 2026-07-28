# AdGuard Home — agent Wazuh, JSON natif (aucun décodeur custom)

Le query log AdGuard Home (`/opt/AdGuardHome/data/querylog.json`) est déjà
en JSON structuré, une ligne par requête DNS — `log_format=json` suffit,
Wazuh décode automatiquement tous les champs (y compris les objets imbriqués,
aplatis en `Result.IsFiltered`, `Result.Reason`...). Premier agent de ce
repo sans le moindre décodeur custom.

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

## 2. Permissions de lecture

`querylog.json` est `0600 root:root` par défaut :

```bash
scp setup-acl.sh root@<adguard>:/tmp/
ssh root@<adguard> 'bash /tmp/setup-acl.sh [/opt/AdGuardHome/data]'
```

## 3. Localfile

Insérer `localfile-snippet.xml` dans `/var/ossec/etc/ossec.conf` (avant
`</ossec_config>`), puis `systemctl restart wazuh-agent`.

## 4. Piège rencontré : latence d'écriture (`size_memory`)

AdGuard Home **bufferise les entrées du query log en mémoire** avant de les
écrire sur disque — `querylog.size_memory` dans `AdGuardHome.yaml`
(défaut **1000** requêtes). Sur un homelab, ça peut représenter des dizaines
de minutes avant qu'une résolution bloquée n'apparaisse dans Wazuh —
vécu en le déployant (fichier immobile plusieurs minutes malgré du trafic DNS
actif). Abaissé à **20** sur adguard-home.lab pour une visibilité quasi
temps réel (coût : plus d'écritures disque, négligeable au débit DNS d'un
homelab) :

```yaml
querylog:
  size_memory: 20   # défaut AdGuard : 1000
```

`systemctl restart AdGuardHome` après modification.

## 5. Règles (déjà dans le repo)

- `wazuh/config/wazuh_cluster/rules/100850-adguard-dns-rules.xml` : grouped
  (level 0, décodeur `json` générique + présence du champ `QH`), requête
  bloquée (`Result.IsFiltered=true`, level 3), nombreuses résolutions
  bloquées depuis la même IP en 60s (level 7, machine potentiellement
  compromise).

Index de destination : `wazuh-dns-*` — routage sur `rule.groups` contient
`dns` (pas `decoder.name`, qui vaut `json` — bien trop générique pour
identifier la source ; risque de collision si un futur agent a aussi des
logs JSON, à surveiller).

## Vérification

```bash
# forcer une résolution bloquée pour tester (adapter le domaine à un filtre actif)
ssh root@<adguard> dig @127.0.0.1 doubleclick.net +short

docker exec wazuh-wazuh.manager-1 grep doubleclick /var/ossec/logs/alerts/alerts.json | tail -1
```

## Pas de remédiation automatisée

Rien de branché ici — visibilité seule.
