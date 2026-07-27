# WireGuard — agent Wazuh + wg-monitor (pas de log natif)

WireGuard (module noyau) n'a **aucun audit natif** : pas de log par pair, pas
d'événement connect/disconnect — seul `wg show` donne un état instantané
(dernier handshake, compteurs). Le `dynamic_debug` noyau (qui journalise
chaque handshake) n'est pas non plus une option ici : `/sys/kernel/debug`
inaccessible même en root sur wireguard.lab (LXC Proxmox — même contrainte
que le manager SOC-AI et sa capture réseau, cf. `wazuh/README.md`).

Solution : `wg-monitor.py`, un script qui interroge `wg show wg0 dump`
périodiquement (systemd timer, 30s), compare à l'état précédent, et loggue
les **transitions** actif/inactif par pair — pas un flot périodique bruyant.

**"Actif"** = dernier handshake dans les 200 dernières secondes (WireGuard
rekey sous trafic toutes les 120-180s ; un pair sans handshake récent n'a
simplement pas de trafic, ce qui n'est pas une "déconnexion" formelle —
WireGuard est sans état de connexion — mais un proxy raisonnable).

## 1. wg-monitor sur l'hôte WireGuard

```bash
scp wg-monitor.py root@<wireguard>:/tmp/
scp wg-monitor.service wg-monitor.timer root@<wireguard>:/tmp/
ssh root@<wireguard> '
  install -o root -g root -m 750 /tmp/wg-monitor.py /usr/local/sbin/wg-monitor.py
  install -o root -g root -m 644 /tmp/wg-monitor.service /etc/systemd/system/wg-monitor.service
  install -o root -g root -m 644 /tmp/wg-monitor.timer /etc/systemd/system/wg-monitor.timer
  touch /var/log/wireguard-events.log
  systemctl daemon-reload
  systemctl enable --now wg-monitor.timer
'
```

`/var/log/wireguard-events.log` (0644 root:root, `/var/log` traversable par
défaut) — pas d'ACL nécessaire, contrairement aux logs sous `/root/*` des
autres agents (NPM, BookStack...).

## 2. Installer et enrôler l'agent Wazuh

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --batch --yes --no-tty --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=4.9.2-1

sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_IP</address>|" /var/ossec/etc/ossec.conf
/var/ossec/bin/agent-auth -m $MANAGER_IP -p 1515
```

`soc-ai.conf` avant tout test d'isolation — cf. `INSTALL.md` §4.

## 3. Localfile

Insérer `localfile-snippet.xml` dans `/var/ossec/etc/ossec.conf` (avant
`</ossec_config>`), puis `systemctl restart wazuh-agent`.

## 4. Décodeur + règles (déjà dans le repo)

- `wazuh/config/wazuh_cluster/decoders/wireguard.xml`
- `wazuh/config/wazuh_cluster/rules/100840-wireguard-rules.xml` : grouped,
  `peer_connected`/`peer_disconnected` (level 3), reconnexions répétées d'un
  même pair en moins de 2 min (level 7, lien instable ou anomalie).

Index de destination : `wazuh-vpn-*` (routage dans `alerts-pipeline.json` sur
`decoder.name=='wg-monitor'`).

## Vérification

```bash
# forcer un cycle de test SANS couper les tunnels actifs (reset du state,
# les pairs déjà actifs sont traités comme une "nouvelle connexion")
ssh root@<wireguard> 'rm -f /var/lib/wg-monitor/state.json && systemctl start wg-monitor.service'

docker exec wazuh-wazuh.manager-1 grep wg-monitor /var/ossec/logs/alerts/alerts.json | tail -1
```

## Pas de remédiation automatisée

Rien de branché ici — visibilité seule. Couper un pair WireGuard (retirer sa
clé de `wg0.conf` + `wg syncconf`) serait faisable en AR mais hors scope de
cette demande.
