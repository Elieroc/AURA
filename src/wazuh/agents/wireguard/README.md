# WireGuard — agent Wazuh + wg-monitor (via la base WGDashboard)

WireGuard (module noyau) n'a **aucun audit natif** : pas de log par pair, pas
d'événement connect/disconnect — seul `wg show` donne un état instantané.
`dynamic_debug` noyau (qui journaliserait chaque handshake) n'est pas non
plus une option ici : `/sys/kernel/debug` inaccessible même en root sur
wireguard.lab (LXC Proxmox — même contrainte que le manager Aura-SOC et sa
capture réseau, cf. `src/wazuh/README.md`).

**wireguard.lab tourne avec [WGDashboard](https://github.com/donaldzou/WGDashboard)**,
qui suit déjà l'état des pairs en continu dans une base SQLite
(`/etc/wgdashboard/src/db/wgdashboard.db`) — inutile de réinventer un second
poller de `wg show` : `wg-monitor.py` lit cette base (lecture seule,
WGDashboard reste l'unique écrivain) plutôt que d'interroger l'interface
directement. Deux tables :

- **`<iface>`** (ex `wg0`) : état courant par pair — `name` (alias lisible,
  ex `yoga-slim-7`), `status` (`running`/`stopped`, **calculé par WGDashboard
  lui-même**, plus fiable qu'un seuil de handshake maison), `endpoint`,
  `allowed_ip`.
- **`<iface>_history_endpoint`** : chaque changement d'IP source d'un pair
  (roaming wifi↔4G, nouvelle session) — signal plus précis qu'un simple
  "handshake récent", WGDashboard l'enregistre nativement dès qu'il change.

`wg-monitor.py` tourne en systemd timer (30s), compare l'état lu à l'appel
précédent (fichier d'état local), et loggue les **transitions** dans
`/var/log/wireguard-events.log` — pas un flot périodique bruyant. Au premier
run, se cale sur l'historique déjà présent sans rien rejouer.

**Piège rencontré en la testant** : lancer le script à la main
(`python3 wg-monitor.py`) pour un test n'écrit RIEN dans le fichier de log —
la redirection stdout -> fichier est posée par `wg-monitor.service`
(`StandardOutput=append:...`), pas par le script lui-même. Toujours tester
via `systemctl start wg-monitor.service`, jamais en invoquant le script
directement.

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

Variables d'environnement du script (défauts adaptés à un déploiement
WGDashboard standard, à surcharger dans `wg-monitor.service` si besoin) :
`WG_IFACE` (`wg0`), `WG_DASHBOARD_DB`
(`/etc/wgdashboard/src/db/wgdashboard.db`), `WG_STATE_FILE`.

**Si WGDashboard n'est pas installé** sur un futur hôte WireGuard : ce script
ne fonctionne pas tel quel (table SQLite absente). Revenir à une variante
interrogeant `wg show wg0 dump` directement — plus pauvre (pas de nom de
pair, seuil de handshake maison au lieu du `status` calculé par
WGDashboard) mais autonome. Pas conservée dans le repo : si ce cas se
présente, la réécrire à partir de ce fichier.

## 2. Installer et enrôler l'agent Wazuh

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --batch --yes --no-tty --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=4.9.2-1

sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_IP</address>|" /var/ossec/etc/ossec.conf
/var/ossec/bin/agent-auth -m $MANAGER_IP -p 1515
```

`soc-ai.conf` avant tout test d'isolation — cf. `docs/INSTALL.md` §4.

## 3. Localfile

Insérer `localfile-snippet.xml` dans `/var/ossec/etc/ossec.conf` (avant
`</ossec_config>`), puis `systemctl restart wazuh-agent`.

## 4. Décodeur + règles (déjà dans le repo)

- `src/wazuh/config/wazuh_cluster/decoders/wireguard.xml`
- `src/wazuh/config/wazuh_cluster/rules/100840-wireguard-rules.xml` : grouped ;
  `peer_connected`/`peer_disconnected`/`endpoint_changed` (level 3) ;
  reconnexions répétées d'un même pair en level 7 (lien instable) ;
  changements d'IP source répétés en level 7 (roaming ou clé partagée entre
  plusieurs machines).

Index de destination : `wazuh-vpn-*` (routage dans `alerts-pipeline.json` sur
`decoder.name=='wg-monitor'`).

## Vérification

```bash
# forcer un cycle de test SANS couper les tunnels actifs : marquer un pair
# actif comme "stopped" dans l'état local force sa prochaine lecture à
# ressortir en "connecté" (transition détectée), sans toucher wg0 ni
# WGDashboard.
ssh root@<wireguard> '
  systemctl stop wg-monitor.timer
  python3 -c "
import json
p = \"/var/lib/wg-monitor/state.json\"
s = json.load(open(p))
k = next(iter(s[\"peers\"]))
s[\"peers\"][k] = \"stopped\"
json.dump(s, open(p, \"w\"))
"
  systemctl start wg-monitor.service   # PAS python3 wg-monitor.py en direct, cf. piège plus haut
  cat /var/log/wireguard-events.log
  systemctl start wg-monitor.timer
'

docker exec wazuh-wazuh.manager-1 grep wg-monitor /var/ossec/logs/alerts/alerts.json | tail -1
```

## Pas de remédiation automatisée

Rien de branché ici — visibilité seule. Couper un pair WireGuard (retirer sa
clé de `wg0.conf` + `wg syncconf`, ou via l'API WGDashboard) serait faisable
en AR mais hors scope de cette demande.
