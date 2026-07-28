# pfSense — syslog direct + Suricata via l'agent

Deux flux distincts remontent du même boîtier :

1. **Firewall (`filterlog`) — syslog UDP direct vers le manager**, décodé côté
   Wazuh. Pas de collecteur à installer ; les alertes arrivent en `agent.id=000`
   (le manager lui-même), c'est le sens de tout ce qui suit jusqu'à la section
   Suricata.
2. **Suricata (IDS) — via un agent Wazuh installé sur pfSense** (`wazuh-agent`
   FreeBSD 4.7.2, paquet `pkg`), qui lit l'EVE JSON. Cf. section dédiée en bas.

Le point 1 précède historiquement le point 2 : le paquet `wazuh-agent` n'est pas
un chemin officiel/supporté pour pfSense, mais il existe dans les dépôts FreeBSD
et fonctionne. Les deux flux atterrissent dans le même index `wazuh-firewall-*`.

## 1. Manager Wazuh

`wazuh/config/wazuh_cluster/wazuh_manager.conf.example` documente déjà le bloc
`<remote>` syslog à ajouter (copier dans `wazuh_manager.conf`, gitignored) :

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>IP_DU_PAREFEU/32</allowed-ips>
</remote>
```

**`allowed-ips` = l'IP telle que VUE PAR LE MANAGER**, pas l'IP WAN/mgmt de
pfSense : un pare-feu multi-interfaces sort avec l'IP de l'interface la plus
proche de la destination. Se tromper ici fait tomber tous les paquets en
silence (reçus par le noyau/docker, jetés par `wazuh-remoted` sans log
exploitable) — vérifier avec un `tcpdump udp port 514` côté manager pendant
qu'un événement pfSense se produit, avant de chercher plus loin.

Recréer le manager après modif :
```bash
docker compose up -d --force-recreate wazuh.manager
```

Decoder + règles dédiés (déjà dans le repo, rien à faire ici) :
- `wazuh/config/wazuh_cluster/decoders/pfsense-nohostname.xml`
- `wazuh/config/wazuh_cluster/rules/100810-100812-*.xml`

**Pourquoi un décodeur custom et pas le natif `0455-pfsense_decoders.xml`** :
le syslogd FreeBSD de pfSense (testé sur 14.0-CURRENT) envoie les messages
`filterlog` **sans hostname** (`<PRI>Mmm dd hh:mm:ss filterlog[pid]: <csv>`),
alors que le décodeur natif attend `... pfSense filterlog: ...`. Le
pré-décodeur syslog de Wazuh assigne le jeton `filterlog[pid]:` au champ
`hostname`, laissant `program_name` vide — le décodeur natif (basé sur
`<program_name>filterlog</program_name>`) ne matche jamais, silencieusement
(`wazuh-logtest` confirme : *"No decoder matched"*). Le décodeur custom
`pf-nohost` matche sur `<prematch>` (texte brut) à la place ; commentaire en
tête du fichier pour le détail des pièges de syntaxe `offset` Wazuh rencontrés
en le construisant.

Index de destination : `wazuh-firewall-*` (routage dans
`alerts-pipeline.json`, sur `decoder.name == 'pf-nohost'` — testé avant le
test `agent.id`, puisque ce flux-là n'a pas d'agent, donc `agent.id`
vaut `000`, comme le manager lui-même).

## 2. pfSense

```bash
scp wazuh/agents/pfsense/configure-syslog.php root@<pfsense>:/tmp/
ssh root@<pfsense> 'php -f /tmp/configure-syslog.php -- <IP_DU_MANAGER>'
```

Le script :
- N'écrase **jamais** `remoteserver` (slot 1, réservé à ce qui existait déjà
  avant nous) — écrit dans `remoteserver2` puis `remoteserver3`.
- Active `<enable>` (syslog remote global) et `<filter>` (catégorie "Firewall
  Events" — sans ça, `filterlog` part seulement dans le fichier local, jamais
  vers le réseau ; c'est un flag séparé du flag global, piège classique).
- Idempotent : ne fait rien si l'IP:port demandé est déjà présent quelque part.
- `write_config()` + `system_syslogd_start()` : mêmes fonctions que la
  webUI pfSense, pas de bidouille XML à la main.

**Root shell direct requis** (pas le menu `pfSsh.php` restreint) — root
possède déjà `/usr/local/bin/php` et l'include path pfSense (`config.inc`,
`system.inc`), donc pas de dépendance à installer.

Alternative manuelle (webUI) : *Status > System Logs > Settings* — cocher
*Firewall Events* dans "What to log remotely", ajouter le manager dans un des
3 champs "Remote log servers", Save. Le script ci-dessus fait exactement ça,
en scriptable/rejouable.

## 3. Vérification

```bash
# côté pfSense : confirmer que filterlog part bien en remote
grep -A2 '!filterlog' /var/etc/syslog.d/*.conf

# côté manager : décodage correct sur un événement réel
docker exec wazuh-wazuh.manager-1 grep pfsense /var/ossec/logs/alerts/alerts.json | tail -1
```

## 4. Suricata (IDS) → Wazuh

Suricata tourne en paquet pfSense (`pfSense-pkg-suricata`), **une instance par
interface**. Piège de nommage : le VLAN `LAN100` est l'interface pfSense `wan`
(vtnet0) — le champ `descr` porte le nom du VLAN, pas la clé de config.

```bash
scp wazuh/agents/pfsense/configure-suricata.php root@<pfsense>:/tmp/
ssh root@<pfsense> 'php -f /tmp/configure-suricata.php -- wan LAN100'
ssh root@<pfsense> '/usr/local/etc/rc.d/suricata.sh restart'
```

Le script est idempotent et applique tout ce qui suit. Détail de ce qu'il fait
et pourquoi :

Configuration **sans la webUI** : un script PHP sur le boîtier qui manipule
`config_get_path('installedpackages/suricata/rule')`, puis `write_config()`,
puis `sync_suricata_package_config()` (définie dans
`/usr/local/pkg/suricata/suricata.inc`). Cette dernière crée les répertoires,
prépare les fichiers de règles et régénère les `suricata.yaml`. Mettre
`global $rebuild_rules; $rebuild_rules = true;` avant l'appel si les catégories
de règles changent, sinon les nouvelles catégories ne sont pas compilées.
Cloner une instance existante comme gabarit évite de deviner les ~200 clés.
Redémarrage : `/usr/local/etc/rc.d/suricata.sh restart`.

**Sortie EVE** : `eve_output_type` doit valoir `regular` (fichier
`eve.json`). Le défaut du paquet est `syslog`, qui part dans le syslog pfSense
que Wazuh ne lit pas — une instance Suricata configurée ainsi ne remonte
strictement rien, sans erreur nulle part.

Côté agent, un seul `localfile` couvre toutes les interfaces :

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/suricata_vtnet*/eve.json</location>
</localfile>
```

Vérifier que le wildcard a bien résolu : `/var/ossec/queue/logcollector/file_status.json`
liste un objet par fichier réellement suivi, avec son `offset`.

**Volume** : désactiver les types de transaction (`eve_log_dns`, `_http`,
`_tls`, `_smb`, …) et ne garder que `alert`, `drop`, `anomaly`. Mesuré sur ce
lab : ~450 Mo/jour et par interface avec les transactions, contre quelques
événements par minute sans.

**Catégorie `stream-events` supprimée sur toutes les interfaces.** Sur ce lab
virtualisé (virtio + TCP offload), Suricata voit des segments que la carte a
déjà réassemblés ou découpés autrement : `SURICATA STREAM ESTABLISHED invalid
ack` et `Packet with invalid ack` tiraient en continu. Mesuré **~200 alertes/s,
127 000 en dix minutes, 98 % du volume Suricata total** — du bruit
d'infrastructure, pas de l'évasion TCP. Suppression via une liste
`stream-noise` (`installedpackages/suricata/suppress/item`, contenu en base64
dans `suppresspassthru`, écrit dans le `threshold.config` de chaque instance),
rattachée aux 5 instances par `suppresslistname`. Après suppression : 37
événements sur 3 min, uniquement ET user-agent et QUIC.

Ce piège ne se voit pas tant que l'EVE part en syslog : le bruit existait déjà,
il était juste jeté. Il apparaît le jour où on branche Wazuh dessus.

Index de destination : `wazuh-firewall-*`, routé sur `rule.groups` contenant
`suricata` (le décodeur est le `json` générique, il ne discrimine rien).

**Niveau des alertes** : le ruleset natif Wazuh (86600+) mappe la sévérité
Suricata sur le niveau Wazuh, et une signature « Informational » donne un
**niveau 3**. Elles sont donc ingérées par le pipeline (`INGEST_MIN_LEVEL=0`) et
peuvent s'attacher à un incident (`ATTACH_MIN_LEVEL=3`), mais **n'en amorcent
aucun** : la corrélation part de niveau ≥ 12. Pour qu'une signature Suricata
déclenche un incident, il faut une règle locale qui remonte son niveau — pas un
réglage côté Suricata.

## Pas de remédiation automatisée

**Aucun script active response déployé sur pfSense.** C'est un flux
read-only (visibilité réseau/firewall), pas une cible pilotée par
`mitigate.py`. L'agent Wazuh présent pour Suricata rendrait techniquement un
canal AR possible, mais rien n'est installé de ce côté : aucun script AR, et le
flux `filterlog` (agent.id=000) n'en aurait de toute façon pas.

## Limites connues

- Seuls `id` (numéro de règle pfSense), `action` (block/pass), `protocol`,
  `srcip`, `srcport`, `dstip`, `dstport` sont extraits en champs structurés.
  Le CSV complet reste dans `full_log` (Discover) quel que soit l'échec
  d'extraction d'un champ — rien n'est perdu, juste pas indexé.
- L'extraction de `srcip`/`dstip`/`protocol` suppose un CSV IPv4 avec le
  nombre de champs standard avant `srcip` ; un format IPv6 (adresses plus
  longues, champs additionnels) peut décaler ces trois champs. `id` et
  `action` restent fiables dans tous les cas observés (position fixe, avant
  la partie variable du CSV).
