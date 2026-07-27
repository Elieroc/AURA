# pfSense — syslog direct (pas d'agent Wazuh)

pfSense (FreeBSD, appliance) n'a pas de paquet wazuh-agent officiel/supporté,
contrairement à Linux/Windows. Le chemin retenu : **syslog UDP direct vers le
manager**, décodé côté Wazuh — pas de collecteur à installer sur pfSense.

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
`alerts-pipeline.json`, sur `rule.groups` contenant `pfsense` — testé avant le
test `agent.id`, puisque pfSense n'a justement pas d'agent, donc `agent.id`
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

## Pas de remédiation automatisée

**Aucun script active response déployé sur pfSense.** C'est un flux
read-only (visibilité réseau/firewall), pas une cible pilotée par
`mitigate.py` — pfSense n'a pas d'agent Wazuh, donc pas de canal d'active
response possible de toute façon (le mécanisme AR de Wazuh est un
agent→manager, pas applicable ici).

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
