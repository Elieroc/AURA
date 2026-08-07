# Active response Aura-SOC

Scripts de remédiation exécutés **sur l'agent**, appelés par l'API Wazuh, le
serveur MCP ou `src/ai/soc_agent/mitigate.py`.

## Pourquoi des scripts maison

Les binaires natifs livrés par le paquet (`firewall-drop`, `disable-account`, …)
lisent la cible **dans l'alerte** (`alert.data.srcip`, `alert.data.dstuser`) et
échouent sur tout appel piloté, qui passe la cible en `extra_args`
(« Cannot read 'srcip' from data »). Ces scripts lisent `extra_args[0]`.

Chaque action a son inverse, par paire : `firewall-drop.sh` / `firewall-allow.sh`,
`disable-account.sh` / `enable-account.sh`, `host-isolate.sh` /
`host-unisolate.sh`. `kill-process.sh` n'en a pas (pas d'« unkill »).

## Déploiement — obligatoire, et à échec silencieux

Les scripts doivent être présents dans `/var/ossec/active-response/bin/` de
**chaque agent** (root:wazuh, 750). `install-agent.sh` s'en charge à
l'installation ; pour un agent déjà en place :

```sh
./scripts/deploy-active-response.sh <ip-agent> [<ip-agent> ...]
```

Sans ces fichiers, **toute remédiation échoue sans rien remonter** : l'`ar.conf`
poussé par le manager déclare bien `firewall-drop.sh`, l'API Wazuh répond `200`
(elle ne fait que transmettre la commande à l'agent), et rien ne s'exécute. Le
seul indice est l'absence de ligne dans le `/var/ossec/logs/active-responses.log`
de l'agent. C'est ce qui peut rendre le blocage d'IP inopérant en silence si le
déploiement des scripts est oublié.

## Appel

Le préfixe `!` est **obligatoire** : il désigne le nom de **fichier** littéral et
court-circuite la résolution par `<command>` d'`ossec.conf`.

```sh
curl -sk -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -X PUT "https://127.0.0.1:55000/active-response?agents_list=003" \
  -d '{"command":"!firewall-drop.sh","arguments":["198.51.100.77"]}'
```

Sans le `!`, l'API cherche un `<command>` d'`ossec.conf` et peut répondre
`1652 The command used is not defined in the configuration`.

## Pare-feu : iptables ou nftables

`firewall-drop.sh` / `firewall-allow.sh` utilisent `iptables` quand il est
présent, sinon **nftables** (table dédiée `inet soc_ai_block`, chaîne `input`
priority -10). Le repli est nécessaire : certains hôtes Debian 12 récents
n'embarquent que `nft`, sans le shim iptables.

La table est **distincte** de `wazuh_isolation` (`host-isolate.sh`) : une
dé-isolation supprime sa table entière et ne doit pas emporter au passage les
blocages d'IP posés séparément.

## Vérification de bout en bout

Ne jamais se fier à la table `mitigations` ni au code retour de l'API. Lire
l'état réel de l'hôte :

```sh
tail /var/ossec/logs/active-responses.log
iptables -S INPUT           # ou : nft list table inet soc_ai_block
chage -l <user>             # disable-account
nft list table inet wazuh_isolation   # isolation
```
