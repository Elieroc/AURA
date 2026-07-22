# Serveur MCP Wazuh

Expose Wazuh à Claude Code via MCP : 54 outils, dont 9 outils d'action
(active response) et 10 outils de vérification / rollback.

Upstream : https://github.com/gensecaihq/Wazuh-MCP-Server
Commit épinglé : voir `patches/UPSTREAM_COMMIT`.

Le clone upstream (`wazuh-mcp-server/`) n'est **pas** versionné ici : seuls la
surcouche locale (`compose.override.yml`, `.env`), les patches et cette doc le
sont.

## Installation

```bash
cd mcp
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git wazuh-mcp-server
cd wazuh-mcp-server
git checkout $(cat ../patches/UPSTREAM_COMMIT)
git apply ../patches/ar-command-name.patch
cp ../compose.override.yml .
cp ../env.example .env   # puis remplir (mots de passe = ceux de wazuh/.env)
docker compose up -d --build
```

`compose.override.yml` fait deux choses :

- publie le port **uniquement sur 127.0.0.1** (le serveur n'a pas de TLS
  intégré, il ne doit pas écouter sur le réseau) ;
- rattache le conteneur au réseau `wazuh_default` pour résoudre `wazuh.manager`
  et `wazuh.indexer`.

## Enregistrement dans Claude Code

L'authentification est en mode `bearer`. La clé `MCP_API_KEY` n'est **pas**
acceptée directement comme bearer : il faut un JWT signé avec `AUTH_SECRET_KEY`.
Génération d'un jeton lecture + écriture (365 j) :

```bash
docker compose exec -T wazuh-main-server python -c "
import os,jwt,datetime
sk=os.environ['AUTH_SECRET_KEY']
now=datetime.datetime.now(datetime.timezone.utc)
print(jwt.encode({'sub':'claude-code','iat':now.timestamp(),
  'exp':(now+datetime.timedelta(days=365)).timestamp(),
  'scope':'wazuh:read wazuh:write'},sk,algorithm='HS256'))
"
```

```bash
claude mcp add --scope local --transport http wazuh http://127.0.0.1:3000/mcp \
  --header "Authorization: Bearer <jeton>"
```

Sans le scope `wazuh:write`, seuls les 35 outils de lecture sont utilisables :
c'est le mode à privilégier pour un usage quotidien.

## Active response

Quatre écarts entre l'upstream et une install Wazuh standard, corrigés ici.
Tous étaient silencieux : l'API répond 200, l'action ne se fait pas.

**1. Nom des commandes.** L'upstream envoie `!<commande>` à l'API. L'API
répond 200 mais `wazuh-execd` sur l'agent ignore le message : il n'exécute que
les commandes dont le nom correspond exactement à une entrée de son
`etc/shared/ar.conf`, soit `<commande><chiffre-de-location>` sans `!`
(`kill-process0`). D'où `patches/ar-command-name.patch`.

**3. Compte à désactiver.** Le binaire `disable-account` lit le compte dans
`alert.data.dstuser`, pas dans `extra_args` : sans alerte il s'arrête sur
`Cannot read 'dstuser' from data`. Le patch renseigne l'alerte.

**4. Rollbacks firewall.** `firewall-drop` et `host-deny` n'annulent un blocage
que sur expiration de timeout (commande `delete` émise par `execd`) et lisent
l'IP dans l'alerte — un appel API ne peut faire ni l'un ni l'autre. Deux
scripts dédiés remplacent ce chemin : `firewall-allow.sh` et `host-allow.sh`.

**2. Commandes absentes.** Une commande n'est poussée dans le `ar.conf` des
agents que si elle apparaît dans un bloc `<active-response>` du manager. Ces
blocs sont déclarés dans `wazuh/config/wazuh_cluster/wazuh_manager.conf` avec
`<rules_id>999999</rules_id>` — règle inexistante, donc **aucun déclenchement
automatique** : seul un appel API (MCP ou Shuffle) exécute l'action.

Les noms attendus par le MCP ne correspondaient pas à nos scripts : cinq
scripts de liaison ont été ajoutés dans `wazuh/active-response/` —
`host-isolation.sh` (route vers `host-isolate.sh` / `host-unisolate.sh` selon
l'argument `undo`), `quarantine.sh`, `enable-account.sh`, `firewall-allow.sh`,
`host-allow.sh`. `kill-process.sh` accepte désormais un PID en plus d'un nom de
process (le MCP envoie un PID).

`firewall-drop` (binaire Wazuh) exige `iptables`, absent d'une Debian 12 qui
n'a que nftables : installer le paquet `iptables` (backend `nf_tables`) sur les
agents Debian, sinon l'action échoue sur
`The iptables file 'iptables' is not accessible`.

Après modification de la conf manager :

```bash
cd wazuh && docker compose restart wazuh.manager
```

Les scripts doivent être présents sur **chaque agent** dans
`/var/ossec/active-response/bin/` (root:wazuh, 750).

### État vérifié sur l'agent 001 (debian-vm)

Les 9 outils d'action ont été exécutés pour de vrai sur l'agent 001, avec leur
rollback, et l'agent a été remis dans son état initial.

| Outil MCP | Effet vérifié sur l'hôte |
|---|---|
| `wazuh_kill_process` | PID ciblé tué, homonymes épargnés, safelist respectée |
| `wazuh_quarantine_file` / `wazuh_restore_file` | fichier déplacé en quarantaine puis restauré |
| `wazuh_isolate_host` / `wazuh_unisolate_host` | table nftables posée puis retirée, réseau rétabli |
| `wazuh_block_ip` / `wazuh_firewall_allow` | règle `DROP` iptables ajoutée puis supprimée |
| `wazuh_host_deny` / `wazuh_host_allow` | ligne `ALL:<ip>` ajoutée puis retirée de `/etc/hosts.deny` |
| `wazuh_disable_user` / `wazuh_enable_user` | compte verrouillé (`passwd -S` = `L`) puis rouvert (`P`) |
| `wazuh_restart` | agent redémarré |

Les outils de vérification `wazuh_check_blocked_ip` et `wazuh_check_user_status`
répondent correctement, mais ils déduisent l'état de l'historique des alertes,
pas de l'hôte : à recouper avec l'agent en cas de doute.
