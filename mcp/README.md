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

Deux écarts entre l'upstream et une install Wazuh standard, corrigés ici.

**1. Nom des commandes.** L'upstream envoie `!<commande>` à l'API. L'API
répond 200 mais `wazuh-execd` sur l'agent ignore le message : il n'exécute que
les commandes dont le nom correspond exactement à une entrée de son
`etc/shared/ar.conf`, soit `<commande><chiffre-de-location>` sans `!`
(`kill-process0`). D'où `patches/ar-command-name.patch`.

**2. Commandes absentes.** Une commande n'est poussée dans le `ar.conf` des
agents que si elle apparaît dans un bloc `<active-response>` du manager. Ces
blocs sont déclarés dans `wazuh/config/wazuh_cluster/wazuh_manager.conf` avec
`<rules_id>999999</rules_id>` — règle inexistante, donc **aucun déclenchement
automatique** : seul un appel API (MCP ou Shuffle) exécute l'action.

Les noms attendus par le MCP ne correspondaient pas à nos scripts : trois
scripts de liaison ont été ajoutés dans `wazuh/active-response/` —
`host-isolation.sh` (route vers `host-isolate.sh` / `host-unisolate.sh` selon
l'argument `undo`), `quarantine.sh`, `enable-account.sh`. `kill-process.sh`
accepte désormais un PID en plus d'un nom de process (le MCP envoie un PID).

Après modification de la conf manager :

```bash
cd wazuh && docker compose restart wazuh.manager
```

Les scripts doivent être présents sur **chaque agent** dans
`/var/ossec/active-response/bin/` (root:wazuh, 750).

### État vérifié sur l'agent 001 (debian-vm)

| Outil MCP | Testé |
|---|---|
| `wazuh_kill_process` | OK (PID ciblé uniquement, safelist respectée) |
| `wazuh_quarantine_file` / `wazuh_restore_file` | OK |
| `wazuh_isolate_host` / `wazuh_unisolate_host` | OK |

Non testés en conditions réelles : `wazuh_block_ip`, `wazuh_firewall_drop`,
`wazuh_host_deny`, `wazuh_disable_user` / `wazuh_enable_user`, `wazuh_restart`.
Les commandes sont câblées, l'exécution reste à valider.
