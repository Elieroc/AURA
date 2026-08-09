# Serveur MCP AURA

Administrer AURA depuis n'importe quel client IA (Claude Code, Claude Desktop,
tout client MCP), par un seul endpoint. Le serveur relaie aussi Wazuh et
DFIR-IRIS : le client n'a qu'une entrée à déclarer.

    client IA  ──HTTP+JWT──►  aura-mcp  ──┬── soc_agent (import direct)
                              :3100        ├── wazuh-mcp  :3000  (relayé, filtré)
                                           └── iris-mcp          (relayé, filtré)

Le serveur **importe `soc_agent`** au lieu de le réimplémenter : les outils
appellent le vrai code du pipeline, avec ses garde-fous. Une couche qui
recopierait la logique divergerait, et la divergence ne se verrait qu'au
moment où une remédiation échoue.

## Mise en service

```bash
cd /opt/AURA
openssl rand -hex 32          # -> AURA_MCP_SECRET dans .env
openssl rand -hex 32          # -> WAZUH_MCP_SECRET dans .env
docker compose -p aura up -d wazuh-mcp aura-mcp
```

Puis émettre un jeton pour le relais Wazuh (`scope` : `wazuh:read wazuh:write`,
signé avec `WAZUH_MCP_SECRET`) et le poser dans `AURA_MCP_WAZUH_TOKEN`.

Émettre un jeton client :

```bash
python3 scripts/aura-mcp-token.py --sujet claude-code --scope aura:read
python3 scripts/aura-mcp-token.py --sujet elie --scope aura:admin --jours 30
```

Vérifier la chaîne complète (poignée de main, auth, inventaire, appel réel) :

```bash
docker run --rm --network host -v /opt/AURA:/w -w /w aura-mcp:latest \
  python scripts/aura-mcp-smoke.py --jeton "$JETON" \
  --outil aura_incidents_list --args '{"limite":2}'
```

Le même script sert de client en ligne de commande pour n'importe quel outil.

## Côté client

`.mcp.json` du projet (les secrets restent dans l'environnement, jamais dans
le fichier versionné) :

```json
{
  "mcpServers": {
    "aura": {
      "type": "http",
      "url": "http://127.0.0.1:3100/mcp",
      "headers": { "Authorization": "Bearer ${AURA_MCP_TOKEN}" }
    }
  }
}
```

Le serveur n'écoute que sur la loopback. Depuis un poste distant, passer par un
tunnel SSH (`ssh -L 3100:127.0.0.1:3100 root@<manager>`) — jamais en ouvrant le
port : qui l'atteint dispose de l'isolation d'hôte.

## Scopes

Chacun inclut le précédent. Le refus est le défaut : un jeton sans scope AURA
reconnu n'obtient rien, pas même la lecture.

| Scope | Ce qu'il ouvre |
|---|---|
| `aura:read` | incidents, alertes, triages, remédiations, whitelist, UEBA, métriques, entonnoir, simulations, santé d'agent, relais Wazuh |
| `aura:write` | cycle, triage, synchro IRIS, réconciliation des retours d'AR, écriture dans les dossiers IRIS |
| `aura:admin` | remédiation, isolation, whitelist, tuning de règles, enrôlement d'agent |

Le scope est porté **par outil**, via `@auth.exige`. `serveur.enregistrer`
refuse d'enregistrer un outil qui n'en déclare pas : un oubli devient une
erreur de démarrage, pas un trou silencieux.

## Les outils

### Lire (`aura:read`)

`aura_incidents_list` · `aura_incident_get` · `aura_alerts_search` ·
`aura_triage_history` · `aura_mitigations_list` · `aura_whitelist_list` ·
`aura_ueba_state` · `aura_funnel_report` · `aura_metrics`

`aura_incident_get` rend le texte **exact** soumis au LLM : un verdict se juge
sur pièces, pas sur son résumé.

### Simuler (`aura:read`, aucun effet)

`aura_simulate_decision` · `aura_validate_whitelist_signature` ·
`aura_ueba_score_group` · `aura_rule_preview` · `aura_isolation_check`

`aura_simulate_decision` passe des actions dans les garde-fous **réels** et
montre ce qu'il en reste. C'est la question à poser avant d'agir.

### Agir (`aura:write` / `aura:admin`)

`aura_run_cycle` · `aura_triage_incident` · `aura_iris_case_sync` ·
`aura_ar_reconcile` · `aura_mitigate_execute` · `aura_isolate` ·
`aura_unisolate` · `aura_whitelist_apply` · `aura_rule_tuning_apply`

Tous en dry-run par défaut (`appliquer` / `confirmer` à `false`). Sans
confirmation, l'outil rend ce qui serait fait **et pourquoi ce serait refusé**.

### Enrôler (`aura:admin`)

`aura_enroll_agent` · `aura_agent_health` · `aura_manager_ar_status`

### Relayer

`wazuh_tools_list` / `wazuh_call` · `iris_tools_list` / `iris_call`

## Ce qui n'est jamais exposé

À aucun scope, et il faut que ça le reste :

- `correlate.recommencer` — efface tous les incidents ;
- `ueba.purger` — supprime définitivement l'historique de baseline ;
- `label.enregistrer` — la vérité terrain sert à **noter** l'IA ; l'IA ne
  l'écrit pas, sinon la mesure de justesse ne mesure plus rien ;
- `iris.nettoyer_iocs(simulation=False)` — suppression irréversible dans IRIS ;
- `llm.completion` — court-circuiterait la pseudonymisation ;
- la table `anonymization_map` — correspondances jetons ↔ valeurs réelles ;
- les 19 outils d'active response du serveur Wazuh amont — ils agiraient sans
  la politique d'AURA (agents protégés, groupes d'infrastructure, comptes
  système).

## Injection de prompt

Le contenu des alertes est écrit par ce qui tourne sur les machines
surveillées, donc éventuellement par un attaquant qui sait qu'une IA va le
lire. Les champs concernés sont balisés `<untrusted>`.

**Ce balisage n'est pas une protection.** Les tests du pipeline montrent que le
modèle se laisse retourner 3 fois sur 4 par une injection bien placée. La
barrière réelle est déterministe et vit dans `soc_agent.actions` : pas de
clôture automatique au-dessus du niveau 14, pas de clôture quand un motif
d'injection est repéré, isolation rétrogradée s'il existe un confinement moins
invasif. Elle s'applique quel que soit l'appelant, y compris ce serveur.

## Enrôlement d'un agent

Poser un agent ne suffit pas. Une machine n'est couverte que si les quatre
étages sont là — l'agent, la télémétrie que les règles attendent, les scripts
d'active response, et la déclaration côté manager. Il manque toujours un de ces
étages sur une machine qui « a pourtant l'agent ».

```
aura_enroll_agent(hote="10.0.1.42", systeme="linux")               # plan
aura_enroll_agent(hote="10.0.1.42", systeme="linux", confirmer=true)
aura_agent_health(hote="10.0.1.42", systeme="linux")
```

Linux : agent Wazuh épinglé, auditd et le jeu de règles `execve` d'AURA,
`/etc/ld.so.preload` créé pour être surveillable, scripts d'active response,
compte `wazuh-admin`. **Un redémarrage est presque toujours nécessaire** :
tant que journald tient le socket netlink, auditd n'émet rien et la machine
paraît calme alors qu'elle est muette. `aura_agent_health` le dit.

Windows : agent, audit de création de processus **avec ligne de commande**,
sous-catégories d'audit AD, ScriptBlock, Sysmon, abonnement aux canaux, puis
les scripts d'active response Windows/AD et leurs lanceurs `.exe`. Reste à
déclarer les blocs `<command>` sur le manager — `aura_manager_ar_status`
vérifie ce qui manque.

Le conteneur MCP joint les machines **en direct** (SSH par clé
`wazuh_ops_ed25519`, ou WinRM) : il ne passe par aucun rebond. Sur les hôtes
déjà enrôlés avec une autre clé, déposer la clé publique d'exploitation avant
d'utiliser `aura_agent_health`.

## Limites connues

- Le relais IRIS est **prévu et non déployé** : le serveur `iris-mcp` amont
  n'existe pas encore sur le manager. `iris_tools_list` répond « indisponible »
  tant que `AURA_MCP_IRIS_URL` est vide. La création de cases par le pipeline
  (`aura_iris_case_sync`) n'en dépend pas.
- `aura_run_cycle` peut durer plusieurs minutes et rend `0` aussi bien pour
  « cycle terminé » que pour « un autre cycle tournait déjà ».
- Un jeton ne se révoque pas : il faut changer le secret, ce qui invalide tous
  les autres. D'où les durées courtes sur `aura:admin`.
