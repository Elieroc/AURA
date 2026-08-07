# Remédiation autonome

Comment une alerte devient une action réelle sur un endpoint, et catalogue
complet des active responses du projet.

Code : [`src/ai/soc_agent/mitigate.py`](../src/ai/soc_agent/mitigate.py) (exécution),
[`src/ai/soc_agent/actions.py`](../src/ai/soc_agent/actions.py) (garde-fous),
[`src/wazuh/active-response/`](../src/wazuh/active-response/) (scripts sur les agents).

## Le principe

**L'action part sur le verdict, sans validation humaine par action.** C'est le
but du projet : un XDR autonome, pas un assistant qui attend un clic. Ce qui
borne l'action n'est pas un accord humain a priori mais des **garde-fous
déterministes**, à trois étages :

1. `actions.appliquer_garde_fous` — entre la sortie du modèle et l'exécution ;
2. `mitigate._cibles_par_machine` — résolution de la cible, « dans le doute, on
   n'agit pas » ;
3. **le script d'active response lui-même**, qui refuse localement. Cet étage
   n'est pas redondant : l'AR est aussi joignable par l'API Wazuh et par le
   serveur MCP, qui ne passent pas par le code Python.

**Le LLM n'est pas une frontière de sécurité.** Mesuré : sur un ransomware
avéré, 3 injections sur 4 dans les logs retournent son verdict en
`false_positive`. Le prompt ne tient pas et ne peut pas tenir ; les barrières
ci-dessus, si — elles ne dépendent d'aucune probabilité et ne s'argumentent pas
avec du texte dans un log.

## Chaîne complète

```
 triage LLM  ──► verdict + actions proposées
      │
      ▼
 actions.deduire()            open_case / close_false_positive déduits du verdict
      │                       (le modèle les oubliait une fois sur deux)
      ▼
 actions.appliquer_garde_fous()
      │   • niveau ≥ 14  → clôture auto interdite
      │   • injection    → clôture auto interdite
      │   • isolation    → retirée si un confinement moins invasif s'applique,
      │                    SAUF compromission active de l'hôte
      ▼
 iris.creer_cases() ──► mitigate.executer(incident)
      │
      │   suspension si motifs d'injection au triage
      │   + complément déterministe : compte créé par l'attaquant sur un TP
      │     → propose_disable_user, même si le LLM ne l'a pas proposé
      ▼
 pour chaque action, dans ORDRE_EXEC :
      _cibles_par_machine()  ──► [(agent, cible), …]
      │
      ▼
 EXECUTEURS[action]  ──►  canal  ──►  script AR sur l'agent
      │                    (Shuffle ou API Wazuh)
      ▼
 table `mitigations` (statut 'émis') + tâche IRIS (onglet Tasks)
      │
      ▼
 l'agent renvoie `ar-result` ──► règles 100931-100934 ──► alerte
      │
      ▼
 reconcilier_resultats_ar()   'émis' → 'exécuté' | 'refusé' | 'échec' | 'sans effet'
```

Deux boucles périodiques complètent le tableau (conteneurs dédiés, verrou
consultatif Postgres) :

- `soc-agent-cycle` (5 min) : ingest → correlate → triage → whitelist → cases
  IRIS, qui appelle la remédiation ;
- `soc-agent-reconcile` (1 min) : rapproche les comptes rendus d'AR **et** annule
  toute remédiation dont la tâche IRIS est passée en `Canceled`.

## Ce qui est exécutable

Six actions, énumération fermée. Le reste de la sortie du modèle (`open_case`,
`close_false_positive`, `escalate_human`) n'est pas une action machine et ne
passe jamais par ici.

| Action | Linux | Windows / AD | Auto ? |
|---|---|---|---|
| `propose_kill_process` | `kill-process.sh` (Shuffle) | `win-kill-process.exe` | ✅ |
| `propose_quarantine_file` | `quarantine.sh` (non exposé à l'IA) | `win-quarantine-file.exe` | ✅ |
| `propose_block_ip` | `firewall-drop.sh` | `win-block-ip.exe` | ✅ |
| `propose_disable_user` | `disable-account.sh` | `ad-disable-account.exe` (sur DC) | ✅ |
| `propose_remove_privileged_group` | — | `ad-remove-group-member.exe` (sur DC) | ❌ **propose-only** |
| `propose_isolate_host` | `host-isolate.sh` (Shuffle) | `win-host-isolate.exe` | ✅ (dernier recours) |

**Ordre d'exécution** (`ORDRE_EXEC`) : tuer le process, mettre le fichier en
quarantaine, couper les flux et les comptes — **puis** isoler. L'isolation part
en dernier parce qu'elle coupe les canaux (API Wazuh, Shuffle) dont dépendent
les autres remédiations.

`propose_remove_privileged_group` reste dans `ACTIONS_MANUELLES` : trop fort
impact pour le palier d'autonomie actuel. L'exécuteur rend `dry_run`, la tâche
IRIS le signale `[SIMULATION]`, l'analyste tranche.

La **collecte forensique n'est pas une action de l'IA** : trop lourde, tirée en
SSH depuis le manager (`scripts/forensic-*.sh`), hors du périmètre du triage.

## Garde-fous

### Étage 1 — `actions.appliquer_garde_fous`

- **Clôture interdite au-dessus du niveau 14.** Une règle qui tire à 14+ a exigé
  plusieurs corrélations côté Wazuh ; la classer en faux positif demande un
  humain. C'est exactement ce qu'une injection cherche à obtenir : faire
  refermer une intrusion en silence.
- **Clôture interdite sur motifs d'injection.** Un verdict rendu sur un contexte
  manipulé ne vaut rien. Le verdict n'est pas réécrit — seule la conséquence
  dangereuse est refusée, et la main rendue à un humain (`escalate_human`).
- **Isolation en dernier recours.** Tant qu'un confinement moins invasif
  s'applique (bloquer l'IP, tuer le process, désactiver le compte, quarantaine),
  c'est lui qui part et l'isolation est retirée — avec `escalate_human` en
  remplacement, pour que l'analyste voie qu'elle a été jugée pertinente.
  Vécu le 2026-07-29 : un scanner internet cherchant `//adminer.php` (404, rien
  servi) a fait isoler le reverse proxy de tout le lab, alors que le blocage
  d'IP était proposé dans le même verdict.
  **Exception** : en compromission active de l'hôte (post-exploitation avérée —
  webshell, reverse shell, rootkit, persistance root, cf.
  `config.RULES_COMPROMISSION_HOTE`), l'isolation est **maintenue** en plus du
  reste : couper une IP ne déloge pas un attaquant déjà installé.

### Étage 2 — résolution de la cible (`_cibles_par_machine`)

La corrélation est cloisonnée par agent, mais un case de **campagne** couvre
plusieurs machines. Chaque remédiation part donc sur **la machine où sa preuve a
été observée** (l'`agent_id` de l'alerte), jamais sur un agent global ; la table
`mitigations` porte l'`agent_id` visé.

- **Agents capteurs d'hôte exclus** (`AGENTS_CAPTEURS`, ex. l'hôte Proxmox) :
  leur télémétrie décrit d'autres machines, donc on ne sait pas où agir. Un
  backdoor vu seulement par un capteur (conteneur sans auditd propre) n'est
  **pas** désactivé automatiquement — c'était le bug où `disable-account` tirait
  sur l'hôte où le compte n'existe pas.
- **Isolation seulement** (`raison_non_isolable`, trois barrières dans l'ordre) :
  agent de `AGENTS_PROTEGES` (défaut `000`, le manager — qui n'a d'ailleurs
  aucun groupe, le mécanisme de groupes ne le couvrirait pas) ; agent d'un
  groupe d'infrastructure (`ISOLATION_GROUPES_INTERDITS` : pare-feu, proxy, DNS,
  VPN — couper une machine qui achemine le trafic d'autrui provoque une panne
  générale au lieu de contenir un incident) ; rôle indéterminable — refus par
  défaut (`ISOLATION_REFUS_SI_ROLE_INCONNU`).
- **`block_ip`** écarte : IP invalide/loopback, IP d'un subnet du parc
  (mouvement latéral ≠ C2), et **IP d'un agent surveillé** (une victime ou un
  pivot n'est pas l'attaquant — ajouté après le purple-team du 2026-07-31 où
  l'hôte pivot a été bloqué à tort). Les IP restantes sont toutes bloquées,
  publiques d'abord : un bruteforce vient de N sources.
  Les IP C2 sont aussi extraites des redirections `/dev/tcp|udp` du proctitle —
  un execve auditd n'a pas de `srcip`, sans quoi un reverse shell détecté
  restait détecté mais jamais bloqué.
- **`disable_user`** : sur Windows, **seuls les comptes créés par l'attaquant**
  sont des cibles, et l'exécution est routée vers un **DC** (`AGENTS_DC`) — le
  `srcuser` d'un 4624 est l'identité qui s'est connectée, donc la victime ou un
  compte système (le purple-team du 2026-08-02 en a tiré `Système`,
  `SERVICE LOCAL` et `ANONYMOUS LOGON`). Sur Linux le `srcuser` provient de
  l'audit de commande, il reste exploitable.
- **`kill_process`** : Linux, uniquement les exécutables lancés depuis
  `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/`, ciblés par nom exact (`pkill
  -x`, `comm` plafonné à 15 caractères). Windows, cible `image#pid` : le script
  ne tue le PID que s'il porte encore cette image — un PID est réutilisé et il
  s'écoule jusqu'à 5 minutes entre l'alerte et la remédiation.

### Étage 3 — refus dans les scripts

Voir le catalogue ci-dessous : chaque script refuse localement ce qui
casserait l'hôte ou la supervision, et **écrit son refus** dans
`active-responses.log` sous forme de ligne `ar-result`.

## Catalogue des active responses

### Linux — [`src/wazuh/active-response/`](../src/wazuh/active-response/)

| Script | Action | Reverse | Garde-fou local |
|---|---|---|---|
| `host-isolate.sh` | isolation nftables (table `wazuh_isolation`), ne laisse joignables que la loopback, le manager (tcp/1514) et SSH depuis le serveur Wazuh | `host-unisolate.sh` | `WAZUH_MANAGER_IP` lu dans `/var/ossec/etc/soc-ai.conf` — une valeur fausse coupe l'agent définitivement ; pose un marqueur `/var/ossec/isolated` |
| `host-unisolate.sh` | supprime la table `wazuh_isolation` et le marqueur | — | — |
| `host-isolation.sh` | **aiguilleur** pour le serveur MCP : une seule commande, `undo` en `extra_args[0]` pour dé-isoler | — | ne signe pas de compte rendu : c'est le script délégué qui le fait |
| `firewall-drop.sh` | bloque une IP (`iptables`, repli **nftables** table `soc_ai_block`) | `firewall-allow.sh` | refuse la loopback et **l'IP du manager** (lue dans `ossec.conf`) |
| `firewall-allow.sh` | retire le blocage posé ci-dessus | — | — |
| `disable-account.sh` | `usermod -L` + `chage -E 1` | `enable-account.sh` (`usermod -U`, `chage -E -1`) | refuse `root`, `wazuh`, `wazuh-admin` |
| `enable-account.sh` | réactivation, **exactement symétrique** | — | — |
| `kill-process.sh` | `pkill -x` (nom exact, pas `-f` : cibler `app` ne doit pas tuer `backup-app-monitor`) | aucun (pas d'« unkill ») | safelist `sshd`, `wazuh-*`, `systemd`, `init` |
| `quarantine.sh` | déplace le fichier dans `/var/ossec/quarantine`, mode 000, `.path` mémorise l'origine ; `restore` en premier `extra_args` | intégré (`restore`) | refuse `/bin /sbin /lib /lib64 /usr/bin /usr/sbin /usr/lib /etc /boot /var/ossec/bin` |
| `host-allow.sh` | retire une ligne `ALL:<ip>` de `/etc/hosts.deny` (rollback du `host-deny` natif) | — | — |

La table nftables `soc_ai_block` est **distincte** de `wazuh_isolation` : une
dé-isolation supprime sa table entière et ne doit pas emporter au passage les
blocages d'IP posés séparément.

### Windows / AD — [`src/wazuh/active-response/windows/`](../src/wazuh/active-response/windows/)

Groupe A — sur l'hôte compromis :

| Script | Action | Reverse | Garde-fou local |
|---|---|---|---|
| `win-host-isolate` | Windows Firewall block-all sauf manager + allowlist (`MITIGATE_ISOLATE_ALLOW`) | `win-host-unisolate` | **refuse d'isoler un DC** |
| `win-kill-process` | `Stop-Process` par PID (image vérifiée) ou par nom | aucun | safelist `lsass`, `services`, agent Wazuh, Sysmon ; images génériques (`powershell`, `cmd`, `net`, `wsmprovhost`) tuables **par PID seulement** |
| `win-quarantine-file` | hash SHA256 + déplacement + deny ACL | `win-restore-file` | refuse les répertoires système |
| `win-block-ip` | blocage pare-feu entrant **et** sortant | `win-allow-ip` | refuse loopback et passerelle |

Groupe B — objets de domaine, routés vers un DC (`AGENTS_DC`) :

| Script | Action | Reverse | Garde-fou local |
|---|---|---|---|
| `ad-disable-account` | `Disable-ADAccount` + expiration | `ad-enable-account` | comptes protégés (Administrateur intégré, `krbtgt`, `Guest`, comptes machine `*$`, comptes de service SOC, tout membre de Domain/Enterprise/Schema Admins) ; **exige un DC** (`Confirm-DomainController`) |
| `ad-remove-group-member` | retire d'un groupe privilégié | `ad-add-group-member` | ne vide jamais un groupe, refuse Administrateur et les comptes machine ; **propose-only** |

Contraintes propres à Windows :

- `wazuh-execd` lance l'`<executable>` par un `CreateProcess` brut : un `.ps1`
  échoue avec `(1317): Could not launch command`. Chaque action est donc un
  **`.exe`** (copie du wrapper compilé `ar-wrapper.cs`, via `csc.exe`) qui lit
  son propre nom et transmet son stdin à `powershell -File <action>.ps1`.
- **ASCII strict** dans les `.ps1` : PowerShell 5.1 lit un fichier sans BOM dans
  la codepage ANSI ; un tiret cadratin casse le parsing et le dot-source de
  `_ar-common.ps1` échoue — les scripts ne font alors *rien*, en silence.

## Contrat d'appel

Message AR sur stdin :

```json
{"command": "add", "parameters": {"extra_args": ["<cible>"]}}
```

`delete` (émis par execd à l'expiration du timeout) est un **no-op** pour les
actions à fort impact : seule la commande inverse défait.

Les scripts maison lisent `extra_args[0]`. Les binaires **natifs** de Wazuh, eux,
lisent la cible dans l'alerte (`alert.data.srcip`, `alert.data.dstuser`) et
échouent donc sur tout appel piloté (« Cannot read 'srcip' from data ») : c'est
la raison d'être de chaque script de ce catalogue. Six tentatives, six échecs
silencieux — la base disait `exécuté` alors qu'aucun compte n'a jamais été
désactivé.

Appel direct par l'API :

```sh
curl -sk -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -X PUT "https://127.0.0.1:55000/active-response?agents_list=003" \
  -d '{"command":"!firewall-drop.sh","arguments":["198.51.100.77"]}'
```

Le préfixe **`!` est obligatoire** : il désigne le nom de fichier littéral. Sans
lui, l'API cherche un `<command>` d'`ossec.conf` et peut répondre `1652 The
command used is not defined in the configuration`.

Les appels successifs sont **espacés** (`MITIGATE_AR_GAP_SECONDS`, 1,5 s) : une
rafale d'AR sur le même agent en perd.

## Canaux

| Canal | Utilisé pour | Pourquoi |
|---|---|---|
| **Shuffle** (webhook) | isolation d'hôte, kill de process Linux | workflow SOAR historique, garde une trace côté SOAR |
| **API Wazuh** (`PUT /active-response`) | blocage IP, comptes, quarantaine, toutes les actions Windows/AD | direct, pas de workflow à maintenir par action |

Shuffle reste réservé aux **actions d'écriture**. L'investigation par l'IA passe
par des collecteurs read-only exposés en MCP : la séparation lecture/écriture est
architecturale, pas un gate humain.

## Comptes rendus et statuts

L'API Wazuh est **fire-and-forget** : un `200` signifie seulement que la commande
est partie. Sans compte rendu, `mitigations.statut` ne voulait rien dire — le
rapport IRIS du 2026-08-02 annonçait 26 quarantaines réussies de binaires
System32 sur un contrôleur de domaine, que le script avait toutes déclinées.

Chaque script écrit donc une ligne `ar-result` (`status`, `target`, `reason`),
décodée par la règle **100930** :

| Règle | Statut AR | Niveau | Sens |
|---|---|---|---|
| 100931 | `applied` | 3 | la modification a été faite |
| 100932 | `refused` | 7 | **un garde-fou a tiré** — le soc-agent a visé ce qu'il ne devait pas |
| 100933 | `error` | 7 | tentée et échouée |
| 100934 | `noop` | 3 | rien à faire (cible absente, déjà dans l'état) |
| 100935 | `noop` + `delete command` | 0 | expiration du timeout execd, pure plomberie |

Le niveau 3 de `noop` n'est pas cosmétique : Wazuh n'écrit aucune alerte sous
`log_alert_level`, donc une règle de niveau 0 n'atteindrait jamais l'indexer et
la mitigation resterait à `émis` pour toujours.

Statuts en base (`mitigations.statut`) :

| Statut | Tâche IRIS | Sens |
|---|---|---|
| `dry_run` | `To do` | décrit, pas déclenché (`MITIGATE_EXECUTE=false`, ou action propose-only) |
| `émis` | `In progress` | commande partie, **aucun compte rendu reçu** — jamais promue en succès |
| `confirmé` | `Done` | `applied` : la modification a été faite sur l'hôte |
| `refusé_agent` | `Canceled` | `refused` : un garde-fou du script a tiré |
| `échec` | `Canceled` | `error` : tentée et échouée |
| `sans_effet` | `On hold` | `noop` : rien à faire sur cette cible — à regarder |
| `annulé` | `Canceled` | reverse rejoué après passage de la tâche IRIS en `Canceled` |
| `annulation_impossible` | — | le reverse n'a pas pu être rejoué |

`confirmé`, `sans_effet`, `refusé_agent`, `annulé` et `annulation_impossible`
sont **figés** (`_STATUTS_FIGES`) : jamais rejoués.

Une action **sans compte rendu reste `émis`** : un script qui meurt avant
d'écrire sa ligne ne doit pas être lu comme un succès. Elle est rejouable tant
que `MITIGATE_MAX_TENTATIVES` (3) n'est pas atteint.

## Annulation

Toute remédiation doit être défaisable. L'analyste passe la **tâche IRIS** de
l'action en `Canceled` ; `soc-agent-reconcile` rejoue le reverse par le **même
canal** que l'aller, commente la tâche et fige le statut à `annulé`.

Un reverse s'exécute **toujours**, indépendamment de `MITIGATE_EXECUTE` : ce
drapeau ne borne que l'exécution automatique depuis un verdict, jamais la
restauration. Le gater était un piège — `reconcilier` marque `annulé` dès que le
reverse rend la main, donc l'annulation était perdue en silence, sans nouvelle
tentative possible.

Une action annulée **ne repart jamais seule** : `_deja_exec` fige aussi le
statut `annulé`.

Isolation/dé-isolation manuelles :

```bash
docker exec soc-agent-cycle python -m soc_agent.mitigate --isoler 003
docker exec soc-agent-cycle python -m soc_agent.mitigate --desisoler 003
```

## Réglages

| Variable | Défaut | Rôle |
|---|---|---|
| `MITIGATE_EXECUTE` | `false` | `true` = les remédiations partent réellement. `false` = dry-run global (bac à sable), **pas** une demande de validation humaine |
| `MITIGATE_MAX_TENTATIVES` | `3` | rejeux d'une action restée `émis` |
| `MITIGATE_AR_GAP_SECONDS` | `1.5` | espacement des appels AR (une rafale se perd) |
| `MITIGATE_ISOLATE_ALLOW` | `192.168.10.5` | IP restant joignables depuis un hôte isolé |
| `AGENTS_PROTEGES` | `000` | jamais une cible |
| `AGENTS_CAPTEURS` | `010` | capteurs d'hôte : jamais une cible (théâtre réel = machine surveillée) |
| `AGENTS_WINDOWS` | `014,015` | route vers les AR Windows |
| `AGENTS_DC` | `014` | contrôleurs de domaine : exécutent les actions AD |
| `SHUFFLE_WEBHOOK_ISOLATE` / `_KILL` | — | webhooks des workflows Shuffle |

## Déploiement des scripts — obligatoire, à échec silencieux

Les scripts doivent être dans `/var/ossec/active-response/bin/` de **chaque
agent** (`root:wazuh`, 750). Sans eux, **toute remédiation échoue sans rien
remonter** : l'`ar.conf` déclare bien la commande, l'API répond `200`, et rien
ne s'exécute. Le seul indice est l'absence de ligne dans
`/var/ossec/logs/active-responses.log` de l'agent. C'est ce qui a rendu le
blocage d'IP inopérant sur le lab jusqu'au 2026-07-29.

```sh
# Linux — depuis le dépôt
./scripts/deploy-active-response.sh <ip-agent> [<ip-agent> ...]

# Windows / AD — via WinRM, + enregistrement des <command> sur le manager
export WINRM_USER='Administrateur' WINRM_PASS='...'
AGENTS='192.168.30.100 192.168.30.49' MANAGER=192.168.10.5 \
  ./wazuh/active-response/windows/deploy-windows-ar.sh

# manager de prod dont wazuh_manager.conf est gitignoré : insertion aux ancres
python3 scripts/patch-manager-ar-windows.py /opt/AURA/wazuh/config/wazuh_cluster/wazuh_manager.conf
```

**L'enregistrement n'est pas optionnel** : execd n'exécute qu'une commande
présente dans `shared/ar.conf`, que le manager construit à partir des
`<command>` **référencés par un `<active-response>`**. Il faut donc les deux
blocs (`<active-response rules_id=999999>` ne se déclenche jamais tout seul),
puis un redémarrage du manager.

## Vérifier ce qui s'est vraiment passé

Ne jamais se fier au code retour de l'API ni au statut en base seul. Lire l'état
réel de l'hôte :

```sh
tail /var/ossec/logs/active-responses.log      # sur l'agent
iptables -S INPUT                               # ou : nft list table inet soc_ai_block
nft list table inet wazuh_isolation             # isolation Linux
chage -l <user>                                 # disable-account
```

Côté base :

```sh
docker exec socagent-db psql -U socagent -d socagent -c \
  "select incident_id, action, cible, agent_id, statut, executed_at
     from mitigations order by id desc limit 20"
```

## Ce qui n'est pas couvert

La remédiation autonome **n'enlève pas la persistance**. Après un exercice
purple-team, il reste à chercher à la main : cron de reverse shell, web shell,
comptes UID 0. Le blocage d'IP et l'isolation coupent l'accès en cours, pas le
point de retour.

## Voir aussi

- [`TRAINING.md`](TRAINING.md) — la fenêtre qui empêche tout ceci de partir sur
  du bruit ambiant au premier jour
- [`../src/wazuh/active-response/README.md`](../src/wazuh/active-response/README.md) —
  contrat AR détaillé, pare-feu iptables/nftables
- [`../src/wazuh/active-response/windows/README.md`](../src/wazuh/active-response/windows/README.md) —
  modèle d'exécution Windows, wrapper `.exe`
- [`../src/shuffle/README.md`](../src/shuffle/README.md) — workflow d'isolation
