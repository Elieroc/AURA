# CMDB — priorité des assets (P1 à P4)

Code : [`src/ai/soc_agent/assets.py`](../src/ai/soc_agent/assets.py) · table
`assets` (schéma [`schema.sql`](../src/ai/soc_agent/schema.sql)) · synchronisée
à chaque cycle (`soc-agent-cycle`) · réglages `PRIORITE_*` dans le `.env`.

## Le problème

Le pipeline ne connaissait qu'une grandeur : `rule_level`, le niveau Wazuh.
C'est une propriété de la **règle** — « à quel point ça tire » — et elle ne dit
rien de la **machine**. Deux incidents de niveau 12, l'un sur le contrôleur de
domaine, l'autre sur un poste de test, arrivaient donc :

- dans le même ordre dans la file de triage (plafonnée à 50 incidents/cycle) ;
- avec la même sévérité affichée à l'analyste ;
- avec le même seuil au-delà duquel le modèle n'a plus le droit de refermer.

Un `net user /add` est une routine d'administration sur un poste jetable et un
backdoor de domaine sur un DC. Sans contexte d'asset, ni le modèle ni le
pipeline ne peuvent faire la différence.

## Le principe

Chaque machine porte un **rôle**, qui lui donne une **priorité P1 à P4**. La
priorité alimente deux choses distinctes :

```
priorité  ──►  ORDRE de traitement (file de triage, budget UEBA)
          └─►  SÉVÉRITÉ effective = niveau Wazuh + bonus, bornée 1-15
```

`max_level` n'est **jamais** modifié : la corrélation, UEBA, les règles de
compromission d'hôte et les seuils existants s'appuient dessus. La sévérité est
une seconde colonne : « à quel point ça tire » × « sur quoi ».

## Le catalogue

| P | Rôles | Ce qu'on perd |
|---|-------|---------------|
| **P1** | `dc`, `firewall`, `soc`, `hypervisor`, `pki`, `backup` | le domaine, le réseau, la capacité de détection, tout ce qui est hébergé, la confiance, la capacité de restauration |
| **P2** | `web`, `db`, `mail`, `proxy`, `dns`, `vpn`, `fileserver` | un service exposé ou des données ; pivot classique |
| **P3** | `serveur`, `admin` | un serveur interne, sans exposition ni donnée sensible |
| **P4** | `endpoint`, `lab`, **et tout rôle non déclaré** | un poste, une VM de laboratoire |

Ajouter un rôle sans toucher au code : `PRIORITY_ROLES="nas=1,jellyfin=3"`.

Effets par priorité (`.env`, valeurs par défaut) :

| | P1 | P2 | P3 | P4 |
|---|---|---|---|---|
| bonus de sévérité (`SEVERITY_BONUS_PRIORITY`) | +2 | +1 | 0 | −1 |
| clôture auto interdite à partir de (`CLOSURE_FORBIDDEN_BY_PRIORITY`) | 12 | 13 | 14 | 14 |
| ordre dans la file de triage | 1ᵉʳ | 2ᵉ | 3ᵉ | 4ᵉ |

La **remédiation autonome n'est pas bridée sur P1** : un asset critique agit
comme les autres. C'est un choix explicite, à réévaluer si un faux positif
coûteux tombe sur un DC — la barrière d'isolation
(`ISOLATION_FORBIDDEN_GROUPS`) reste, elle, en place et couvre déjà pare-feu,
proxy, DNS et VPN.

## Source de vérité : les groupes Wazuh

Le rôle est porté par un **groupe Wazuh préfixé `role-`** (`role-dc`,
`role-web`…). C'est l'inventaire natif : il survit au redéploiement de la
stack, et l'opérateur qui enrôle une machine déclare son rôle au même endroit
que le reste de sa configuration. Le préfixe évite toute collision avec les
groupes de configuration existants (`default`, `infrastructure`).

La table `assets` n'en est qu'un **miroir interrogeable**, reconstruit à chaque
cycle. Une seule chose n'y est pas reconstruisible : la priorité posée à la main
par un opérateur (`priorite_source = 'operateur'`), que la synchronisation
n'écrase jamais.

```bash
python -m soc_agent.assets --sync         # aligner sur le manager
python -m soc_agent.assets --lister
python -m soc_agent.assets --couverture   # qui tourne sans rôle déclaré
python -m soc_agent.assets --definir 007 --role dc
```

Côté MCP : `aura_assets_list` (lecture), `aura_asset_set` (`aura:write`),
et `aura_enroll_agent(role=…)`.

## Déclarer le rôle à l'enrôlement

```
aura_enroll_agent(hote="192.168.3.20", systeme="linux", role="dc", confirmer=true)
./install-agent.sh -m 192.168.3.5 -k "ssh-ed25519 …" -n win-dc -g role-dc
```

L'enrôlement crée le groupe s'il manque, y range l'agent, et inscrit l'asset.

## Les deux pièges

**1. Sans rôle déclaré, la machine est traitée en P4.** C'est le choix
opérateur : ce qui n'est pas déclaré ne prend pas la place de ce qui l'est. Le
revers est réel — une machine importante jamais déclarée est traitée comme un
poste jetable. D'où `priorite_source = 'defaut'` et
`assets --couverture` / `aura_assets_list(dette_seulement=true)` : la dette
d'inventaire doit être **visible**, pas devinée. À regarder après chaque vague
d'enrôlement.

**2. Un agent capteur ne transmet pas sa priorité à ce qu'il observe.** Le
pare-feu qui porte Suricata *est* un asset P1, mais les alertes qu'il remonte
décrivent le trafic des postes du LAN. Sans garde-fou, chaque scan vu par l'IDS
deviendrait un incident P1 et noierait la file — la priorisation dégraderait le
tri au lieu de l'améliorer. Les agents listés dans `AGENTS_SENSORS` sont donc
rabattus sur `PRIORITY_SENSOR` (P3), sauf quand l'alerte porte le conteneur
d'origine (`alerts.container`) : c'est alors **ce dernier** qui est résolu, et
la vraie machine reprend sa priorité.

## Ce que ça change à l'exécution

- La priorité est **figée à l'ouverture** de l'incident (`incidents.priorite`).
  Reclasser un asset ne réécrit pas l'histoire : un case reste lisible avec le
  contexte qui était le sien.
- Le prompt de triage porte une ligne `criticité asset`, avec la conséquence
  écrite en clair — « P1 » seul n'apprend rien à un modèle.
- Le case IRIS porte un tag `P1`…`P4` (filtrable), la sévérité effective dans sa
  description, et **sa sévérité IRIS est calculée** (voir plus bas).
- Les KPI exportés (`wazuh-ai-*`) portent la priorité : un MTTD moyen ne veut
  rien dire tant qu'il mélange le DC et les postes de test.

## Sévérité du case IRIS

IRIS pose « Low » à tout case créé, et `add_case` n'expose pas la sévérité :
elle se règle après coup (`/manage/cases/update/<id>`, `case_severity_id`), à la
création comme à chaque rafraîchissement — une salve qui fait monter le niveau
max doit changer la couleur du case.

Le barème part de la **sévérité effective**, pas de `max_level` : le projet n'a
qu'une définition de la gravité, et l'analyste retrouve dans sa file l'ordre que
le pipeline a appliqué.

| Sévérité effective | Case IRIS | Exemple |
|---|---|---|
| ≥ 15 | Critical | niveau 13 sur un P1, niveau 15 sur un P3 |
| 12-14 | High | niveau 12 (seuil d'ouverture), niveau 12 sur un P1 → 14 |
| 8-11 | Medium | niveau 12 sur un P4 → 11 |
| 4-7 | Low | |
| ≤ 3 | Informational | |

Deux correctifs par-dessus le barème :

- **plancher UEBA à Medium.** Un incident comportemental a un `max_level` bas
  *par construction* (alertes 3-11) : le barème le peindrait « Low » alors qu'il
  n'existe que parce qu'un écart statistique l'a justifié.
- **plafond « Low » sur un faux positif** — une activité jugée légitime ne
  trône pas en tête de file. **Sauf** si le garde-fou déterministe a refusé la
  clôture (`escalate_human` dans les actions finales) : le verdict est alors
  précisément ce qu'on ne croit pas, et rétrograder la sévérité reviendrait à
  appliquer la décision qu'on vient de refuser — ce qu'une injection cherche
  justement à obtenir.

**Piège 1 : le champ qui marche est `severity_id`.** `case_severity_id` — le
nom qu'on déduit de `case_classification_id` — est accepté par l'API, répond
« updated », et ne change rien. Et aucun endpoint ne RELIT la sévérité
(`/manage/cases/<id>`, `/manage/cases/list`, `/case/summary` : aucun ne la
renvoie), donc l'échec est totalement muet. Le seul contrôle possible est en
base :

```bash
docker exec iris-db psql -U postgres -d iris_db \
  -c "select case_id, severity_id from cases order by case_id desc limit 5"
```

**Piège 2 : les ids de l'échelle IRIS ne suivent pas l'ordre de gravité** —
`3`=Informational, `4`=Low, `1`=Medium, `5`=High, `6`=Critical, `2`=Unspecified.
Une correspondance écrite sur les ids serait silencieusement fausse. Le code
raisonne sur les **noms** et résout l'id à l'exécution
(`/manage/severities/list`), avec repli journalisé si le serveur ne répond pas.
