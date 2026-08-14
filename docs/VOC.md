# VOC — gestion des vulnérabilités du parc

Code : [`src/ai/soc_agent/vulns.py`](../src/ai/soc_agent/vulns.py) · tables
`vulnerabilites` / `vuln_scans` ([`schema.sql`](../src/ai/soc_agent/schema.sql))
· conteneur `soc-agent-vulns` (cadence horaire) · index `wazuh-voc-*` ·
dashboard **VOC** · réglages `VOC_*` dans le `.env`.

## Le problème

Wazuh sait **détecter** les vulnérabilités. Il ne sait pas en **suivre la
gestion**, et la raison est structurelle : `wazuh-states-vulnerabilities-*` est
un index d'**état**. Quand un paquet est corrigé, le document est *supprimé*.

On y lit donc en permanence « où on en est », et jamais :

- combien y en avait-il il y a un mois — pas de **burn-down** ;
- en combien de temps corrige-t-on — pas de **MTTR** ;
- qu'est-ce qui a dépassé son délai — pas de **SLA**.

Les alertes 23504-23506 ne comblent pas le trou : elles datent la *détection*,
jamais la *résolution*. Les compter revient à compter des re-détections.

Ce module construit l'historique manquant, et rien d'autre : la détection reste
entièrement à Wazuh.

```
Wazuh VD  ──►  wazuh-states-vulnerabilities-*   (état, destructif)
                        │
                  soc_agent.vulns  (horaire)
                        ├──►  table `vulnerabilites`   journal : vue_a / corrigee_a
                        ├──►  index `wazuh-voc-*`      dashboard VOC
                        └──►  `exposition()`           section « Exposition » des cases IRIS
```

## Prérequis côté Wazuh

Déjà en place sur cette stack, à vérifier après toute reconstruction :

```xml
<!-- ossec.conf du manager -->
<wodle name="syscollector">
  <disabled>no</disabled>
  <packages>yes</packages>   <!-- VD en dépend entièrement -->
</wodle>

<vulnerability-detection>
  <enabled>yes</enabled>
  <index-status>yes</index-status>     <!-- sans lui, pas d'index d'état -->
  <feed-update-interval>60m</feed-update-interval>
</vulnerability-detection>
```

Contrôle rapide :

```bash
curl -sk -u admin:$INDEXER_PASSWORD \
  "https://localhost:9200/_cat/indices/wazuh-states-vulnerabilities-*?v"
```

**Couverture mesurée le 2026-08-12 : 14 machines sur 16.** Les deux absentes ne
sont pas une panne, et il ne faut pas chercher à les « réparer » :

| Agent | Cause |
|---|---|
| `000` wazuh.manager (Amazon Linux, conteneur) | l'image du manager n'est pas un asset du parc ; son inventaire de paquets existe mais le feed ne produit rien d'exploitable dessus |
| `008` pfsense (FreeBSD) | **BSD n'est pas couvert par le feed CTI de Wazuh.** Aucune version du module n'y changera quoi que ce soit — le suivi des vulnérabilités de pfSense se fait hors AURA |

Ces deux machines apparaissent dans `voc.machines_muettes` et dans la sortie de
`--sans-export`. C'est voulu : une machine sans inventaire doit rester visible,
pas disparaître du compte.

## Le score d'exposition

Un nombre par machine, de 0 à 100 :

```
charge  = Σ poids(sévérité de chaque CVE ouverte)
score   = 100 × log10(1 + charge × facteur_priorité) / log10(1 + VOC_MAX_LOAD)
```

| Sévérité | Poids | | Priorité | Facteur |
|---|---:|---|---|---:|
| Critical | 10 | | P1 | ×4 |
| High | 4 | | P2 | ×2 |
| Medium | 1 | | P3 | ×1 |
| Low | 0,2 | | P4 | ×0,5 |
| non classée | 0,5 | | | |

Deux choix à comprendre avant de lire un score :

- **L'échelle des poids est très non linéaire.** Il faut dix Medium, ou
  cinquante Low, pour peser une Critical. Sans cela le score serait dominé par
  le bruit de fond des distributions (2 535 CVE ouvertes sur un Debian à jour,
  en écrasante majorité Low/Medium) et classerait les machines par nombre de
  paquets installés.
- **Le score sature.** Il est log-compressé pour étaler un intervalle qui va de
  quelques unités à plusieurs dizaines de milliers. Au-delà de `VOC_MAX_LOAD`,
  deux machines à 100 **ne sont plus comparables** — ce sont alors les
  compteurs bruts (`voc.critical`, `voc.hors_sla_total`) qui départagent. Le
  score sert à **classer**, pas à mesurer un risque absolu.

La sévérité manquante (334 CVE par hôte Debian) est reclassée depuis le score
CVSS quand il existe (seuils v3 : ≥9 critical, ≥7 high, ≥4 medium).

## Les SLA

Délai de correction attendu, en jours, par sévérité **et** priorité d'asset :

| | P1 | P2 | P3 | P4 |
|---|---:|---:|---:|---:|
| Critical | 7 | 14 | 30 | 60 |
| High | 15 | 30 | 60 | 90 |
| Medium | 30 | 60 | 90 | 180 |
| Low | 90 | 180 | 365 | 365 |

Ce sont des **objectifs de service internes**, pas une norme externe. Leur seule
fonction est de rendre le retard mesurable : sans échéance, « ouverte depuis
210 jours » n'est qu'un nombre. Réglables par `VOC_SLA_DAYS`
(`critical:7,14,30,60;high:15,30,60,90`).

Le compteur court depuis `vulnerabilites.vue_a` — **notre** première
observation — et non depuis `vulnerability.detected_at` de Wazuh, qui se
réinitialise quand le scanner recalcule. Sur cette date-là, un redémarrage du
manager remettrait tous les compteurs de retard à zéro et le VOC se
féliciterait tout seul.

> **Conséquence à connaître : le journal ne mesure pas de retard plus long que
> sa propre existence.** Au premier scan, *toutes* les vulnérabilités sont
> « ouvertes depuis 0 jour » et *aucune* n'est hors délai — sur un parc qui
> traîne pourtant des CVE de 2019. Ces chiffres sont exacts et trompeurs : ils
> décrivent l'ancienneté de la **mesure**, pas l'état du parc. Le premier
> hors-délai apparaîtra au bout de 7 jours (Critical sur P1) et la courbe de
> MTTR ne veut rien dire avant plusieurs semaines. Les compteurs par sévérité,
> eux, sont valables immédiatement. La note IRIS et la CLI affichent
> l'avertissement tant que le journal a moins de 30 jours.

## Le garde-fou qui compte

> Une machine qui a cessé de répondre disparaît de l'index d'état **avec toutes
> ses vulnérabilités**.

Un diff naïf conclurait à une remédiation massive : burn-down parfait, MTTR
magnifique, et un parc devenu invisible. C'est le seul mensonge que ce module
peut raconter, et il serait indétectable à la lecture du dashboard.

Deux protections, cumulées :

1. **La clôture ne s'applique qu'aux agents ayant répondu au scan en cours**
   (`vulns.CLOTURE`, clause `agent_id = ANY(...)`). Un agent muet garde ses
   vulnérabilités ouvertes, et son retard continue de courir.
2. **La couverture se lit avant le burn-down.** `voc.couverture_pct` et
   `voc.machines_muettes` occupent la deuxième ligne du dashboard, au-dessus de
   la courbe de dette. Une dette qui baisse pendant que la couverture baisse
   n'est pas une amélioration.

Un scan totalement vide (indexer injoignable, VD désactivé) ne clôture **rien**
et journalise un avertissement.

## Le dashboard VOC

Index pattern `wazuh-voc-*`. Trois natures de documents, distinguées par
`event_type` :

| `event_type` | Granularité | Sert à |
|---|---|---|
| `voc_parc` | 1 par passage | burn-down, flux apparues/corrigées, couverture |
| `voc_asset` | 1 par machine par passage | classement des machines par exposition |
| `voc_vuln` | 1 par vulnérabilité, **réécrit** à chaque passage | MTTR, hors-délai, top paquets |

Panneaux, dans l'ordre de lecture :

1. **Compteurs** — ouvertes, critiques, hors délai, machine la plus exposée.
2. **Couverture** — % de machines inventoriées, machines muettes. *Avant* le
   reste, cf. ci-dessus.
3. **Dette dans le temps** — aires empilées par sévérité. Le burn-down.
4. **Apparues / corrigées** — la capacité de remédiation. Une dette stable avec
   un flux élevé des deux côtés est un parc vivant ; une dette stable sans
   mouvement est un parc abandonné.
5. **Délai moyen de correction** + par sévérité — le MTTR.
6. **Machines les plus exposées** / **par priorité d'asset** — où patcher.
7. **Paquets porteurs de la dette** — le meilleur retour sur investissement : un
   seul méta-paquet noyau porte souvent la moitié de la dette d'un hôte Debian.
8. **Vulnérabilités hors délai** — la file d'attente réelle, triée par retard.

### Deux pièges d'index

- **Fenêtre de temps.** Les documents `voc_vuln` sont horodatés à leur
  **première observation**. Une fenêtre de 30 jours masquerait les
  vulnérabilités vues il y a plus longtemps — c'est-à-dire les plus vieilles,
  donc les plus en retard. Le dashboard s'ouvre donc sur `now-3y`. Ne pas le
  réduire sans savoir ce qu'on cache.
- **`wazuh-voc-vulns` n'est pas un index daté.** Les séries temporelles vont
  dans `wazuh-voc-YYYY.MM.DD`, mais le cycle de vie va dans un index **stable**,
  parce que son `_id` est déterministe : un index daté en créerait une copie par
  jour, chacune figée sur l'état de son jour, et tous les compteurs seraient
  multipliés par la rétention. Ne pas lui appliquer de politique de rétention
  par date.

Le template d'index est obligatoire (`wazuh-voc-template.json`) : `voc.hors_sla`
est un **booléen** sur `voc_vuln` tandis que les agrégats portent
`voc.hors_sla_total`, un entier. Sans mapping explicite, le premier document
indexé fixe le type et les suivants sont rejetés **en silence**.

## Dans les cases IRIS

Chaque case porte une note **« Exposition aux vulnérabilités »** (répertoire
`Exposition`), reprise en **section 4** du rapport d'investigation. Elle donne
le score de la machine touchée, sa répartition par sévérité, son retard, et ce
qui rattache — ou non — l'exposition à cet incident précis.

Le contenu est **calculé en Python**, jamais rédigé par le modèle : c'est un
relevé, pas une analyse. D'où le répertoire distinct de « Analyse IA » — mélanger
les deux ferait porter à des faits l'avertissement « verdict produit par un
LLM », et donnerait au récit du modèle l'autorité d'une mesure.

Trois degrés de certitude, jamais confondus :

| Section | Statut |
|---|---|
| **Vulnérabilités citées dans l'incident** | **Fait.** La CVE apparaît littéralement dans les évènements (règle locale 100660, « CVE identifier in command ») *et* est ouverte ici. Conséquence écrite noir sur blanc : remédier l'incident ne suffit pas |
| **Citées mais non ouvertes ici** | Information sur la **méthode** de l'attaquant, pas sur l'exposition de l'hôte |
| **Vecteurs possibles** | **Hypothèse.** L'incident porte une technique d'exploitation (T1190, T1068, T1210…) et la machine a des CVE graves ouvertes. Aucun élément ne les relie |

Le modèle reçoit de son côté une ligne de **métadonnée de confiance** — score,
compteurs, et les CVE confirmées — sans nom d'hôte ni de paquet, sur le même
principe que la ligne « télémétrie disponible ». Sans elle, le rapport écrivait
« aucun élément ne permet de savoir si la machine était vulnérable » alors que
le SOC avait l'inventaire.

La note est posée **aussi sur les faux positifs** : le verdict porte sur
l'évènement, pas sur l'état de l'hôte. Une machine en retard de correction le
reste, que l'alerte du jour ait été fondée ou non.

Quand la machine n'a jamais été inventoriée, la note le dit explicitement plutôt
que d'afficher zéro — « aucune vulnérabilité connue » et « jamais inventoriée »
sont deux affirmations opposées.

## Exploitation

```bash
# scan + export (ce que fait le conteneur, toutes les heures)
docker compose -p aura run --rm soc-agent-vulns python -m soc_agent.vulns

# exposition du parc, sans rien écrire
python -m soc_agent.vulns --state

# détail d'une machine (celui qui alimente la note IRIS)
python -m soc_agent.vulns --agent 013

# montrer les documents au lieu de les indexer
python -m soc_agent.vulns --simulation
```

## Ce que ce module ne dit pas

À rappeler à qui lit le dashboard comme un tableau de bord de risque :

- **Le feed ne dit rien de l'exploitabilité.** Une CVE critique sur une
  bibliothèque jamais appelée par un service exposé ne vaut pas une CVE moyenne
  sur le serveur web en frontal. Le score pondère par la priorité de l'asset,
  pas par l'exposition réelle du composant.
- **Faux positifs de backport.** Debian et RHEL corrigent sans remonter la
  version amont : une CVE peut rester affichée alors qu'elle est corrigée.
- **Périmètre limité aux paquets système.** Les dépendances applicatives
  (npm, pip, maven) sont hors du champ de syscollector, donc hors du VOC.
- **Ce n'est pas de la détection.** Une vulnérabilité ouverte n'est pas un
  incident, et rien dans ce module n'ouvre de case. Le seul lien avec le
  pipeline de détection est la section « Exposition » des cases existants.
