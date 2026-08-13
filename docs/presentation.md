# AURA — présentation client

> Document source destiné à la génération de slides. Chaque `##` = une slide.
> Public non technique (direction, RSSI, décideur achat). Aucun prérequis
> outillage. Les termes techniques sont introduits une fois puis réutilisés.

---

## 1. En une phrase

**AURA est un SOC qui fonctionne sans analyste de garde.**

Il surveille le parc informatique, décide lui-même si une alerte est une vraie
attaque, ouvre le dossier d'enquête, et agit sur la machine concernée — en
quelques minutes, 24 h/24, sans attendre qu'un humain lise l'alerte.

*AURA = Autonomous UEBA Response Analysis.*

---

## 2. Le problème qu'on adresse

Un SOC classique repose sur trois choses qui ne passent pas à l'échelle :

| Ce qu'on attend d'un SOC | Ce qui se passe en vrai |
|---|---|
| Toutes les alertes sont regardées | Le parc en produit des dizaines de milliers ; on regarde les plus fortes |
| Une alerte est traitée vite | Elle attend l'ouverture du service, ou la fin de la file du jour |
| Le SOC apprend de ses erreurs | Le même faux positif est rejugé chaque semaine, indéfiniment |
| La réaction est immédiate | La réaction attend une validation humaine, puis une intervention manuelle |

**Le goulot n'est pas la détection : c'est le temps d'attention humaine
disponible.** Les outils voient déjà beaucoup plus de choses qu'un analyste n'a
le temps d'en lire.

Conséquence mesurée sur un parc réel de référence : **~32 000 alertes de faible
niveau pour ~110 alertes de niveau élevé**. Les 32 000 ne sont jamais lues. Une
intrusion discrète vit entièrement dans ces 32 000.

---

## 3. Le principe d'AURA

Un entonnoir : on réduit énormément le volume **avant** de faire intervenir
l'intelligence artificielle, puis on la fait décider, puis on agit.

```
Toutes les machines du parc
        │
        ▼
1. DÉTECTER      capteurs sur chaque machine + réseau + renseignement menace
        │        (des dizaines de milliers d'événements)
        ▼
2. RÉDUIRE       filtres de bruit, réputation de fichiers/IP, analyse
        │        comportementale, regroupement en incidents
        │        (gratuit : aucun appel à l'IA à cette étape)
        ▼
3. DÉCIDER       l'IA lit l'incident complet, rend un verdict :
        │        vraie attaque / faux positif, avec justification
        ▼
4. TRACER        un dossier d'enquête est ouvert automatiquement,
        │        avec rapport rédigé, chronologie, preuves
        ▼
5. AGIR          isolation machine, blocage IP, coupure de session,
        │        désactivation de compte — sans validation humaine
        ▼
6. APPRENDRE     un faux positif récurrent devient une exception
                 permanente : il ne sera plus jamais rejugé
```

**Point clé pour le client** : l'étape 2 est ce qui rend l'étape 3 économiquement
possible. Payer une IA pour lire 32 000 événements est absurde ; lui faire lire
quelques incidents déjà constitués ne l'est pas.

---

## 4. Les briques, et à quoi elles servent

Six briques. Chacune répond à une question du client.

### 4.1 Les capteurs et la détection — *« que se passe-t-il sur mes machines ? »*

Un agent léger est installé sur chaque serveur et chaque poste. Il remonte :

- les commandes exécutées et par qui ;
- les fichiers sensibles modifiés (intégrité) ;
- les connexions, les créations de comptes, les tâches planifiées ;
- le trafic réseau analysé au niveau du pare-feu.

À cela s'ajoute une vérification de **réputation** : un fichier ou une adresse IP
inconnue est confrontée à des bases publiques de menaces avant même qu'un humain
ou l'IA n'en entende parler.

**Bénéfice client** : couverture Windows, Linux, Active Directory, réseau, avec
un seul point de collecte.

### 4.2 L'analyse comportementale (UEBA) — *« et ce qui ne déclenche aucune alerte ? »*

C'est la brique qui traite l'angle mort des 32 000 événements ignorés.

AURA apprend ce qui est **normal** pour chaque machine et chaque compte : quels
programmes, quelles heures, quels pays de connexion, quels volumes. Ensuite il
mesure les écarts et regroupe les écarts voisins.

Exemple concret : un compte se connecte depuis un pays jamais vu, puis lance un
outil d'énumération, puis crée une tâche planifiée. Pris un par un, ce sont trois
logs de routine, notés faibles, invisibles. Regroupés, c'est un scénario
d'intrusion — et il devient un incident.

**Bénéfice client** : on détecte l'attaquant qui reste discret, pas seulement
celui qui fait du bruit. Sans coût supplémentaire : cette étape ne consomme pas
d'IA.

### 4.3 La priorisation par valeur d'actif (CMDB) — *« mes machines n'ont pas la même importance »*

Chaque machine porte un rôle et une priorité **P1 à P4**.

| Priorité | Exemples de rôles | Ce qu'on perd si ça tombe |
|---|---|---|
| **P1** | contrôleur de domaine, pare-feu, hyperviseur, sauvegarde, autorité de certification | le domaine, le réseau, tout l'hébergé, la capacité de restauration |
| **P2–P3** | serveurs applicatifs, serveurs de fichiers | un service, des données métier |
| **P4** | postes de test, machines jetables | presque rien |

Un même événement — la création d'un compte administrateur — est une routine sur
un poste de test et une porte dérobée sur un contrôleur de domaine. La priorité
change **l'ordre de traitement** et la **gravité affichée**, et interdit à l'IA
de refermer trop vite un incident sur un actif critique.

**Bénéfice client** : le SOC parle le langage du métier, pas celui de l'outil.

### 4.4 Le renseignement sur la menace (CTI) — *« est-ce que cet attaquant est déjà connu ? »*

AURA collecte en continu les indicateurs publiés par les sources de référence
(CERT-FR, CIRCL, abuse.ch et autres) et les stocke localement. Chaque événement
du parc est confronté à cette mémoire, instantanément et sans appel réseau.

En plus des flux structurés, AURA **lit les articles publics de sécurité** et en
extrait lui-même, par IA, les adresses, domaines et empreintes de fichiers
mentionnés — puis les ajoute à sa mémoire de menaces.

**Bénéfice client** : une infrastructure d'attaque publiée hier soir est
détectée ce matin, sans qu'un analyste ait eu à lire la publication.

### 4.5 Le dossier d'enquête (case management) — *« qu'est-ce qui s'est passé, et qu'a-t-on fait ? »*

Chaque incident jugé réel ouvre automatiquement un dossier contenant :

- un **rapport d'investigation rédigé en français** par l'IA : ce qui s'est
  passé, sur quelle machine, quel compte, quelle probable intention ;
- la **chronologie** des événements et les preuves brutes associées ;
- les **indicateurs** (adresses, fichiers, comptes) impliqués ;
- l'**exposition aux vulnérabilités** de la machine concernée ;
- la **liste des actions engagées**, une par une, avec leur résultat.

**Bénéfice client** : la traçabilité et la matière d'audit sont produites
automatiquement — c'est habituellement le travail le plus coûteux et le plus
souvent bâclé d'un SOC.

### 4.6 La remédiation automatique — *« et qui décroche à 3 h du matin ? »*

Personne. AURA agit seul, sur verdict de vraie attaque :

- **isoler** la machine du réseau ;
- **bloquer** l'adresse de l'attaquant sur le pare-feu et les hôtes ;
- **couper** la session ou le processus malveillant ;
- **désactiver** le compte compromis ou créé par l'attaquant.

Ce qui borne l'action n'est **pas** un accord humain, mais des **garde-fous
écrits en dur dans le code**, à trois niveaux indépendants : avant l'action,
au moment de choisir la cible, et dans le script exécuté sur la machine
elle-même. Certains actifs (le SOC lui-même, les comptes système) ne sont
jamais touchables, quel que soit le verdict.

**Bénéfice client** : le délai entre détection et confinement passe d'heures à
minutes, y compris la nuit et le week-end.

### 4.7 En bonus : gestion des vulnérabilités et pilotage

- **Suivi des vulnérabilités dans le temps** : combien y en avait-il il y a un
  mois, en combien de temps corrige-t-on, qu'est-ce qui a dépassé son délai
  (burn-down, MTTR, SLA). Les outils du marché montrent l'état du jour et
  effacent l'historique ; AURA le conserve.
- **Tableaux de bord** : volumes, verdicts, actions engagées, coût de l'IA — sur
  le même écran et le même axe de temps que les alertes.
- **Pilotage depuis un assistant IA** : un responsable peut interroger AURA en
  langage naturel (« montre-moi les incidents de la nuit », « isole cette
  machine ») depuis son propre client IA.

---

## 5. Le rôle exact de l'IA

C'est la question que posera le client. Réponse en une ligne : **l'IA décide et
rédige ; elle ne détecte pas et elle ne garde pas les clés.**

### Ce que l'IA fait

| Rôle | Ce que ça remplace |
|---|---|
| **Juger** un incident : vraie attaque ou faux positif, avec justification écrite | Le travail de triage niveau 1, le plus volumineux et le plus répétitif |
| **Proposer** les actions de confinement adaptées au scénario | Le playbook lu et appliqué à la main |
| **Rédiger** le rapport d'investigation et la chronologie | La rédaction de case, souvent reportée puis jamais faite |
| **Extraire** les indicateurs des publications de sécurité | La veille manuelle |
| **Reconnaître** un faux positif récurrent pour le neutraliser durablement | Le tuning de règles, éternellement remis à plus tard |

### Ce que l'IA ne fait pas

- **Elle ne détecte pas.** La détection reste faite par des règles
  déterministes, lisibles, contestables et auditables. On peut expliquer à un
  auditeur pourquoi une alerte est partie.
- **Elle ne voit pas le tout-venant.** Elle n'est appelée que sur des incidents
  déjà constitués et déjà réduits. Les étapes de réduction ne coûtent rien.
- **Elle n'est pas la barrière de sécurité.** Le point le plus important de
  cette slide.

### Le point d'honnêteté qui rassure les techniques

Un attaquant peut écrire du texte dans un journal, et ce texte arrive dans le
contexte de l'IA. **Nous avons mesuré la manipulation : sur un cas de
ransomware avéré, 3 tentatives sur 4 d'écrire « ceci est un faux positif » dans
les logs retournent effectivement le verdict du modèle.**

C'est pour cette raison précise que la décision d'agir passe par des garde-fous
déterministes qui, eux, ne s'argumentent pas avec du texte. Le modèle est un
accélérateur de jugement, pas un contrôle d'accès.

Autres protections concrètes :

- **Pseudonymisation avant sortie** : noms de machines, comptes et adresses
  internes sont remplacés avant l'envoi au modèle, et l'appel est **refusé** si
  une valeur réelle a survécu au masquage. Le contexte est réhydraté à la
  réponse. Le reste des données ne quitte jamais l'infrastructure.
- **Verdicts incohérents détectés** : un verdict qui se contredit est signalé,
  pas appliqué en silence.
- **Mode apprentissage au démarrage** : pendant les premiers jours, AURA
  observe le bruit normal du système d'information et **n'agit pas**. Sans cela,
  le premier jour, un SOC autonome isolerait des serveurs sains dont les
  sauvegardes légitimes ressemblent à une attaque.

---

## 6. AURA face à un service SOC classique

### 6.1 Le tableau de comparaison

| | **SOC classique (interne ou MSSP)** | **AURA** |
|---|---|---|
| **Qui trie les alertes** | Analystes N1, en file d'attente | L'IA, en continu |
| **Disponibilité réelle** | Heures ouvrées, ou 24/7 au prix d'une équipe de garde | 24/7 par construction |
| **Délai détection → confinement** | Heures à jours (triage + escalade + validation + intervention) | Minutes |
| **Volume traité** | Le haut de la pile ; le reste est ignoré faute de temps | Tout le flux est réduit puis jugé, y compris le faible niveau |
| **Attaque discrète (bas niveau)** | Angle mort structurel | Couverte par l'analyse comportementale |
| **Faux positifs** | Rejugés indéfiniment ; le tuning attend un projet | Neutralisés automatiquement à deux niveaux, définitivement |
| **Rapport d'incident** | Rédigé à la main, souvent après coup | Généré à chaque incident, sans surcoût |
| **Action de confinement** | Ticket → validation → intervention manuelle | Exécutée automatiquement, bornée par garde-fous |
| **Coût dominant** | Masse salariale, croissante avec le volume | Infrastructure + consommation IA, quasi plate |
| **Priorisation métier** | Dépend de la connaissance qu'a l'analyste du parc | Encodée : rôle et priorité P1-P4 par machine |
| **Montée en charge** | Recruter et former | Ajouter des machines surveillées |
| **Dépendance humaine** | Turnover, congés, nuit, astreinte | Aucune pour le fonctionnement courant |

### 6.2 Ce qu'AURA ne remplace pas

À dire explicitement — c'est ce qui rend le reste crédible.

- **L'expertise de réponse à incident avancée.** Sur une compromission majeure,
  il faut des humains. AURA leur livre un dossier déjà constitué, un périmètre
  déjà confiné et une chronologie déjà écrite — il fait gagner les premières
  heures, celles qui comptent le plus.
- **La décision de risque.** Débrancher un site de production, payer ou non,
  déclarer à une autorité : ce n'est pas une décision d'outil.
- **L'ingénierie de détection sur mesure.** Les règles propres au métier du
  client se travaillent avec lui.

### 6.3 Le positionnement en une phrase

> Un SOC classique vend des heures d'analystes. AURA vend un dispositif qui n'en
> a pas besoin pour fonctionner au quotidien — et qui garde les humains pour ce
> qui les mérite vraiment.

---

## 7. Ce que ça coûte à héberger

Volontairement modeste : AURA tourne sur une seule machine.

| Ressource | Strict minimum | Recommandé |
|---|---|---|
| CPU | 4 vCPU | 8 vCPU |
| RAM | 8 Gio | 16 Gio |
| Disque | 60 Gio SSD | 100 Gio SSD |

- **Déploiement** : entièrement conteneurisé, un seul fichier de configuration,
  une seule commande de démarrage.
- **Souveraineté** : toute la plateforme (collecte, détection, base de données,
  dossiers d'enquête, tableaux de bord) est **chez le client**. Sortent
  uniquement : le contexte pseudonymisé envoyé au modèle, et des empreintes de
  fichiers / adresses IP envoyées aux services de réputation.
- **Coût variable** : la consommation IA, mesurée et affichée en tableau de bord,
  proportionnelle au nombre d'**incidents** — pas au nombre d'alertes.

---

## 8. Comment se déroule une mise en service

1. **Installation** de la plateforme (une machine, conteneurs) et des agents sur
   le parc.
2. **Inventaire** : on attribue à chaque machine son rôle et sa priorité P1-P4.
3. **Mode apprentissage** : quelques jours d'observation. AURA voit tout, note le
   bruit normal, **n'agit pas**. À l'échéance, un dossier récapitule chaque
   exception apprise — chacune révocable une par une.
4. **Mise en surveillance active** : triage IA et dossiers d'enquête, actions
   encore en simulation. On compare les verdicts au réel.
5. **Autonomie** : les actions de confinement s'exécutent réellement.

Chaque étape est réversible, et le passage à l'étape suivante est une décision
du client, pas un automatisme.

---

## 9. Une journée type, racontée

**02 h 14** — Un compte de service se connecte à un serveur de fichiers depuis
une adresse jamais vue, publiée trois jours plus tôt par le CERT-FR comme
infrastructure d'attaque. Deux minutes plus tard, un binaire inconnu est déposé
et exécuté ; des fichiers commencent à être chiffrés.

**02 h 16** — AURA a regroupé les 25 alertes en **un seul incident**, pas 25.
Le comportement s'écarte franchement de la normale de cette machine, et
l'adresse est reconnue par sa mémoire de menaces. La machine est un actif **P2**.

**02 h 17** — L'IA rend son verdict : attaque réelle, rançongiciel en cours,
haute confiance. Elle propose l'isolation de la machine, le blocage de
l'adresse, la désactivation du compte.

**02 h 18** — Les garde-fous valident les actions, qui s'exécutent. La machine
est hors réseau. Le chiffrement s'arrête là.

**02 h 19** — Un dossier d'enquête existe, avec rapport en français,
chronologie, indicateurs, vulnérabilités de la machine et liste des actions
engagées.

**08 h 30** — L'équipe arrive, lit un dossier complet sur un incident **déjà
confiné**. Elle passe sa matinée sur la restauration et la recherche de
persistance — pas sur le triage.

Dans un SOC classique, à 08 h 30, la première alerte de 02 h 14 n'a encore été
lue par personne.

---

## 10. Les trois messages à retenir

1. **La réduction avant l'IA.** C'est ce qui rend le dispositif abordable :
   filtres, réputation, comportement, regroupement — tout cela sans coût d'IA.
   L'IA ne voit que des incidents, jamais du tout-venant.
2. **L'autonomie est le produit, pas une option.** Aucune validation humaine
   par action. Ce qui borne l'IA, ce sont des garde-fous déterministes — pas un
   humain, et pas une consigne écrite dans un prompt.
3. **La boucle se ferme.** Chaque faux positif traité rend le SOC durablement
   plus silencieux. Un SOC humain, lui, rejuge le même bruit chaque semaine.

---

## Annexe — glossaire pour la slide de fin

| Terme | En clair |
|---|---|
| **SOC** | l'équipe et les outils qui surveillent la sécurité |
| **MDR** | un SOC qui, en plus de détecter, réagit sur les machines |
| **Faux positif** | une alerte qui n'était pas une attaque |
| **UEBA** | analyse des comportements pour repérer ce qui sort de l'ordinaire |
| **CTI** | renseignement sur les attaquants connus |
| **Confinement / isolation** | couper une machine du réseau pour arrêter la propagation |
| **MTTR** | temps moyen pour corriger |
| **Garde-fou déterministe** | une règle écrite en dur, qui ne se discute pas et ne dépend d'aucune probabilité |
