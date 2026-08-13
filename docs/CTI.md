# CTI — renseignement sur la menace

Le SOC savait détecter des COMPORTEMENTS (auditd, FIM, Suricata, UEBA). Il ne
savait rien des ACTEURS : une IP publiée la veille par le CERT-FR comme
infrastructure de commande, un domaine de C2 listé par abuse.ch, l'empreinte
d'un implant connu passaient exactement comme du trafic ordinaire. Aucun log,
aucune alerte, aucun angle mort visible — le renseignement n'existait tout
simplement pas dans le dispositif.

Ce volet le comble en trois pièces, volontairement découplées.

```
   ┌──────────────────────┐   feeds     ┌──────────────────────────────────┐
   │   MISP (mémoire)     │◄────────────┤ CERT-FR · CIRCL · Botvrij ·      │
   │ événements, tags,    │             │ ThreatFox · URLhaus              │
   │ corrélations, UI     │             └──────────────────────────────────┘
   └──────────┬───────────┘
              │ /attributes/restSearch (to_ids, publiés, 90 j)
              ▼
   ┌──────────────────────┐  téléchargement direct  ┌───────────────────────┐
   │  soc-agent-cti       │◄────────────────────────┤ Data-Shield · CINS ·  │
   │  (cti.py, horaire)   │                         │ blocklist.de · Tor ·  │
   └──────────┬───────────┘                         │ OpenPhish             │
              │ écriture atomique                   └───────────────────────┘
              ▼
   ┌──────────────────────┐   lookup local, 0 appel réseau
   │  cache SQLite        │◄──────────────┐
   │  aura_cti_ioc (ro)   │               │
   └──────────────────────┘     ┌─────────┴──────────────┐
                                │ custom-misp            │
      alerte Wazuh ────────────►│ (intégration manager)  │──► règles 100950-100957
                                └────────────────────────┘

   ┌──────────────────────┐  RSS / annuaire   ┌────────────────────────────┐
   │ soc-agent-cti-articles│◄─────────────────┤ TheHackerNews · Bleeping · │
   │ regex -> LLM -> code  │                  │ RST Cloud · Malpedia       │
   └──────────┬────────────┘                  └────────────────────────────┘
              │ événements MISP tagués `aura:source:extracted` -> 100957
              ▼  (remontent ensuite par le même chemin que les feeds)
```

## Pourquoi un cache, et pas un appel à MISP par alerte

C'est LA décision de conception de ce module, et elle va à l'encontre de la
plupart des intégrations MISP/Wazuh publiées.

`wazuh-integratord` appelle l'intégration en série, pour chaque alerte retenue.
Y mettre une requête HTTP vers MISP place la détection de tout le parc derrière
la latence et la disponibilité d'un service PHP : MISP lent, et c'est la file
d'alertes qui prend du retard ; MISP arrêté pour une migration, et le SOC ne
voit plus aucun IOC — sans que rien ne le signale, puisqu'une intégration qui
échoue ne produit pas d'alerte.

Le cache inverse la dépendance. La détection lit un fichier local, MISP peut
tomber ou traîner sans qu'une seule alerte en pâtisse, et la seule panne qui
reste — un cache qui ne se met plus à jour — est elle-même détectée
(règle 100956, niveau 12). MISP garde ce qu'il fait mieux que tout le reste :
le contexte, la corrélation et l'investigation.

## Les feeds

Le catalogue est dans [`src/ai/soc_agent/cti_feeds.yaml`](../src/ai/soc_agent/cti_feeds.yaml),
avec la justification de chaque entrée. Deux familles, traitées différemment
parce qu'elles n'ont pas la même nature.

### Renseignement curé — ingéré dans MISP (niveau 12-14)

| Feed | Ce qu'il apporte |
|---|---|
| **CERT-FR / ANSSI** (`misp.cert.ssi.gouv.fr/feed-misp/`) | IOC publics TLP:CLEAR du CERT national. Le seul feed de la liste centré sur les campagnes visant des organisations françaises. |
| **CIRCL OSINT** | La référence de fait du projet MISP : rapports APT, campagnes, malware, avec leur contexte. |
| **Botvrij.eu** | IOC extraits de rapports publics, très peu de faux positifs, recouvrement seulement partiel avec le CIRCL. |
| **ThreatFox** (abuse.ch) | C2 en activité, avec la famille de malware. Un match ici veut dire « cette machine parle à un C2 connu ». |
| **URLhaus** (abuse.ch) | URL de distribution de charge utile. Match sur un log proxy/web = téléchargement. |

### Réputation de masse — tirée en direct (niveau 10)

| Liste | Ce qu'elle apporte |
|---|---|
| **Data-Shield IPv4** (duggytuxy) | ~100 000 IP de scanners/attaquants visant le web (`prod`) et l'infra exposée (`prod_critical`), fenêtre glissante de 15 jours, rafraîchie toutes les 6 h. |
| **blocklist.de** | IP ayant attaqué un capteur fail2ban (SSH, mail, web). Fenêtre courte, bon signal de fraîcheur. |
| **CINS Army** | Mauvaise réputation confirmée par plusieurs capteurs, seuil de confiance élevé. |
| **Tor exit nodes** | Provenance, pas malveillance — retombe au niveau 5 (règle 100954). |
| **OpenPhish** (flux gratuit) | URL de phishing actives. |

Ces listes **ne passent pas par la base MISP**. 300 000 attributs réécrits
toutes les six heures dans MariaDB ruinent l'instance pour zéro gain
analytique : aucun de ces IOC ne porte d'événement à corréler. Elles sont
déclarées à MISP en **cache seul** (cache Redis, interrogeable depuis l'UI :
« cette IP est-elle connue ? ») et tirées en direct par `cti.py` pour la
détection.

### Renseignement non structuré — articles publics (niveau 12)

| Source | Mécanique | Rendement observé |
|---|---|---|
| **The Hacker News** | RSS (50 articles) | faible : la plupart des billets ne décrivent aucune infrastructure |
| **BleepingComputer** | RSS (15 articles) | faible, même raison |
| **RST Cloud** ([@rst_cloud](https://medium.com/@rst_cloud)) | RSS Medium, **contenu complet dans le flux** | très élevé : un « TI Report Digest » porte ~400 candidats |
| **Malpedia** | `/api/get/references` + curseur sur les URL vues | file de rapports techniques, **avec attribution** |

Ces sources publient les IOC **en prose**, souvent défangés (`hxxp://evil[.]com`),
sans format commun. `cti_articles.py` les traite en trois étages :

1. **Récupération** — RSS ou annuaire, puis texte de l'article (les balises
   `<script>`/`<nav>` sont retirées : elles sont pleines de domaines tiers,
   donc de faux candidats).
2. **Candidats** (déterministe) — défanging puis expressions régulières. Trouve
   tout ce qui *ressemble* à un IOC, sans juger.
3. **Arbitrage** (LLM) — décide lesquels appartiennent à la menace décrite.

**Pourquoi le LLM et pas une regex de plus.** Un article cite en permanence des
domaines légitimes : le média lui-même, ses sources, l'éditeur du rapport, la
victime, les outils détournés. Mesuré sur un article de The Hacker News, l'étage
régulier remonte `1.1.1.1` (résolveur Cloudflare), `1.7.2.0` et `1.7.3.0` (des
**numéros de version** pris pour des IP) et `release.zip` (un **nom de fichier**,
`.zip` étant un TLD réel) — le modèle a rejeté les quatre, et retenu les trois
vrais domaines Lazarus d'un autre article. Un faux IOC coûte plus cher qu'un IOC
manqué : il fait alerter au niveau 12 sur du trafic normal.

**Le LLM n'est pas une frontière de sécurité**, donc sa sortie est revérifiée
par du code : présence *littérale* de chaque valeur dans les candidats
(anti-hallucination), exclusions dures (IP privées et de documentation, infra du
SOC, domaines des médias par suffixe), warninglists MISP, plafond par article.
Mesuré sur 148 IOC extraits d'un digest : zéro rejet — le modèle recopie, il
n'invente pas.

Les IOC retenus deviennent un **événement MISP** (lien vers l'article en premier
attribut, famille de malware en tag), publié et tagué `aura:source:extracted`.
`cti.py` relit ce tag et classe l'IOC en `extracted` : il matche la
règle **100957 (niveau 12)** et non 100952 (niveau 14). Une extraction
automatique d'article de presse ne vaut pas un IOC signé par un CERT, et le
ruleset doit le dire.

À savoir sur le coût et la robustesse :

- les candidats sont soumis par **lots** (le modèle est raisonnant, son
  raisonnement épuise le budget de sortie sur un gros lot et l'appel ne rend
  alors *rien*). L'article est renvoyé à chaque lot, mais le préfixe étant
  identique il est servi par le cache DeepSeek (50× moins cher) ;
- un lot qui déborde est **rejoué en deux moitiés** ; un lot définitivement
  perdu ne fait pas perdre l'article (mesuré : 6 lots perdus, 148 IOC quand
  même publiés) ;
- ce qui dépasse `MAX_LOTS` est écarté mais **journalisé** — un plafond muet
  laisserait croire à un article entièrement couvert ;
- les articles **sans** IOC sont enregistrés aussi, avec le motif : c'est ce qui
  évite de les relire à chaque passe, et ce qui rend le rendement de chaque
  source mesurable.

### Écartés, et pourquoi

- **firehol_level1**, **Spamhaus DROP** : publiés en CIDR. Le cache fait une
  égalité exacte sur la valeur, il ne sait pas dire « cette IP est dans ce
  /24 ». Les charger donnerait une liste qui ne matche jamais — pire
  qu'absente. Leur place est une CDB list Wazuh (`lookup="address_match_key"`,
  qui gère le CIDR), à ajouter si le besoin se confirme.
- **Feodo Tracker** : figé depuis le 2026-03-04 (vérifié le 2026-08-12). Un
  feed mort donne une fausse impression de couverture.
- **DigitalSide Threat-Intel** : injoignable au 2026-08-12.

## Ce qui est cherché dans une alerte

L'intégration est branchée sur le **niveau** (>= 3) et non sur un groupe,
contrairement à AbuseIPDB : un IOC peut apparaître dans n'importe quelle
famille d'alerte. Filtrer par groupe, c'est décider à l'avance par où passe
l'attaquant.

| Type | Champs lus |
|---|---|
| IP | `data.srcip`, `data.src_ip`, `data.dstip`, `data.dest_ip`, Sysmon `destinationIp`/`sourceIp` |
| Domaine | `data.dns.rrname`, `data.dns.question.name`, `data.tls.sni`, `data.http.hostname`, `data.win.eventdata.queryName`… |
| URL | `data.url`, `data.http.url`, et l'URL **recollée** depuis hôte + chemin |
| Empreinte | `syscheck.*_after` (FIM), enrichissement VirusTotal, `data.win.eventdata.hashes` (Sysmon) |

Les IP privées ne sont jamais cherchées : une IP RFC1918 ne peut pas être un
IOC public, et un feed qui en publie une par erreur (ça arrive) ferait alerter
sur nos propres machines.

## Les champs de l'alerte enrichie

Tous sous `data.misp.*`, **noms en anglais** comme les descriptions de règles :
ils partent dans les alertes, les dashboards et les cases IRIS, à côté des
champs natifs de Wazuh.

| Champ | Contenu |
|---|---|
| `ioc` | l'indicateur qui a matché, sous sa forme normalisée |
| `ioc_type` | `ip` \| `domain` \| `url` \| `hash` |
| `field` | où il a été trouvé dans l'alerte d'origine (`data.srcip`, `syscheck.sha256_after`…) |
| `direction` | `inbound` \| `outbound` \| `artifact` |
| `source` | feed ou organisation MISP |
| `confidence` | `curated` \| `bulk` — décide du niveau de la règle |
| `category`, `event_info`, `tags`, `threat_level` | contexte MISP |
| `event_id`, **`event_url`** | l'événement MISP et son lien direct (vide pour une liste de masse) |
| **`search_url`** | recherche de la valeur dans MISP — toujours résolu |
| `match_count` | nombre de sources qui portent cet IOC |
| `source_alert_rule_id`, `source_alert_description` | l'alerte qui a déclenché le lookup |
| `agent`, `agent_id` | la machine concernée |
| `error`, `cache` | uniquement sur l'alerte 100956 (cache inutilisable) |

Les deux liens sont construits à partir de **`MISP_BASE_URL`** (l'URL publique),
que `cti.py` recopie dans le cache — un lien vers `https://127.0.0.1:8444` ne
serait cliquable que depuis le manager. `search_url` existe parce que les
listes de masse vivent dans le cache Redis de MISP et ne portent aucun
événement : sans lui, la moitié la plus volumineuse du renseignement n'aurait
aucun point d'entrée.

## Les règles

| ID | Niveau | Ce qu'elle dit |
|---|---|---|
| 100950 | 3 | Correspondance CTI (règle parente, toute source) |
| 100951 | 12 | Contact **entrant** depuis un IOC curé |
| 100952 | **14** | Contact **sortant** vers une infrastructure malveillante connue |
| 100953 | 10 | IP sur une liste de réputation de masse |
| 100954 | 5 | Nœud de sortie Tor |
| 100955 | 13 | Empreinte de fichier malveillant connue sur une machine |
| 100957 | 12 | IOC **extrait d'un article public** par le modèle |
| 100956 | 12 | **Cache d'IOC inutilisable ou périmé** (auto-surveillance) |

Deux choix de niveau portent tout le dispositif :

**Sortant (14) contre entrant (12).** Une IP malveillante qui nous parle veut
dire que quelqu'un a essayé ; une de nos machines qui parle à une IP
malveillante veut dire que quelque chose tourne déjà chez nous et appelle son
opérateur. Ce n'est pas le même incident, ça ne peut pas être le même niveau.

**Attention aux automates relayés par les feeds OSINT.** Le feed du CIRCL
relaie les publications quotidiennes de Maltrail (agrégation de blacklists) :
255 361 des 692 543 IOC « curés » du cache le 2026-08-12, soit 37 %, tous avec
`to_ids=1`. En `curated` ils matchaient aux niveaux 12 à 14 — donc un incident
et un triage LLM par match, sur ce qui est par construction une blocklist. Ils
sont désormais classés `bulk` d'après leur propre tag de taxonomie MISP,
`misp:automation-level="unsupervised"`. À vérifier après tout ajout de feed :

```sql
-- côté cache : ce qui prétend être curé sans l'être
SELECT source, count(*) FROM ioc WHERE confiance='curated' GROUP BY 1 ORDER BY 2 DESC;
```

**Trois niveaux de confiance, trois niveaux d'alerte.** `curated` (feed d'un
CERT ou d'un projet reconnu) > `extracted` (IOC tiré d'un article par le modèle)
> `bulk` (réputation de masse). Quand une même valeur est portée par plusieurs
sources, c'est la meilleure qui décide du niveau.

**Masse à 10, une marche SOUS le seuil d'incident** (`MIN_LEVEL=12`). Ces
listes tiennent 100 000 IP tournantes : le moindre SSH ou port web exposé les
matche plusieurs fois par heure. Les promouvoir en incident noierait le
pipeline IA dans le bruit qu'il a été construit pour couper. Le signal garde sa
valeur de **contexte** : visible au dashboard, et rattaché automatiquement à un
incident ouvert par une autre règle (`ATTACH_MIN_LEVEL=3`).

## Mise en service

```bash
# 1. Renseigner la section MISP / CTI du .env (MISP_KEY : openssl rand -hex 20)
#    db/misp-mariadb est créé par le service aura-init, dont misp-db dépend.
docker compose up -d misp-db misp-redis misp-core misp-modules

# 2. Premier démarrage : MISP applique ses migrations (plusieurs minutes).
docker compose logs -f misp-core        # attendre le healthcheck

# 3. Déclarer les feeds et lancer le premier tirage (idempotent)
docker compose up -d soc-agent-cti
docker compose exec soc-agent-cti python -m soc_agent.cti --feeds

# 4. Vérifier le cache une fois MISP passé sur ses feeds (compter ~15 min)
docker compose exec soc-agent-cti python -m soc_agent.cti --etat
docker compose exec soc-agent-cti python -m soc_agent.cti --test 185.220.101.1

# 5. Brancher l'intégration côté manager : reprendre le bloc <integration>
#    custom-misp de wazuh_manager.conf.example dans le wazuh_manager.conf
#    déployé, puis
docker compose restart wazuh.manager
```

### Veille (extraction d'articles)

```bash
# AMORÇAGE OBLIGATOIRE avant le premier démarrage : marque l'existant comme vu
# sans rien traiter. Sans lui, la première passe tente de faire lire au modèle
# toute la bibliographie Malpedia (des dizaines de milliers de rapports).
docker compose run --rm soc-agent-cti-articles \
    python -m soc_agent.cti_articles --amorcage

docker compose up -d soc-agent-cti-articles

# Essai à blanc sur un article précis (n'écrit ni dans MISP ni en base)
docker compose exec soc-agent-cti-articles \
    python -m soc_agent.cti_articles --url https://... --simulation
```

Rendement par source (`iocs_retenus = 0` est le résultat NORMAL pour la presse) :

```sql
SELECT source, count(*) articles, sum(iocs_retenus) iocs,
       count(*) FILTER (WHERE iocs_retenus > 0) utiles
FROM cti_articles GROUP BY source ORDER BY iocs DESC;
```

UI MISP : https://127.0.0.1:8444 — `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD`.

### Publier l'UI (tunnel, ou reverse proxy)

Le port n'écoute que sur la loopback par défaut. Sans rien changer :

```bash
ssh -L 8444:127.0.0.1:8444 root@<manager>   # puis https://localhost:8444
```

Pour placer un reverse proxy devant, trois variables et **pas une de moins** :

| Variable | Rôle |
|---|---|
| `MISP_BIND_ADDR` | interface d'écoute du port publié (IP d'admin plutôt que `0.0.0.0`) |
| `MISP_BASE_URL` | URL **publique** du proxy — les liens, cookies et redirections de MISP en dépendent |
| `MISP_REAL_IP_FROM` + `MISP_X_FORWARDED_FOR=true` | sinon toutes les connexions sont journalisées avec l'IP du proxy |

`MISP_REAL_IP_FROM` doit lister **tous** les sauts de confiance, et le premier
n'est pas celui qu'on croit : le port étant publié par `docker-proxy`, le nginx
de MISP voit comme source la passerelle du réseau docker, pas le reverse proxy.
Nginx ne remonte la chaîne `X-Forwarded-For` que de saut en saut — il faut donc
les deux, sinon il s'arrête au premier et journalise l'adresse du proxy.
Mesuré en prod le 2026-08-12 :

```
MISP_REAL_IP_FROM=172.23.0.0/16,192.168.2.11   # bridge docker, puis le proxy
```

Vérification (l'IP doit être celle du client, pas celle d'un intermédiaire) :

```sql
SELECT ip, action, created FROM logs ORDER BY id DESC LIMIT 5;
```

Contrepartie assumée : nginx fait alors confiance à l'en-tête `X-Forwarded-For`
de tout ce qui vient du bridge docker. Quiconque atteint directement le port
publié peut donc falsifier l'adresse journalisée. C'est acceptable tant que ce
port n'est ouvert qu'au réseau d'administration ; ça ne l'est plus s'il est
exposé plus largement.

`MISP_URL` est l'URL **client** du soc-agent : elle doit suivre
`MISP_BIND_ADDR` (le port n'écoute que sur cette interface — viser la loopback
alors que le bind est sur l'IP d'admin donne un « Connection refused », mesuré
le 2026-08-12), mais ne doit **jamais** être l'URL publique du proxy. Le
pipeline CTI n'a pas à dépendre du proxy et du DNS pour parler à un service qui
tourne sur la même machine.

## Vérifier que ça détecte vraiment

Le seul test qui prouve quelque chose part d'un IOC **réellement présent dans
le cache** :

```bash
# une valeur qui matche, prise dans le cache
docker compose exec soc-agent-cti sh -c \
  "sqlite3 /var/lib/aura-cti/ioc.db \"SELECT valeur FROM ioc WHERE confiance='curated' AND type='ip' LIMIT 1\""

# la rejouer dans une alerte, et regarder ce que l'analyseur en fait
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest
```

Rappel du piège documenté dans
[`rules/README.md`](../src/wazuh/config/wazuh_cluster/rules/README.md) :
`wazuh-logtest` sur une entrée saisie à la main route vers le décodeur `json` et
peut masquer un décalage de champ. La validation qui compte se fait sur une
alerte réelle du pipeline.

## Fraîcheur : ce que `CTI_FENETRE` ne fait pas

Le paramètre `last` de l'API MISP filtre sur la date de **dernière
modification** de l'attribut, pas sur l'âge du renseignement. Tout ce qu'un
feed vient d'importer a été modifié aujourd'hui : au premier import,
`CTI_FENETRE=90d` ne filtre quasiment rien. Mesuré à la mise en service du
2026-08-12 — des IP publiées comme C2 en **2015** (rapport Rocket Kitten,
via CIRCL) étaient dans le cache, prêtes à déclencher du niveau 12-14.

Le vrai filtre de fraîcheur est `CTI_IP_MAX_JOURS` (365 par défaut), qui porte
sur la date de l'**événement** et ne vise **que les IP** :

| Type | Périme ? | Pourquoi |
|---|---|---|
| IP | oui | Seul IOC qui change de main. Une IP de C2 de 2015 est aujourd'hui un hébergeur mutualisé ou un CDN. |
| Empreinte | non | Le fichier est le même pour toujours. |
| Domaine / URL | non | Reste rattaché à qui l'a déposé. |

## Modes de panne à connaître

- **Cache périmé.** Une CTI figée ne lève aucune erreur : elle répond, avec du
  renseignement de plus en plus faux. C'est le même angle mort qu'un capteur
  muet (règles 100800+), et il se traite pareil — par un signal positif. Passé
  `CTI_PEREMPTION_HEURES` (24 h), l'intégration émet un événement qui matche la
  règle 100956, au plus une fois par heure (sinon le SOC se noie sous son
  propre voyant de panne).
- **Divergence de normalisation.** Le cache est écrit par le soc-agent et lu
  par un script du manager, qui tourne avec l'interpréteur embarqué de Wazuh et
  ne peut pas importer `soc_agent`. La fonction `normaliser()` est donc écrite
  **deux fois**. Une divergence ne casse rien : plus rien ne matche, jamais.
  `tests/test_cti.py::test_normalisation_identique_cote_wazuh` compare les deux
  implémentations sur le même jeu de cas — toute modification de l'une doit
  être reportée sur l'autre.
- **Boucle de réinjection.** L'intégration réinjecte des événements dans
  l'analyseur ; une alerte CTI porte les mêmes IOC que celle qui l'a produite.
  Le garde-fou (identifiants 100950-100959 et champ `data.integration` ignorés)
  est en tête de `main()` et ne doit jamais être déplacé.
- **Retard de `wazuh-integratord`.** Le script sort immédiatement quand
  l'alerte ne porte aucun indicateur et ne fait aucun appel réseau, mais il
  reste un fork par alerte. Sur un parc très bavard, le premier réglage est de
  monter `<level>` de l'intégration à 6 ou 7.
