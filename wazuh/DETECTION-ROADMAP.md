# Plan d'action — détections manquantes

> **ÉTAT AU 2026-07-27 — P1, P2 et P3 sont FAITS**, dans le cadre de la révision
> complète des règles High/Critical. Voir `DETECTION-REVIEW.md` pour le détail
> des règles, des pièges rencontrés et des tests.
>
> Ce que la révision a changé par rapport au plan ci-dessous :
> - **Plage d'identifiants** : 100700-100730 était réservée ici, mais les règles
>   web ont pris 100700-100702 et 100710-100712 entre-temps. La persistance FIM
>   est donc en **100740-100750**, la post-exploitation en **100760-100773**,
>   l'auto-surveillance du SOC en **100800-100806**. Ne pas réutiliser
>   100703-100709.
> - **Cause A/B incomplètes** : la revue a trouvé une cause C, plus grave que les
>   deux autres — le capteur auditd était **éteint** (`enabled 0`), rendant 19
>   règles de niveau ≥ 12 inertes. Aucune règle nouvelle n'aurait rien changé.
>   Corrigé par `-e 2` (audit immuable) ; cause racine : systemd-journald.
> - **P4 (méta-corrélation « host owned ») reste À FAIRE** — seul point non
>   traité de cette liste.

Établi après le scénario d'attaque web→root rejoué sur `debian-vm` (2026-07-24).
Le rapport d'analyse IA ne couvrait qu'une partie de la kill chain. Deux causes,
deux réponses.

## Cause A — étapes détectées mais sous le seuil (RÉSOLU)

L'énumération (id, uname, `cat /etc/passwd`, `sudo -l`, lecture de `id_rsa`) et
l'exploitation (`find -exec sh -p`, `chmod u+s`) ne généraient que de l'audit de
commande **niveau 3** (règle 80792), filtré par les seuils de corrélation.

**Fait** : `ATTACH_MIN_LEVEL` descendu de 6 à **3** (et `MIN_LEVEL` 12→8). Une
fois un incident confirmé, TOUTES les alertes de l'hôte dans la fenêtre y sont
rattachées, et le rapport reconstitue les commandes depuis le proctitle auditd
(section « Commandes exécutées »). Rien de plus à écrire côté règles.

## Cause B — étapes NON détectées (aucune règle) → à construire

Ces comportements n'ont déclenché **aucune** règle. Aucune baisse de seuil ne
les fera apparaître : il faut créer la détection. Priorisé par valeur/effort.

Convention repo (cf. `CLAUDE.md`) : règles dans
`wazuh/config/wazuh_cluster/local_rules.xml`, plage libre à partir de **100700**,
validation `wazuh-logtest` + rejeu de régression → PR git → merge humain. Jamais
d'écriture directe en prod. Pièges auditd connus (cf. mémoire) : `audit.exe`
tronqué à la première ponctuation, argv hex-encodé — matcher le `full_log` via
`<regex>` quand un chemin contient `.`/`-`.

### P1 — Persistance par fichier (FIM temps réel + règle)

Le plus gros trou : cron, clés SSH, service systemd, édition directe de
`/etc/passwd` — tous invisibles faute de FIM temps réel sur ces chemins.

**1. Étendre le FIM (agent `ossec.conf`, `<syscheck>`), en `realtime`** :

```xml
<directories realtime="yes" report_changes="yes" check_all="yes">/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/var/spool/cron</directories>
<directories realtime="yes" report_changes="yes" check_all="yes">/etc/systemd/system,/lib/systemd/system</directories>
<directories realtime="yes" report_changes="yes" check_all="yes">/root/.ssh,/home</directories>   <!-- authorized_keys -->
<directories realtime="yes" report_changes="yes" check_all="yes">/etc/passwd,/etc/shadow,/etc/sudoers,/etc/sudoers.d</directories>
```

**2. Règles sur les événements FIM (`syscheck` → `rule id="550"` parent)** :

- `100700` (niv. 12, T1053.003) — ajout/modif dans `/etc/cron.d` ou `crontab` :
  ```xml
  <rule id="100700" level="12">
    <if_sid>550,554</if_sid>
    <field name="file">^/etc/cron|/var/spool/cron</field>
    <description>Persistance : tâche cron créée/modifiée ($(file))</description>
    <mitre><id>T1053.003</id></mitre>
  </rule>
  ```
- `100701` (niv. 12, T1098.004) — `authorized_keys` créé/modifié sous
  `/root/.ssh` ou `/home/*/.ssh`.
- `100702` (niv. 12, T1543.002) — unit systemd déposée dans
  `/etc/systemd/system` ou `/lib/systemd/system`.
- `100703` (niv. 13, T1136 / T1078) — `report_changes` sur `/etc/passwd` dont
  le diff introduit un **second UID 0** (matcher `content_changes` sur
  `^\+\w+::?0:0` ). Backdoor uid0 — priorité maximale.

`report_changes="yes"` est ce qui donne le `content_changes` nécessaire pour
distinguer un ajout uid0 d'une modif banale de `/etc/passwd`.

### P2 — Persistance par exécution (corrélation auditd)

Complément du FIM : capter l'ACTION même quand le fichier n'est pas (encore)
sous FIM. On corrèle sur les commandes auditd (déjà collectées, règle 80792).

- `100710` (niv. 10, T1543.002) — `systemctl enable` observé (proctitle
  auditd), surtout hors fenêtre de maintenance.
- `100711` (niv. 10, T1136.001) — `useradd`/`usermod -aG sudo` (complète la
  règle syslog 5902 par le contexte auditd, utile si syslog manque).
- `100712` (niv. 10, T1053.003) — `crontab -e`/écriture via `tee`/`>>` vers un
  chemin cron.

Ces règles matchent le `full_log` (proctitle décodé) — voir la section IOC de
`iris.py` pour le décodage hex du proctitle, réutilisable comme decoder.

### P3 — Accès initial web (decoder + règle sur l'access.log Apache)

L'injection `?host=127.0.0.1;<cmd>` n'a rien déclenché : les règles web 31xxx
ciblent des signatures connues (SQLi…), pas une injection de commande générique.

- Decoder/règle `100720` (niv. 12, T1190/T1059) sur `web-accesslog` : requête
  dont le query string contient des métacaractères shell (`;`, `|`, `` ` ``,
  `$(`, `&&`, `/dev/tcp`, `nc `, `bash -i`) vers un `.cgi`/`.php`.
  ```xml
  <rule id="100720" level="12">
    <if_sid>31100</if_sid>
    <url>\.cgi\?|\.php\?</url>
    <regex>[;|`]|\$\(|&&|/dev/tcp|bash -i|nc </regex>
    <description>Injection de commande probable via requête web</description>
    <mitre><id>T1190</id><id>T1059</id></mitre>
  </rule>
  ```
  Attention faux positifs (query strings légitimes avec `;`) — affiner par
  chemin/hôte, mettre en niveau modéré d'abord, mesurer.

### P4 — Méta-corrélation : « compromission complète »

Au-delà des règles unitaires, une règle composite qui s'allume quand plusieurs
tactiques tombent sur le même hôte dans une courte fenêtre — la signature d'une
intrusion aboutie, pas d'un événement isolé.

- `100730` (niv. 14, corrélation) — reverse shell (100650) **puis** privesc
  (100656) **puis** persistance (100700-100702 ou 5902) sur le même agent en
  < 10 min. `<frequency>`/`<timeframe>` + `<same_source_ip>`/`<same_field>` sur
  `agent`. Donne à l'analyste (et à l'IA) un signal unique « host owned » de
  très haut niveau, indépendant de la corrélation applicative du soc-agent.

Note : le soc-agent corrèle DÉJÀ ces étapes en incident. Cette règle Wazuh est
le filet redondant côté SIEM (utile si le pipeline IA est arrêté).

## Process de mise en œuvre

1. Écrire decoder/règle dans `local_rules.xml` (plage 100700+).
2. `wazuh-logtest` sur un échantillon réel de chaque log (proctitle, FIM,
   access.log) — vérifier le niveau et le champ matché.
3. Rejeu de régression : s'assurer qu'aucune règle existante ne casse.
4. PR git, merge humain, puis restart manager (le ruleset chargé en mémoire
   prime sur le fichier — cf. mémoire infra).
5. Rejouer le scénario web→root : vérifier que chaque étape (B) déclenche
   désormais une alerte et entre dans l'incident.

## Ordre recommandé

P1 (FIM persistance) d'abord — c'est le trou le plus dangereux (backdoors
durables) et le moins sujet aux faux positifs. Puis P4 (méta-corrélation, gros
gain analyste pour peu de code). P3 (web) demande du réglage anti-FP. P2 est un
complément de robustesse.
