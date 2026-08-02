# Purple Team — Couverture MITRE ATT&CK / Atomic Red Team

Suivi de la couverture de détection SOC-AI (Wazuh + soc-agent) contre les tests
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).

## Lab

| Hôte | Rôle | Accès | OS | Atomic |
|------|------|-------|-----|--------|
| debian | endpoint Linux | `root@192.168.30.15` | Debian | ✅ |
| winsrv | Contrôleur de domaine (DC) | `192.168.30.100` | Windows Server | ✅ |
| win10 | Poste joint au domaine | `192.168.30.49` | Windows 10 | ✅ |
| soc-ai | SIEM/XDR prod (supervision) | `root@192.168.10.5` | — | manager Wazuh |

## Télémétrie collectée (état initial, relevé 2026-08-01)

Agents Wazuh v4.9.2 enrôlés sur manager `192.168.10.5`, config **par défaut** (aucun
script de remédiation déployé). ID manager : **014 winsrv**, **015 win10**. Debian = 011.

**Canaux (identiques winsrv/win10) :** eventchannel `Security`, `Application`, `System`
+ FIM (dossiers/registre sensibles) + SCA. **Pas de Sysmon. Pas de PowerShell
ScriptBlock (4103/4104).**

**Politique d'audit (winsrv DC & win10) :**

| Sous-catégorie | Événements | winsrv | win10 |
|----------------|-----------|--------|-------|
| Logon | 4624/4625 | ✅ S+E | ✅ S+E |
| **Process Creation** | **4688 (+ cmdline)** | ❌ **Pas d'audit** | ❌ **Pas d'audit** |
| User Account Mgmt | 4720/4722/4726 | ✅ | ✅ |
| Computer Account Mgmt | 4741 | ✅ | — |
| Security Group Mgmt | 4728/4732/4756 | ✅ | ✅ |
| Directory Service Access | 4662 | ✅ (DC) | n/a |
| Kerberos Service Ticket | 4769 | ✅ (DC) | n/a |
| Kerberos Auth | 4768 | ✅ (DC) | n/a |

### Mise à niveau télémétrie appliquée (2026-08-01) ✅

Le trou initial (4688 off, pas de Sysmon) a été comblé sur **winsrv ET win10** :

- **Audit Process Creation (4688) = activé (Succès)** — `auditpol /set` sous-catégorie
  `{0CCE922B}`.
- **Ligne de commande dans 4688 = activée** — reg
  `HKLM\...\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`.
- **Sysmon v15.21 installé** avec config SwiftOnSecurity (`sysmonconfig-export.xml`),
  service `Sysmon64` = Running.
- **Wazuh collecte le canal Sysmon** — `<localfile>` `Microsoft-Windows-Sysmon/Operational`
  ajouté à l'`ossec.conf` des deux agents, service redémarré.
- **PowerShell ScriptBlock (4104) = activé** — reg
  `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`,
  canal `Microsoft-Windows-PowerShell/Operational` ajouté aux agents. Vérifié : 16
  alertes PowerShell reçues côté manager depuis winsrv, 14 depuis win10.
- **Chaîne validée bout en bout** : events Sysmon + PowerShell reçus au manager depuis
  les 2 agents, règles déclenchées (92066, 92213 sur l'activité d'install elle-même).

Config host-local (pas de GPO) → suffisant pour le lab ; une GPO de domaine serait la
route durable si le lab grossit.

**Script réutilisable :** `wazuh/config/agent/Install-WazuhAgent-Windows.ps1` déploie
tout ce bloc (agent + audit 4688/cmdline + audit AD + 4104 + Sysmon + canaux Wazuh) en
une passe idempotente sur un nouvel hôte Windows. Détecte automatiquement les DC pour
activer l'audit Kerberos/DS Access. Validé en rejeu sur winsrv.

Plus aucun angle mort de source pour les 10 techniques AD.

## Légende détection

| Symbole | Sens |
|---------|------|
| ⬜ | Non testé |
| ✅ | Détecté — règle Wazuh valide, alerte HIGH/CRITICAL, case IRIS |
| 🟡 | Partiel — événement collecté mais pas d'alerte, ou niveau trop bas |
| ❌ | Angle mort — aucune télémétrie / pas de détection |
| ⛔ | Non applicable sur ce lab |

### Ce qui autorise à cocher ✅

Une règle **écrite** n'est pas une règle **qui détecte**. Les quatre règles AD
du 2026-08-02 ont été notées comme des correctifs le jour même, et **aucune n'a
tiré** sur l'attaque réelle qui a suivi : l'une avait une regex qui ne matchait
pas la ligne de commande réelle, deux attendaient une télémétrie que le parc
n'émet pas. Un ✅ demande donc **trois** preuves, pas une :

1. la règle est **chargée** (`Total rules enabled` a augmenté après le
   redémarrage du manager) ;
2. elle **tire** sur l'événement réel — `wazuh-logtest` rejoué sur un
   `full_log` extrait de la campagne, pas sur un log de synthèse ;
3. l'effet attendu **existe** : alerte au niveau visé, case IRIS créé, et pour
   une remédiation un compte rendu d'agent (`ar-result status=applied`), pas un
   simple accusé de réception de l'API.

Idem côté remédiation : `mitigations.statut = 'émis'` signifie « l'API a pris la
commande », rien de plus. Seul `confirmé` vaut ✅.

Colonnes : `Test` = GUID/numéro Atomic testé. `Règle` = ID règle Wazuh qui a tiré.
`Case` = numéro case IRIS généré (le cas échéant).

---

## Campagnes purple-team AD (10 techniques)

Deux campagnes Atomic Red Team sur winsrv (DC, 014) + win10 (015).
**#1 (2026-08-01)** : Defender bloquait les outils → 7/10 exécutées.
**#2 (2026-08-02, 09:19 UTC)** : Defender désactivé → 10/10 exécutées, en 8 secondes.

Note de la campagne #2, **réévaluée sur preuves** le 2026-08-02 après-midi :
**54/100** (détection 22/40, analyse IRIS 15/30, remédiation 17/30). Le 64/100
noté à chaud créditait les quatre règles AD — dont aucune n'a tiré — et des
remédiations que les scripts avaient refusées.

| # | Technique | Détection au moment de #2 | Après correctifs |
|---|-----------|---------------------------|------------------|
| 1 | T1558.003 Kerberoasting | ❌ L4 — aucun 4769 émis, 100910 inerte | 🟡 **100925** sur la ligne de commande |
| 2 | T1003.003 NTDS (vssadmin) | ❌ L4 — 100921 exigeait `vssadmin\s+create`, le 4688 porte `vssadmin.exe  create shadow` | ✅ **100921** corrigée, rejeu OK |
| 3 | T1003.001 LSASS | ❌ L6 — aucun Sysmon EID 10 (ProcessAccess vidé par SwiftOnSecurity) | ✅ **100924** + EID 10 activé à l'install |
| 4 | T1136.002 Create Domain Account | ✅ 4720 + 92040 L12 | ✅ |
| 5 | T1098.007 Add Domain Admins | 🟡 60110 L8 | 🟡 **laissé en Medium, choix assumé** |
| 6 | T1550.002 Pass the Hash | 🟡 L6 — `sekurlsa::pth` visible en cmdline, aucune règle | ✅ **100924** |
| 7 | T1003.006 DCSync / T1558.001 Golden | 🟡 L15 par effet de bord (dépôt d'exe) — aucun 4662, 100915 inerte | ✅ **100924** + SACL de réplication posée à l'install |
| 8 | T1482 Domain Trust Discovery | ❌ L4 | ✅ **100928** L8 |
| 9 | T1087.002 Domain Account Discovery | ✅ 92039 / 92040 L12 | ✅ |
| 10 | T1021.006 WinRM Lateral | ✅ 91822 L12 | ✅ |

**Ce qui a réellement échoué, et pourquoi (2026-08-02) :**

- **Détection.** Les 4 règles AD étaient chargées (manager redémarré à 09:09,
  campagne à 09:19) et ont tiré **zéro fois**. Deux causes distinctes : une
  regex écrite contre la commande *tapée* et non contre la ligne de commande
  *journalisée* (100921), et deux règles adossées à une télémétrie absente
  (4662 sans SACL, Sysmon EID 10 filtré). Les modules mimikatz
  (`lsadump::dcsync`, `kerberos::golden`, `sekurlsa::pth`) étaient pourtant en
  clair dans les 4688 — d'où **100924**, qui détecte la syntaxe de l'outil et
  couvre trois techniques d'un coup sans dépendre de la configuration d'audit.
- **Remédiation.** 58 actions, toutes enregistrées « exécutées ». En réalité 26
  ordres de quarantaine visaient des binaires signés de System32 d'un
  contrôleur de domaine (`cmd.exe`, `net.exe`, `powershell.exe`, `dsquery`,
  `klist`…), tous refusés par la safelist du script AR — la dernière ligne de
  défense, pas la première. Cause unique : les chemins de l'eventchannel
  arrivent avec les backslashes doublés, le filtre des répertoires système ne
  matchait donc jamais. Les kills, eux, sont bien partis : `powershell.exe` et
  `wsmprovhost.exe` tués **par nom** sur le DC ont coupé toutes les sessions
  d'administration et WinRM de la machine.
- **Compte rendu.** Aucun moyen de savoir tout cela depuis le manager : le
  canal d'AR est fire-and-forget. Le rapport IRIS affirmait « ✅ exécuté » sur
  26 actions non faites. C'est le défaut le plus grave de la campagne — un
  rapport faux est pire qu'un rapport incomplet.
- **Analyse.** Le rapport LLM des deux cases a échoué (`finish_reason=length`,
  raisonnement au-delà des 6000 tokens) et le repli a écrasé un rapport abouti
  par la raison du triage, recopiée à l'identique dans « Résumé » et
  « Analyse ». `mimikatz.exe` ne figurait dans aucun IOC ; son absence a aussi
  empêché la fusion de campagne entre les deux hôtes qui l'exécutaient.

**La remédiation Windows n'exécutait rien du tout** (établi le 2026-08-02
après-midi, en instrumentant le DC). Trois défauts empilés, chacun masquant le
suivant :

1. Les onze commandes d'active response Windows/AD n'étaient pas déclarées dans
   la configuration du manager, donc absentes du `shared\ar.conf` poussé aux
   agents. `wazuh-execd` ignore en silence toute commande absente de ce
   fichier — vérifié au débogueur : le message est bien reçu
   (`receive_msg: '#!-execd ... "command": "!soc-probe.exe"'`) mais aucune ligne
   `ExecdRun` ne suit. L'API répond pourtant 200. Les blocs existaient dans
   `wazuh/active-response/windows/register-commands.xml`, qui documentait déjà
   ce piège ; ils n'avaient jamais été reportés, très probablement parce que
   `wazuh_manager.conf` est gitignoré (clés d'API) et échappe donc au `git pull`.
   Posés désormais par `scripts/patch-manager-ar-windows.py`.
2. Aucun script d'AR Windows ne pouvait écrire dans `active-responses.log` :
   `wazuh-execd` garde le fichier ouvert, `Add-Content` demande un partage que
   l'OS refuse, et le `catch {}` avalait l'erreur. D'où un journal ne contenant
   que les lignes d'execd lui-même, et l'impossibilité totale de vérifier quoi
   que ce soit. Corrigé par un `FileStream` en `FileShare.ReadWrite`.
3. Preuve terrain : `art-backdoor`, le compte de domaine créé par l'attaquant,
   **est toujours actif** sur le DC, et `C:\Windows\System32\cmd.exe` n'a jamais
   bougé. Le diagnostic du matin — « refusées par la safelist du script » —
   était faux : les actions n'ont jamais atteint le script. Le garde-fou n'a pas
   sauvé la situation, il n'a simplement jamais été sollicité.

**Le « délai » de la remédiation Windows était un interblocage.** Symptôme :
une AR n'était exécutée qu'au redémarrage du service de l'agent. Cause :
`ar-wrapper.exe` lisait son entrée standard avec `Console.In.ReadToEnd()`, donc
attendait un EOF — or `wazuh-execd` ne ferme pas le tube avant la sortie du
fils, et attend cette sortie. Chacun attendait l'autre. Le thread d'active
response de l'agent restant bloqué derrière ce fils, **toutes** les
remédiations suivantes s'empilaient sans jamais partir ; le redémarrage du
service fermait le tube et libérait d'un coup un wrapper vieux de plusieurs
minutes, ce qui donnait l'illusion d'une simple latence.

Preuve : un `win-kill-process.exe` vivant et bloqué a été trouvé sur les deux
hôtes. Les scripts Linux, eux, ont toujours lu **une seule ligne**
(`read -r INPUT_JSON`) — c'est le contrat, et c'est la seule lecture qui rend
la main. Le wrapper lit désormais une ligne (`ReadLine`) et ferme lui-même le
tube du script PowerShell.

Après correctif, sans aucun redémarrage : exécution immédiate, et **5 AR
envoyées en rafale traitées en 2 secondes** sur le DC, chacune remontée au
manager en règle 100934 avec ses champs. La remédiation Windows agit
maintenant en secondes.

**Correctifs livrés** (commit « Purple-team 2026-08-02 : remédiation qui vise
juste, et qui dit vrai ») : normalisation des chemins Windows, kill par PID avec
vérification d'image, `disable_user` restreint aux comptes créés, boucle de
compte rendu d'AR (`ar-result` → décodeur → règles 100930-100935 →
`reconcilier_resultats_ar`), règles 100924-100926 et 100928, SACL DCSync et
Sysmon EID 10 dans le script d'install, budget de rapport à 14000 tokens,
protection contre l'écrasement d'un rapport abouti, IOC des exécutables
Windows, et section « à faire à la main » (double reset de krbtgt).

---

### Campagne #3 (2026-08-02, 12:11 UTC) — rejeu des 10 techniques

Mêmes 10 techniques rejouées sur winsrv (014) + win10 (015), Defender déjà
désactivé, **10/10 exécutées avec preuve d'effet** (shadow copy créée, LSASS
dumpé 159 Mo / 60 Mo, DCSync a sorti le hash krbtgt, Golden ticket généré et
soumis, compte `T1136.002_Admin` créé + ajouté aux Domain Admins, mimikatz
`sekurlsa::pth` en R/W sur win10). Numéros Atomic : T1558.003-1, T1003.003-1,
T1003.001-1, T1136.002-1, T1098.007 (manuel `net`/`Add-ADGroupMember`),
T1003.006-1, T1558.001-1, T1482-1, T1087.002-1, T1021.006-2.

**Pas de nouveaux cases** : dans la fenêtre de lien fort (6 h), les alertes #3
ont rejoint les incidents ouverts de #2 → **case 90** (winsrv/1993) et **case 91**
(win10/1995), toujours **deux cases séparés** (fusion campagne non faite).

**Notes réévaluées sur preuves : Détection 50/100 · Analyse IRIS 48/100 ·
Remédiation 45/100.**

| # | Technique | Exéc. | Détection #3 (règle, niveau) | Statut | Remédiation (état réel) |
|---|-----------|:-----:|------------------------------|:------:|-------------------------|
| 1 | T1558.003 Kerberoasting | ✅ | L4 scriptblock PS uniquement — 100910 (4769 RC4) et 100925 morts | ❌ | — |
| 2 | T1003.003 NTDS vssadmin | ✅ | 67027 L3 générique ; 60702 L5 (VSS idle) — **100921 mort** | ❌ | shadow auto-nettoyée (timeout VSS), aucune AR |
| 3 | T1003.001 LSASS | ✅ | **92900 L12** (Sysmon EID 10, accès lsass) sur 014 ET 015 | ✅ | procdump quarantiné, **ar-result applied** (3/hôte) |
| 4 | T1136.002 Create Domain Account | ✅ | **92040 L12** + 60109 L8 | 🟡 | ❌ `disable_user` **jamais proposé** — compte resté actif |
| 5 | T1098.007 Add Domain Admins | ✅ | **60159 L12** « Domain Admins Group Changed » + 60148 L5 | ✅ | — |
| 6 | T1550.002 Pass the Hash (win10) | ✅ | 92900 L12 (accès lsass par mimikatz) — **100924 mort** | 🟡 | quarantaine mimikatz **émise, non confirmée** |
| 7 | T1003.006 DCSync + T1558.001 Golden | ✅ | 92213 L15 (dépôt exe) + 92900 L12 — **100915/100924 morts, aucun 4662** | 🟡 | **mimikatz NON quarantiné** (chemin faux) ; reset krbtgt non signalé |
| 8 | T1482 Trust Discovery | ✅ | 92031/92033 L3, 92103 L6 — **100928 mort** | 🟡 | — |
| 9 | T1087.002 Account Discovery | ✅ | 92039 L3 générique (bas) | 🟡 | — |
| 10 | T1021.006 WinRM Lateral | ✅ | **91822 L12 / 91823 L14** | ✅ | kill powershell/wsmprovhost émis |

**Cause racine de la détection spécifique nulle (nouvelle, non vue en #2) :** les
**8 règles AD custom** (100910, 100915, 100918, 100921, 100924, 100925, 100926,
100928) déclarent toutes `<decoded_as>json</decoded_as>`. Or les événements
Windows réels sont décodés par le décodeur **`windows_eventchannel`**, jamais par
le décodeur générique `json`. Ce préfiltre ne matche donc **jamais** : les règles
sont chargées mais **jamais évaluées** sur la vraie télémétrie. Prouvé : la
cmdline `"cmd.exe" /c ...mimikatz.exe "lsadump::dcsync ..."` est bien présente
dans `data.win.eventdata.commandLine` (regex 100924 satisfaite) mais l'alerte
émise est 92052 L4 ; scan de `alerts.json` sur la fenêtre → **0** occurrence de
100910/100915/100921/100924/100925/100926/100928. Les règles built-in qui, elles,
tirent s'accrochent correctement à l'arbre (`<if_group>sysmon_event1</if_group>`,
`<if_sid>60103</if_sid>`). Le « fix » de #2 a corrigé les regex mais laissé ce
mismatch de décodeur — d'où l'échec **identique** de la couche spécifique.
**Correctif : remplacer `<decoded_as>json</decoded_as>` par
`<decoded_as>windows_eventchannel</decoded_as>`** (ou attacher via
`if_group sysmon_event1` + un frère pour le canal Security 4688).

**Remédiation — ce qui marche enfin, ce qui manque :**
- La remédiation Windows **s'exécute et se confirme** vraiment : 6 `ar-result
  status=applied` (rule 100931) pour la quarantaine de procdump sur 014 et 015 —
  le défaut central de #2 (« n'exécutait rien ») est corrigé. Cibles justes cette
  fois : **vrais outils** (procdump/mimikatz dans `AtomicRedTeam\ExternalPayloads`),
  routage par agent correct (014→1993, 015→1995), **aucun System32** dans les
  actions #3.
- **mimikatz.exe non retiré** : la cible dérivée `...\ExternalPayloads\x64\mimikatz.exe`
  a perdu le segment `mimikatz\` (vrai chemin `...\ExternalPayloads\mimikatz\x64\mimikatz.exe`)
  → aucun `ar-result applied` → **binaire toujours sur disque** (vérifié).
- **Compte attaquant non désactivé** : `T1136.002_Admin`, créé et promu Domain
  Admin cette campagne, est resté `Enabled=True` (vérifié) — **aucun**
  `disable_user` proposé (l'incident DC 1993 n'a pas été re-trié après 12:11).
- Reset krbtgt (Golden Ticket) non signalé à l'analyste sur le case DC.

**Analyse IRIS — deux cases, deux qualités :**
- **Case 91 (win10) : bon rapport, régénéré par le triage #3 (12:17).** Chaîne
  d'attaque reconstituée, MITRE en union (T1550.002, T1003.001, T1562.001,
  T1021.006, …), IOC mimikatz présent, **statuts de remédiation honnêtes**
  (« 📤 commande émise, effet non confirmé » + avertissement explicite), section
  « couverture et limites ». C'est la preuve que les correctifs de #2 tiennent
  quand un triage frais tourne.
- **Case 90 (DC) : rapport dégradé de #2, non régénéré.** Résumé = Analyse
  (copie mot pour mot), MITRE unique **T1059.001**, faux « ✅ exécuté » sur des
  binaires System32 et sur `Système`/`ANONYMOUS LOGON`, 1 seul IOC. + 2 **faux
  IOC** (sha1 attribués à des clés de registre BITS/BAM « signalées par VT »),
  IOC compte périmés (art-backdoor/soc-test-bad de #2, pas `T1136.002_Admin`).
  L'hôte le plus critique porte le rapport le plus faux.

**Axes de correction #3 (par valeur/effort) :**
1. **[fort/faible]** `decoded_as json` → `windows_eventchannel` sur les 8 règles
   AD : ressuscite toute la couche de détection spécifique en une passe.
2. **[fort/moyen]** Rafraîchir/re-trier l'incident DC quand de nouvelles alertes
   s'y rattachent (poser `needs_refresh`), sinon le case le plus grave reste figé
   sur un vieux rapport faux.
3. **[fort/moyen]** `disable_user` doit se déclencher sur tout compte vu créé
   (4720/92040) puis ajouté à un groupe admin (4728/60159), indépendamment d'un
   re-triage LLM.
4. **[moyen/faible]** Corriger la dérivation du chemin de quarantaine mimikatz
   (segment de répertoire perdu) ; croiser cible vs chemins réels de l'alerte.
5. **[moyen/faible]** Purger les faux IOC (verdict VT porté par une clé de
   registre) du case 90.

### Correctifs livrés post-#3 (2026-08-02, commit `9c66c55`)

Axes 1, 3 (volet idempotence) et le drop de rafale d'AR, traités et **déployés
sur le manager prod** :

1. **Décodeur des 8 règles AD** (axe 1) — `<decoded_as>json</decoded_as>` →
   `<decoded_as>windows_eventchannel</decoded_as>` sur 100910/100915/100918/
   100921/100924/100925/100926/100928. Déployé, manager redémarré à 12:44 UTC.
   **Validation partielle :** le nom du décodeur est confirmé — l'événement
   `lsadump::dcsync` réel de la campagne porte bien `decoder=windows_eventchannel`
   et la règle native 60000 (qui a fait tirer 67027 sur ce même événement)
   utilise exactement cette porte ; la regex de 100924 était déjà prouvée (L13
   sous le décodeur `json` dans le rapport #3). **Preuve observée manquante :**
   `wazuh-logtest` ne peut PAS valider une règle eventchannel — un JSON fourni
   sur stdin est routé vers le décodeur `json`, pas `windows_eventchannel` (aucune
   règle eventchannel ne tire alors, même les natives). C'est précisément le
   piège qui a laissé passer le « fix » de #2. Le ✅ demande un événement Windows
   frais poussé dans le pipeline réel (un `echo` bénin portant `lsadump::dcsync`
   dans sa ligne de commande suffit) — **à faire via WinRM, en attente**.

2. **Idempotence `disable_user`** (axe 3, volet réémission) — `'émis'` n'est plus
   un statut figé dans `_deja_exec` : une remédiation partie mais jamais confirmée
   par un `ar-result` est retentée jusqu'à `MITIGATE_MAX_TENTATIVES` (3). Nouvelle
   colonne `mitigations.tentatives`. Corrige le blocage de `art-backdoor` (compte
   recréé sous un incident déjà ouvert, figé sur un `'émis'` hérité de #2). Le
   volet « déclencher sur 4728/60159 » reste à faire.

3. **Rafale d'AR tronquée** (nouvel axe, cause du mimikatz non quarantiné) —
   sérialisation des envois dans `_wazuh_ar` (`MITIGATE_AR_GAP_SECONDS`, 1,5 s) :
   une rafale de commandes rapprochées saturait `wazuh-execd`, qui en dropait une
   partie avant le script.

Restent ouverts : axe 2 (rafraîchir le case DC), axe 3 volet déterministe sur
groupe admin, axe 4 (chemin quarantaine mimikatz), axe 5 (faux IOC case 90).

---

## TA0001 — Initial Access

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1078 | Valid Accounts | winsrv/win10 | — | ⬜ | | | |
| T1190 | Exploit Public-Facing App | debian | — | ⬜ | | | |
| T1566 | Phishing | win10 | — | ⬜ | | | |

## TA0002 — Execution

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1059.001 | PowerShell | win10/winsrv | — | ⬜ | | | |
| T1059.003 | Windows Command Shell | win10 | — | ⬜ | | | |
| T1059.004 | Bash | debian | — | ⬜ | | | |
| T1053.005 | Scheduled Task | win10 | — | ⬜ | | | |
| T1053.003 | Cron | debian | — | ⬜ | | | |
| T1204.002 | Malicious File | win10 | — | ⬜ | | | |
| T1047 | WMI | winsrv | — | ⬜ | | | |

## TA0003 — Persistence

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1136.001 | Create Local Account | debian/win10 | — | ⬜ | | | |
| T1136.002 | Create Domain Account | winsrv | — | ⬜ | | | |
| T1098 | Account Manipulation | winsrv | — | ⬜ | | | |
| T1547.001 | Registry Run Keys | win10 | — | ⬜ | | | |
| T1543.003 | Windows Service | win10 | — | ⬜ | | | |
| T1053.005 | Scheduled Task (persist) | win10 | — | ⬜ | | | |
| T1505.003 | Web Shell | debian | — | ⬜ | | | |
| T1546.003 | WMI Event Subscription | winsrv | — | ⬜ | | | |
| T1098.007 | Additional Local/Domain Groups | winsrv | — | ⬜ | | | |

## TA0004 — Privilege Escalation

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1548.003 | Sudo / Sudo Caching | debian | — | ⬜ | | | |
| T1068 | Exploit for Priv Esc | debian | — | ⬜ | | | |
| T1134 | Access Token Manipulation | win10 | — | ⬜ | | | |
| T1055 | Process Injection | win10 | — | ⬜ | | | |
| T1484.001 | GPO Modification | winsrv | — | ⬜ | | | |

## TA0005 — Defense Evasion

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1070.004 | File Deletion | debian | — | ⬜ | | | |
| T1070.002 | Clear Linux/Mac Logs | debian | — | ⬜ | | | |
| T1070.001 | Clear Windows Event Logs | win10 | — | ⬜ | | | |
| T1562.001 | Disable/Modify Tools | debian/win10 | — | ⬜ | | | |
| T1562.004 | Disable/Modify Firewall | win10 | — | ⬜ | | | |
| T1027 | Obfuscated Files | win10 | — | ⬜ | | | |
| T1112 | Modify Registry | win10 | — | ⬜ | | | |
| T1218.011 | Rundll32 | win10 | — | ⬜ | | | |
| T1036 | Masquerading | debian/win10 | — | ⬜ | | | |

## TA0006 — Credential Access

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1003.001 | LSASS Memory | win10/winsrv | — | ⬜ | | | |
| T1003.002 | Security Account Manager | win10 | — | ⬜ | | | |
| T1003.003 | NTDS (ntds.dit) | winsrv | — | ⬜ | | | |
| T1003.008 | /etc/passwd & /etc/shadow | debian | — | ⬜ | | | |
| T1558.003 | Kerberoasting | winsrv | — | ⬜ | | | |
| T1558.001 | Golden Ticket | winsrv | — | ⬜ | | | |
| T1110 | Brute Force | winsrv/debian | — | ⬜ | | | |
| T1552.001 | Credentials in Files | debian | — | ⬜ | | | |
| T1555 | Credentials from Stores | win10 | — | ⬜ | | | |

## TA0007 — Discovery

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1087.001 | Local Account Discovery | debian/win10 | — | ⬜ | | | |
| T1087.002 | Domain Account Discovery | winsrv | — | ⬜ | | | |
| T1482 | Domain Trust Discovery | winsrv | — | ⬜ | | | |
| T1018 | Remote System Discovery | win10 | — | ⬜ | | | |
| T1046 | Network Service Scanning | debian | — | ⬜ | | | |
| T1069.002 | Domain Groups | winsrv | — | ⬜ | | | |
| T1016 | System Network Config | debian/win10 | — | ⬜ | | | |
| T1057 | Process Discovery | debian/win10 | — | ⬜ | | | |

## TA0008 — Lateral Movement

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1021.001 | RDP | win10 | — | ⬜ | | | |
| T1021.002 | SMB / Admin Shares | win10/winsrv | — | ⬜ | | | |
| T1021.006 | WinRM | winsrv | — | ⬜ | | | |
| T1021.004 | SSH | debian | — | ⬜ | | | |
| T1550.002 | Pass the Hash | win10 | — | ⬜ | | | |
| T1550.003 | Pass the Ticket | winsrv | — | ⬜ | | | |

## TA0009 — Collection

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1560.001 | Archive via Utility | debian | — | ⬜ | | | |
| T1005 | Data from Local System | debian/win10 | — | ⬜ | | | |
| T1119 | Automated Collection | win10 | — | ⬜ | | | |

## TA0011 — Command and Control

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1071.001 | Web Protocols | debian | — | ⬜ | | | |
| T1105 | Ingress Tool Transfer | debian/win10 | — | ⬜ | | | |
| T1571 | Non-Standard Port | debian | — | ⬜ | | | |
| T1572 | Protocol Tunneling | debian | — | ⬜ | | | |
| T1219 | Remote Access Software | win10 | — | ⬜ | | | |

## TA0010 — Exfiltration

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1048 | Exfil over Alt Protocol | debian | — | ⬜ | | | |
| T1041 | Exfil over C2 Channel | debian | — | ⬜ | | | |

## TA0040 — Impact

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1486 | Data Encrypted for Impact | debian/win10 | — | ⬜ | | | |
| T1490 | Inhibit System Recovery | win10 | — | ⬜ | | | |
| T1489 | Service Stop | debian/win10 | — | ⬜ | | | |
| T1529 | System Shutdown/Reboot | debian/win10 | — | ⬜ | | | |

---

## Récap couverture

| Statut | Compte |
|--------|--------|
| ✅ Détecté | 0 |
| 🟡 Partiel | 0 |
| ❌ Angle mort | 0 |
| ⬜ Non testé | tous |

_Mis à jour au fil des tests. Chaque ligne validée → mettre le GUID Atomic, l'ID de
règle Wazuh qui a tiré, et le case IRIS._
