# Purple Team — Couverture MITRE ATT&CK / Atomic Red Team

Suivi de la couverture de détection Aura-SOC (Wazuh + soc-agent) contre les tests
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

### Campagne #4 (2026-08-02, 19:52 UTC) — premier vrai test du fix décodeur

Mêmes 10 techniques rejouées sur winsrv (014) + win10 (015), Defender déjà
désactivé (service Defender arrêté sur le DC, RTP off sur win10), **10/10
exécutées avec preuve d'effet** : shadow copy `{de80768b…}` créée, LSASS dumpé
160 Mo (DC) / 60 Mo (win10) sur disque, DCSync a sorti le hash krbtgt
(`c07ddde68e603a57ba200ac1f68b4203` + clés aes256), Golden ticket
`goldenticketfakeuser` généré et soumis (`/ptt`), compte `T1136.002_Admin` créé
`Enabled=True` + ajouté à « Admins du domaine » (RID-512, confirmé), dsquery
trustedDomain + net user /domain exécutés, WinRM invoke-command tenté. Numéros
Atomic identiques à #3. État remis à zéro avant la campagne : cases neufs à
partir de **#97**.

**Notes réévaluées sur preuves : Détection 44/100 · Analyse IRIS 30/100 ·
Remédiation 10/100.**

**RÉSULTAT CLÉ — le fix décodeur (9c66c55) est NÉCESSAIRE mais INSUFFISANT.**
Les 8 règles AD custom (100910/100915/100918/100921/100924/100925/100926/100928)
portent bien `<decoded_as>windows_eventchannel</decoded_as>` (déployé,
manager redémarré 12:44 ; `Total rules enabled: 136040`, aucune erreur de
chargement), et les événements réels de la campagne sont bien décodés
`windows_eventchannel` **avec** la ligne de commande dans
`data.win.eventdata.commandLine` (ex. `mimikatz.exe "lsadump::dcsync
/domain:lab.local /user:krbtgt@lab.local"`, regex 100924 satisfaite). Pourtant :
scan de `alerts.json` sur 34 événements de campagne qui matchent → **0 tir** des
8 règles (comme #2 et #3). **Cause racine nouvelle et prouvée** : la racine de
l'arbre eventchannel est la règle native **60000** (`<decoded_as>windows_eventchannel</decoded_as>` + `<category>ossec</category>`), et **toutes** les règles
natives qui tirent sur ces événements s'y accrochent par `<if_sid>`/`<if_group>`
(67027→`if_sid 60103`, 92052→`if_group sysmon_event1`, 60009→`if_sid 60000`).
Les 8 règles custom n'ont **qu'un `<decoded_as>` nu, sans `if_sid`/`if_group`** :
un second `decoded_as` frère de 60000 n'est jamais évalué sur les événements
eventchannel. Le fix de #3 a corrigé le nom du décodeur mais laissé les règles
détachées de l'arbre.

| # | Technique | Exéc. | Détection #4 (règle, niveau) | Statut | Remédiation (état réel) |
|---|-----------|:-----:|------------------------------|:------:|-------------------------|
| 1 | T1558.003 Kerberoasting | ✅ | L4 scriptblock PS générique — 100910/100925 muettes | ❌ | — |
| 2 | T1003.003 NTDS vssadmin | ✅ | 67027/92032 L3, 92052 L4, 60702 L5 — **100921 muette** | ❌ | shadow non ciblée, aucune AR |
| 3 | T1003.001 LSASS | ✅ | 92213 L15 (dépôt exe) + génériques — **92900 muette cette fois (aucun Sysmon EID10), 100918 muette** | 🟡 | ❌ procdump non quarantiné (0 AR) |
| 4 | T1136.002 Create Domain Account | ✅ | 92040 L12 a **tiré** mais l'alerte est **VT-supprimée** → jamais corrélée | ❌ | ❌ `disable_user` jamais proposé — compte resté Enabled + Domain Admin |
| 5 | T1098.007 Add Domain Admins | ✅ | **60159 L12** « Domain Admins Group Changed » (incident 2180 isolé) | 🟡 | ❌ 2180 trié needs_investigation→escalate_human, pas de disable |
| 6 | T1003.006 DCSync | ✅ | 67027/92032 L3 + 92213 L15 (exe) — **100924/100915 muettes, aucun 4662** | 🟡 | mimikatz non retiré |
| 7 | T1558.001 Golden Ticket | ✅ | 67027/92032 L3 + 92213 L15 — **100924 muette** | 🟡 | krbtgt double-reset non signalé |
| 8 | T1482 Trust Discovery | ✅ | 92031/92033 L3, 92103 L6 — **100928 muette** | 🟡 | — |
| 9 | T1087.002 Account Discovery | ✅ | 92039 L3 générique | 🟡 | — |
| 10 | T1021.006 WinRM Lateral | ✅ | **91822 L12 / 91823 L14** | ✅ | — |

**Détection (44/100).** Télémétrie présente pour les 10 ; incidents L15/L14
créés et triés TP sur les deux hôtes → le SOC « voit » la compromission en HIGH.
Mais la couche technique-spécifique AD reste **0/8 règles custom**, et les trois
techniques credential-access les plus graves (DCSync, Golden, Kerberoasting) ne
produisent aucune alerte nommant la technique — seulement un « exe déposé »
générique (92213). Deux régressions vs #3 : **92900/Sysmon EID10 muet** (aucun
`ProcessAccess` LSASS cette campagne) et **92040 VT-supprimée**.

**Analyse IRIS (30/100).** Deux cases neufs, TP, rapports structurés
(résumé ≠ analyse — défaut #3 corrigé), honnêtes sur les limites et sur le
statut de remédiation (« 📤 émise, effet non confirmé »), **aucun faux IOC**.
MAIS : **MITRE réduit à T1059.001** sur les deux (au lieu de l'union d'une
dizaine de techniques), rapport **aveugle au credential access** (ni krbtgt, ni
golden ticket, ni Domain Admin créé sur le case DC #97). Cause : le heuristique
de disponibilité télémétrie déclare à tort « exécution de processus
(auditd)=ABSENT » sur les hôtes Windows (il ne connaît qu'auditd/Linux, pas
Sysmon/4688) → le LLM se croit privé des lignes de commande et n'analyse pas les
cmdlines mimikatz pourtant présentes. IOC quasi nuls : #97 = 1 (golden.bat,
fichier transitoire), #98 = 0 ; mimikatz.exe (SHA256 dans les events),
procdump.exe, hash krbtgt, compte `T1136.002_Admin` **tous absents**. **Pas de
fusion campagne** : deux cases séparés (#97 DC, #98 win10), le lien inter-hôte
cite `powershell.exe` de System32 (binaire légitime, mauvais marqueur).

**Remédiation (10/100).** **1 seule action émise** sur toute la campagne :
quarantaine `golden.bat` (case #97, statut `émis`, **0 ar-result**, et le fichier
avait déjà été auto-supprimé par l'atomic → **aucun effet**). win10 (#98) :
2 actions décidées au triage (kill + quarantaine) mais « pas de cible
exploitable » → rien émis. **`disable_user` jamais proposé** : l'alerte pivot
92040 (création `T1136.002_Admin`, L12) est **VT-supprimée** (voir plus bas),
et 60159 (Domain Admins) arrive seule dans l'incident 2180 sans contexte, trié
`needs_investigation→escalate_human`. État hôte post-cycle (vérifié) : compte
**Enabled=True + toujours Domain Admin**, mimikatz.exe/procdump.exe/lsass_dump.dmp
**tous encore sur disque**. **0 `ar-result status=applied` sur la campagne** —
strictement rien de remédié (pire que #3, qui confirmait 6 quarantaines
procdump). Points non nuls : verdict/ouverture de case corrects, statuts
honnêtes (aucun faux « ✅ exécuté »), aucun mauvais ciblage de binaire System32.

**Trou de correspondance — le backlog empoisonne le cycle.** Les 148 incidents
backlog (re-corrélés) saturent la phase triage (~1,5 triage/min → ~90 min avant
que la création de cases, dernière étape du cycle, démarre) ; et un incident
backlog périmé (#1488, purgé) a **avorté toute la transaction de création de
cases** au cycle 19:50 (`FK anonymization_map` → « création de cases IRIS
sautée »). Les cases #97/#98 ont donc été obtenus en ciblant le même code du
pipeline (`iris --incident 2176/2177`), les autres incidents de campagne
(2178 WinRM, 2179, 2180) restant sans case au moment du rapport.

**Cause racine du `disable_user` manquant (nouvelle, prouvée) :** l'alerte 92040
(L12, « net1.exe executed a user creation command », cmdline nommant
`T1136.002_Admin`) est **VT-supprimée** —
`suppress_reason = vt_legit_exe: 0/75 moteurs positifs`. Le filtre VT a haché
`net1.exe` (LOLBin Microsoft signé, propre) et supprimé l'alerte, alors que
92040 est une détection **comportementale** (la malveillance est dans l'action,
pas le binaire). L'exemption « LOLBin propre de System32 reste analysé » n'a pas
matché parce que l'entité arrive avec backslashes doublés
(`C:\\Windows\\System32\\net1.exe`) et l'exemption teste `C:\Windows\System32` —
même famille de bug backslash que #2. Résultat : le signal le plus clair
(« un compte de domaine vient d'être créé ») est silencieusement jeté.

**Axes de correction #4 (par valeur/effort) :**
1. **[fort/faible]** Ré-ancrer les 8 règles AD dans l'arbre eventchannel :
   remplacer le `<decoded_as>` nu par `<if_sid>60103</if_sid>` (canal Security
   4688) **et** un frère `<if_group>sysmon_event1</if_group>` (Sysmon EID1),
   ou `<if_sid>60000</if_sid>`. C'est LE correctif qui ressuscite toute la
   couche spécifique — le `decoded_as` seul ne suffit pas, prouvé par #4.
2. **[fort/faible]** VT filter : ne jamais supprimer une alerte dont le binaire
   est un LOLBin de System32, et normaliser les backslashes doublés avant le
   test de répertoire système. Corrige la suppression de 92040 → rend possible
   le `disable_user`.
3. **[fort/moyen]** Rapport LLM : reconnaître Sysmon EID1/4688 comme télémétrie
   d'« exécution de processus » sur les hôtes Windows (le heuristique est câblé
   sur auditd) — sinon tout rapport Windows reste aveugle aux lignes de commande
   et le MITRE s'effondre sur T1059.001.
4. **[fort/moyen]** `disable_user` déterministe sur 60159/4728 (ajout groupe
   admin) même sans re-triage LLM ; et corréler 92040 (création) avec 60159 dans
   un même incident (marqueur = nom de compte).
5. **[moyen/moyen]** IOC : extraire `image`/hash Sysmon des alertes 92213/92032
   (mimikatz.exe, procdump.exe, leur SHA256) et les promouvoir en IOC + marqueur
   de fusion campagne, au lieu de `powershell.exe`.
6. **[moyen/faible]** Robustesse cycle : ignorer (au lieu d'avorter la
   transaction) un incident dont la ligne a disparu ; borner/prioriser le triage
   pour que le backlog ne retarde pas la création de cases des incidents récents.
7. **[moyen/faible]** Ciblage remédiation : préférer les artefacts persistants
   (mimikatz.exe, procdump.exe, lsass_dump.dmp) aux fichiers transitoires
   (golden.bat, auto-supprimé) ; croiser cible vs chemins réels de l'alerte.

**Nettoyage confirmé :** `T1136.002_Admin` supprimé de l'AD (retire aussi de
Domain Admins), shadow copy supprimée (`vssadmin delete` + Atomic `-Cleanup`
T1003.003), `lsass_dump.dmp` supprimé sur les deux hôtes (+ `-Cleanup`
T1003.001), tickets Kerberos purgés (`klist purge`), `golden.bat` déjà
auto-supprimé. Binaires prereq Atomic (mimikatz/procdump dans `ExternalPayloads`)
laissés en place comme en #3.

### Correctifs livrés post-#4 (2026-08-02, commits `daf3b56` + `9117bca`)

Les axes 1 à 5 traités, **déployés sur le prod ET vérifiés**, pas seulement
proposés.

1. **Règles AD ré-ancrées dans l'arbre eventchannel** (axe 1) — le
   `<decoded_as>windows_eventchannel</decoded_as>` nu ne fait jamais tirer une
   règle : Wazuh n'émet qu'une règle par événement, la plus **profonde**, et un
   `decoded_as` frère de la racine 60000 perd toujours face aux sous-arbres
   natifs (`if_sid 60103`, `if_group sysmon_event1`). `if_sid 60000` ne suffit
   pas non plus (trop haut). Chaque règle ré-ancrée à la profondeur de la
   gagnante native (elle charge après → gagne) : 100921/100924/100925/100926/
   100928 → `if_group sysmon_event1` ; 100918 → `if_group sysmon_event_10` ;
   100910/100915 → `if_sid 60103`. **Vérifié en réel** (echo bénins poussés via
   WinRM sur le DC, pipeline complet) : **100921, 100924 (×2), 100928 tirent**
   enfin dans `alerts.json`. Manager redéployé + redémarré.

2. **VT ne supprime plus une détection comportementale sur LOLBin propre**
   (cause du `disable_user` manquant) — `vt._hors_systeme` faisait un
   `replace("\", "\")` **no-op** ; le chemin eventchannel à backslashes doublés
   (`C:\\Windows\\System32\\net1.exe`) ne matchait jamais le préfixe système, si
   bien que `net1.exe` (LOLBin propre de System32) était traité comme un payload
   déposé et l'alerte 92040 (création de Domain Admin, L12) supprimée. Backslashes
   doublés repliés avant le test. **Vérifié** : `net1.exe` de System32 redevient
   « dans système / protégé ». 92040 survivra → corrélée → alimente le triage et
   la cible du `disable_user`.

3. **Rapport LLM : « exécution de processus » n'est plus câblée sur le seul
   auditd** (axe analyse) — `iris._CAPTEURS` reconnaît maintenant Sysmon EID1 et
   PowerShell comme télémétrie d'exécution de processus. Sur les hôtes Windows le
   rapport ne se déclarera plus aveugle aux lignes de commande — c'est ce qui
   effondrait le MITRE sur T1059.001 et masquait DCSync/Golden/création de
   Domain Admin.

4. **Fusion de campagne : plus de marqueur générique** — `powershell.exe`/`cmd.exe`
   et consorts ne peuvent plus lier deux hôtes (nouveau `correlate.entite_generique`,
   comparaison sur le nom de fichier, branché aux 4 points d'usage). Un vrai
   marqueur d'attaquant (mimikatz.exe, compte créé, IP C2) reste discriminant.

5. **IOC et ciblage de remédiation, corrigés en cascade par l'axe 1** — les
   règles 100924 (L13) / 100926 (L10) tirant enfin sur les événements
   `image=mimikatz.exe`, ceux-ci entrent dans le case : `iris._iocs` extrait
   `mimikatz.exe` (le code d'extraction existait déjà mais ne voyait que du L3
   sous le seuil), et `mitigate` dispose du vrai chemin à quarantiner.

Déploiement : 6 règles copiées sur le manager prod + redémarrage ; image
`soc-agent:latest` reconstruite, conteneurs recréés ; fixes confirmés à
l'import. **Restent en durcissement** : `disable_user` **déterministe** sur
60159/4728 (aujourd'hui encore dépendant du verdict LLM) ; robustesse du cycle
(un incident backlog périmé avorte toute la transaction de création de cases —
`FK anonymization_map`) ; ciblage des artefacts persistants plutôt que des
fichiers transitoires (golden.bat).

---

### Campagne #5 (2026-08-02, 20:46 UTC) — validation des correctifs #4

Cases IRIS purgés, incidents #4 supprimés, mêmes 10 techniques rejouées sur
winsrv (014) + win10 (015), **10/10 exécutées avec preuve** (compte
`T1136.002_Admin` créé + Domain Admin, shadow copy, LSASS 160/60 Mo, krbtgt
dumpé, Golden ticket soumis). Pipeline piloté à la main (cycle stoppé pour
éviter la saturation par le backlog), même code que le cycle.

**Notes : Détection 78/100 · Analyse IRIS 72/100 · Remédiation 28/100**
(contre 44 / 30 / 10 en #4). Les correctifs tiennent sur une campagne réelle.

| # | Technique | Détection #5 (règle, niveau) | Δ vs #4 |
|---|-----------|------------------------------|:-------:|
| 1 | T1558.003 Kerberoasting | L4 scriptblock — 100910/100925 ne matchent pas l'atomic PowerShell (pas de 4769 RC4 ni outil nommé) | = |
| 2 | T1003.003 NTDS vssadmin | **100921 L12** tire (+ génériques) | ✅ |
| 3 | T1003.001 LSASS | **100918 L12** (Sysmon EID10) tire — dans le case | ✅ |
| 4 | T1136.002 Create Domain Account | **92040 L12 non supprimée**, corrélée | ✅ |
| 5 | T1098.007 Add Domain Admins | 60159 L12 | = |
| 6 | T1003.006 DCSync | **100915 L12 + 100924 L13** tirent | ✅✅ |
| 7 | T1558.001 Golden Ticket | **100924 L13** (kerberos::golden) | ✅ |
| 8 | T1482 Trust Discovery | **100928 L8** tire | ✅ |
| 9 | T1087.002 Account Discovery | 92039 L3 générique | = |
| 10 | T1021.006 WinRM Lateral | 91823 L14 / 91822 L12 | = |

**Détection (78).** **6 des 8 règles AD custom tirent enfin** sur la vraie
télémétrie et **entrent dans le case** : 100915 (DCSync), 100918 (LSASS),
100921 (NTDS), 100924 (syntaxe mimikatz, L13), 100926 (outil nommé), 100928
(trust). DCSync a désormais une détection **spécifique** (100915 4662 + 100924).
92040 (création de compte) survit au filtre VT et est corrélée. Restent hors
couverture : Kerberoasting (l'atomic PowerShell ne déclenche ni 4769 RC4 ni
100925 — écart atomic/règle, pas un bug) et l'account discovery (générique).

**Analyse (72).** Rapport du case fusionné **#111** (les deux hôtes réunis —
fusion campagne **réussie**, marqueur = `mimikatz.exe` et non plus
`powershell.exe`). Chaîne credential-access **reconstituée avec justesse** :
procdump→lsass (100918), mimikatz (100924), DCSync avec droits de réplication
(100915), création de compte (92040), Invoke-Command latéral (91823). Ligne de
télémétrie corrigée (« exécution de processus (auditd / Sysmon EID1 / 4688)=
présent »). **6 IOC** dont `mimikatz.exe` (2 chemins) et le compte
`T1136.002_Admin`. Section « à faire à la main » avec le **double reset krbtgt**
(DCSync). Défauts résiduels : l'en-tête « technique » reste mono-valeur
(T1003.006) alors que le corps couvre l'union ; le **nom** de case n'a pas été
généré (`finish_reason=length`, budget du nom à 1500 tokens trop court).

**Remédiation (28).** La **proposition** est enfin juste (cascade des fixes) :
`disable_user` ciblant `T1136.002_Admin`, quarantaine des **vrais chemins**
mimikatz.exe/procdump, kills par PID — 13 actions, toutes en tâches IRIS. Mais
l'**effet ne se pose toujours pas** (0 `ar-result applied` utile ; compte resté
Enabled, mimikatz resté sur disque), pour **deux causes nouvelles isolées** :
- **Rafale d'AR tronquée par execd.** Sur 13 actions émises (gap 1,5 s), 9
  seulement remontent un `ar-result` (kills « not running » car process déjà
  terminés ; quarantaines de fichiers transitoires « file not found »). Les **4
  actions à effet réel** (quarantaine mimikatz ×2, quarantaine procdump,
  `disable_user`) n'ont **aucune ligne** dans `active-responses.log` — droppées.
  Le mécanisme marche pourtant (quarantaine d'un Sysmon.exe de Temp = `applied`
  observée hors rafale). La sérialisation 1,5 s ne suffit pas.
- **Garde-fou anti-lockout qui refuse le compte attaquant.** Testé isolément,
  `ad-disable-account` **s'exécute mais REFUSE** : `account is member of
  protected group 'Admins du domaine' - refused`. Or le compte est Domain Admin
  précisément parce que l'attaquant l'y a ajouté (T1098.007) — le garde-fou
  censé protéger les admins légitimes bloque la remédiation du compte malveillant.

**Axes de correction #5 (par valeur/effort) :**
1. **[fort/moyen]** Fiabiliser l'émission des AR : attendre le compte rendu de
   chaque AR avant d'envoyer la suivante (ou augmenter nettement le gap /
   dédupliquer), pour que les actions à effet réel de fin de rafale ne soient
   plus droppées par `wazuh-execd`.
2. **[fort/faible]** `ad-disable-account` : distinguer un compte **système/admin
   légitime** (RID 500, comptes préexistants) d'un compte **créé par l'attaquant
   puis promu** (vu en 4720/92040 dans la fenêtre). Le garde-fou protégé ne doit
   pas couvrir ce dernier ; sinon tout compte escaladé en Domain Admin devient
   ineffaçable automatiquement.
3. **[moyen/faible]** Budget du **nom** de case (générateur court) à relever
   comme le rapport (le corps, lui, passe à 14000).
4. **[moyen/faible]** En-tête MITRE du rapport : porter l'**union** des
   techniques, pas la seule graine du triage.
5. **[faible/faible]** Dérivation de chemin procdump (`procdump64.exe` inexistant
   ciblé) — mineur, la vraie détection LSASS passe par 100918.

**Nettoyage confirmé :** compte `T1136.002_Admin` supprimé, shadow copy + dumps
supprimés (Atomic `-Cleanup`), tickets purgés, cycle soc-agent redémarré.

---

### Campagne #6 (2026-08-06, 18:41 UTC) — 6 techniques hors-AD, 2 hôtes (winsrv + debian .15)

Première campagne qui sort du bloc AD credential-access : 3 techniques Windows de
**persistance / évasion** sur winsrv (DC, agent 014) + 3 techniques Linux sur
**debian** (agent 011, `192.168.30.15`). Cible Linux initiale `debian2`
(`192.168.30.46`) écartée en cours de route : **isolée du réseau par la
remédiation** (règle iptables `-A INPUT -s 192.168.30.5/32 -j DROP` posée par
`firewall-drop.sh` — bloquait le relais SSH), et Atomic non installé. Basculé sur
`.15` (Atomic + pwsh déjà en place). Defender déjà désactivé sur le DC (RTP off).

**Techniques (6/6 exécutées avec preuve) :**

| # | Hôte | Technique | Atomic | Preuve d'exécution |
|---|------|-----------|--------|--------------------|
| 1 | winsrv 014 | T1053.005 Scheduled Task | tous sous-tests | tâches `atomic red team` / `CompMgmtBypass` / `EventViewerBypass` / `spawn` / `T1053_005_OnLogon` = Ready |
| 2 | winsrv 014 | T1547.001 Registry Run Keys | tous sous-tests | clé Run HKLM `calc=calc.exe`, BootExecute, RunOnceEx, secedit |
| 3 | winsrv 014 | T1070.001 Clear Windows Event Logs | **manuel** (`.yaml` absent des atomics locaux) | `wevtutil cl "Windows PowerShell"` → System EID104 @18:42 |
| 4 | debian 011 | T1053.003 Cron | -1..-4 | `persistevil` dans cron.d + cron.hourly + spool, crontab root modifié |
| 5 | debian 011 | T1136.001 Create Local Account | -1 | `evil_user` (uid999) créé |
| 6 | debian 011 | T1003.008 /etc/passwd & /etc/shadow | -2/-3/-5 | passwd + shadow lus |

**Notes réévaluées sur preuves : Détection 35/100 · Analyse IRIS 45/100 ·
Remédiation 25/100.** Un seul incident (#2529 winsrv, 257 alertes, L15) → un seul
case (**#188**). debian n'a produit **aucun incident**.

| # | Technique | Exéc. | Détection #6 (règle, niveau) | Statut | Remédiation (état réel) |
|---|-----------|:-----:|------------------------------|:------:|-------------------------|
| 1 | T1053.005 Scheduled Task | ✅ | 92201 L9 (nouvelle tâche PS) + 92203 L6 — pas de règle HIGH, **T1053 même absent du mapping MITRE du rapport** | 🟡 | ❌ tâches toujours `Ready` — aucune action sur la persistance |
| 2 | T1547.001 Run Keys | ✅ | **92041 L10** (base64 en valeur de registre) + 92302 L6 (run au prochain logon) — meilleure des trois, T1547.001 mappée | 🟡 | ❌ clé Run `calc` intacte ; seul le binaire `calc.exe` (copie Temp) quarantiné |
| 3 | T1070.001 Clear Logs | ✅ | **63104 L5** (log effacé) — tiré mais bas | 🟡 | — |
| 4 | T1053.003 Cron (Linux) | ✅ | **550 L7** (FIM sur un fichier cron) uniquement | ❌ | ❌ cron `persistevil` ×3 toujours en place, aucun case |
| 5 | T1136.001 Create Account (Linux) | ✅ | **rien** — aucune règle ≥ L8, 0 alerte ingérée | ❌ | ❌ `evil_user` toujours actif |
| 6 | T1003.008 passwd/shadow (Linux) | ✅ | **rien** | ❌ | — |

**Détection (35).** winsrv est bien vu comme un **incident critique** (L15) et trié
TP avec case — mais le niveau HIGH est porté par la règle **générique** 92213
« exe déposé dans un dossier typique de malware » (les outils Atomic PsTools /
GhostTask), pas par une règle nommant la technique. Les 3 techniques choisies ne
déclenchent que du medium/bas (L10 / L9 / L5). **debian = aveugle total** :
`ausearch -m execve` sur .15 rend **0** événement → création de compte et accès
`/etc/shadow` invisibles, cron capté uniquement par FIM (550 L7, sous le seuil de
corrélation L12) → **aucun incident, aucun case**. Cause côté endpoint (règles
auditd non chargées / journald tient netlink, cf. `wazuh-auditd-sensor-traps`),
**pas** un problème de pipeline : `INDEXER_ALERT_INDICES` couvre bien
`wazuh-linux-*` et `wazuh-windows-*` (l'ancien blind-spot de routage d'indices est
**résolu**).

**Analyse IRIS (45).** Case #188 (winsrv) = **bon rapport** : résumé ≠ analyse,
**17 techniques MITRE en union** (T1547.001, T1112, T1070, T1027, T1105, T1059…),
**68 lignes de commande reconstituées** (les vraies `schtasks /create`, `reg add`,
`wevtutil`…), **33 IOC honnêtes** (aucun faux IOC, aucun verdict VT bidon), tableau
de remédiation franc (« 📤 émise, effet non confirmé »), section couverture/limites.
Défauts : **titre inventé** « [EXECUTIVE MALICE] … C2 détecté » alors qu'aucun C2
n'a eu lieu ; **T1053 (tâche planifiée) absent** du mapping bien que jouée ; IOC
uniquement des noms de fichiers (ni tâche planifiée, ni clé Run, ni payload
base64 promus en IOC). Surtout : **debian n'a aucun case** → la moitié de la
campagne n'est pas investiguée.

**Remédiation (25).** winsrv : la quarantaine **agit pour de vrai** — vérifié sur
disque, `PsExec.exe`, `GhostTask.exe`, `batstartup.bat`/`vbsstartup.vbs` (dossier
Démarrage) et la copie Temp `calc.exe` **supprimés** (30 tâches IRIS `Done`,
`mitigations.statut=confirmé`). Kills tous `sans_effet` (process non résidents —
no-op correct). Cibles justes, **aucun System32**, statut honnête. **Mais la
persistance survit intégralement** : les 5 tâches planifiées sont toujours `Ready`
et la clé Run `calc` toujours posée — on retire le binaire déposé, pas le mécanisme
qui le relance. debian : **remédiation nulle** (pas de case) — `evil_user` et le
cron `persistevil` toujours vivants.

**Trouvaille terrain (hors campagne) :** compte `butter` (uid 1002, **gid 0**,
home `/root`, shell bash) présent dans `/etc/passwd` de debian .15 — backdoor
**préexistant**, sans rapport avec cette campagne. À investiguer/nettoyer à la main.

**Axes de correction #6 (par valeur/effort) :**
1. **[fort/moyen]** Capteur auditd sur debian .15 (et audit de la flotte Linux) :
   0 execve = angle mort total sur exécution, création de compte, accès secrets.
   Rejouer `deploy-auditd-sensor.sh` + **reboot** (journald tient le netlink).
2. **[fort/moyen]** Remédiation Windows de la **persistance**, pas seulement du
   payload : ajouter `delete_scheduled_task` (sur 92201/92226) et
   `delete_run_key` / suppression de valeur de registre (sur 92041/92302). Aujourd'hui
   on quarantine l'exe et on laisse l'autorun.
3. **[moyen/faible]** Règles HIGH dédiées : T1053.005 (création de tâche planifiée
   par processus anormal) et T1070.001 (log effacé, 63104 monté de L5 → L12) — les
   deux ne sortent pas du bruit.
4. **[moyen/faible]** IOC : promouvoir les noms de tâches planifiées, chemins de
   clés Run et payloads base64 en IOC, pas seulement les binaires déposés.
5. **[faible/faible]** Rapport : ne pas fabriquer « C2 détecté » dans le titre sans
   alerte réseau ; inclure T1053 dans le mapping quand `schtasks` est vu.

**Nettoyage : NON encore fait** (persistance laissée en place pour inspection) —
voir la section proposée à l'utilisateur en fin de campagne.

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
| T1053.005 | Scheduled Task | winsrv | #6 tous sous-tests | 🟡 | 92201 L9 / 92203 L6 | 188 | générique, pas de règle HIGH ; T1053 absent du mapping MITRE |
| T1053.003 | Cron | debian .15 | #6 -1..-4 | ❌ | 550 L7 (FIM) | — | auditd sans execve → sous-seuil, aucun incident/case |
| T1204.002 | Malicious File | win10 | — | ⬜ | | | |
| T1047 | WMI | winsrv | — | ⬜ | | | |

## TA0003 — Persistence

| ID | Technique | Hôte | Test | Détection | Règle | Case | Notes |
|----|-----------|------|------|-----------|-------|------|-------|
| T1136.001 | Create Local Account | debian .15 | #6 -1 | ❌ | — | — | `evil_user` créé, aucune alerte (auditd sans execve), non remédié |
| T1136.002 | Create Domain Account | winsrv | — | ⬜ | | | |
| T1098 | Account Manipulation | winsrv | — | ⬜ | | | |
| T1547.001 | Registry Run Keys | winsrv | #6 tous sous-tests | 🟡 | 92041 L10 / 92302 L6 | 188 | meilleure des 3 (base64 en valeur registre) ; clé Run non remédiée |
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
| T1070.001 | Clear Windows Event Logs | winsrv | #6 manuel (yaml absent) | 🟡 | 63104 L5 | 188 | tiré mais trop bas (L5) pour sortir du bruit |
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
| T1003.008 | /etc/passwd & /etc/shadow | debian .15 | #6 -2/-3/-5 | ❌ | — | — | aucune alerte (auditd sans execve) |
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
