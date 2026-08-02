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

**Correctifs livrés** (commit « Purple-team 2026-08-02 : remédiation qui vise
juste, et qui dit vrai ») : normalisation des chemins Windows, kill par PID avec
vérification d'image, `disable_user` restreint aux comptes créés, boucle de
compte rendu d'AR (`ar-result` → décodeur → règles 100930-100935 →
`reconcilier_resultats_ar`), règles 100924-100926 et 100928, SACL DCSync et
Sysmon EID 10 dans le script d'install, budget de rapport à 14000 tokens,
protection contre l'écrasement d'un rapport abouti, IOC des exécutables
Windows, et section « à faire à la main » (double reset de krbtgt).

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
