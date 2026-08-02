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

Colonnes : `Test` = GUID/numéro Atomic testé. `Règle` = ID règle Wazuh qui a tiré.
`Case` = numéro case IRIS généré (le cas échéant).

---

## Campagnes purple-team AD (10 techniques)

Deux campagnes Atomic Red Team sur winsrv (DC, 014) + win10 (015).
**#1 (2026-08-01)** : Defender bloquait les outils → 7/10 exécutées.
**#2 (2026-08-02)** : Defender désactivé → 10/10 exécutées. Notes globales : #1 ≈63/100, #2 ≈64/100.

| # | Technique | Exécutée | Détection générique | Détection spécifique | Remédiation |
|---|-----------|:--------:|:-------------------:|:--------------------:|-------------|
| 1 | T1558.003 Kerberoasting | #2 | 🟡 exe/PS | ❌ → **règle 100910** (4769 RC4) | — |
| 2 | T1003.003 NTDS (ntdsutil) | ✅ | 🟡 process | ❌ → **règle 100921** | quarantine (fix) |
| 3 | T1003.001 LSASS (comsvcs) | ✅ | 🟡 exe | ❌ → **règle 100918** (EID10) | kill (fix) |
| 4 | T1136.002 Create Domain Account | ✅ | ✅ 60109/92040 L12 | ✅ | disable_user (fix : extraction 4720) |
| 5 | T1098.007 Add Domain Admins | ✅ | ✅ 60110 L8 | 🟡 | remove-group (manuel) |
| 6 | T1550.002 Pass the Hash | #2 | 🟡 exe | ❌ | — |
| 7 | T1003.006 DCSync / T1558.001 Golden | #2 | 🟡 exe | ❌ → **règle 100915** (4662) | — |
| 8 | T1482 Domain Trust Discovery | ✅ | ✅ 92031/discovery | 🟡 | — |
| 9 | T1087.002 Domain Account Discovery | ✅ | ✅ 92039 net.exe | ✅ | — |
| 10 | T1021.006 WinRM Lateral | ✅ | ✅ 91822 L12 | ✅ | — |

**Constats & fixs (2026-08-02) :**
- **Détection** : télémétrie présente (4769/4662/EID10/cmdline) mais **règles AD absentes** → 4 règles ajoutées (100910 Kerberoasting, 100915 DCSync, 100918 LSASS, 100921 NTDS/SAM).
- **Remédiation** #1 : suspendue à tort (faux positif injection « User: »), cibles erronées (Administrateur). **Corrigé** (`sanitize.py`, `_compte_protege`).
- **Remédiation** #2 : pipeline s'exécute mais résolution de cibles **Linux-centrée** → 0 cible Windows. **Corrigé** : `_iocs` extrait le compte Windows créé (4720 / `net user /add`) → filet déterministe `disable_user` ; `_cibles_par_machine` résout process (kill) et fichier (quarantine) Windows depuis Sysmon.

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
