# Règles locales Aura-SOC — un fichier par règle

`wazuh_manager.conf` charge `<rule_dir>etc/rules</rule_dir>`, donc **tous** les
`*.xml` de ce répertoire, dans l'ordre **alphabétique**. Les fichiers étant
nommés `<id>-<slug>.xml` avec des identifiants de longueur fixe, l'ordre
alphabétique est l'ordre numérique des identifiants.

## Ce que l'ordre change, et ce qu'il ne change pas

**Une règle chaînée par `if_sid` doit porter un identifiant SUPÉRIEUR à celui de
sa parente.** Wazuh ne rattache l'enfant que si la parente est **déjà chargée**
au moment où il lit le fichier ; comme les fichiers sont lus dans l'ordre des
identifiants, un enfant numéroté avant sa parente n'est rattaché à rien. Il ne
lève aucune erreur au démarrage, `wazuh-logtest` ne le mentionne pas : il est
simplement absent.

Mesuré le 2026-08-01 : l'exclusion `100642` (`<if_sid>100653</if_sid>`) était
**morte depuis sa création** pour cette seule raison. Renumérotée en `100665`,
elle matche immédiatement, à contenu identique. Vérification faite sur tout le
ruleset, c'était le seul cas — à revérifier après toute création d'exclusion :

```sh
python3 - <<'EOF'
import glob, re
for f in sorted(glob.glob('*.xml')):
    for m in re.finditer(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', open(f).read(), re.S):
        for p in re.findall(r'<if_sid>(\d+)</if_sid>', m.group(2)):
            if int(p) >= 100000 and int(p) > int(m.group(1)):
                print(f'MORTE {m.group(1)} (if_sid {p}) dans {f}')
EOF
```

`if_group` et `if_matched_sid` ne sont pas concernés : ils ne référencent pas un
identifiant à résoudre au chargement.

Il change l'arbitrage entre règles **sœurs et indépendantes** qui pourraient
matcher le même événement : la première chargée gagne. Deux cas réels rencontrés
en construisant ce ruleset :

- `100653` (accès `/etc/shadow`) captait aussi les événements du watch auditd et
  masquait totalement `100643`. Résolu en cloisonnant par `audit.key`, pas par
  l'ordre — c'est la bonne façon de faire.
- `100800` (heartbeat) perdait face à la règle native `530`, qui capte toute
  sortie de `<localfile><command>`. Résolu par `<if_sid>530</if_sid>`.

**Règle de conduite** : deux règles qui peuvent matcher le même événement doivent
être rendues mutuellement exclusives par leurs conditions (`audit.key`, un champ
discriminant) ou explicitement chaînées. Ne jamais compter sur l'ordre des
fichiers. Après toute création ou renommage, rejouer
`scripts/test-detection-rules.sh` : il vérifie précisément quelle règle gagne.

## Domaines

Le commentaire d'en-tête de chaque `<group>` documentait un domaine entier ; il
n'avait pas de sens dupliqué dans chaque fichier. Il est repris ci-dessous.

### `soc_selfcheck,wazuh,`

Règles : 100800, 100801, 100802, 100805, 100806, 100803, 100804

```
Règles locales Aura-SOC -->

<!-- ==========================================================================
     Auto-surveillance du SOC (T1562.001 / T1562.006)

     Le trou le plus grave trouvé sur cette infra n'était pas une regex trop
     etroite : c'etait un capteur coupe. Le 2026-07-26, `auditctl -e 0` a laisse
     auditd `active`, l'agent connecte, /var/log/audit/audit.log en place - et le
     noyau muet. 19 des 24 regles locales de niveau >= 12 dependent de
     `if_group audit` : aveugles pendant 2 h, zero alerte.

     Une regle de correlation ne peut pas detecter une absence : elle ne raisonne
     que sur des evenements presents. La detection d'une coupure de capteur passe
     donc par un signal POSITIF periodique (heartbeat pousse par agent.conf,
     alias `audit-status`) sur lequel on alerte par la VALEUR.

     Ces regles sont volontairement en niveau >= 12 : sans capteur, le reste du
     ruleset est decoratif, et le pipeline soc-agent doit voir passer l'incident.
```

### `abuseipdb,threat_intel,`

Règles : 100621, 100622, 100623, 100624

### `threat_hunting,linux,`

Règles : 100625, 100629, 100626, 100630, 100632, 100631, 100633, 100634, 100636, 100635

### `threat_hunting,linux,mitre_gaps,`

Règles : 100650, 100651, 100652, 100653, 100665, 100666, 100643, 100644, 100649, 100654, 100645, 100646, 100647, 100648, 100655, 100656, 100657, 100658, 100660, 100661, 100662, 100663, 100664

```
Pack "gaps MITRE" - techniques Linux non couvertes par le ruleset
     Wazuh par defaut. 100% base sur l'audit execve en place (cle
     audit-wazuh-c, cf. 100625). Chaque regle validee end-to-end via
     wazuh-logtest sur le manager (events auditd reels + agreges).

     Rappel decodeur (cf. [[wazuh-auditd-exe-hex-encoding]] / regle 100629) :
     - audit.exe / audit.command / audit.execve.a0..a7 disponibles (argv
       plafonne a a7). Pour un match de sous-chaine dans l'argv, on utilise
       <regex> sur le full_log (robuste au plafond a7 et a l'agregation
       multiline), et <field name="audit.exe"> pour cibler le binaire.
```

### `ransomware,threat_hunting,linux,`

Règles : 100670, 100671, 100672, 100673, 100674, 100680, 100681, 100682

```
Detection ransomware (T1486 / T1490 / T1489)
     Strategie : deception (fichiers canaris) plutot que detection de masse.
     Un burst FIM sur /home genere des FP garantis (rsync, apt, git, CI) ;
     un canari n'est touche par AUCUN process legitime -> 1 evenement = 1 alerte.
     Le FIM ne pose des watches que sur les fichiers matchant `restrict`
     (voir agent.conf), donc cout inotify negligeable et volume d'events ~0.
```

### `authentication,ssh,threat_hunting,`

Règles : 100690, 100691

```
Brute force SSH REUSSI (T1110 -> T1078)

     Trou de detection du ruleset par defaut : il sait dire "on brute force"
     (5720, 5763) et "quelqu'un s'est connecte" (5715), mais jamais "celui qui
     brute forcait vient d'entrer". Or c'est le seul des trois qui est un
     incident : les deux autres sont du bruit de fond sur toute machine exposee.

     On correle sur les echecs bruts et non sur 5763/5712 (le brute force deja
     qualifie) : ces deux regles portent ignore="60", donc apres declenchement
     elles restent muettes 60s - exactement la fenetre pendant laquelle le succes
     a le plus de chances de tomber. Chainer dessus perdrait le cas nominal.

     Deux regles jumelles, une par sid d'echec, parce que les deux syntaxes plus
     compactes ont ete testees et ne fonctionnent PAS (verifie en logtest, le cas
     nominal cessait de declencher) :
       - <if_matched_group>authentication_failed</if_matched_group> : ne matche
         jamais, meme quand les echecs viennent bien de ce groupe.
       - <if_matched_sid>5710,5760</if_matched_sid> : la liste n'est pas parsee,
         if_matched_sid n'accepte qu'un seul sid.
     Il FAUT couvrir les deux sids : un brute force sur compte inexistant sort en
     5710 et non en 5760, or c'est le scenario le plus courant (l'attaquant essaie
     admin/root/test, puis tombe sur un compte valide). Ne chainer que sur 5760
     rate ce cas - c'etait le trou de la premiere version.

     Double alerte possible si les deux compteurs franchissent le seuil sur le
     meme incident : assume, deux alertes valent mieux qu'un scenario manque.

     Pas de correlation sur le compte (same_field srcuser) : elle casse le
     comptage de frequence (meme piege que 100658/100682, cf. README). On reste
     donc au niveau IP - un attaquant qui echoue sur `admin` puis reussit sur
     `backup` depuis la meme IP declenche quand meme, ce qui est le comportement
     voulu (password spraying).
```

### `web,attack,web_attack_soc,`

Règles : 100700, 100701, 100702

```
Détection attaques web : web shells, injections/RCE HTTP, reverse shells.
     Sources de données mesurées sur cet hôte (debian-vm, Apache + auditd) :
       - access.log décodé par Wazuh (base rule 31100, champ `url`). Les
         injections classiques (LFI/SQLi/XSS) remontent en 31103-31106 (niveau 6)
         mais l'injection de commande (?cmd=id) et l'accès web shell restent en
         niveau 0 : angle mort comblé ici.
       - auditd execve : champs `audit.command`, `audit.euid`, et `full_log`
         complet. Piège : les arguments contenant des espaces (one-liners de
         reverse shell passés à `sh -c`) sont encodés en HEXA dans EXECVE/
         PROCTITLE (ex. /dev/tcp/ -> 2F6465762F7463702F). On matche donc le
         `full_log` en clair ET en hexa. Cf. mémoire wazuh-auditd-exe-hex-encoding.
     Recherche : blog officiel Wazuh "Web shell attack detection" (FIM 100500-
     100502 + audit.key), et patterns reverse shell communautaires (/dev/tcp,
     nc -e, socket).
```

### `persistence,threat_hunting,linux,syscheck,`

Règles : 100740, 100741, 100742, 100743, 100744, 100745, 100746, 100747, 100748, 100749, 100750

```
PERSISTANCE ET INTEGRITE SYSTEME (FIM) - plage 100740-100759

     Comble le P1 de DETECTION-ROADMAP.md, jamais implemente : cron, cles SSH,
     unit systemd, sudoers, PAM, ld.so.preload, second UID 0. C'etait le trou le
     plus dangereux du dispositif - une backdoor durable ne generait aucune
     alerte, a aucun niveau.

     Ces regles supposent le FIM temps reel etendu de agent.conf. Sans lui,
     /etc n'est scanne que periodiquement : un fichier cron depose puis retire
     entre deux passes reste invisible, et l'alerte arrive avec des heures de
     retard. Config et regles sont indissociables.

     PLAGE D'IDENTIFIANTS : la roadmap reservait 100700-100730 pour ce pack, mais
     les regles web ont pris 100700-100702 et 100710-100712 entre-temps. D'ou le
     decalage en 100740+. Ne pas reutiliser 100703-100709.

     Niveaux : 12 pour un vecteur de persistance, 13-14 quand la modification
     donne un acces root direct (sudoers, PAM, ld.so.preload, second UID 0).
```

### `threat_hunting,linux,post_exploitation,`

Règles : 100760, 100761, 100762, 100763, 100764, 100765, 100766, 100767, 100768, 100770, 100771, 100772, 100773, 100769

```
TECHNIQUES POST-EXPLOITATION NON COUVERTES (auditd) - plage 100760-100779

     Categories absentes du ruleset avant cette revision, choisies pour leur
     rapport valeur/bruit : chargement de module noyau, creation de compte
     privilegie, effacement d'historique, tunneling C2, telechargement pipe vers
     un shell, evasion de conteneur, abus de binaire SUID (GTFOBins), capacites
     Linux, scan sortant.

     Toutes ancrent sur `a\d+=` et non sur `a0=` ni sur `audit.exe` : le noyau
     reecrit l'argv des scripts a shebang en inserant l'interpreteur en tete
     (piege documente en detail sur 100654).
```

### `audit,web_attack,web_shell,`

Règles : 100710, 100711, 100712, 100713, 100714

## Convention

Un fichier par règle, nommé `<id>-<slug>.xml`. **Tout est en anglais** dans ces
fichiers — descriptions comme commentaires. Les descriptions ne sont pas de la
documentation : elles partent dans les alertes, dans les cases DFIR-IRIS et dans
le contexte envoyé au LLM de triage.

Le fichier rejoue le `<group name="…">` d'origine — les groupes ne sont pas
décoratifs, ils portent le routage (`if_group`) et les tags MITRE/PCI. Le
commentaire qui explique la règle vit avec elle ; l'exclusion de niveau 0
associée a son propre fichier, immédiatement voisin par numérotation
(`100643` / `100644`).

### Piège : renommer une description touche le pipeline

`src/ai/soc_agent/correlate.py` écarte des graines d'incident toute alerte dont la
description matche `\bagent (connected|started|stopped|disconnected|…)\b` — un
filtre visant le bruit de statut du ruleset natif, écrit en anglais. Depuis que
nos règles le sont aussi, `100803` (« SOC tampering: Wazuh agent stopped »)
tombait dedans et ne pouvait plus ouvrir de case, **sans rien signaler**. D'où la
liste d'exception `SIDS_STATUT_AGENT_GRAINE`, par identifiant et non par texte.

Avant de reformuler une description, vérifier qu'aucun code ne la matche :

```sh
grep -rn "rule_desc" ai/soc_agent/
```

## Déploiement

`docker-compose.yml` monte ce répertoire **directement** sur
`/var/ossec/etc/rules` du manager. C'est délibéré : le mécanisme
`/wazuh-config-mount` utilisé pour les autres fichiers de configuration **copie**
et ne supprime jamais. Une règle renommée ou supprimée dans le dépôt survivait
donc dans le volume, et le manager chargeait l'ancienne **et** la nouvelle.

Mesuré lors du passage des règles en anglais : 164 fichiers chargés au lieu de
82, chaque règle définie deux fois, et `wazuh-analysisd` démarrant sans la
moindre erreur. Le montage direct fait du dépôt la seule source de vérité.

Vérification après tout changement :

```sh
docker exec wazuh-wazuh.manager-1 sh -c \
  'ls /var/ossec/etc/rules/*.xml | wc -l;
   grep -h "<rule id=" /var/ossec/etc/rules/*.xml | grep -oE "id=\"[0-9]+\"" | sort | uniq -d'
```

Le compte doit égaler le nombre de fichiers du dépôt, et la liste des doublons
ressortir **vide**. Puis rejouer `scripts/test-detection-rules.sh`.

Si un manager a déjà tourné avec l'ancien `local_rules.xml` ou avec le montage
`/wazuh-config-mount`, purger une fois le résidu du volume :

```sh
docker exec wazuh-wazuh.manager-1 rm -f /var/ossec/etc/rules/local_rules.xml
```
