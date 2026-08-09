"""Enrôlement d'une machine dans AURA : agent, télémétrie, remédiation.

Poser un agent Wazuh ne suffit pas — c'est l'erreur qui a laissé le parc à
moitié aveugle pendant des semaines. Une machine n'est réellement couverte que
si les quatre étages sont là :

1. **l'agent**, enrôlé et connecté au manager ;
2. **la télémétrie** que les règles attendent : auditd `execve` côté Linux,
   audit de création de processus avec ligne de commande + ScriptBlock + Sysmon
   côté Windows. Sans elle, les règles 1006xx/1007xx ne se déclenchent jamais
   et le SOC croit la machine calme ;
3. **les scripts d'active response**, sans lesquels toute remédiation échoue
   **en silence** : le manager transmet, l'API répond 200, et rien ne se passe ;
4. **la déclaration côté manager** (`ar.conf` généré depuis les blocs
   `<command>`), sans laquelle `execd` refuse la commande sans le dire.

Ce module n'invente rien : il exécute les recettes déjà éprouvées du dépôt
(`scripts/install-agent.sh`, `src/wazuh/config/agent/Install-WazuhAgent-Windows.ps1`,
`src/wazuh/active-response/`). Le chemin Windows reprend pas à pas ce que fait
`src/wazuh/active-response/windows/deploy-windows-ar.sh` — dont l'outillage
(NetExec) n'est pas installable dans cette image — en passant par WinRM.
"""

import base64
import os
import pathlib
import re
import subprocess

# Racine du dépôt montée en lecture seule dans le conteneur (voir le service
# aura-mcp du compose). Les recettes d'enrôlement sont des fichiers du dépôt,
# pas des chaînes recopiées ici : une divergence entre les deux serait invisible
# jusqu'au jour où la remédiation échoue sur une machine.
DEPOT = pathlib.Path(os.environ.get("AURA_DEPOT", "/aura"))
CLE_SSH = os.environ.get("SSH_KEY", "/root/.ssh/wazuh_ops_ed25519")
MANAGER = os.environ.get("WAZUH_MANAGER_IP", "")

AR_WINDOWS = DEPOT / "src/wazuh/active-response/windows"
AR_LINUX = DEPOT / "src/wazuh/active-response"
INSTALL_LINUX = DEPOT / "scripts/install-agent.sh"
INSTALL_WINDOWS = DEPOT / "src/wazuh/config/agent/Install-WazuhAgent-Windows.ps1"
REGLES_AUDIT = DEPOT / "src/wazuh/config/agent/zz-audit-wazuh.rules"

BIN_AR_WINDOWS = r"C:\Program Files (x86)\ossec-agent\active-response\bin"
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# Délai généreux : l'installation télécharge un MSI ou des paquets apt, et
# Sysmon prend son temps. Un timeout court ferait échouer un enrôlement qui
# aurait abouti, en laissant la machine à moitié configurée.
DELAI = int(os.environ.get("AURA_ENROLL_TIMEOUT", "900"))


class ErreurEnrolement(Exception):
    """Échec explicite, avec la sortie de la commande fautive."""


# --------------------------------------------------------------------------
# Validation des paramètres
# --------------------------------------------------------------------------
#
# `_ssh` transmet sa commande en un seul argument : c'est le shell DISTANT qui
# la découpe. Tout ce qui est interpolé dans cette chaîne — nom d'agent, adresse
# du manager — est donc du code, pas une donnée. Idem côté Windows, où les mêmes
# valeurs partent dans un `run_ps`.
#
# Le client de ce serveur MCP est un agent IA qui lit des alertes écrites par
# les machines surveillées, donc potentiellement par un attaquant (cf. les
# INSTRUCTIONS du serveur, et les mesures de sanitize.py : trois charges
# d'injection sur quatre retournent le verdict du modèle). Une valeur suggérée
# par un contenu d'alerte ne doit pas pouvoir devenir une commande. Partout
# ailleurs dans AURA les cibles d'action sont dérivées par le code et jamais
# choisies librement ; ces trois champs étaient l'exception.
#
# Liste blanche, pas échappement : on sait exactement à quoi ressemblent un nom
# d'agent Wazuh, un nom d'hôte et un compte Unix, et tout le reste est refusé.

_RE_NOM_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RE_HOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,253}$")
_RE_UTILISATEUR = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,31}$")


def _valider(valeur: str, motif: re.Pattern, champ: str, exemple: str) -> str:
    valeur = str(valeur or "").strip()
    if not motif.match(valeur):
        raise ErreurEnrolement(
            f"{champ} refusé : « {valeur[:80]} ». Cette valeur est interpolée "
            f"dans une commande exécutée en root sur la machine cible, elle est "
            f"donc restreinte au strict nécessaire (exemple : {exemple}).")
    return valeur


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------

OPTIONS_SSH = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    # L'hôte n'est pas encore connu au premier enrôlement. On accepte sa clé à
    # la première rencontre et on la fige ensuite : refuser bloquerait tout
    # premier déploiement, ignorer la vérification pour toujours serait pire.
    "-o", "StrictHostKeyChecking=accept-new",
]


def _ssh(hote: str, utilisateur: str, commande: str) -> str:
    r = subprocess.run(
        ["ssh", *OPTIONS_SSH, "-i", CLE_SSH, f"{utilisateur}@{hote}", commande],
        capture_output=True, text=True, timeout=DELAI)
    if r.returncode != 0:
        raise ErreurEnrolement(
            f"ssh {utilisateur}@{hote} : code {r.returncode}\n"
            f"{r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def _scp(hote: str, utilisateur: str, sources: list[pathlib.Path],
         destination: str) -> None:
    r = subprocess.run(
        ["scp", *OPTIONS_SSH, "-i", CLE_SSH, "-r",
         *[str(s) for s in sources], f"{utilisateur}@{hote}:{destination}"],
        capture_output=True, text=True, timeout=DELAI)
    if r.returncode != 0:
        raise ErreurEnrolement(f"scp vers {hote} : {r.stderr.strip()}")


def cle_publique() -> str:
    """Clé publique d'exploitation, déposée dans le `authorized_keys` de l'agent.

    C'est elle qui donnera au SOC l'accès `wazuh-admin` sur la machine, pour
    l'investigation et la collecte forensique.
    """
    pub = pathlib.Path(f"{CLE_SSH}.pub")
    if pub.is_file():
        return pub.read_text().strip()
    r = subprocess.run(["ssh-keygen", "-y", "-f", CLE_SSH],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise ErreurEnrolement(
            f"Impossible de dériver la clé publique de {CLE_SSH} : "
            f"{r.stderr.strip()}")
    return r.stdout.strip()


def enroler_linux(hote: str, nom_agent: str | None, utilisateur: str,
                  manager: str) -> dict:
    """Pose l'agent, auditd et les scripts d'active response sur un hôte Linux."""
    hote = _valider(hote, _RE_HOTE, "hote", "192.168.10.12 ou srv-web.lab")
    utilisateur = _valider(utilisateur, _RE_UTILISATEUR, "ssh_user", "root")
    manager = _valider(manager, _RE_HOTE, "manager", "192.168.10.5")
    nom_agent = _valider(nom_agent or hote, _RE_NOM_AGENT, "nom_agent",
                         "srv-web-01")

    for chemin in (INSTALL_LINUX, REGLES_AUDIT, AR_LINUX):
        if not chemin.exists():
            raise ErreurEnrolement(
                f"{chemin} absent du conteneur — la racine du dépôt doit être "
                f"montée sur {DEPOT} (service aura-mcp du compose).")

    etapes = []
    # On rejoue l'arborescence que `install-agent.sh` attend (il résout ses
    # dépendances en relatif depuis son propre emplacement), plutôt que de
    # patcher le script : il reste utilisable à la main, à l'identique.
    _ssh(hote, utilisateur,
         "rm -rf /tmp/aura-enroll && "
         "mkdir -p /tmp/aura-enroll/scripts "
         "/tmp/aura-enroll/src/wazuh/config/agent "
         "/tmp/aura-enroll/src/wazuh/active-response")
    _scp(hote, utilisateur, [INSTALL_LINUX], "/tmp/aura-enroll/scripts/")
    _scp(hote, utilisateur, [REGLES_AUDIT],
         "/tmp/aura-enroll/src/wazuh/config/agent/")
    _scp(hote, utilisateur, sorted(AR_LINUX.glob("*.sh")),
         "/tmp/aura-enroll/src/wazuh/active-response/")
    etapes.append({"etape": "copie", "ok": True})

    pubkey = cle_publique()
    nom = nom_agent or hote
    sortie = _ssh(
        hote, utilisateur,
        f"chmod +x /tmp/aura-enroll/scripts/install-agent.sh && "
        f"/tmp/aura-enroll/scripts/install-agent.sh "
        f"-m {manager} -n {nom} -k '{pubkey}'")
    etapes.append({"etape": "install-agent.sh", "ok": True, "sortie": sortie})

    etapes.append(assurer_identite(hote, utilisateur, nom, manager))
    return {"etapes": etapes,
            "verification": verifier_linux(hote, utilisateur, nom)}


def identite_agent(hote: str, utilisateur: str) -> tuple[str | None, str | None]:
    """(id, nom) déclarés dans le `client.keys` de la machine, ou (None, None)."""
    brut = _ssh(hote, utilisateur,
                "cat /var/ossec/etc/client.keys 2>/dev/null | head -1").strip()
    if not brut:
        return None, None
    morceaux = brut.split()
    return (morceaux[0], morceaux[1]) if len(morceaux) >= 2 else (None, None)


def assurer_identite(hote: str, utilisateur: str, nom: str,
                     manager: str) -> dict:
    """Force l'agent à porter SA propre identité sur le manager.

    `install-agent.sh` n'enrôle qu'à l'installation du paquet : sur une machine
    où l'agent est déjà présent, il passe son chemin. Or c'est précisément là
    que se cache le pire cas — une machine **clonée**, qui a hérité du
    `client.keys` de son modèle. Deux agents présentent alors la même identité :
    le manager n'en accepte qu'un, l'autre boucle en connexion/déconnexion, et
    tout ce qu'il observe est perdu. Vu de l'inventaire, il « existe » pourtant.

    On compare donc le nom déclaré localement au nom voulu, et on ré-enrôle
    (`agent-auth` contre l'authd du manager, port 1515) s'ils divergent ou si
    aucune clé n'est présente.
    """
    # Revalidé ici et pas seulement chez l'appelant : cette fonction construit
    # elle aussi une commande distante, et elle est appelable directement.
    nom = _valider(nom, _RE_NOM_AGENT, "nom_agent", "srv-web-01")
    manager = _valider(manager, _RE_HOTE, "manager", "192.168.10.5")

    ident, nom_local = identite_agent(hote, utilisateur)
    if nom_local == nom:
        return {"etape": "identite", "ok": True, "reenrole": False,
                "agent_id": ident, "nom": nom_local}

    detail = ("aucune clé d'enrôlement" if not nom_local
              else f"la machine porte l'identité « {nom_local} » "
                   f"(agent {ident}), pas « {nom} »")
    _ssh(hote, utilisateur,
         f"systemctl stop wazuh-agent; "
         f"/var/ossec/bin/agent-auth -m {manager} -A {nom} 2>&1 | tail -3; "
         f"systemctl start wazuh-agent")
    ident, nom_local = identite_agent(hote, utilisateur)
    return {"etape": "identite", "ok": nom_local == nom, "reenrole": True,
            "motif": detail, "agent_id": ident, "nom": nom_local}


def etat_sur_le_manager(nom: str) -> dict:
    """Ce que le MANAGER dit de cet agent — la seule vérité qui compte.

    Une machine peut avoir l'agent actif, auditd chargé et les scripts en
    place tout en n'étant connue de personne : identité en double, pare-feu
    sur 1514, enrôlement jamais abouti. Tant que le manager ne la voit pas
    `active`, elle n'est pas surveillée, quoi qu'en dise la machine.
    """
    import json
    import urllib.error
    import urllib.parse
    import urllib.request

    from soc_agent import config as soc_config

    ssl_ctx = __import__("ssl")._create_unverified_context()
    base = soc_config.WAZUH_API_URL.rstrip("/")

    def _appel(chemin: str, entetes: dict) -> dict:
        requete = urllib.request.Request(f"{base}{chemin}", headers=entetes)
        with urllib.request.urlopen(requete, context=ssl_ctx,
                                    timeout=20) as reponse:
            return json.loads(reponse.read())

    try:
        import base64
        creds = base64.b64encode(
            f"{soc_config.WAZUH_API_USER}:"
            f"{soc_config.WAZUH_API_PASSWORD}".encode()).decode()
        jeton = _appel("/security/user/authenticate",
                       {"Authorization": f"Basic {creds}"})["data"]["token"]
        agents = _appel(
            "/agents?name=" + urllib.parse.quote(nom),
            {"Authorization": f"Bearer {jeton}"})["data"]["affected_items"]
    except (urllib.error.URLError, KeyError, ValueError) as e:
        return {"connu": None, "erreur": f"API Wazuh injoignable : {e}"}

    if not agents:
        return {"connu": False,
                "consequence": f"Le manager ne connaît aucun agent « {nom} » : "
                               f"cette machine n'est pas surveillée, quel que "
                               f"soit son état local."}
    a = agents[0]
    return {"connu": True, "agent_id": a["id"], "statut": a.get("status"),
            "ip": a.get("ip"), "version": a.get("version"),
            "dernier_contact": a.get("lastKeepAlive"),
            "groupes": a.get("group", [])}


def verifier_linux(hote: str, utilisateur: str,
                   nom_agent: str | None = None) -> dict:
    """Contrôle d'après la machine elle-même, pas d'après le code de retour.

    `audit_actif` est le point qui décide de tout : tant que `auditd` n'a pas
    la main sur le socket netlink (journald le lui prend), aucune règle
    d'exécution ne se déclenche — et il faut un REDÉMARRAGE pour le régler.
    """
    # Atteignable en `aura:read` (aura_agent_health). Les commandes ci-dessous
    # sont figées, mais l'hôte et le compte partent dans une cible SSH : on les
    # borne à ce qu'ils sont censés être plutôt que de compter sur le fait que
    # subprocess n'ouvre pas de shell.
    hote = _valider(hote, _RE_HOTE, "hote", "192.168.10.12 ou srv-web.lab")
    utilisateur = _valider(utilisateur, _RE_UTILISATEUR, "ssh_user", "root")

    commandes = {
        "agent_actif": "systemctl is-active wazuh-agent",
        "auditd_actif": "systemctl is-active auditd",
        "regles_audit": "auditctl -l 2>/dev/null | grep -c execveat || true",
        "audit_actif": "auditctl -s 2>/dev/null | awk '/^enabled/{print $2}'",
        "scripts_ar": "ls -1 /var/ossec/active-response/bin/*.sh 2>/dev/null "
                      "| wc -l",
    }
    resultat: dict = {}
    echecs = 0
    for cle, commande in commandes.items():
        try:
            resultat[cle] = _ssh(hote, utilisateur,
                                 f"{commande} 2>/dev/null || true").strip()
        except ErreurEnrolement as e:
            resultat[cle] = None
            resultat.setdefault("erreur_ssh", str(e))
            echecs += 1

    # Un hôte injoignable ne « va » pas bien : il n'est pas mesuré. Répondre
    # que tout est indisponible ET qu'un redémarrage s'impose serait deux fois
    # faux — le second point ferait redémarrer une machine sans raison.
    resultat["joignable"] = echecs < len(commandes)
    if not resultat["joignable"]:
        resultat["redemarrage_requis"] = None
        resultat["conseil"] = (
            f"Aucune commande n'a pu être exécutée sur {hote}. Vérifier que "
            f"la clé {CLE_SSH} est autorisée pour l'utilisateur "
            f"« {utilisateur} » sur cet hôte : le conteneur MCP joint les "
            f"machines EN DIRECT, il ne passe par aucun rebond.")
        return resultat

    # `enabled 2` = audit actif ET configuration verrouillée : c'est l'état
    # visé, pas une anomalie (install-agent.sh, lui, ne teste que `= 1` et
    # crie au loup sur une machine parfaitement instrumentée).
    connu = resultat.get("audit_actif") in ("0", "1", "2")
    resultat["redemarrage_requis"] = (
        resultat.get("audit_actif") not in ("1", "2") if connu else None)

    # L'identité locale et ce que le manager en sait. Sans ce contrôle, une
    # machine clonée passe pour enrôlée : agent actif, auditd chargé, scripts
    # en place… et pas une alerte, parce qu'elle parle avec l'identité d'une
    # autre.
    ident, nom_local = identite_agent(hote, utilisateur)
    resultat["identite_locale"] = {"agent_id": ident, "nom": nom_local}
    if nom_agent:
        resultat["manager"] = etat_sur_le_manager(nom_agent)
        resultat["surveille"] = bool(
            resultat["manager"].get("connu")
            and resultat["manager"].get("statut") == "active"
            and nom_local == nom_agent)
    if resultat["redemarrage_requis"]:
        resultat["pourquoi_redemarrer"] = (
            "L'audit noyau n'est pas actif : journald tient le socket netlink. "
            "Tant que la machine n'a pas redémarré, aucune règle d'exécution "
            "(1006xx/1007xx) ne peut se déclencher — la machine paraîtra calme "
            "parce qu'elle est muette.")
    return resultat


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------

def _winrm(hote: str, utilisateur: str, motdepasse: str, script: str) -> str:
    """Exécute du PowerShell sur l'hôte. Import tardif : WinRM est optionnel."""
    try:
        import winrm  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover
        raise ErreurEnrolement(
            "Le module pywinrm est absent de l'image — l'enrôlement Windows "
            "ne peut pas fonctionner.") from e

    session = winrm.Session(f"http://{hote}:5985/wsman",
                            auth=(utilisateur, motdepasse), transport="ntlm")
    r = session.run_ps(script)
    if r.status_code != 0:
        raise ErreurEnrolement(
            f"WinRM {hote} : code {r.status_code}\n"
            f"{r.std_err.decode('utf-8', 'replace')[:2000]}")
    return r.std_out.decode("utf-8", "replace")


def _pousser_fichier(hote: str, u: str, p: str, source: pathlib.Path,
                     nom: str) -> None:
    """Écrit un fichier sur l'hôte via WinRM, en base64.

    Même canal que `deploy-windows-ar.sh` : tout passe par WinRM, ce qui
    fonctionne même quand SMB/445 est filtré. L'écriture est binaire — un
    `Set-Content` réencoderait et casserait les scripts.
    """
    b64 = base64.b64encode(source.read_bytes()).decode()
    _winrm(hote, u, p,
           f"[IO.File]::WriteAllBytes('{BIN_AR_WINDOWS}\\{nom}', "
           f"[Convert]::FromBase64String('{b64}'))")


def deployer_ar_windows(hote: str, utilisateur: str, motdepasse: str) -> dict:
    """Pose les scripts d'active response Windows/AD et leurs lanceurs .exe.

    Reprend `deploy-windows-ar.sh`. Deux pièges y sont traités et doivent le
    rester :

    - `wazuh-execd` lance l'exécutable enregistré par un `CreateProcess` brut,
      qui ne démarre qu'un vrai `.exe` : un `.ps1` échoue avec « (1317): Could
      not launch command ». D'où le wrapper compilé, recopié sous le nom de
      chaque action.
    - un wrapper resté bloqué tient son propre `.exe` ouvert : la copie
      échouerait en « file in use ». On tue donc les wrappers en cours avant.
    """
    if not AR_WINDOWS.is_dir():
        raise ErreurEnrolement(f"{AR_WINDOWS} absent du conteneur.")

    _winrm(hote, utilisateur, motdepasse,
           f"New-Item -ItemType Directory -Force -Path '{BIN_AR_WINDOWS}' "
           f"| Out-Null")

    scripts = [p for p in sorted(AR_WINDOWS.glob("*.ps1"))]
    for ps1 in scripts:
        _pousser_fichier(hote, utilisateur, motdepasse, ps1, ps1.name)

    _winrm(hote, utilisateur, motdepasse,
           "Get-CimInstance Win32_Process | Where-Object { "
           "$_.Name -match '^(win-|ad-|ar-wrapper)' } | ForEach-Object { "
           "Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }")

    wrapper = AR_WINDOWS / "ar-wrapper.cs"
    _pousser_fichier(hote, utilisateur, motdepasse, wrapper, "ar-wrapper.cs")
    _winrm(hote, utilisateur, motdepasse,
           f"& '{CSC}' /nologo /target:exe "
           f"/out:'{BIN_AR_WINDOWS}\\ar-wrapper.exe' "
           f"'{BIN_AR_WINDOWS}\\ar-wrapper.cs' 2>&1 | Out-Null")

    poses = []
    for ps1 in scripts:
        if ps1.name == "_ar-common.ps1":
            continue
        exe = f"{ps1.stem}.exe"
        _winrm(hote, utilisateur, motdepasse,
               f"Copy-Item '{BIN_AR_WINDOWS}\\ar-wrapper.exe' "
               f"'{BIN_AR_WINDOWS}\\{exe}' -Force")
        poses.append(exe)
    return {"scripts": [p.name for p in scripts], "executables": poses}


def enroler_windows(hote: str, nom_agent: str | None, utilisateur: str,
                    motdepasse: str, manager: str,
                    sans_sysmon: bool = False) -> dict:
    """Pose l'agent Windows, sa télémétrie complète, puis l'active response."""
    # `options` est concaténé dans un script PowerShell exécuté sur la cible :
    # même exigence que côté Linux.
    hote = _valider(hote, _RE_HOTE, "hote", "192.168.10.20 ou win-dc.lab")
    manager = _valider(manager, _RE_HOTE, "manager", "192.168.10.5")
    nom_agent = _valider(nom_agent or hote, _RE_NOM_AGENT, "nom_agent",
                         "WIN-DC")

    if not INSTALL_WINDOWS.is_file():
        raise ErreurEnrolement(f"{INSTALL_WINDOWS} absent du conteneur.")

    distant = r"C:\Windows\Temp\Install-WazuhAgent-Windows.ps1"
    b64 = base64.b64encode(INSTALL_WINDOWS.read_bytes()).decode()
    _winrm(hote, utilisateur, motdepasse,
           f"[IO.File]::WriteAllBytes('{distant}', "
           f"[Convert]::FromBase64String('{b64}'))")

    nom = nom_agent or hote
    options = f"-Manager {manager} -AgentName {nom}"
    if sans_sysmon:
        options += " -SkipSysmon"
    sortie = _winrm(hote, utilisateur, motdepasse,
                    f"& '{distant}' {options}")

    ar = deployer_ar_windows(hote, utilisateur, motdepasse)
    return {
        "installation": sortie[-4000:],
        "active_response": ar,
        "verification": verifier_windows(hote, utilisateur, motdepasse),
    }


def verifier_windows(hote: str, utilisateur: str, motdepasse: str) -> dict:
    """Contrôle sur la machine : service, canaux d'évènements, binaires d'AR."""
    script = f"""
$svc = (Get-Service WazuhSvc -EA SilentlyContinue).Status
$exe = (Get-ChildItem '{BIN_AR_WINDOWS}\\*.exe' -EA SilentlyContinue).Count
$sys = (Get-Service Sysmon64,Sysmon -EA SilentlyContinue | Select -First 1).Status
$cmd = (auditpol /get /subcategory:"{{0CCE922B-69AE-11D9-BED3-505054503030}}" 2>$null | Out-String)
"agent=$svc;ar_exe=$exe;sysmon=$sys;audit_process=$($cmd -match 'Succ')"
"""
    brut = _winrm(hote, utilisateur, motdepasse, script).strip()
    resultat = {}
    for morceau in brut.split(";"):
        if "=" in morceau:
            cle, valeur = morceau.split("=", 1)
            resultat[cle] = valeur
    resultat["brut"] = brut
    return resultat
