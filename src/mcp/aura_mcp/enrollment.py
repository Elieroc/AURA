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
REPO = pathlib.Path(os.environ.get("AURA_DEPOT", "/aura"))
SSH_KEY = os.environ.get("SSH_KEY", "/root/.ssh/wazuh_ops_ed25519")
MANAGER = os.environ.get("WAZUH_MANAGER_IP", "")

AR_WINDOWS = REPO / "src/wazuh/active-response/windows"
AR_LINUX = REPO / "src/wazuh/active-response"
INSTALL_LINUX = REPO / "scripts/install-agent.sh"
INSTALL_WINDOWS = REPO / "src/wazuh/config/agent/Install-WazuhAgent-Windows.ps1"
AUDIT_RULES = REPO / "src/wazuh/config/agent/zz-audit-wazuh.rules"

BIN_AR_WINDOWS = r"C:\Program Files (x86)\ossec-agent\active-response\bin"
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# Délai généreux : l'installation télécharge un MSI ou des paquets apt, et
# Sysmon prend son temps. Un timeout court ferait échouer un enrôlement qui
# aurait abouti, en laissant la machine à moitié configurée.
TIMEOUT = int(os.environ.get("AURA_ENROLL_TIMEOUT", "900"))


class EnrollmentError(Exception):
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

_RE_AGENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,253}$")
_RE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,31}$")


def _validate(value: str, pattern: re.Pattern, field: str, example: str) -> str:
    value = str(value or "").strip()
    if not pattern.match(value):
        raise EnrollmentError(
            f"{field} refusé : « {value[:80]} ». Cette valeur est interpolée "
            f"dans une commande exécutée en root sur la machine cible, elle est "
            f"donc restreinte au strict nécessaire (exemple : {example}).")
    return value


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------

SSH_OPTIONS = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    # L'hôte n'est pas encore connu au premier enrôlement. On accepte sa clé à
    # la première rencontre et on la fige ensuite : refuser bloquerait tout
    # premier déploiement, ignorer la vérification pour toujours serait pire.
    "-o", "StrictHostKeyChecking=accept-new",
]


def _ssh(host: str, user: str, command: str) -> str:
    r = subprocess.run(
        ["ssh", *SSH_OPTIONS, "-i", SSH_KEY, f"{user}@{host}", command],
        capture_output=True, text=True, timeout=TIMEOUT)
    if r.returncode != 0:
        raise EnrollmentError(
            f"ssh {user}@{host} : code {r.returncode}\n"
            f"{r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def _scp(host: str, user: str, sources: list[pathlib.Path],
         destination: str) -> None:
    r = subprocess.run(
        ["scp", *SSH_OPTIONS, "-i", SSH_KEY, "-r",
         *[str(s) for s in sources], f"{user}@{host}:{destination}"],
        capture_output=True, text=True, timeout=TIMEOUT)
    if r.returncode != 0:
        raise EnrollmentError(f"scp vers {host} : {r.stderr.strip()}")


def public_key() -> str:
    """Clé publique d'exploitation, déposée dans le `authorized_keys` de l'agent.

    C'est elle qui donnera au SOC l'accès `wazuh-admin` sur la machine, pour
    l'investigation et la collecte forensique.
    """
    pub = pathlib.Path(f"{SSH_KEY}.pub")
    if pub.is_file():
        return pub.read_text().strip()
    r = subprocess.run(["ssh-keygen", "-y", "-f", SSH_KEY],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise EnrollmentError(
            f"Impossible de dériver la clé publique de {SSH_KEY} : "
            f"{r.stderr.strip()}")
    return r.stdout.strip()


# --------------------------------------------------------------------------
# Rôle et priorité de l'asset (CMDB)
# --------------------------------------------------------------------------

# Un nom de groupe Wazuh, et un segment d'URL de l'API : liste blanche stricte,
# comme partout ailleurs dans ce module.
_RE_ROLE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def _default_priority() -> int:
    from soc_agent import config as soc_config  # noqa: PLC0415
    return soc_config.DEFAULT_PRIORITY


def _group_of_role(role: str) -> str:
    from soc_agent import config as soc_config  # noqa: PLC0415
    return f"{soc_config.CMDB_GROUP_PREFIX}{role}"


def _api(path: str, method: str = "GET", body: dict | None = None) -> dict:
    """Appel authentifié à l'API Wazuh. Lève sur échec, sauf 4xx explicités."""
    import json  # noqa: PLC0415
    import ssl  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    from soc_agent import config as soc_config  # noqa: PLC0415

    ctx = ssl._create_unverified_context()
    base = soc_config.WAZUH_API_URL.rstrip("/")
    creds = base64.b64encode(
        f"{soc_config.WAZUH_API_USER}:"
        f"{soc_config.WAZUH_API_PASSWORD}".encode()).decode()
    auth = urllib.request.Request(
        f"{base}/security/user/authenticate",
        headers={"Authorization": f"Basic {creds}"})
    with urllib.request.urlopen(auth, context=ctx, timeout=20) as r:
        token = json.loads(r.read())["data"]["token"]

    query = urllib.request.Request(
        f"{base}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(query, context=ctx, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def _create_group(group: str) -> None:
    """Crée le groupe s'il n'existe pas. Un groupe déjà là n'est pas une erreur."""
    import urllib.error  # noqa: PLC0415
    try:
        _api("/groups", "POST", {"group_id": group})
    except urllib.error.HTTPError as e:
        # 400 « group already exists » : c'est le cas nominal au deuxième
        # enrôlement d'un même rôle. Toute autre erreur remonte.
        if e.code != 400:
            raise EnrollmentError(
                f"création du groupe {group} refusée par l'API Wazuh "
                f"({e.code}) : {e.read()[:300]!r}") from e


def _assign_group(agent_id: str, group: str) -> None:
    import urllib.error  # noqa: PLC0415
    try:
        _api(f"/agents/{agent_id}/group/{group}", "PUT")
    except urllib.error.HTTPError as e:
        raise EnrollmentError(
            f"affectation de l'agent {agent_id} au groupe {group} refusée "
            f"({e.code}) : {e.read()[:300]!r}") from e


def declare_role(agent_name: str, role: str | None) -> dict:
    """Range l'agent dans son groupe `role-…` et l'inscrit dans la CMDB.

    C'est ici que se décide la PRIORITÉ de la machine (P1-P4), donc l'ordre dans
    lequel ses incidents seront analysés et la sévérité qu'ils porteront. Le
    groupe Wazuh est la source de vérité (inventaire natif, survit au
    redéploiement de la stack) ; la table `assets` n'en est qu'un miroir
    interrogeable, reconstruit par `soc_agent.assets --sync`.

    Sans rôle déclaré, la machine retombe sur `PRIORITE_DEFAUT` (P4) : ses
    incidents passent après ceux des assets déclarés. C'est un choix assumé —
    ce qui n'est pas déclaré ne prend pas la place de ce qui l'est — dont le
    revers est réel : une machine importante jamais déclarée est traitée comme
    un poste jetable. D'où la trace `priorite_source = 'defaut'` et le rapport
    `soc_agent.assets --couverture`, qui rend cette dette visible.
    """
    from soc_agent import assets as soc_assets  # noqa: PLC0415

    state = state_on_manager(agent_name)
    if not state.get("connu"):
        return {"etape": "role", "ok": False, "role": role,
                "pattern": "agent inconnu du manager : rôle non déclarable "
                         "(l'enrôlement n'a pas abouti)"}
    agent_id = state["agent_id"]

    if not role:
        # Inscription quand même : un asset connu et sans rôle est une dette
        # d'inventaire VISIBLE, alors qu'un asset absent de la table est un
        # angle mort. Il sera de toute façon revu au prochain --sync.
        soc_assets.set_asset(agent_id, priority=_default_priority(),
                           source="defaut",
                           notes="enrôlé sans rôle déclaré")
        return {"etape": "role", "ok": True, "role": None,
                "agent_id": agent_id, "priority": _default_priority(),
                "avertissement":
                    f"aucun rôle déclaré : la machine est traitée en "
                    f"P{_default_priority()} (fin de file). La déclarer avec "
                    f"aura_asset_set dès que son usage est connu."}

    from soc_agent import config as soc_config  # noqa: PLC0415
    role = _validate(role.lower(), _RE_ROLE, "role", "dc, web, firewall")
    if role not in soc_config.PRIORITY_ROLES:
        # Vérifié AVANT de toucher au manager : un rôle inconnu n'a pas de
        # priorité, donc créer son groupe ne servirait qu'à faire croire à une
        # déclaration alors que la machine resterait en P4.
        raise EnrollmentError(
            f"rôle inconnu : « {role} ». Rôles connus : "
            f"{', '.join(sorted(soc_config.PRIORITY_ROLES))}. En ajouter un "
            f"via PRIORITE_ROLES (ex. PRIORITE_ROLES=\"nas=1\").")
    group = _group_of_role(role)
    _create_group(group)
    _assign_group(agent_id, group)

    # Le groupe a-t-il RÉELLEMENT pris ? L'API accepte l'affectation sans
    # broncher sur des agents qui ne peuvent pas appartenir à un groupe — le
    # manager lui-même (000) en est un. Sans ce contrôle, la déclaration
    # paraissait réussie et la resynchronisation suivante remettait la machine
    # en P4, en silence : constaté sur `wazuh.manager`, classé soc puis
    # redescendu au premier `assets --sync`.
    #
    # Dans ce cas on bascule sur la source `operateur`, la seule que la
    # synchronisation ne réécrit jamais.
    groups = {str(g).lower()
               for g in (state_on_manager(agent_name).get("groups") or [])}
    tenu = group.lower() in groups
    line = soc_assets.set_asset(agent_id, role=role,
                               source="groupe" if tenu else "operateur",
                               notes=None if tenu else
                               f"agent {agent_id} : le manager n'accepte pas "
                               f"le groupe {group}, priorité posée en dur")
    return {"etape": "role", "ok": True, "role": role, "groupe": group,
            "agent_id": agent_id, "priority": line["priority"],
            "source": line["priority_source"],
            **({} if tenu else {
                "avertissement":
                    f"le manager n'a pas retenu le groupe {group} pour "
                    f"l'agent {agent_id} (cas du manager lui-même) : la "
                    f"priorité est enregistrée en source « operateur », que "
                    f"la synchronisation ne réécrit pas."}),
            }


def enroll_linux(host: str, agent_name: str | None, user: str,
                  manager: str, role: str | None = None) -> dict:
    """Pose l'agent, auditd et les scripts d'active response sur un hôte Linux."""
    host = _validate(host, _RE_HOST, "hote", "192.168.10.12 ou srv-web.lab")
    user = _validate(user, _RE_USER, "ssh_user", "root")
    manager = _validate(manager, _RE_HOST, "manager", "192.168.10.5")
    agent_name = _validate(agent_name or host, _RE_AGENT_NAME, "nom_agent",
                         "srv-web-01")

    for path in (INSTALL_LINUX, AUDIT_RULES, AR_LINUX):
        if not path.exists():
            raise EnrollmentError(
                f"{path} absent du conteneur — la racine du dépôt doit être "
                f"montée sur {REPO} (service aura-mcp du compose).")

    steps = []
    # On rejoue l'arborescence que `install-agent.sh` attend (il résout ses
    # dépendances en relatif depuis son propre emplacement), plutôt que de
    # patcher le script : il reste utilisable à la main, à l'identique.
    _ssh(host, user,
         "rm -rf /tmp/aura-enroll && "
         "mkdir -p /tmp/aura-enroll/scripts "
         "/tmp/aura-enroll/src/wazuh/config/agent "
         "/tmp/aura-enroll/src/wazuh/active-response")
    _scp(host, user, [INSTALL_LINUX], "/tmp/aura-enroll/scripts/")
    _scp(host, user, [AUDIT_RULES],
         "/tmp/aura-enroll/src/wazuh/config/agent/")
    _scp(host, user, sorted(AR_LINUX.glob("*.sh")),
         "/tmp/aura-enroll/src/wazuh/active-response/")
    steps.append({"etape": "copie", "ok": True})

    pubkey = public_key()
    name = agent_name or host
    output = _ssh(
        host, user,
        f"chmod +x /tmp/aura-enroll/scripts/install-agent.sh && "
        f"/tmp/aura-enroll/scripts/install-agent.sh "
        f"-m {manager} -n {name} -k '{pubkey}'")
    steps.append({"etape": "install-agent.sh", "ok": True, "sortie": output})

    steps.append(ensure_identity(host, user, name, manager))
    steps.append(declare_role(name, role))
    return {"etapes": steps,
            "verification": check_linux(host, user, name)}


def agent_identity(host: str, user: str) -> tuple[str | None, str | None]:
    """(id, nom) déclarés dans le `client.keys` de la machine, ou (None, None)."""
    raw = _ssh(host, user,
                "cat /var/ossec/etc/client.keys 2>/dev/null | head -1").strip()
    if not raw:
        return None, None
    chunks = raw.split()
    return (chunks[0], chunks[1]) if len(chunks) >= 2 else (None, None)


def ensure_identity(host: str, user: str, name: str,
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
    name = _validate(name, _RE_AGENT_NAME, "nom_agent", "srv-web-01")
    manager = _validate(manager, _RE_HOST, "manager", "192.168.10.5")

    ident, local_name = agent_identity(host, user)
    if local_name == name:
        return {"etape": "identite", "ok": True, "reenrole": False,
                "agent_id": ident, "name": local_name}

    detail = ("aucune clé d'enrôlement" if not local_name
              else f"la machine porte l'identité « {local_name} » "
                   f"(agent {ident}), pas « {name} »")
    _ssh(host, user,
         f"systemctl stop wazuh-agent; "
         f"/var/ossec/bin/agent-auth -m {manager} -A {name} 2>&1 | tail -3; "
         f"systemctl start wazuh-agent")
    ident, local_name = agent_identity(host, user)
    return {"etape": "identite", "ok": local_name == name, "reenrole": True,
            "pattern": detail, "agent_id": ident, "name": local_name}


def state_on_manager(name: str) -> dict:
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

    def _call(path: str, headers: dict) -> dict:
        query = urllib.request.Request(f"{base}{path}", headers=headers)
        with urllib.request.urlopen(query, context=ssl_ctx,
                                    timeout=20) as response:
            return json.loads(response.read())

    try:
        import base64
        creds = base64.b64encode(
            f"{soc_config.WAZUH_API_USER}:"
            f"{soc_config.WAZUH_API_PASSWORD}".encode()).decode()
        token = _call("/security/user/authenticate",
                       {"Authorization": f"Basic {creds}"})["data"]["token"]
        agents = _call(
            "/agents?name=" + urllib.parse.quote(name),
            {"Authorization": f"Bearer {token}"})["data"]["affected_items"]
    except (urllib.error.URLError, KeyError, ValueError) as e:
        return {"connu": None, "error": f"API Wazuh injoignable : {e}"}

    if not agents:
        return {"connu": False,
                "consequence": f"Le manager ne connaît aucun agent « {name} » : "
                               f"cette machine n'est pas surveillée, quel que "
                               f"soit son état local."}
    a = agents[0]
    return {"connu": True, "agent_id": a["id"], "status": a.get("status"),
            "ip": a.get("ip"), "version": a.get("version"),
            "dernier_contact": a.get("lastKeepAlive"),
            "groups": a.get("group", [])}


def check_linux(host: str, user: str,
                   agent_name: str | None = None) -> dict:
    """Contrôle d'après la machine elle-même, pas d'après le code de retour.

    `audit_actif` est le point qui décide de tout : tant que `auditd` n'a pas
    la main sur le socket netlink (journald le lui prend), aucune règle
    d'exécution ne se déclenche — et il faut un REDÉMARRAGE pour le régler.
    """
    # Atteignable en `aura:read` (aura_agent_health). Les commandes ci-dessous
    # sont figées, mais l'hôte et le compte partent dans une cible SSH : on les
    # borne à ce qu'ils sont censés être plutôt que de compter sur le fait que
    # subprocess n'ouvre pas de shell.
    host = _validate(host, _RE_HOST, "hote", "192.168.10.12 ou srv-web.lab")
    user = _validate(user, _RE_USER, "ssh_user", "root")

    commands = {
        "agent_actif": "systemctl is-active wazuh-agent",
        "auditd_actif": "systemctl is-active auditd",
        "regles_audit": "auditctl -l 2>/dev/null | grep -c execveat || true",
        "audit_actif": "auditctl -s 2>/dev/null | awk '/^enabled/{print $2}'",
        "scripts_ar": "ls -1 /var/ossec/active-response/bin/*.sh 2>/dev/null "
                      "| wc -l",
    }
    result: dict = {}
    failures = 0
    for key, command in commands.items():
        try:
            result[key] = _ssh(host, user,
                                 f"{command} 2>/dev/null || true").strip()
        except EnrollmentError as e:
            result[key] = None
            result.setdefault("erreur_ssh", str(e))
            failures += 1

    # Un hôte injoignable ne « va » pas bien : il n'est pas mesuré. Répondre
    # que tout est indisponible ET qu'un redémarrage s'impose serait deux fois
    # faux — le second point ferait redémarrer une machine sans raison.
    result["joignable"] = failures < len(commands)
    if not result["joignable"]:
        result["redemarrage_requis"] = None
        result["conseil"] = (
            f"Aucune commande n'a pu être exécutée sur {host}. Vérifier que "
            f"la clé {SSH_KEY} est autorisée pour l'utilisateur "
            f"« {user} » sur cet hôte : le conteneur MCP joint les "
            f"machines EN DIRECT, il ne passe par aucun rebond.")
        return result

    # `enabled 2` = audit actif ET configuration verrouillée : c'est l'état
    # visé, pas une anomalie (install-agent.sh, lui, ne teste que `= 1` et
    # crie au loup sur une machine parfaitement instrumentée).
    known = result.get("audit_actif") in ("0", "1", "2")
    result["redemarrage_requis"] = (
        result.get("audit_actif") not in ("1", "2") if known else None)

    # L'identité locale et ce que le manager en sait. Sans ce contrôle, une
    # machine clonée passe pour enrôlée : agent actif, auditd chargé, scripts
    # en place… et pas une alerte, parce qu'elle parle avec l'identité d'une
    # autre.
    ident, local_name = agent_identity(host, user)
    result["identite_locale"] = {"agent_id": ident, "name": local_name}
    if agent_name:
        result["manager"] = state_on_manager(agent_name)
        result["surveille"] = bool(
            result["manager"].get("connu")
            and result["manager"].get("status") == "active"
            and local_name == agent_name)
    if result["redemarrage_requis"]:
        result["pourquoi_redemarrer"] = (
            "L'audit noyau n'est pas actif : journald tient le socket netlink. "
            "Tant que la machine n'a pas redémarré, aucune règle d'exécution "
            "(1006xx/1007xx) ne peut se déclencher — la machine paraîtra calme "
            "parce qu'elle est muette.")
    return result


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------

def _winrm(host: str, user: str, password: str, script: str) -> str:
    """Exécute du PowerShell sur l'hôte. Import tardif : WinRM est optionnel."""
    try:
        import winrm  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover
        raise EnrollmentError(
            "Le module pywinrm est absent de l'image — l'enrôlement Windows "
            "ne peut pas fonctionner.") from e

    session = winrm.Session(f"http://{host}:5985/wsman",
                            auth=(user, password), transport="ntlm")
    r = session.run_ps(script)
    if r.status_code != 0:
        raise EnrollmentError(
            f"WinRM {host} : code {r.status_code}\n"
            f"{r.std_err.decode('utf-8', 'replace')[:2000]}")
    return r.std_out.decode("utf-8", "replace")


def _push_file(host: str, u: str, p: str, source: pathlib.Path,
                     name: str) -> None:
    """Écrit un fichier sur l'hôte via WinRM, en base64.

    Même canal que `deploy-windows-ar.sh` : tout passe par WinRM, ce qui
    fonctionne même quand SMB/445 est filtré. L'écriture est binaire — un
    `Set-Content` réencoderait et casserait les scripts.
    """
    b64 = base64.b64encode(source.read_bytes()).decode()
    _winrm(host, u, p,
           f"[IO.File]::WriteAllBytes('{BIN_AR_WINDOWS}\\{name}', "
           f"[Convert]::FromBase64String('{b64}'))")


def deploy_ar_windows(host: str, user: str, password: str) -> dict:
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
        raise EnrollmentError(f"{AR_WINDOWS} absent du conteneur.")

    _winrm(host, user, password,
           f"New-Item -ItemType Directory -Force -Path '{BIN_AR_WINDOWS}' "
           f"| Out-Null")

    scripts = [p for p in sorted(AR_WINDOWS.glob("*.ps1"))]
    for ps1 in scripts:
        _push_file(host, user, password, ps1, ps1.name)

    _winrm(host, user, password,
           "Get-CimInstance Win32_Process | Where-Object { "
           "$_.Name -match '^(win-|ad-|ar-wrapper)' } | ForEach-Object { "
           "Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }")

    wrapper = AR_WINDOWS / "ar-wrapper.cs"
    _push_file(host, user, password, wrapper, "ar-wrapper.cs")
    _winrm(host, user, password,
           f"& '{CSC}' /nologo /target:exe "
           f"/out:'{BIN_AR_WINDOWS}\\ar-wrapper.exe' "
           f"'{BIN_AR_WINDOWS}\\ar-wrapper.cs' 2>&1 | Out-Null")

    placed = []
    for ps1 in scripts:
        if ps1.name == "_ar-common.ps1":
            continue
        exe = f"{ps1.stem}.exe"
        _winrm(host, user, password,
               f"Copy-Item '{BIN_AR_WINDOWS}\\ar-wrapper.exe' "
               f"'{BIN_AR_WINDOWS}\\{exe}' -Force")
        placed.append(exe)
    return {"scripts": [p.name for p in scripts], "executables": placed}


def enroll_windows(host: str, agent_name: str | None, user: str,
                    password: str, manager: str,
                    sans_sysmon: bool = False, role: str | None = None) -> dict:
    """Pose l'agent Windows, sa télémétrie complète, puis l'active response."""
    # `options` est concaténé dans un script PowerShell exécuté sur la cible :
    # même exigence que côté Linux.
    host = _validate(host, _RE_HOST, "hote", "192.168.10.20 ou win-dc.lab")
    manager = _validate(manager, _RE_HOST, "manager", "192.168.10.5")
    agent_name = _validate(agent_name or host, _RE_AGENT_NAME, "nom_agent",
                         "WIN-DC")

    if not INSTALL_WINDOWS.is_file():
        raise EnrollmentError(f"{INSTALL_WINDOWS} absent du conteneur.")

    remote = r"C:\Windows\Temp\Install-WazuhAgent-Windows.ps1"
    b64 = base64.b64encode(INSTALL_WINDOWS.read_bytes()).decode()
    _winrm(host, user, password,
           f"[IO.File]::WriteAllBytes('{remote}', "
           f"[Convert]::FromBase64String('{b64}'))")

    name = agent_name or host
    options = f"-Manager {manager} -AgentName {name}"
    if sans_sysmon:
        options += " -SkipSysmon"
    output = _winrm(host, user, password,
                    f"& '{remote}' {options}")

    ar = deploy_ar_windows(host, user, password)
    return {
        "installation": output[-4000:],
        "active_response": ar,
        "role": declare_role(name, role),
        "verification": check_windows(host, user, password),
    }


def check_windows(host: str, user: str, password: str) -> dict:
    """Contrôle sur la machine : service, canaux d'évènements, binaires d'AR."""
    script = f"""
$svc = (Get-Service WazuhSvc -EA SilentlyContinue).Status
$exe = (Get-ChildItem '{BIN_AR_WINDOWS}\\*.exe' -EA SilentlyContinue).Count
$sys = (Get-Service Sysmon64,Sysmon -EA SilentlyContinue | Select -First 1).Status
$cmd = (auditpol /get /subcategory:"{{0CCE922B-69AE-11D9-BED3-505054503030}}" 2>$null | Out-String)
"agent=$svc;ar_exe=$exe;sysmon=$sys;audit_process=$($cmd -match 'Succ')"
"""
    raw = _winrm(host, user, password, script).strip()
    result = {}
    for chunk in raw.split(";"):
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            result[key] = value
    result["brut"] = raw
    return result
