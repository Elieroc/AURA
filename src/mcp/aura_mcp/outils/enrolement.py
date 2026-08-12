"""Outils d'enrôlement : mettre une machine sous surveillance AURA.

`aura:admin` : installer un agent modifie durablement la machine cible
(paquets, politique d'audit, compte d'administration, exécution root déléguée
au manager par le canal d'active response).

Le point qui compte plus que l'installation elle-même : la **vérification**.
Un agent « installé » qui n'émet pas d'`execve`, ou dont les scripts d'active
response manquent, produit exactement la même chose qu'une machine saine —
rien. C'est pour cela que chaque enrôlement se termine par un contrôle lu sur
la machine, et que l'outil dit franchement ce qui n'est pas encore bon.
"""

from soc_agent import config as soc_config

from .. import auth, enrolement, sortie
from ..serveur import enregistrer


@auth.exige("aura:admin")
def aura_enroll_agent(
    hote: str,
    systeme: str,
    nom_agent: str | None = None,
    manager: str | None = None,
    ssh_user: str = "root",
    winrm_user: str | None = None,
    winrm_password: str | None = None,
    sans_sysmon: bool = False,
    role: str | None = None,
    confirmer: bool = False,
) -> dict:
    """Installe un agent Wazuh complet sur une machine. MODIFIE LA MACHINE.

    Pose les quatre étages sans lesquels la couverture est illusoire : l'agent,
    la télémétrie que les règles attendent, les scripts d'active response, et
    l'accès d'administration du SOC.

    **Linux** (Debian/Ubuntu, accès SSH par clé) : agent Wazuh épinglé, auditd
    avec le jeu de règles `execve` d'AURA, `/etc/ld.so.preload` créé pour être
    surveillable, scripts d'active response, compte `wazuh-admin` en sudo sans
    mot de passe accessible par la clé du SOC.

    **Windows** (WinRM) : agent, audit de création de processus AVEC ligne de
    commande, sous-catégories d'audit AD, journalisation ScriptBlock
    PowerShell, Sysmon, abonnement de l'agent aux canaux — puis les scripts
    d'active response Windows/AD et leurs lanceurs `.exe` compilés.

    Après un enrôlement Linux, un REDÉMARRAGE est presque toujours nécessaire :
    tant que journald tient le socket netlink, auditd n'émet rien et la machine
    paraît calme alors qu'elle est muette. La vérification le signale.

    Côté Windows, il reste une étape sur le MANAGER : déclarer les blocs
    `<command>`/`<active-response>` (`aura_manager_ar_status` le vérifie). Sans
    eux, `execd` refuse chaque action sans le dire, l'API répondant 200.

    Args:
        hote: adresse IP ou nom de la machine à enrôler.
        systeme: `linux` ou `windows`.
        nom_agent: nom enregistré sur le manager (défaut : l'hôte).
        manager: adresse du manager Wazuh (défaut : `WAZUH_MANAGER_IP`).
        ssh_user: compte SSH pour un enrôlement Linux — doit être root ou
            pouvoir le devenir.
        winrm_user: compte administrateur Windows.
        winrm_password: mot de passe associé.
        sans_sysmon: Windows seulement — sauter l'installation de Sysmon
            (hôte sans accès Internet).
        role: rôle de la machine, qui fixe sa PRIORITÉ (P1-P4) dans le SOC :
            `dc`, `firewall`, `soc`, `hypervisor`, `pki`, `backup` (P1) ;
            `web`, `db`, `mail`, `proxy`, `dns`, `vpn`, `fileserver` (P2) ;
            `serveur`, `admin` (P3) ; `endpoint`, `lab` (P4). L'agent est rangé
            dans le groupe Wazuh `role-<role>`, qui est la source de vérité.
            **Sans rôle, la machine est traitée en P4** — ses incidents passent
            en fin de file et sa sévérité est minorée d'un niveau. À déclarer
            même approximativement : un rôle discutable vaut mieux qu'un asset
            critique invisible.
        confirmer: doit valoir `true` pour agir. À `false` (défaut), l'outil
            rend le plan sans rien toucher.
    """
    systeme = systeme.lower().strip()
    if systeme not in ("linux", "windows"):
        return {"erreur": "systeme doit valoir 'linux' ou 'windows'."}

    manager = manager or enrolement.MANAGER
    if not manager:
        return {"erreur": "Adresse du manager inconnue : passer `manager` ou "
                          "renseigner WAZUH_MANAGER_IP dans le .env."}
    if systeme == "windows" and not (winrm_user and winrm_password):
        return {"erreur": "winrm_user et winrm_password sont requis pour "
                          "Windows."}

    plan = _plan(systeme, hote, nom_agent or hote, manager, sans_sysmon, role)
    if not confirmer:
        return {"execute": False, "plan": plan,
                "raison": "confirmer=false — la machine n'a pas été touchée."}

    try:
        if systeme == "linux":
            resultat = enrolement.enroler_linux(hote, nom_agent, ssh_user,
                                                manager, role)
        else:
            resultat = enrolement.enroler_windows(
                hote, nom_agent, winrm_user, winrm_password, manager,
                sans_sysmon, role)
    except enrolement.ErreurEnrolement as e:
        # Un enrôlement peut échouer à mi-chemin. Le dire avec l'étape fautive
        # vaut mieux qu'une trace : la machine est peut-être à moitié
        # configurée, et c'est une information opérationnelle.
        return {"execute": True, "succes": False, "erreur": str(e),
                "avertissement": "La machine peut être partiellement "
                                 "configurée. Relancer l'outil est sans "
                                 "danger : les recettes sont idempotentes."}

    return {"execute": True, "succes": True, "systeme": systeme,
            "hote": hote, "manager": manager,
            **sortie.jsonifiable(resultat),
            "suite": _suite(systeme)}


def _plan(systeme: str, hote: str, nom: str, manager: str,
          sans_sysmon: bool, role: str | None = None) -> list[str]:
    classement = (
        f"Ranger l'agent dans le groupe role-{role} et l'inscrire dans la CMDB."
        if role else
        f"AUCUN rôle déclaré : la machine sera traitée en "
        f"P{soc_config.PRIORITE_DEFAUT} (fin de file d'analyse, sévérité "
        f"minorée). Passer `role` pour la classer.")
    if systeme == "linux":
        return [
            f"Copier les recettes d'AURA sur {hote} (SSH par clé).",
            f"Installer l'agent Wazuh, enrôlé sur {manager} sous le nom {nom}.",
            "Installer auditd et le jeu de règles execve d'AURA "
            "(préfixe zz- obligatoire, sinon le -D de Debian les efface).",
            "Créer /etc/ld.so.preload s'il manque, pour le rendre surveillable.",
            "Poser les scripts d'active response.",
            "Créer le compte wazuh-admin (sudo sans mot de passe, SSH par clé).",
            classement,
            "Vérifier sur la machine, et signaler si un redémarrage est requis.",
        ]
    return [
        f"Pousser la recette d'installation sur {hote} (WinRM).",
        f"Installer l'agent Wazuh, enrôlé sur {manager} sous le nom {nom}.",
        "Activer l'audit de création de processus AVEC ligne de commande, "
        "les sous-catégories AD et la journalisation ScriptBlock.",
        "Installer Sysmon." if not sans_sysmon else "Sauter Sysmon (demandé).",
        "Abonner l'agent aux canaux Sysmon et PowerShell Operational.",
        "Pousser les scripts d'active response Windows/AD, compiler le "
        "wrapper et le recopier sous le nom de chaque action.",
        classement,
        "Vérifier sur la machine.",
    ]


def _suite(systeme: str) -> list[str]:
    commun = [
        "Vérifier que l'agent remonte : aura_alerts_search sur son nom.",
        "Déclencher une action inoffensive et contrôler le retour "
        "(aura_ar_reconcile) — ne jamais se fier au 200 de l'API.",
    ]
    if systeme == "linux":
        return ["REDÉMARRER la machine si la vérification le demande : sans "
                "cela auditd n'émet rien et la machine paraîtra calme.",
                *commun]
    return ["Déclarer les blocs <command>/<active-response> Windows sur le "
            "manager (aura_manager_ar_status le vérifie) : sans eux execd "
            "refuse chaque action en silence.",
            *commun]


@auth.exige("aura:read")
def aura_agent_health(hote: str, systeme: str, nom_agent: str | None = None,
                      ssh_user: str = "root",
                      winrm_user: str | None = None,
                      winrm_password: str | None = None) -> dict:
    """Cette machine est-elle réellement couverte ? Contrôle sur pièces.

    Ne modifie rien. Répond à la question que le tableau de bord ne sait pas
    poser : l'agent est vert, mais **émet-il** ? Un agent connecté dont
    l'audit noyau est coupé, ou dont les scripts d'active response manquent,
    est indiscernable d'une machine saine — jusqu'au jour où on lui demande
    quelque chose.

    Deux points décident, et aucun ne se lit sur un tableau de bord :

    - `surveille` : le manager voit-il cet agent `active` ET la machine
      porte-t-elle bien SA propre identité ? Une machine clonée hérite du
      `client.keys` de son modèle, présente une identité déjà prise, et boucle
      en connexion/déconnexion — tout en paraissant parfaitement installée.
    - `redemarrage_requis` : tant que journald tient le socket netlink, auditd
      n'émet rien.

    Args:
        hote: adresse de la machine.
        systeme: `linux` ou `windows`.
        nom_agent: nom attendu côté manager. Sans lui, le contrôle reste local
            et ne peut pas dire si la machine est réellement surveillée.
        ssh_user: compte SSH (Linux).
        winrm_user: compte administrateur (Windows).
        winrm_password: mot de passe associé (Windows).
    """
    systeme = systeme.lower().strip()
    try:
        if systeme == "linux":
            etat = enrolement.verifier_linux(hote, ssh_user, nom_agent)
        elif systeme == "windows":
            if not (winrm_user and winrm_password):
                return {"erreur": "winrm_user et winrm_password requis."}
            etat = enrolement.verifier_windows(hote, winrm_user,
                                               winrm_password)
        else:
            return {"erreur": "systeme doit valoir 'linux' ou 'windows'."}
    except enrolement.ErreurEnrolement as e:
        return {"hote": hote, "joignable": False, "erreur": str(e)}
    # `joignable` vient de la vérification elle-même : côté Linux, chaque
    # contrôle est une commande distante qui peut échouer seule.
    return {"hote": hote, "systeme": systeme, "joignable": True, **etat}


@auth.exige("aura:read")
def aura_manager_ar_status() -> dict:
    """Les actions de remédiation déclarées côté manager sont-elles au complet ?

    `execd` valide chaque action demandée contre le `ar.conf` que le manager
    génère depuis ses blocs `<command>`. Une action absente est refusée **sans
    message** : l'API répond 200 et rien ne se produit sur la machine. C'est le
    mode d'échec le plus coûteux d'AURA, parce qu'il ressemble à un succès.

    Cet outil compare les actions attendues par le pipeline à ce que le manager
    déclare réellement.
    """
    import re

    conf = enrolement.DEPOT / "src/wazuh/config/wazuh_cluster/wazuh_manager.conf"
    if not conf.is_file():
        return {"erreur": f"{conf} illisible depuis le conteneur — la racine "
                          f"du dépôt doit être montée sur {enrolement.DEPOT}."}
    texte = conf.read_text(encoding="utf-8", errors="replace")
    declarees = set(re.findall(r"<command>\s*<name>([^<]+)</name>", texte))
    declarees |= set(re.findall(r"<name>([^<]+)</name>\s*<executable>", texte))
    referencees = set(re.findall(
        r"<active-response>.*?<command>([^<]+)</command>", texte, re.S))

    attendues = set(soc_config.__dict__.get("AR_ATTENDUES", ())) or {
        "firewall-drop", "firewall-allow", "host-deny", "host-allow",
        "disable-account", "enable-account", "host-isolate", "host-unisolate",
        "kill-process", "quarantine", "win-host-isolate", "win-host-unisolate",
        "win-kill-process", "win-quarantine-file", "win-restore-file",
        "win-block-ip", "win-allow-ip", "ad-disable-account",
        "ad-enable-account", "ad-remove-group-member", "ad-add-group-member",
    }

    return {
        "declarees": sorted(declarees),
        "referencees_par_un_active_response": sorted(referencees),
        "manquantes": sorted(attendues - declarees),
        "declarees_mais_non_referencees": sorted(declarees - referencees),
        "rappel": "Une action déclarée mais jamais référencée par un bloc "
                  "<active-response> est refusée par execd, même appelée par "
                  "l'API. Le motif rules_id 999999 (règle inexistante) sert "
                  "exactement à cela : référencer sans déclencher.",
    }


enregistrer(aura_enroll_agent)
enregistrer(aura_agent_health)
enregistrer(aura_manager_ar_status)
