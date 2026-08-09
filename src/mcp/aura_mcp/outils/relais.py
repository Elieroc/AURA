"""Relais vers les serveurs MCP Wazuh et DFIR-IRIS.

Deux outils par serveur amont — un pour découvrir, un pour appeler — plutôt
que la trentaine d'outils relayés un par un. C'est le même compromis que celui
qui justifie le gateway : le catalogue amont représente 60 outils, soit
l'essentiel du contexte d'un client avant qu'il ait lu une seule alerte. En
deux étapes, il ne paie que ce qu'il utilise, et le catalogue reste filtré par
la liste d'autorisation.

Le filtre est appliqué **à l'appel**, pas seulement à la découverte : demander
un outil masqué est refusé, même si son nom a été appris ailleurs.
"""

from .. import auth, gateway
from ..serveur import enregistrer

REFUS_AR = (
    "Cet outil agit directement sur le manager Wazuh, sans connaître la "
    "politique d'AURA : agents protégés, groupes d'infrastructure, comptes "
    "système, plancher de clôture. Il est masqué délibérément. Pour remédier, "
    "passer par aura_mitigate_execute, aura_isolate ou aura_unisolate, qui "
    "appliquent ces garde-fous."
)


def _amont(nom: str) -> gateway.Amont | None:
    return next((a for a in gateway.amonts() if a.nom == nom), None)


async def _lister(nom: str) -> dict:
    amont = _amont(nom)
    if not amont:
        return {"disponible": False,
                "raison": f"Aucun serveur MCP {nom} configuré "
                          f"(AURA_MCP_{nom.upper()}_URL)."}
    outils = await amont.outils()
    if not outils:
        return {"disponible": False,
                "raison": f"Serveur MCP {nom} injoignable — AURA reste "
                          f"interrogeable sans lui."}
    gardes = [t for t in outils if gateway.autorise(amont, t.name)]
    return {
        "disponible": True,
        "outils": [{"nom": t.name, "description": t.description,
                    "arguments": t.input_schema} for t in gardes],
        "total_amont": len(outils),
        "relayes": len(gardes),
        "note": f"{len(outils) - len(gardes)} outil(s) de l'amont ne sont pas "
                f"relayés (hors liste d'autorisation, ou action masquée).",
    }


async def _appeler(nom: str, outil: str, arguments: dict | None) -> dict:
    amont = _amont(nom)
    if not amont:
        return {"erreur": f"Aucun serveur MCP {nom} configuré."}
    if outil in gateway.WAZUH_MASQUES:
        return {"erreur": f"Outil {outil} masqué.", "explication": REFUS_AR}
    if not gateway.autorise(amont, outil):
        return {"erreur": f"Outil {outil} hors de la liste d'autorisation du "
                          f"relais {nom}.",
                "conseil": f"Lister les outils relayés avec "
                           f"{nom}_tools_list."}
    try:
        return await amont.appeler(outil, arguments or {})
    except Exception as e:  # noqa: BLE001
        return {"erreur": f"Appel {nom}.{outil} échoué : {e}"}


@auth.exige("aura:read")
async def wazuh_tools_list() -> dict:
    """Les outils Wazuh relayés par AURA, avec leurs arguments.

    Couvre ce que la base AURA ne sait pas dire : l'état du parc d'agents, les
    alertes à la source (AURA n'ingère pas tout), les vulnérabilités, la santé
    de l'infrastructure de détection.

    Les 19 outils d'active response du serveur Wazuh sont **masqués** : ils
    agiraient sans les garde-fous d'AURA. La remédiation passe par les outils
    `aura_*`.
    """
    return await _lister("wazuh")


@auth.exige("aura:read")
async def wazuh_call(outil: str, arguments: dict | None = None) -> dict:
    """Appelle un outil Wazuh relayé.

    Args:
        outil: nom exact rendu par `wazuh_tools_list`.
        arguments: arguments de l'outil, tels que décrits par son schéma.
    """
    return await _appeler("wazuh", outil, arguments)


@auth.exige("aura:read")
async def iris_tools_list() -> dict:
    """Les outils DFIR-IRIS relayés : dossiers, notes, IOC, actifs, tâches.

    AURA crée et met à jour ses propres cases par `aura_iris_case_sync` — ces
    outils-ci servent au travail d'analyste sur un dossier : ajouter une note,
    un IOC découvert à la main, une tâche.
    """
    return await _lister("iris")


@auth.exige("aura:write")
async def iris_call(outil: str, arguments: dict | None = None) -> dict:
    """Appelle un outil DFIR-IRIS relayé.

    En `aura:write` : ces outils écrivent dans les dossiers. C'est réversible
    et sans effet sur les machines, mais ce n'est pas de la lecture.

    Args:
        outil: nom exact rendu par `iris_tools_list`.
        arguments: arguments de l'outil, tels que décrits par son schéma.
    """
    return await _appeler("iris", outil, arguments)


enregistrer(wazuh_tools_list)
enregistrer(wazuh_call)
enregistrer(iris_tools_list)
enregistrer(iris_call)
