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
from ..server import register

AR_DENIED = (
    "Cet outil agit directement sur le manager Wazuh, sans connaître la "
    "politique d'AURA : agents protégés, groupes d'infrastructure, comptes "
    "système, plancher de clôture. Il est masqué délibérément. Pour remédier, "
    "passer par aura_mitigate_execute, aura_isolate ou aura_unisolate, qui "
    "appliquent ces garde-fous."
)


def _upstream(name: str) -> gateway.Upstream | None:
    return next((a for a in gateway.upstreams() if a.name == name), None)


async def _list(name: str) -> dict:
    upstream = _upstream(name)
    if not upstream:
        return {"disponible": False,
                "raison": f"Aucun serveur MCP {name} configuré "
                          f"(AURA_MCP_{name.upper()}_URL)."}
    tools = await upstream.tools()
    if not tools:
        return {"disponible": False,
                "raison": f"Serveur MCP {name} injoignable — AURA reste "
                          f"interrogeable sans lui."}
    guards = [t for t in tools if gateway.allowed(upstream, t.name)]
    return {
        "disponible": True,
        "outils": [{"name": t.name, "description": t.description,
                    "arguments": t.input_schema} for t in guards],
        "total_amont": len(tools),
        "relayes": len(guards),
        "note": f"{len(tools) - len(guards)} outil(s) de l'amont ne sont pas "
                f"relayés (hors liste d'autorisation, ou action masquée).",
    }


async def _call(name: str, tool: str, arguments: dict | None) -> dict:
    upstream = _upstream(name)
    if not upstream:
        return {"error": f"Aucun serveur MCP {name} configuré."}
    if tool in gateway.WAZUH_MASKED:
        return {"error": f"Outil {tool} masqué.", "explication": AR_DENIED}
    if not gateway.allowed(upstream, tool):
        return {"error": f"Outil {tool} hors de la liste d'autorisation du "
                          f"relais {name}.",
                "conseil": f"Lister les outils relayés avec "
                           f"{name}_tools_list."}
    try:
        return await upstream.call(tool, arguments or {})
    except Exception as e:  # noqa: BLE001
        return {"error": f"Appel {name}.{tool} échoué : {e}"}


@auth.require("aura:read")
async def wazuh_tools_list() -> dict:
    """Les outils Wazuh relayés par AURA, avec leurs arguments.

    Couvre ce que la base AURA ne sait pas dire : l'état du parc d'agents, les
    alertes à la source (AURA n'ingère pas tout), les vulnérabilités, la santé
    de l'infrastructure de détection.

    Les 19 outils d'active response du serveur Wazuh sont **masqués** : ils
    agiraient sans les garde-fous d'AURA. La remédiation passe par les outils
    `aura_*`.
    """
    return await _list("wazuh")


@auth.require("aura:read")
async def wazuh_call(tool: str, arguments: dict | None = None) -> dict:
    """Appelle un outil Wazuh relayé.

    Args:
        outil: nom exact rendu par `wazuh_tools_list`.
        arguments: arguments de l'outil, tels que décrits par son schéma.
    """
    return await _call("wazuh", tool, arguments)


@auth.require("aura:read")
async def iris_tools_list() -> dict:
    """Les outils DFIR-IRIS relayés : dossiers, notes, IOC, actifs, tâches.

    AURA crée et met à jour ses propres cases par `aura_iris_case_sync` — ces
    outils-ci servent au travail d'analyste sur un dossier : ajouter une note,
    un IOC découvert à la main, une tâche.
    """
    return await _list("iris")


@auth.require("aura:write")
async def iris_call(tool: str, arguments: dict | None = None) -> dict:
    """Appelle un outil DFIR-IRIS relayé.

    En `aura:write` : ces outils écrivent dans les dossiers. C'est réversible
    et sans effet sur les machines, mais ce n'est pas de la lecture.

    Args:
        outil: nom exact rendu par `iris_tools_list`.
        arguments: arguments de l'outil, tels que décrits par son schéma.
    """
    return await _call("iris", tool, arguments)


register(wazuh_tools_list)
register(wazuh_call)
register(iris_tools_list)
register(iris_call)
