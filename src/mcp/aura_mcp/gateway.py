"""Relais des serveurs MCP amont : Wazuh et DFIR-IRIS.

Pourquoi relayer plutôt que laisser le client déclarer trois serveurs :

1. **Budget de contexte.** Le serveur MCP Wazuh expose 54 outils, IRIS une
   dizaine. Ajoutés aux 25 d'AURA, l'inventaire devient le gros du contexte
   d'un client avant qu'il ait lu la moindre alerte. Une liste d'autorisation
   en garde une trentaine, choisis.

2. **Les garde-fous ne doivent pas être contournables.** Le serveur Wazuh
   expose 19 outils d'active response — `wazuh_isolate_host`, `wazuh_kill_process`,
   `wazuh_disable_user`… — qui parlent directement à l'API du manager, sans
   rien connaître des agents protégés d'AURA, des comptes système, ni du
   plancher de clôture. Un client qui les voit peut isoler le pare-feu.
   **Ils sont donc masqués**, sans exception : la remédiation passe par les
   outils `aura_*`, qui appliquent la politique.

3. **Un seul point d'authentification et d'audit.**

Un serveur amont absent n'empêche pas le démarrage : ses outils manquent, le
serveur le dit dans son journal, et le reste fonctionne. AURA doit rester
interrogeable même quand une brique est tombée — c'est souvent à ce
moment-là qu'on en a besoin.
"""

import logging
import os

log = logging.getLogger("aura_mcp.gateway")

# --- Serveurs amont -------------------------------------------------------
WAZUH_URL = os.environ.get("AURA_MCP_WAZUH_URL", "")
WAZUH_TOKEN = os.environ.get("AURA_MCP_WAZUH_TOKEN", "")
IRIS_URL = os.environ.get("AURA_MCP_IRIS_URL", "")
IRIS_TOKEN = os.environ.get("AURA_MCP_IRIS_TOKEN", "")

# Plafond de la réponse d'un outil relayé, plus large que celui d'un champ
# d'alerte : ces réponses sont des inventaires (agents, vulnérabilités), pas
# des fragments de journal.
PLAFOND_RELAI = int(os.environ.get("AURA_MCP_RELAI_MAX", "12000"))

# --- Ce que l'on relaie ---------------------------------------------------
# Liste d'AUTORISATION, jamais d'interdiction : un outil ajouté en amont par
# une montée de version n'apparaît pas tout seul chez les clients. Un nouvel
# outil d'action qui passerait par une liste noire oubliée, si.
WAZUH_AUTORISES = {
    # État du parc — ce que la base AURA ne sait pas dire
    "get_wazuh_agents", "get_wazuh_running_agents", "check_agent_health",
    "get_agent_configuration", "get_agent_ports", "get_agent_processes",
    # Alertes à la source (AURA n'ingère pas tout)
    "get_wazuh_alerts", "get_wazuh_alert_summary", "get_alerts_aggregated",
    "search_security_events", "analyze_alert_patterns",
    "get_top_security_threats",
    # Vulnérabilités et conformité
    "get_wazuh_vulnerabilities", "get_wazuh_critical_vulnerabilities",
    "get_wazuh_vulnerability_summary", "get_sca_policy_checks",
    "run_compliance_check",
    # Santé de l'infrastructure de détection
    "get_wazuh_cluster_health", "get_wazuh_cluster_nodes",
    "get_wazuh_statistics", "get_wazuh_log_collector_stats",
    "get_wazuh_remoted_stats", "get_wazuh_manager_error_logs",
    "search_wazuh_manager_logs", "get_wazuh_rules_summary",
    "validate_wazuh_connection",
}

IRIS_AUTORISES = {
    "list_cases", "get_case", "add_note", "add_ioc", "add_asset", "add_task",
    "add_event", "list_ioc_types", "list_severities",
}

# Masqués explicitement, pour que la raison soit lisible dans le code et non
# seulement dans l'absence d'une entrée. Ce sont les outils qui agiraient sur
# la production en court-circuitant la politique d'AURA.
WAZUH_MASQUES = {
    "wazuh_active_response", "wazuh_isolate_host", "wazuh_unisolate_host",
    "wazuh_check_agent_isolation", "wazuh_block_ip", "wazuh_check_blocked_ip",
    "wazuh_firewall_drop", "wazuh_firewall_allow", "wazuh_host_deny",
    "wazuh_host_allow", "wazuh_kill_process", "wazuh_check_process",
    "wazuh_quarantine_file", "wazuh_restore_file",
    "wazuh_check_file_quarantine", "wazuh_disable_user", "wazuh_enable_user",
    "wazuh_check_user_status", "wazuh_restart",
}

# Tous les outils relayés sont en lecture : l'écriture passe par les outils
# `aura_*`. IRIS fait exception — créer une note ou un IOC dans un dossier est
# du travail d'analyste, réversible, et sans effet sur les machines.
SCOPE_WAZUH = "aura:read"
SCOPE_IRIS = "aura:write"


class Amont:
    """Un serveur MCP amont, joint en HTTP streamable.

    Une session par appel plutôt qu'une session longue : le relais est un
    chemin froid (quelques appels par investigation), et une session longue
    devrait être reconnectée à chaque redémarrage de l'amont — complexité pour
    rien.
    """

    def __init__(self, nom: str, url: str, jeton: str, prefixe: str):
        self.nom = nom
        self.url = url
        self.jeton = jeton
        self.prefixe = prefixe

    async def _session(self):
        import httpx2
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        entetes = {"Authorization": f"Bearer {self.jeton}"} if self.jeton else {}
        http = httpx2.AsyncClient(headers=entetes, timeout=60)
        flux = streamable_http_client(self.url, http_client=http)
        return http, flux, ClientSession

    async def outils(self) -> list:
        """Inventaire de l'amont. Liste vide s'il est injoignable."""
        try:
            http, flux, ClientSession = await self._session()
            async with http, flux as (lire, ecrire):
                async with ClientSession(lire, ecrire) as session:
                    await session.initialize()
                    return list((await session.list_tools()).tools)
        except Exception as e:  # noqa: BLE001
            log.warning("serveur MCP %s injoignable (%s) : ses outils ne "
                        "seront pas relayés", self.nom, e)
            return []

    async def appeler(self, outil: str, arguments: dict) -> dict:
        http, flux, ClientSession = await self._session()
        async with http, flux as (lire, ecrire):
            async with ClientSession(lire, ecrire) as session:
                await session.initialize()
                resultat = await session.call_tool(outil, arguments)
                textes = [getattr(b, "text", str(b)) for b in resultat.content]
                # Borné comme tout le reste : un `get_wazuh_agents` sur un parc
                # de 16 machines rend déjà 8 Ko de JSON. Relayer sans limite
                # annulerait la raison d'être du gateway — le budget de
                # contexte du client.
                from . import sortie
                return {"amont": self.nom, "outil": outil,
                        "erreur": resultat.is_error,
                        "resultat": sortie.borner("\n".join(textes),
                                                  PLAFOND_RELAI)}


def amonts() -> list[Amont]:
    """Les serveurs amont configurés. Vide = gateway désactivé."""
    liste = []
    if WAZUH_URL:
        liste.append(Amont("wazuh", WAZUH_URL, WAZUH_TOKEN, "wazuh_"))
    if IRIS_URL:
        liste.append(Amont("iris", IRIS_URL, IRIS_TOKEN, "iris_"))
    return liste


def autorise(amont: Amont, nom: str) -> bool:
    """Cet outil amont doit-il être relayé ?

    Le nom est comparé nu ET préfixé : les serveurs amont ne nomment pas leurs
    outils de la même façon (`get_wazuh_agents` chez l'un, `wazuh_block_ip`
    chez l'autre pour la même famille).
    """
    if amont.nom == "wazuh":
        if nom in WAZUH_MASQUES or nom.replace("wazuh_", "") in {
                m.replace("wazuh_", "") for m in WAZUH_MASQUES}:
            return False
        return nom in WAZUH_AUTORISES
    return nom in IRIS_AUTORISES
