"""Rendu d'un incident en texte pour le LLM.

Toute la difficulté est là. Un incident ransomware regroupe 31 alertes ; les
donner brutes ferait 15 000 tokens pour un seul verdict. C'est payé au token, et
surtout noyé : plus le contexte est long, moins le modèle distingue ce qui
tranche.

On résume donc agressivement, en gardant ce qui sert à décider : quelles règles
ont tiré et combien de fois, sur quel hôte, contre quels objets, avec quel
enrichissement de réputation. Le détail alerte par alerte reste en base pour
l'analyste ; le modèle n'en a pas besoin pour trancher.
"""

import json
from typing import Any

from .sanitize import detect, neutralize

# Plafonds de rendu. Au-delà, on n'ajoute plus d'information utile à la
# décision, seulement du volume.
MAX_RULES = 6
MAX_OBJECTS = 5
MAX_IPS = 3

# Valeur de `asset_role` posée par la corrélation quand la priorité vient du
# rabattement capteur (cf. assets.priorite_agent) et non du rôle de la machine.
ROLE_SENSOR = "sensor"

# Ce que « P1 » signifie, en clair. Un chiffre nu n'apprend rien au modèle : il
# lui faut la CONSÉQUENCE d'une compromission pour la peser dans son verdict.
SCALE_PRIORITY = {
    1: "compromission = perte du domaine, du réseau ou de la capacité de "
       "détection ; aucun doute ne se referme tout seul",
    2: "service exposé ou porteur de données, pivot classique",
    3: "serveur interne sans exposition ni donnée sensible",
    4: "poste client, machine de laboratoire ou rôle non déclaré",
}


def _truncate(values: list[str], max_items: int) -> str:
    """Liste bornée, avec mention explicite de ce qui est masqué.

    Le « (+N autres) » compte : sans lui, le modèle voit cinq fichiers touchés
    au lieu de deux mille et sous-estime l'ampleur.
    """
    if not values:
        return "-"
    if len(values) <= max_items:
        return ", ".join(values)
    return ", ".join(values[:max_items]) + f" (+{len(values) - max_items} autres)"


def _enrichment(alerts: list[dict]) -> list[str]:
    """Réputation et géoloc, extraites des documents bruts.

    C'est l'information qui fait basculer un verdict — une IP notée 96/100 par
    AbuseIPDB n'est pas une IP quelconque — et elle est enfouie dans le JSON.
    """
    lines: list[str] = []
    seen: set[str] = set()

    for a in alerts:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        data = raw.get("data", {})

        abuse = data.get("abuseipdb", {})
        if abuse and abuse.get("srcip") not in seen:
            seen.add(abuse.get("srcip"))
            détail = [f"AbuseIPDB {abuse.get('srcip')} : score "
                      f"{abuse.get('abuse_confidence_score')}/100"]
            if abuse.get("total_reports"):
                détail.append(f"{abuse['total_reports']} signalements")
            if abuse.get("country_code"):
                détail.append(f"pays {abuse['country_code']}")
            if str(abuse.get("is_tor", "")).lower() == "true":
                détail.append("noeud Tor")
            if abuse.get("isp"):
                détail.append(f"ISP {abuse['isp']}")
            lines.append("  " + ", ".join(détail))

        vt = data.get("virustotal", {})
        if vt and vt.get("source", {}).get("file") not in seen:
            seen.add(vt.get("source", {}).get("file"))
            lines.append(
                f"  VirusTotal {vt.get('source', {}).get('file')} : "
                f"{vt.get('positives')}/{vt.get('total')} moteurs positifs")

        geo = raw.get("GeoLocation", {})
        if geo.get("country_name") and geo["country_name"] not in seen:
            seen.add(geo["country_name"])
            city = geo.get("city_name")
            lines.append(f"  GeoIP : {geo['country_name']}"
                          + (f" ({city})" if city else ""))

    return lines


def injection_patterns(alerts: list[dict]) -> list[str]:
    """Motifs d'instruction repérés dans les champs contrôlés par l'attaquant.

    Leur présence dans un champ de log est anormale en soi. Elle interdit la
    clôture automatique de l'incident (`actions.appliquer_garde_fous`) : un
    verdict rendu sur un contexte manipulé ne vaut rien.
    """
    found: set[str] = set()
    for a in alerts:
        for field in ("rule_desc", "srcuser", "entity"):
            value = a.get(field)
            if value:
                found.update(detect(str(value)))
    return sorted(found)


def render(incident: dict, alerts: list[dict], max_rules: int = MAX_RULES) -> str:
    """Incident + ses alertes -> bloc de données non fiables pour le prompt.

    `max_regles` borne le nombre de règles listées. Le triage le garde bas — il
    n'a besoin que de quoi trancher ; le rapport peut le relever pour que
    l'analyse voie toute la chaîne, pas seulement le pic.
    """
    # Regroupement par règle : « x25 » porte l'information de répétition sans
    # payer 25 fois les mêmes tokens.
    by_rule: dict[str, dict[str, Any]] = {}
    for a in alerts:
        e = by_rule.setdefault(a["rule_id"], {
            "n": 0, "level": a["rule_level"], "desc": a["rule_desc"] or ""})
        e["n"] += 1

    rules = sorted(by_rule.items(),
                    key=lambda kv: (-kv[1]["level"], -kv[1]["n"]))

    lines = [
        f"hôte             : {incident['agent_name']} (agent {incident['agent_id']})",
        f"période          : {incident['first_seen']:%Y-%m-%d %H:%M:%S} "
        f"-> {incident['last_seen']:%H:%M:%S} UTC",
        f"volume           : {incident['alert_count']} alertes, "
        f"niveau max {incident['max_level']}/15",
    ]

    # Criticité de la machine. Le niveau Wazuh décrit ce que la règle a vu ;
    # celui-ci décrit ce qu'on perd. Le même `net user /add` est une routine
    # d'admin sur un poste de test et un backdoor de domaine sur un DC — sans
    # cette ligne, le modèle n'a aucun moyen de faire la différence. Les rôles
    # sont explicités plutôt que codés : « P1 » seul ne veut rien dire pour lui.
    priority = incident.get("priority")
    if priority:
        role = incident.get("asset_role")
        if role == ROLE_SENSOR:
            # Le rôle propre de la machine (pare-feu, hyperviseur) serait ici
            # trompeur : ce qu'elle remonte décrit d'AUTRES machines. Le dire au
            # modèle change son analyse — l'hôte visé n'est pas celui qui parle.
            detail = ("agent capteur — sa télémétrie décrit l'activité d'autres "
                      "machines (IDS, hyperviseur), la machine réellement "
                      "concernée est à identifier dans les données")
        else:
            detail = SCALE_PRIORITY.get(int(priority), "")
        lines.append(
            f"criticité asset  : P{priority}"
            + ("" if role == ROLE_SENSOR else
               f" — {role}" if role else " — rôle non déclaré")
            + f" ({detail})")

    tactics = incident.get("mitre_tactics") or []
    if tactics:
        lines.append(f"tactiques MITRE  : {', '.join(tactics)}")

    # Origine UEBA : sans cette explication, le modèle voit une poignée
    # d'alertes de niveau 5 et conclut mécaniquement au faux positif — c'est
    # d'ailleurs le bon réflexe SUR LE NIVEAU SEUL. Ce qui rend l'incident
    # jugeable, c'est la rareté mesurée : « ce binaire n'a jamais été vu sur cet
    # hôte ni sur aucun autre ». Quelques dizaines de tokens qui remplacent
    # avantageusement les alertes brutes.
    if incident.get("ueba"):
        lines.append("")
        lines.append(
            "origine          : moteur comportemental UEBA (aucune règle de "
            "niveau >= 12 n'a tiré ; l'incident est ouvert sur un écart "
            f"statistique au comportement habituel, score {incident.get('ueba_score')})")
        patterns = incident.get("ueba_patterns") or []
        if patterns:
            lines.append("écarts mesurés (le niveau des règles est BAS, "
                          "c'est la rareté qui porte le signal) :")
            for m in patterns[:6]:
                value = m.get("value") or ""
                scope = ("sur cet hôte" if m.get("scope") == "host"
                          else "pour ce compte sur cet hôte")
                lines.append(
                    f"  {m.get('trait')} {neutralize(str(value), 80)} "
                    f"{scope} — {m.get('note')} (+{m.get('bits')} bits)")

    ips = sorted({a["srcip"] for a in alerts if a["srcip"]})
    if ips:
        lines.append(f"IP sources       : {_truncate(ips, MAX_IPS)}")

    accounts = sorted({a["srcuser"] for a in alerts if a["srcuser"]})
    if accounts:
        lines.append("comptes          : "
                      + _truncate([neutralize(c) for c in accounts], MAX_IPS))

    objects = sorted({a["entity"] for a in alerts if a["entity"]})
    if objects:
        lines.append("objets touchés   : "
                      + _truncate([neutralize(o) for o in objects], MAX_OBJECTS))

    lines.append("")
    lines.append("règles déclenchées :")
    for rid, e in rules[:max_rules]:
        lines.append(f"  [{rid}] niveau {e['level']:2d}  "
                      f"x{e['n']:<3d} {neutralize(e['desc'], 110)}")
    if len(rules) > max_rules:
        lines.append(f"  (+{len(rules) - max_rules} autres règles)")

    enrich = _enrichment(alerts)
    if enrich:
        lines.append("")
        lines.append("enrichissement threat intel :")
        lines.extend(enrich[:6])

    return "\n".join(lines)
