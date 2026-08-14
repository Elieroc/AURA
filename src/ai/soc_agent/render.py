"""Rendering an incident as text for the LLM.

This is where the whole difficulty sits. A ransomware incident groups 31 alerts;
handing them over raw would be 15,000 tokens for a single verdict. That is paid
per token, and above all it drowns the signal: the longer the context, the less
the model tells apart what actually decides.

So we summarise aggressively, keeping what serves the decision: which rules
fired and how many times, on which host, against which objects, with which
reputation enrichment. The alert-by-alert detail stays in database for the
analyst; the model does not need it to decide.

The rendered text stays in French on purpose: it is the untrusted-data block of
a French prompt (see prompts/system.md), and the model answers in French for the
analysts reading IRIS.
"""

import json
from typing import Any

from .sanitize import detect, neutralize

# Rendering caps. Past them we no longer add information useful to the
# decision, only volume.
MAX_RULES = 6
MAX_OBJECTS = 5
MAX_IPS = 3

# Value of `asset_role` set by correlation when the priority comes from the
# sensor fallback (see assets.agent_priority) and not from the machine's role.
ROLE_SENSOR = "sensor"

# What "P1" means, spelled out. A bare number teaches the model nothing: it
# needs the CONSEQUENCE of a compromise to weigh it in its verdict.
SCALE_PRIORITY = {
    1: "compromission = perte du domaine, du réseau ou de la capacité de "
       "détection ; aucun doute ne se referme tout seul",
    2: "service exposé ou porteur de données, pivot classique",
    3: "serveur interne sans exposition ni donnée sensible",
    4: "poste client, machine de laboratoire ou rôle non déclaré",
}


def _truncate(values: list[str], max_items: int) -> str:
    """Bounded list, with an explicit mention of what is hidden.

    The "(+N autres)" matters: without it the model sees five affected files
    instead of two thousand and underestimates the scale.
    """
    if not values:
        return "-"
    if len(values) <= max_items:
        return ", ".join(values)
    return ", ".join(values[:max_items]) + f" (+{len(values) - max_items} autres)"


def _enrichment(alerts: list[dict]) -> list[str]:
    """Reputation and geolocation, extracted from the raw documents.

    This is the information that flips a verdict — an IP rated 96/100 by
    AbuseIPDB is not just any IP — and it is buried in the JSON.
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
    """Instruction patterns spotted in attacker-controlled fields.

    Their presence in a log field is abnormal in itself. It forbids automatic
    closure of the incident (`actions.apply_guardrails`): a verdict rendered on
    a manipulated context is worthless.
    """
    found: set[str] = set()
    for a in alerts:
        for field in ("rule_desc", "srcuser", "entity"):
            value = a.get(field)
            if value:
                found.update(detect(str(value)))
    return sorted(found)


def render(incident: dict, alerts: list[dict], max_rules: int = MAX_RULES) -> str:
    """Incident + its alerts -> untrusted data block for the prompt.

    `max_rules` bounds the number of rules listed. Triage keeps it low — it only
    needs enough to decide; the report can raise it so the analysis sees the
    whole chain, not just the peak.
    """
    # Grouped by rule: "x25" carries the repetition without paying for the
    # same tokens 25 times over.
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

    # Criticality of the machine. The Wazuh level describes what the rule saw;
    # this one describes what we lose. The same `net user /add` is admin routine
    # on a test box and a domain backdoor on a DC — without this line the model
    # has no way to tell the difference. Roles are spelled out rather than
    # coded: "P1" alone means nothing to it.
    priority = incident.get("priority")
    if priority:
        role = incident.get("asset_role")
        if role == ROLE_SENSOR:
            # The machine's own role (firewall, hypervisor) would be
            # misleading here: what it reports describes OTHER machines. Telling
            # the model changes its analysis — the targeted host is not the one
            # talking.
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

    # UEBA origin: without this explanation the model sees a handful of level
    # 5 alerts and mechanically concludes false positive — which is in fact the
    # right reflex ON THE LEVEL ALONE. What makes the incident judgeable is the
    # measured rarity: "this binary has never been seen on this host nor on any
    # other". A few dozen tokens that beat the raw alerts.
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
