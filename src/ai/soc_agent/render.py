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

from .sanitize import detecter, neutraliser

# Plafonds de rendu. Au-delà, on n'ajoute plus d'information utile à la
# décision, seulement du volume.
MAX_REGLES = 6
MAX_OBJETS = 5
MAX_IPS = 3


def _tronquer(valeurs: list[str], maxi: int) -> str:
    """Liste bornée, avec mention explicite de ce qui est masqué.

    Le « (+N autres) » compte : sans lui, le modèle voit cinq fichiers touchés
    au lieu de deux mille et sous-estime l'ampleur.
    """
    if not valeurs:
        return "-"
    if len(valeurs) <= maxi:
        return ", ".join(valeurs)
    return ", ".join(valeurs[:maxi]) + f" (+{len(valeurs) - maxi} autres)"


def _enrichissement(alertes: list[dict]) -> list[str]:
    """Réputation et géoloc, extraites des documents bruts.

    C'est l'information qui fait basculer un verdict — une IP notée 96/100 par
    AbuseIPDB n'est pas une IP quelconque — et elle est enfouie dans le JSON.
    """
    lignes: list[str] = []
    vus: set[str] = set()

    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        data = raw.get("data", {})

        abuse = data.get("abuseipdb", {})
        if abuse and abuse.get("srcip") not in vus:
            vus.add(abuse.get("srcip"))
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
            lignes.append("  " + ", ".join(détail))

        vt = data.get("virustotal", {})
        if vt and vt.get("source", {}).get("file") not in vus:
            vus.add(vt.get("source", {}).get("file"))
            lignes.append(
                f"  VirusTotal {vt.get('source', {}).get('file')} : "
                f"{vt.get('positives')}/{vt.get('total')} moteurs positifs")

        geo = raw.get("GeoLocation", {})
        if geo.get("country_name") and geo["country_name"] not in vus:
            vus.add(geo["country_name"])
            ville = geo.get("city_name")
            lignes.append(f"  GeoIP : {geo['country_name']}"
                          + (f" ({ville})" if ville else ""))

    return lignes


def motifs_injection(alertes: list[dict]) -> list[str]:
    """Motifs d'instruction repérés dans les champs contrôlés par l'attaquant.

    Leur présence dans un champ de log est anormale en soi. Elle interdit la
    clôture automatique de l'incident (`actions.appliquer_garde_fous`) : un
    verdict rendu sur un contexte manipulé ne vaut rien.
    """
    trouves: set[str] = set()
    for a in alertes:
        for champ in ("rule_desc", "srcuser", "entity"):
            valeur = a.get(champ)
            if valeur:
                trouves.update(detecter(str(valeur)))
    return sorted(trouves)


def rendre(incident: dict, alertes: list[dict], max_regles: int = MAX_REGLES) -> str:
    """Incident + ses alertes -> bloc de données non fiables pour le prompt.

    `max_regles` borne le nombre de règles listées. Le triage le garde bas — il
    n'a besoin que de quoi trancher ; le rapport peut le relever pour que
    l'analyse voie toute la chaîne, pas seulement le pic.
    """
    # Regroupement par règle : « x25 » porte l'information de répétition sans
    # payer 25 fois les mêmes tokens.
    par_regle: dict[str, dict[str, Any]] = {}
    for a in alertes:
        e = par_regle.setdefault(a["rule_id"], {
            "n": 0, "level": a["rule_level"], "desc": a["rule_desc"] or ""})
        e["n"] += 1

    regles = sorted(par_regle.items(),
                    key=lambda kv: (-kv[1]["level"], -kv[1]["n"]))

    lignes = [
        f"hôte             : {incident['agent_name']} (agent {incident['agent_id']})",
        f"période          : {incident['first_seen']:%Y-%m-%d %H:%M:%S} "
        f"-> {incident['last_seen']:%H:%M:%S} UTC",
        f"volume           : {incident['alert_count']} alertes, "
        f"niveau max {incident['max_level']}/15",
    ]

    tactiques = incident.get("mitre_tactics") or []
    if tactiques:
        lignes.append(f"tactiques MITRE  : {', '.join(tactiques)}")

    ips = sorted({a["srcip"] for a in alertes if a["srcip"]})
    if ips:
        lignes.append(f"IP sources       : {_tronquer(ips, MAX_IPS)}")

    comptes = sorted({a["srcuser"] for a in alertes if a["srcuser"]})
    if comptes:
        lignes.append("comptes          : "
                      + _tronquer([neutraliser(c) for c in comptes], MAX_IPS))

    objets = sorted({a["entity"] for a in alertes if a["entity"]})
    if objets:
        lignes.append("objets touchés   : "
                      + _tronquer([neutraliser(o) for o in objets], MAX_OBJETS))

    lignes.append("")
    lignes.append("règles déclenchées :")
    for rid, e in regles[:max_regles]:
        lignes.append(f"  [{rid}] niveau {e['level']:2d}  "
                      f"x{e['n']:<3d} {neutraliser(e['desc'], 110)}")
    if len(regles) > max_regles:
        lignes.append(f"  (+{len(regles) - max_regles} autres règles)")

    enrich = _enrichissement(alertes)
    if enrich:
        lignes.append("")
        lignes.append("enrichissement threat intel :")
        lignes.extend(enrich[:6])

    return "\n".join(lignes)
