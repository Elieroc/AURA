#!/usr/bin/env python3
"""Génère le ndjson des dashboards Aura-SOC pour Wazuh dashboard (OSD 2.x).

Dashboards :
- Threat Intel : carte GeoIP, réputation AbuseIPDB, détections VirusTotal
- Global      : timeline des alertes par niveau, compteur global d'événements,
                MTTD / MTTR (délais issus de l'index wazuh-ai-*)
- Linux       : top règles, échecs d'auth, top alertes (index wazuh-linux-*)
- Windows     : Event IDs, types d'ouverture de session, processus créés, fichiers
                déposés, accès aux identifiants, PowerShell (index wazuh-windows-*)
- AI          : tokens, coût, latence et qualité des verdicts (index wazuh-ai-*,
                alimenté par le conteneur soc-agent-metrics)
"""
import json
import os

IDX_ALL = "soc-ai-all-alerts"    # pattern combiné wazuh-alerts-*,wazuh-linux-*,wazuh-windows-*,wazuh-web-*,wazuh-firewall-*,wazuh-proxy-*
IDX_LINUX = "wazuh-linux-*"
IDX_WINDOWS = "wazuh-windows-*"
IDX_WEB = "wazuh-web-*"
IDX_YARA = "wazuh-yara-*"
IDX_AI = "wazuh-ai-*"      # métriques d'IA produites par ai/soc_agent/metrics.py
IDX_VOC = "wazuh-voc-*"    # VOC : vulnérabilités du parc, produit par ai/soc_agent/vulns.py
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc-ai-dashboards.ndjson")

HIST_PARAMS = {
    "type": "histogram", "grid": {"categoryLines": False},
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                       "show": True, "style": {}, "scale": {"type": "linear"},
                       "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                    "position": "left", "show": True, "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                    "title": {"text": "Nombre d'alertes"}}],
    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                       "data": {"label": "Count", "id": "1"},
                       "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                       "lineWidth": 2, "showCircles": True}],
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "times": [], "addTimeMarker": False, "labels": {"show": False},
    "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
}

# PIEGE (vecu, 3 allers-retours) : ne JAMAIS ajouter `.keyword` a un champ ici.
# Wazuh declare tous ses champs string en `keyword` PUR dans son template
# (_template/wazuh) — pas en `text` + sous-champ `.keyword` comme le fait le
# mapping dynamique par defaut d'OpenSearch. `agent.name.keyword`,
# `rule.description.keyword`, `data.virustotal.source.file.keyword`... n'existent
# donc pas, et la visualisation affiche "No results found" en silence.
# Les index custom (wazuh-linux-*, wazuh-web-*, wazuh-proxy-*, ...) heritent du
# meme mapping via le template `soc-ai-routing` (clone de celui de wazuh, cf.
# wazuh/README.md) — la regle vaut donc pour eux aussi.
# Verifier avant d'ajouter un champ :
#   curl -sk -u admin:$INDEXER_PASSWORD \
#     "https://localhost:9200/wazuh-alerts-*/_mapping/field/<champ>"
TERMS = {"orderBy": "1", "order": "desc", "otherBucket": False, "otherBucketLabel": "Other",
         "missingBucket": False, "missingBucketLabel": "Missing"}

# Alertes actionnables : sévérité >= Medium (rule.level >= 7)
SEV_ACTIONABLE = 'rule.severity:("Medium" or "High" or "Critical")'

# Ce qu'on REGARDE, par opposition à ce qu'on compte. Même seuil que celui à
# partir duquel le pipeline IA ouvre un incident (config.MIN_LEVEL = 12 ~ High) :
# le flux du dashboard Global montre donc exactement ce que le soc-agent a pu
# prendre en compte, ni plus ni moins.
SEV_HIGH_CRIT = 'rule.severity:("High" or "Critical")'

# Couleurs par sévérité (palette Elastic/OSD)
SEV_COLORS = {"vis": {"colors": {
    "Critical": "#BD271E",   # rouge
    "High": "#E7664C",       # orange
    "Medium": "#D6BF57",     # jaune
    "Low": "#54B399",        # vert
    "Info": "#6092C0",       # bleu
}}}

# Tri des buckets sévérité par rule.severity_order (Critical=5 ... Info=1)
SEV_TERMS = {**TERMS, "field": "rule.severity", "size": 5, "orderBy": "custom", "order": "desc",
             "orderAgg": {"id": "orderAgg", "enabled": True, "type": "max", "schema": "orderAgg",
                          "params": {"field": "rule.severity_order"}}}


def vis(vid, title, vis_state, idx, query="", ui_state=None):
    return {
        "attributes": {
            "title": title,
            "uiStateJSON": json.dumps(ui_state) if ui_state else "{}",
            "visState": json.dumps(vis_state),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": query, "language": "kuery"},
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
            })},
        },
        "id": vid,
        "references": [{"id": idx, "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern"}],
        "type": "visualization",
        "version": "1",
    }


def saved_search(sid, title, description, columns, idx, query="", sort=None):
    """Recherche sauvegardée — liste chronologique d'événements (panneau de dashboard)."""
    return {
        "attributes": {
            "title": title,
            "description": description,
            "hits": 0,
            "columns": columns,
            "sort": sort or [["timestamp", "desc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": query, "language": "kuery"},
                "highlightAll": True,
                "version": True,
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
            })},
        },
        "id": sid,
        "references": [{"id": idx, "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern"}],
        "type": "search",
        "version": "1",
    }


def dashboard(did, title, description, layout, time_from="now-30d"):
    """layout: liste de (obj_id, x, y, w, h[, type]) — grille 48 colonnes.
    type vaut "visualization" (défaut) ou "search".

    `time_from` : fenêtre restaurée à l'ouverture. Paramétrable pour le VOC, dont
    les documents de vulnérabilité sont horodatés à leur PREMIÈRE observation —
    une fenêtre de 30 jours y masquerait justement les plus anciennes, donc les
    plus en retard.
    """
    panels, refs = [], []
    for i, item in enumerate(layout, 1):
        vid, x, y, w, h = item[:5]
        ptype = item[5] if len(item) > 5 else "visualization"
        panels.append({"version": "2.13.0",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                       "panelIndex": str(i), "embeddableConfig": {},
                       "panelRefName": f"panel_{i}"})
        refs.append({"id": vid, "name": f"panel_{i}", "type": ptype})
    return {
        "attributes": {
            "title": title,
            "description": description,
            "hits": 0,
            "timeRestore": True,
            "timeFrom": time_from,
            "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 60000},
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "id": did,
        "references": refs,
        "type": "dashboard",
        "version": "1",
    }


objs = []

# ---------- Visualisations : Threat Intel ----------

objs.append(vis("soc-ai-geoip-map", "Carte des IP sources (GeoIP)", {
    "title": "Carte des IP sources (GeoIP)",
    "type": "tile_map",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "geohash_grid", "schema": "segment",
         "params": {"field": "GeoLocation.location", "autoPrecision": True, "precision": 2,
                     "useGeocentroid": True, "isFilteredByCollar": True}},
    ],
    "params": {"colorSchema": "Yellow to Red", "mapType": "Scaled Circle Markers",
               "isDesaturated": True, "addTooltip": True, "heatClusterSize": 1.5,
               "legendPosition": "bottomright", "mapZoom": 2, "mapCenter": [15, 5],
               "wms": {"enabled": False, "options": {"format": "image/png", "transparent": True}}},
}, IDX_ALL))

objs.append(vis("soc-ai-abuseipdb-table", "Réputation IP (AbuseIPDB)", {
    "title": "Réputation IP (AbuseIPDB)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.srcip", "size": 20, "customLabel": "IP source"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.abuse_confidence_score", "orderBy": "_key",
                     "size": 5, "customLabel": "Score abus"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.dstip", "size": 5,
                     "missingBucket": True, "missingBucketLabel": "-", "customLabel": "IP destination"}},
        {"id": "5", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.country_code", "size": 5, "customLabel": "Pays"}},
        {"id": "6", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.isp", "size": 5, "customLabel": "ISP"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_ALL, query="data.abuseipdb.srcip:*"))

objs.append(vis("soc-ai-virustotal-table", "Détections VirusTotal", {
    "title": "Détections VirusTotal",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.virustotal.source.file", "size": 20, "customLabel": "Fichier"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.virustotal.positives", "orderBy": "_key",
                     "size": 5, "customLabel": "Moteurs positifs"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 5, "customLabel": "Machine"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_ALL, query="data.virustotal.positives:* and not data.virustotal.positives:0"))

objs.append(vis("soc-ai-vt-total", "Détections VirusTotal (total)", {
    "title": "Détections VirusTotal (total)",
    "type": "metric",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Détections VT"}},
    ],
    "params": {"addTooltip": True, "addLegend": False, "type": "metric",
               "metric": {"percentageMode": False, "useRanges": False,
                          "colorSchema": "Green to Red", "metricColorMode": "None",
                          "colorsRange": [{"from": 0, "to": 10000}],
                          "labels": {"show": True},
                          "invertColors": False,
                          "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                     "subText": "", "fontSize": 60}}},
}, IDX_ALL, query="data.virustotal.positives:* and not data.virustotal.positives:0"))

objs.append(vis("soc-ai-abuseipdb-countries", "Top pays (AbuseIPDB)", {
    "title": "Top pays (AbuseIPDB)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Détections"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.abuseipdb.country_code", "size": 10, "customLabel": "Pays"}},
    ],
    "params": {"type": "histogram", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                                  "show": True, "style": {}, "scale": {"type": "linear"},
                                  "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 200},
                                  "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1", "type": "value",
                               "position": "bottom", "show": True, "style": {},
                               "scale": {"type": "linear", "mode": "normal"},
                               "labels": {"show": True, "rotate": 75, "filter": True, "truncate": 100},
                               "title": {"text": "Détections"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Détections", "id": "1"},
                                  "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                  "lineWidth": 2, "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                                  "color": "#E7664C"}},
}, IDX_ALL, query="data.abuseipdb.srcip:*"))

# ---------- Visualisations : Global ----------

objs.append(vis("soc-ai-alerts-timeline", "Alertes par sévérité (timeline)", {
    "title": "Alertes par sévérité (timeline)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": SEV_TERMS},
    ],
    "params": HIST_PARAMS,
}, IDX_ALL, ui_state=SEV_COLORS))

objs.append(saved_search("soc-ai-latest-alerts", "Dernières alertes (High / Critical)",
    "Flux chronologique des alertes High et Critical, plus récentes en tête. "
    "Le seuil ≥ Medium noyait ce flux sous le bruit de scan du reverse proxy — "
    "des dizaines de milliers de 4xx par jour, aucune actionnable.",
    ["agent.name", "rule.severity", "rule.level", "rule.description", "data.srcip",
     "rule.mitre.tactic"],
    IDX_ALL, query=SEV_HIGH_CRIT))

objs.append(vis("soc-ai-total-events", "Nombre d'événements global", {
    "title": "Nombre d'événements global",
    "type": "metric",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Événements"}},
    ],
    "params": {"addTooltip": True, "addLegend": False, "type": "metric",
               "metric": {"percentageMode": False, "useRanges": False,
                          "colorSchema": "Green to Red", "metricColorMode": "None",
                          "colorsRange": [{"from": 0, "to": 10000}],
                          "labels": {"show": True},
                          "invertColors": False,
                          "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                     "subText": "", "fontSize": 60}}},
}, IDX_ALL))

# ---------- Visualisations : Linux (index wazuh-linux-*) ----------

objs.append(vis("soc-ai-top-rules", "Top règles déclenchées", {
    "title": "Top règles déclenchées",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.description", "size": 10,
                     "otherBucket": True, "otherBucketLabel": "Autres"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}, IDX_LINUX, query=SEV_ACTIONABLE))

objs.append(vis("soc-ai-auth-failures", "Échecs d'authentification", {
    "title": "Échecs d'authentification",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "agent.name", "size": 10}},
    ],
    "params": HIST_PARAMS,
}, IDX_LINUX,
   query='rule.groups:("authentication_failed" or "authentication_failures" or "invalid_login") or rule.id:(5710 or 5716 or 5760)'))

objs.append(vis("soc-ai-linux-top-alerts", "Top alertes", {
    "title": "Top alertes",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alerte"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Sévérité"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 3, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_LINUX, query=SEV_ACTIONABLE))

def hbar_agents(vid, title, metric_label, query="", idx=IDX_LINUX, field="agent.name",
                bucket_label="Agent"):
    return vis(vid, title, {
        "title": title,
        "type": "horizontal_bar",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric",
             "params": {"customLabel": metric_label}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {**TERMS, "field": field, "size": 10, "customLabel": bucket_label}},
        ],
        "params": {"type": "histogram", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                                      "show": True, "style": {}, "scale": {"type": "linear"},
                                      "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 200},
                                      "title": {}}],
                   "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1", "type": "value",
                                   "position": "bottom", "show": True, "style": {},
                                   "scale": {"type": "linear", "mode": "normal"},
                                   "labels": {"show": True, "rotate": 75, "filter": True, "truncate": 100},
                                   "title": {"text": metric_label}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                      "data": {"label": metric_label, "id": "1"},
                                      "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                      "lineWidth": 2, "showCircles": True}],
                   "addTooltip": True, "addLegend": False, "legendPosition": "right",
                   "times": [], "addTimeMarker": False, "labels": {},
                   "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                                      "color": "#E7664C"}},
    }, idx, query=query)


objs.append(hbar_agents("soc-ai-linux-agents-alerts", "Top agents par alertes (sévérité ≥ Medium)",
                        "Alertes", query=SEV_ACTIONABLE))
objs.append(hbar_agents("soc-ai-linux-agents-logs", "Top agents par volume de logs",
                        "Événements"))

# ---------- Visualisations : Web (index wazuh-web-*) ----------
# Niveaux des règles web bas (attaques = 6) : le filtre pertinent est le groupe "attack".

objs.append(vis("soc-ai-web-top-rules", "Top règles web (attaques)", {
    "title": "Top règles web (attaques)",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.description", "size": 10,
                     "otherBucket": True, "otherBucketLabel": "Autres"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}, IDX_WEB, query='rule.groups:"attack"'))

objs.append(vis("soc-ai-web-top-alerts", "Top alertes web", {
    "title": "Top alertes web",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alerte"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Sévérité"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 3, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WEB, query='rule.groups:"attack"'))

objs.append(vis("soc-ai-web-timeline", "Alertes web (timeline)", {
    "title": "Alertes web (timeline)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "agent.name", "size": 10}},
    ],
    "params": HIST_PARAMS,
}, IDX_WEB))

objs.append(vis("soc-ai-web-top-urls", "Top URLs ciblées", {
    "title": "Top URLs ciblées",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Hits"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.url", "size": 15, "customLabel": "URL"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.id", "size": 3, "customLabel": "Code HTTP"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WEB, query='rule.groups:"attack"'))

objs.append(vis("soc-ai-web-top-srcips", "Top IP sources web", {
    "title": "Top IP sources web",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Requêtes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.srcip", "size": 10, "customLabel": "IP source"}},
    ],
    "params": {"type": "histogram", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                                  "show": True, "style": {}, "scale": {"type": "linear"},
                                  "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 200},
                                  "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1", "type": "value",
                               "position": "bottom", "show": True, "style": {},
                               "scale": {"type": "linear", "mode": "normal"},
                               "labels": {"show": True, "rotate": 75, "filter": True, "truncate": 100},
                               "title": {"text": "Requêtes"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Requêtes", "id": "1"},
                                  "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                  "lineWidth": 2, "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                                  "color": "#E7664C"}},
}, IDX_WEB))

objs.append(vis("soc-ai-web-http-codes", "Codes HTTP", {
    "title": "Codes HTTP",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.id", "size": 10, "customLabel": "Code HTTP"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}, IDX_WEB))

# ---------- Visualisations : YARA (index wazuh-yara-*) ----------
# Loki/YARITRUST : les logs loki portent leur propre niveau dans data.level
# (ALERT/WARNING/NOTICE) ; la machine scannee est dans data.yara.scanned_host
# (le champ hostname natif de loki est TOUJOURS le scanner, cf. rule 100900).

objs.append(vis("soc-ai-yara-total", "Fichiers malveillants detectes (total)", {
    "title": "Fichiers malveillants detectes (total)",
    "type": "metric",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Matches YARA/IOC"}},
    ],
    "params": {"addTooltip": True, "addLegend": False, "type": "metric",
               "metric": {"percentageMode": False, "useRanges": False,
                          "colorSchema": "Green to Red", "metricColorMode": "None",
                          "colorsRange": [{"from": 0, "to": 10000}],
                          "labels": {"show": True}, "invertColors": False,
                          "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                     "subText": "", "fontSize": 60}}},
}, IDX_YARA))

objs.append(vis("soc-ai-yara-timeline", "Matches YARA par gravite (timeline)", {
    "title": "Matches YARA par gravite (timeline)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "data.level", "size": 3}},
    ],
    "params": HIST_PARAMS,
}, IDX_YARA, ui_state={"vis": {"colors": {"ALERT": "#BD271E", "WARNING": "#E7664C", "NOTICE": "#6092C0"}}}))

objs.append(vis("soc-ai-yara-top-hosts", "Top machines infectees", {
    "title": "Top machines infectees",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Matches"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.yara.scanned_host", "size": 15, "customLabel": "Machine"}},
    ],
    "params": {"type": "histogram", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                                  "show": True, "style": {}, "scale": {"type": "linear"},
                                  "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 200},
                                  "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1", "type": "value",
                               "position": "bottom", "show": True, "style": {},
                               "scale": {"type": "linear", "mode": "normal"},
                               "labels": {"show": True, "rotate": 75, "filter": True, "truncate": 100},
                               "title": {"text": "Matches"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Matches", "id": "1"},
                                  "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                  "lineWidth": 2, "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                                  "color": "#E7664C"}},
}, IDX_YARA))

objs.append(vis("soc-ai-yara-top-files", "Fichiers detectes", {
    "title": "Fichiers detectes",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.file_path", "size": 20, "customLabel": "Fichier"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.yara.scanned_host", "size": 3, "customLabel": "Machine"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.sha256", "size": 1, "customLabel": "SHA256"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_YARA))

objs.append(saved_search("soc-ai-yara-latest", "Derniers matches YARA",
    "Flux chronologique des fichiers detectes par Loki/YARITRUST, plus recents en tete.",
    ["data.yara.scanned_host", "data.score", "rule.severity", "data.file_path", "data.sha256"],
    IDX_YARA))


# ---------- Visualisations : AI (index wazuh-ai-*) ----------
#
# Deux familles de documents dans cet index, toujours filtrer sur `event_type` :
#   event_type:llm_call -> consommation (tokens, latence, coût), un doc par appel
#   event_type:triage   -> qualité (verdict, incohérences, garde-fous)
# Sans ce filtre, un compteur mélange les deux et ne veut rien dire.

Q_LLM = "event_type:llm_call"
Q_TRIAGE = "event_type:triage"

# Couleurs de verdict : vrai positif rouge, faux positif vert, doute jaune.
VERDICT_COLORS = {"vis": {"colors": {
    "true_positive": "#BD271E",
    "false_positive": "#54B399",
    "needs_investigation": "#D6BF57",
}}}


def metric_vis(vid, title, label, idx, query, agg):
    """Grand chiffre unique. `agg` est l'agrégation de métrique (count, sum...)."""
    return vis(vid, title, {
        "title": title,
        "type": "metric",
        "aggs": [{"id": "1", "enabled": True, "schema": "metric",
                  **agg, "params": {**agg.get("params", {}), "customLabel": label}}],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "colorsRange": [{"from": 0, "to": 10 ** 12}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgFill": "#000", "bgColor": False,
                                        "labelColor": False, "subText": "",
                                        "fontSize": 48}}},
    }, idx, query=query)


objs.append(metric_vis("soc-ai-ai-tokens-total", "Tokens consommes (total)",
                       "Tokens", IDX_AI, Q_LLM,
                       {"type": "sum", "params": {"field": "ai.total_tokens"}}))

objs.append(metric_vis("soc-ai-ai-calls-total", "Appels au modele",
                       "Appels", IDX_AI, Q_LLM, {"type": "count"}))

objs.append(metric_vis("soc-ai-ai-cost-total", "Cout estime (USD, approx.)",
                       "USD (approx.)", IDX_AI, Q_LLM,
                       {"type": "sum", "params": {"field": "ai.cost_usd"}}))

objs.append(metric_vis("soc-ai-ai-latency-avg", "Latence moyenne (ms)",
                       "ms", IDX_AI, Q_LLM,
                       {"type": "avg", "params": {"field": "ai.duration_ms"}}))

# Tokens dans le temps, empiles entree/sortie : c'est le rapport entre les deux
# qui explique le cout (la sortie est facturee plus cher partout), et un pic de
# sortie signale un modele qui raisonne long.
objs.append(vis("soc-ai-ai-tokens-timeline", "Tokens dans le temps (entree / sortie)", {
    "title": "Tokens dans le temps (entree / sortie)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.prompt_tokens", "customLabel": "Tokens entree"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.completion_tokens", "customLabel": "Tokens sortie"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Tokens"}}]},
}, IDX_AI, query=Q_LLM,
   ui_state={"vis": {"colors": {"Tokens entree": "#6092C0", "Tokens sortie": "#E7664C"}}}))

# Par appelant : dit OU part le budget. Le triage n'est qu'un des consommateurs
# — le rapport IRIS coute souvent plus cher (4000 tokens de budget contre 3000).
objs.append(vis("soc-ai-ai-tokens-by-usage", "Tokens par usage", {
    "title": "Tokens par usage",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.total_tokens", "customLabel": "Tokens"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "ai.usage", "size": 10, "customLabel": "Usage"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_AI, query=Q_LLM))

# Cout dans le temps. Titre explicite sur l'approximation : les tarifs viennent
# de la grille publique, pas d'une facture (cf. config.LLM_COUT_USD_PAR_MTOKEN_*).
objs.append(vis("soc-ai-ai-cost-timeline", "Cout estime dans le temps (USD, approx.)", {
    "title": "Cout estime dans le temps (USD, approx.)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.cost_usd", "customLabel": "USD (approx.)"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "USD (estimation)"}}]},
}, IDX_AI, query=Q_LLM))

# Part de l'entree servie par le cache : c'est le principal levier de cout, le
# cache hit etant facture 50x moins cher que le cache miss.
objs.append(vis("soc-ai-ai-cache", "Entree : cache hit vs cache miss", {
    "title": "Entree : cache hit vs cache miss",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.cache_hit_tokens", "customLabel": "Cache hit"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.cache_miss_tokens", "customLabel": "Cache miss"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Tokens d'entree"}}]},
}, IDX_AI, query=Q_LLM,
   ui_state={"vis": {"colors": {"Cache hit": "#54B399", "Cache miss": "#E7664C"}}}))

objs.append(vis("soc-ai-ai-calls-by-model", "Appels par modele", {
    "title": "Appels par modele",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Appels"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "ai.model", "size": 10, "customLabel": "Modele"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_AI, query=Q_LLM))

# Latence : moyenne ET 95e centile. La moyenne seule cache les appels qui
# partent en timeout, et c'est le 95e qui dit si le cycle de 5 min tient.
objs.append(vis("soc-ai-ai-latency-timeline", "Latence des appels (moyenne / p95)", {
    "title": "Latence des appels (moyenne / p95)",
    "type": "line",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "ai.duration_ms", "customLabel": "Moyenne (ms)"}},
        {"id": "3", "enabled": True, "type": "percentiles", "schema": "metric",
         "params": {"field": "ai.duration_ms", "percents": [95],
                    "customLabel": "p95 (ms)"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {**HIST_PARAMS, "type": "line",
               "seriesParams": [{"show": True, "type": "line", "mode": "normal",
                                 "data": {"label": "Moyenne (ms)", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Millisecondes"}}]},
}, IDX_AI, query=Q_LLM))

# Budget : un completion_tokens qui colle a max_tokens explique un content vide
# (finish_reason=length sur les modeles raisonnants).
objs.append(vis("soc-ai-ai-budget", "Sortie vs budget par usage", {
    "title": "Sortie vs budget par usage",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "ai.completion_tokens", "customLabel": "Sortie moy."}},
        {"id": "3", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "ai.completion_tokens", "customLabel": "Sortie max"}},
        {"id": "4", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "ai.max_tokens", "customLabel": "Budget"}},
        {"id": "5", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Appels"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "ai.usage", "size": 10, "customLabel": "Usage"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_AI, query=Q_LLM))

objs.append(vis("soc-ai-ai-errors", "Appels en echec", {
    "title": "Appels en echec",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Appels"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "ai.error", "size": 10, "customLabel": "Erreur"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "ai.usage", "size": 5, "customLabel": "Usage"}},
    ],
    "params": {"perPage": 5, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_AI, query="event_type:llm_call and ai.ok:false"))

# ---------- Qualite des verdicts (event_type:triage) ----------

objs.append(vis("soc-ai-ai-verdicts", "Repartition des verdicts", {
    "title": "Repartition des verdicts",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Triages"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "triage.verdict", "size": 5,
                    "customLabel": "Verdict"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_AI, query=Q_TRIAGE, ui_state=VERDICT_COLORS))

objs.append(vis("soc-ai-ai-verdicts-timeline", "Verdicts dans le temps", {
    "title": "Verdicts dans le temps",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "triage.verdict", "size": 5}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Triages"}}]},
}, IDX_AI, query=Q_TRIAGE, ui_state=VERDICT_COLORS))

objs.append(vis("soc-ai-ai-confidence", "Confiance par verdict", {
    "title": "Confiance par verdict",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Triages"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "triage.verdict", "size": 5,
                    "customLabel": "Verdict"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "triage.confidence", "size": 3,
                    "customLabel": "Confiance"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Triages", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Triages"}}]},
}, IDX_AI, query=Q_TRIAGE,
   ui_state={"vis": {"colors": {"high": "#BD271E", "medium": "#D6BF57",
                                "low": "#6092C0"}}}))

# Les trois signaux de degradation lisibles SANS jeu labellise. Une barre qui
# monte ici precede toujours un probleme : prompt casse, ou donnees hostiles.
objs.append(vis("soc-ai-ai-quality", "Garde-fous, incoherences, injections", {
    "title": "Garde-fous, incoherences, injections",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "triage.garde_fou_count", "customLabel": "Garde-fous"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "triage.incoherence_count", "customLabel": "Incoherences"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Occurrences"}}]},
}, IDX_AI, query=Q_TRIAGE,
   ui_state={"vis": {"colors": {"Garde-fous": "#E7664C", "Incoherences": "#D6BF57"}}}))

objs.append(vis("soc-ai-ai-actions", "Actions proposees", {
    "title": "Actions proposees",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "triage.actions", "size": 10,
                    "customLabel": "Action"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Occurrences", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Occurrences"}}]},
}, IDX_AI, query=Q_TRIAGE))

objs.append(vis("soc-ai-ai-cost-by-agent", "Cout et tokens par machine", {
    "title": "Cout et tokens par machine",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Triages"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.prompt_tokens", "customLabel": "Tokens entree"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "incident.agent_name", "size": 15,
                    "customLabel": "Machine"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_AI, query=Q_TRIAGE))

objs.append(saved_search("soc-ai-ai-latest", "Derniers appels au modele",
    "Flux chronologique des appels DeepSeek : usage, tokens, duree, incident.",
    ["ai.usage", "ai.model", "ai.prompt_tokens", "ai.completion_tokens",
     "ai.duration_ms", "ai.ok", "incident.id"],
    IDX_AI, query=Q_LLM))


# ---------- Delais de bout en bout : MTTD / MTTR (event_type:incident_kpi) ----------
#
# Les deux chiffres qu'on demande a un SOC. Ils viennent de l'index wazuh-ai-*
# et NON des alertes : le delai se calcule entre des bornes qui vivent dans
# trois tables Postgres (incidents, triages, mitigations), et OSD ne sait pas
# soustraire deux dates de deux documents. Le calcul est fait a l'export
# (soc_agent/metrics.py, `_doc_kpi`), un document par incident.
#
#   MTTD = premier evenement observe -> incident cree par la correlation.
#   MTTR = incident cree -> premiere remediation REELLEMENT appliquee
#          (statuts execute/confirme/sans_effet ; ni dry_run, ni 'emis' non
#          confirme). Les deux s'additionnent pour le delai total.
#
# La moyenne SEULE ment ici : un seul incident rattrape par le balayage de
# retard (alerte indexee des heures apres l'evenement) la fait tripler. D'ou la
# mediane a cote, et le nombre d'incidents derriere le chiffre — une moyenne sur
# 3 incidents n'a pas le meme poids qu'une moyenne sur 300.
Q_KPI = "event_type:incident_kpi"


def kpi_delai(vid, titre, champ, query, compte_label):
    return vis(vid, titre, {
        "title": titre,
        "type": "metric",
        "aggs": [
            {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
             "params": {"field": champ, "customLabel": "Moyenne (min)"}},
            {"id": "2", "enabled": True, "type": "percentiles", "schema": "metric",
             "params": {"field": champ, "percents": [50],
                        "customLabel": "Mediane (min)"}},
            {"id": "3", "enabled": True, "type": "count", "schema": "metric",
             "params": {"customLabel": compte_label}},
        ],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "colorsRange": [{"from": 0, "to": 10 ** 12}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgFill": "#000", "bgColor": False,
                                        "labelColor": False, "subText": "",
                                        "fontSize": 36}}},
    }, IDX_AI, query=query)


objs.append(kpi_delai(
    "soc-ai-mttd", "MTTD — delai de detection", "kpi.mttd_minutes",
    Q_KPI, "Incidents detectes"))

# Filtre explicite sur l'existence du delai : la moyenne ignorerait les nuls de
# toute facon, mais le COMPTE, lui, dirait « 11 incidents » la ou seuls 3 ont
# ete remedies. Le denominateur affiche doit etre celui de la moyenne affichee.
objs.append(kpi_delai(
    "soc-ai-mttr", "MTTR — delai de remediation", "kpi.mttr_minutes",
    f"{Q_KPI} and kpi.remediated:true", "Incidents remedies"))


def compteur(vid, title, label, query="", idx=IDX_ALL, agg=None):
    """Grand chiffre unique sur l'index combiné."""
    return vis(vid, title, {
        "title": title,
        "type": "metric",
        "aggs": [{"id": "1", "enabled": True, "schema": "metric",
                  **(agg or {"type": "count"}),
                  "params": {**(agg or {}).get("params", {}), "customLabel": label}}],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "colorsRange": [{"from": 0, "to": 10 ** 12}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgFill": "#000", "bgColor": False,
                                        "labelColor": False, "subText": "",
                                        "fontSize": 48}}},
    }, idx, query=query)


objs.append(compteur("soc-ai-actionable-events", "Alertes actionnables (>= Medium)",
                     "Alertes", query=SEV_ACTIONABLE))

objs.append(compteur("soc-ai-highcrit-events", "Alertes High + Critical",
                     "Alertes", query=SEV_HIGH_CRIT))

# Cardinalite sur agent.name : compte les machines qui ont REELLEMENT emis,
# pas les agents enroles. Un agent muet (capteur coupe, agent arrete) fait
# baisser ce chiffre — c'est le but.
objs.append(compteur("soc-ai-active-agents", "Machines emettrices",
                     "Machines",
                     agg={"type": "cardinality", "params": {"field": "agent.name"}}))

objs.append(vis("soc-ai-severity-pie", "Repartition par severite", {
    "title": "Repartition par severite",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": SEV_TERMS},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_ALL, ui_state=SEV_COLORS))

# Evenements par machine, EMPILES par severite : le simple total par host dit
# qui est bavard, pas qui va mal. Une machine avec peu d'evenements mais une
# barre rouge compte davantage qu'une machine noyee sous du niveau 3.
objs.append(vis("soc-ai-events-by-host", "Evenements par machine (par severite)", {
    "title": "Evenements par machine (par severite)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Evenements"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "agent.name", "size": 20,
                    "customLabel": "Machine"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": SEV_TERMS},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Evenements", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Evenements"}}]},
}, IDX_ALL, ui_state=SEV_COLORS))

# Par index : mesure ce que produit CHAQUE capteur, et donc ou part la charge de
# la plateforme. `_index` est un champ meta d'OpenSearch, agregeable tel quel —
# c'est la seule facon de voir le routage (alerts-pipeline.json) depuis une
# visualisation, puisque le nom de l'index n'existe dans aucun champ du document.
objs.append(vis("soc-ai-events-by-index", "Evenements par index (capteur)", {
    "title": "Evenements par index (capteur)",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Evenements"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "_index", "size": 20,
                    "customLabel": "Index"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_ALL))

objs.append(vis("soc-ai-global-top-rules", "Top regles (toutes sources)", {
    "title": "Top regles (toutes sources)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15,
                    "customLabel": "Regle"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.level", "orderBy": "_key", "order": "desc",
                    "size": 3, "customLabel": "Niveau"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_ALL))

# Restreint aux alertes actionnables : sur un parc expose, le top des IP toutes
# severites confondues n'est qu'un classement de scanners.
objs.append(vis("soc-ai-global-top-srcips", "Top IP sources (>= Medium)", {
    "title": "Top IP sources (>= Medium)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.srcip", "size": 15,
                    "customLabel": "IP source"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Alertes", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Alertes"}}]},
}, IDX_ALL, query=SEV_ACTIONABLE))

# Tactiques MITRE : dit a quel STADE d'une intrusion on se trouve. Une bascule
# de Reconnaissance vers Execution/Persistence est le signal qui compte, et il
# ne se lit sur aucun compteur de volume.
objs.append(vis("soc-ai-mitre-tactics", "Tactiques MITRE (>= Medium)", {
    "title": "Tactiques MITRE (>= Medium)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.mitre.tactic", "size": 12,
                    "customLabel": "Tactique"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Alertes", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Alertes"}}]},
}, IDX_ALL, query=SEV_ACTIONABLE))

# ---------- Visualisations : Windows (index wazuh-windows-*) ----------
# Le volume Windows est ecrase par les 4624/4634 (ouverture / fermeture de
# session) : 32 000 des 43 000 evenements, tous en Info. Les panneaux qui
# comptent le bruit (Event IDs, types de session, volume par agent) le lisent
# donc BRUT, et ceux qui montrent une menace filtrent >= Medium ou ciblent un
# comportement precis. Melanger les deux donnerait un dashboard ou tout est vert
# parce que tout est noye.

# Les groupes Wazuh cotes Windows arrivent parfois avec un espace de tete
# (" powershell", " WEF") : la liste <group> des regles built-in est ecrite sur
# plusieurs lignes dans le XML et l'espace d'indentation part dans la valeur.
# `rule.groups:"powershell"` (terme exact sur un keyword) ne matche donc RIEN.
# D'ou les jokers : ce sont eux qui rendent ces requetes fiables, pas du confort.
Q_WIN_CRED = ('rule.groups:(*credential_access* or *lsass_dump* or *mimikatz* or '
              '*kerberoasting* or *ntds_dump* or *dcsync*) or rule.id:(100910 or 100915 or 100918)')
Q_WIN_PS = 'rule.groups:*powershell* or data.win.system.eventID:("4103" or "4104")'
Q_WIN_AUTH_FAIL = ('rule.groups:(*authentication_failed* or *win_authentication_failed*) or '
                   'data.win.system.eventID:("4625" or "4771" or "4776" or "4740")')

objs.append(compteur("soc-ai-win-total-events", "Evenements Windows",
                     "Evenements", idx=IDX_WINDOWS))

objs.append(compteur("soc-ai-win-actionable", "Alertes actionnables (>= Medium)",
                     "Alertes", query=SEV_ACTIONABLE, idx=IDX_WINDOWS))

# Cardinalite sur data.win.system.computer et non agent.name : c'est le nom vu
# DANS l'event, donc le FQDN reel de la machine (WIN-DC.lab.local). Un agent
# dont l'identite a ete clonee depuis un template emet sous le nom d'agent d'une
# autre machine — les deux chiffres divergent alors, et c'est le signal.
objs.append(compteur("soc-ai-win-hosts", "Machines Windows emettrices",
                     "Machines", idx=IDX_WINDOWS,
                     agg={"type": "cardinality",
                          "params": {"field": "data.win.system.computer"}}))

objs.append(compteur("soc-ai-win-cred-count", "Acces aux identifiants",
                     "Evenements", query=Q_WIN_CRED, idx=IDX_WINDOWS))

objs.append(vis("soc-ai-win-timeline", "Alertes Windows par severite (timeline)", {
    "title": "Alertes Windows par severite (timeline)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                     "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group", "params": SEV_TERMS},
    ],
    "params": HIST_PARAMS,
}, IDX_WINDOWS, query=SEV_ACTIONABLE, ui_state=SEV_COLORS))

objs.append(vis("soc-ai-win-mitre", "Tactiques MITRE Windows (>= Medium)", {
    "title": "Tactiques MITRE Windows (>= Medium)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.mitre.tactic", "size": 12,
                    "customLabel": "Tactique"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Alertes", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "categoryAxes": [{**HIST_PARAMS["categoryAxes"][0], "position": "left",
                                 "labels": {"show": True, "rotate": 0, "filter": False,
                                            "truncate": 200}}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0], "name": "BottomAxis-1",
                              "position": "bottom", "title": {"text": "Alertes"}}],
               "addLegend": False},
}, IDX_WINDOWS, query=SEV_ACTIONABLE))

objs.append(vis("soc-ai-win-top-rules", "Top regles Windows (>= Medium)", {
    "title": "Top regles Windows (>= Medium)",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.description", "size": 10,
                     "otherBucket": True, "otherBucketLabel": "Autres"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True,
                                            "last_level": True, "truncate": 100}},
}, IDX_WINDOWS, query=SEV_ACTIONABLE))

objs.append(vis("soc-ai-win-top-alerts", "Top alertes Windows", {
    "title": "Top alertes Windows",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alerte"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severite"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 3, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query=SEV_ACTIONABLE))

# Volume BRUT (pas de filtre severite) : la lecture utile ici est la forme de la
# telemetrie, pas la menace. Un Event ID qui disparait de ce graphe = une
# sous-categorie d'audit qui s'est eteinte sur la machine.
objs.append(hbar_agents("soc-ai-win-event-ids", "Top Event IDs Windows",
                        "Evenements", idx=IDX_WINDOWS,
                        field="data.win.system.eventID", bucket_label="Event ID"))

objs.append(vis("soc-ai-win-logon-types",
                "Ouvertures de session par type (2 interactif, 3 reseau, 5 service, 10 RDP)", {
    "title": "Ouvertures de session par type (2 interactif, 3 reseau, 5 service, 10 RDP)",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Sessions"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.win.eventdata.logonType", "size": 10,
                     "customLabel": "Type"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": True, "values": True,
                                            "last_level": True, "truncate": 100}},
}, IDX_WINDOWS, query='data.win.system.eventID:"4624"'))

objs.append(hbar_agents("soc-ai-win-top-accounts", "Top comptes cibles (ouvertures de session)",
                        "Sessions", idx=IDX_WINDOWS,
                        field="data.win.eventdata.targetUserName", bucket_label="Compte",
                        query='data.win.system.eventID:"4624"'))

objs.append(vis("soc-ai-win-auth-failures", "Echecs d'authentification Windows", {
    "title": "Echecs d'authentification Windows",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                     "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "agent.name", "size": 10}},
    ],
    "params": HIST_PARAMS,
}, IDX_WINDOWS, query=Q_WIN_AUTH_FAIL))

# Filiation parent -> enfant, pas la liste des processus : un powershell.exe
# seul ne dit rien, un powershell.exe lance par winword.exe dit tout.
objs.append(vis("soc-ai-win-processes", "Processus crees (parent -> enfant)", {
    "title": "Processus crees (parent -> enfant)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Executions"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.win.eventdata.parentImage", "size": 10,
                     "customLabel": "Processus parent"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.win.eventdata.image", "size": 3,
                     "customLabel": "Processus cree"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS))

objs.append(vis("soc-ai-win-dropped-files", "Fichiers deposes (Sysmon EID 11)", {
    "title": "Fichiers deposes (Sysmon EID 11)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Depots"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.win.eventdata.targetFilename", "size": 15,
                     "customLabel": "Fichier"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query='data.win.eventdata.targetFilename:*'))

# Regles maison 100910 / 100915 / 100918 (kerberoasting RC4, DCSync, dump lsass)
# + groupes built-in equivalents. C'est le panneau ou une compromission AD se
# voit en premier, d'ou sa place au-dessus du flux brut.
objs.append(vis("soc-ai-win-cred-access", "Acces aux identifiants (lsass, DCSync, Kerberoasting)", {
    "title": "Acces aux identifiants (lsass, DCSync, Kerberoasting)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Evenements"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alerte"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severite"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query=Q_WIN_CRED))

objs.append(vis("soc-ai-win-powershell", "Activite PowerShell", {
    "title": "Activite PowerShell",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Evenements"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alerte"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severite"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query=Q_WIN_PS))

objs.append(hbar_agents("soc-ai-win-agents-alerts", "Top agents Windows par alertes (>= Medium)",
                        "Alertes", query=SEV_ACTIONABLE, idx=IDX_WINDOWS))
objs.append(hbar_agents("soc-ai-win-agents-logs", "Top agents Windows par volume de logs",
                        "Evenements", idx=IDX_WINDOWS))

objs.append(saved_search("soc-ai-win-latest", "Dernieres alertes Windows (High / Critical)",
    "Flux chronologique des alertes Windows High et Critical, plus recentes en tete. "
    "Colonnes choisies pour trancher sans ouvrir le document : qui (targetUserName), "
    "sur quoi (computer), avec quoi (commandLine).",
    ["agent.name", "rule.severity", "rule.level", "rule.description",
     "data.win.system.eventID", "data.win.eventdata.targetUserName",
     "data.win.eventdata.commandLine"],
    IDX_WINDOWS, query=SEV_HIGH_CRIT))

# ---------- Dashboards ----------

objs.append(dashboard("soc-ai-threat-intel", "Threat Intel",
    "Threat intel : carte GeoIP des IP sources, réputation AbuseIPDB, détections VirusTotal.",
    [
        ("soc-ai-geoip-map",             0,  0, 48, 16),
        ("soc-ai-abuseipdb-table",       0, 16, 24, 14),
        ("soc-ai-virustotal-table",     24, 16, 24, 14),
        ("soc-ai-vt-total",              0, 30, 12, 12),
        ("soc-ai-abuseipdb-countries",  12, 30, 36, 12),
    ]))

objs.append(dashboard("soc-ai-global", "Global",
    "Vue globale : volume et severite, delais de detection et de remediation "
    "(MTTD / MTTR), repartition par machine et par capteur, tactiques MITRE, "
    "flux des alertes High/Critical.",
    [
        ("soc-ai-total-events",       0,  0, 12, 10),
        ("soc-ai-actionable-events", 12,  0, 12, 10),
        ("soc-ai-highcrit-events",   24,  0, 12, 10),
        ("soc-ai-active-agents",     36,  0, 12, 10),
        # Deuxieme ligne : ce que la plateforme MET DE TEMPS a faire, en face de
        # ce qu'elle voit. Volontairement au-dessus des courbes de volume : un
        # SOC se juge sur ces deux chiffres avant de se juger sur son debit.
        ("soc-ai-mttd",               0, 10, 24, 10),
        ("soc-ai-mttr",              24, 10, 24, 10),
        ("soc-ai-alerts-timeline",    0, 20, 32, 15),
        ("soc-ai-severity-pie",      32, 20, 16, 15),
        ("soc-ai-events-by-host",     0, 35, 32, 16),
        ("soc-ai-events-by-index",   32, 35, 16, 16),
        ("soc-ai-global-top-rules",   0, 51, 26, 14),
        ("soc-ai-mitre-tactics",     26, 51, 22, 14),
        ("soc-ai-global-top-srcips",  0, 65, 24, 14),
        ("soc-ai-geoip-map",         24, 65, 24, 14),
        ("soc-ai-latest-alerts",      0, 79, 48, 20, "search"),
    ]))

objs.append(dashboard("soc-ai-linux", "Linux",
    "Alertes Linux (index wazuh-linux-*) : top règles, top alertes, échecs d'authentification.",
    [
        ("soc-ai-top-rules",        0,  0, 24, 15),
        ("soc-ai-linux-top-alerts",24,  0, 24, 15),
        ("soc-ai-auth-failures",    0, 15, 48, 14),
        ("soc-ai-linux-agents-alerts", 0, 29, 24, 12),
        ("soc-ai-linux-agents-logs",  24, 29, 24, 12),
    ]))

objs.append(dashboard("soc-ai-windows", "Windows",
    "Alertes Windows / Active Directory (index wazuh-windows-*) : Event IDs, "
    "ouvertures de session, echecs d'authentification, filiation de processus, "
    "fichiers deposes, acces aux identifiants (lsass / DCSync / Kerberoasting), "
    "activite PowerShell.",
    [
        ("soc-ai-win-total-events",   0,  0, 12, 10),
        ("soc-ai-win-actionable",    12,  0, 12, 10),
        ("soc-ai-win-cred-count",    24,  0, 12, 10),
        ("soc-ai-win-hosts",         36,  0, 12, 10),
        ("soc-ai-win-timeline",       0, 10, 32, 15),
        ("soc-ai-win-mitre",         32, 10, 16, 15),
        ("soc-ai-win-top-rules",      0, 25, 24, 15),
        ("soc-ai-win-top-alerts",    24, 25, 24, 15),
        ("soc-ai-win-event-ids",      0, 40, 20, 14),
        ("soc-ai-win-logon-types",   20, 40, 12, 14),
        ("soc-ai-win-top-accounts",  32, 40, 16, 14),
        ("soc-ai-win-auth-failures",  0, 54, 48, 13),
        ("soc-ai-win-processes",      0, 67, 26, 15),
        ("soc-ai-win-dropped-files", 26, 67, 22, 15),
        ("soc-ai-win-cred-access",    0, 82, 24, 14),
        ("soc-ai-win-powershell",    24, 82, 24, 14),
        ("soc-ai-win-agents-alerts",  0, 96, 24, 12),
        ("soc-ai-win-agents-logs",   24, 96, 24, 12),
        ("soc-ai-win-latest",         0, 108, 48, 20, "search"),
    ]))

objs.append(dashboard("soc-ai-web", "Web",
    "Alertes web (index wazuh-web-*) : attaques, URLs ciblées, IP sources, codes HTTP.",
    [
        ("soc-ai-web-top-rules",   0,  0, 24, 15),
        ("soc-ai-web-top-alerts", 24,  0, 24, 15),
        ("soc-ai-web-timeline",    0, 15, 48, 12),
        ("soc-ai-web-top-urls",    0, 27, 24, 13),
        ("soc-ai-web-top-srcips", 24, 27, 12, 13),
        ("soc-ai-web-http-codes", 36, 27, 12, 13),
    ]))

objs.append(dashboard("soc-ai-yara", "YARA",
    "Scans YARA/IOC Loki (YARITRUST, index wazuh-yara-*) : fichiers malveillants detectes par machine.",
    [
        ("soc-ai-yara-total",     0,  0, 12, 12),
        ("soc-ai-yara-timeline", 12,  0, 36, 12),
        ("soc-ai-yara-top-hosts", 0, 12, 24, 14),
        ("soc-ai-yara-top-files",24, 12, 24, 14),
        ("soc-ai-yara-latest",    0, 26, 48, 20, "search"),
    ]))

objs.append(dashboard("soc-ai-ai", "AI",
    "Utilisation du modele (index wazuh-ai-*) : tokens, cout, latence, et "
    "qualite des verdicts rendus par le triage.",
    [
        ("soc-ai-ai-tokens-total",     0,  0, 12, 10),
        ("soc-ai-ai-calls-total",     12,  0, 12, 10),
        ("soc-ai-ai-cost-total",      24,  0, 12, 10),
        ("soc-ai-ai-latency-avg",     36,  0, 12, 10),
        ("soc-ai-ai-tokens-timeline",  0, 10, 32, 14),
        ("soc-ai-ai-tokens-by-usage", 32, 10, 16, 14),
        ("soc-ai-ai-latency-timeline", 0, 24, 32, 13),
        ("soc-ai-ai-calls-by-model",  32, 24, 16, 13),
        ("soc-ai-ai-cost-timeline",    0, 37, 32, 13),
        ("soc-ai-ai-cache",           32, 37, 16, 13),
        ("soc-ai-ai-budget",           0, 50, 24, 12),
        ("soc-ai-ai-errors",          24, 50, 24, 12),
        ("soc-ai-ai-verdicts",         0, 62, 16, 14),
        ("soc-ai-ai-verdicts-timeline",16, 62, 32, 14),
        ("soc-ai-ai-confidence",       0, 76, 24, 13),
        ("soc-ai-ai-actions",         24, 76, 24, 13),
        ("soc-ai-ai-quality",          0, 89, 32, 13),
        ("soc-ai-ai-cost-by-agent",   32, 89, 16, 13),
        ("soc-ai-ai-latest",           0, 102, 48, 20, "search"),
    ]))

# ---------- Visualisations : VOC (index wazuh-voc-*) ----------
#
# Trois natures de documents dans le meme index pattern, distinguees par
# event_type (meme convention que wazuh-ai-*) :
#
#   voc_parc  : une ligne par passage du scanner — compteurs du parc entier.
#               C'est la SERIE TEMPORELLE : burn-down, flux, couverture.
#   voc_asset : une ligne par machine par passage — score d'exposition.
#   voc_vuln  : une ligne par vulnerabilite, REECRITE a chaque passage, dans
#               l'index STABLE wazuh-voc-vulns. Horodatee a sa premiere
#               observation, pas au run : c'est ce qui permet de lire l'age.
#
# PIEGE, consequence directe : toute visualisation basee sur voc_vuln est
# tributaire de la fenetre de temps du dashboard. Une fenetre de 30 jours
# masquerait les vulnerabilites vues il y a plus de 30 jours — c'est-a-dire
# exactement les plus vieilles, donc les plus en retard, donc les seules qui
# comptent pour un VOC. D'ou le time_from a 3 ans sur ce dashboard.

Q_PARC = "event_type:voc_parc"
Q_ASSET = "event_type:voc_asset"
Q_VULN_OUVERTE = "event_type:voc_vuln and voc.statut:ouverte"
Q_VULN_CORRIGEE = "event_type:voc_vuln and voc.resolue:true"


def dernier(vid, titre, champ, label, query=Q_PARC, taille=48):
    """Grand chiffre = DERNIERE valeur relevee, via top_hits.

    Pas `max` ni `avg` : ces documents sont des JAUGES, pas des evenements. Un
    `max` sur 30 jours afficherait le pic de dette du mois en le faisant passer
    pour l'etat courant — exactement le contraire de ce qu'un VOC doit montrer.
    """
    return vis(vid, titre, {
        "title": titre,
        "type": "metric",
        "aggs": [{"id": "1", "enabled": True, "type": "top_hits",
                  "schema": "metric",
                  "params": {"field": champ, "aggregate": "concat", "size": 1,
                             "sortField": "timestamp", "sortOrder": "desc",
                             "customLabel": label}}],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "colorsRange": [{"from": 0, "to": 10 ** 12}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgFill": "#000", "bgColor": False,
                                        "labelColor": False, "subText": "",
                                        "fontSize": taille}}},
    }, IDX_VOC, query=query)


objs.append(dernier("soc-ai-voc-ouvertes", "Vulnerabilites ouvertes",
                    "voc.ouvertes", "Ouvertes"))
objs.append(dernier("soc-ai-voc-critical", "Dont critiques",
                    "voc.critical", "Critical"))
objs.append(dernier("soc-ai-voc-horssla", "Hors delai (SLA depasse)",
                    "voc.hors_sla_total", "Hors SLA"))
objs.append(dernier("soc-ai-voc-score-max", "Machine la plus exposee (score)",
                    "voc.score_max", "Score /100"))

# La couverture d'abord, et en premier ecran du dashboard. Une dette qui baisse
# parce que des machines ont cesse de repondre n'est pas une amelioration : sans
# ce chiffre a cote du burn-down, rien ne permet de faire la difference. Le VOC
# de la flotte a deja connu ce type d'angle mort (auditd absent partout, agents
# clones muets) — la lecon est cablee ici.
objs.append(dernier("soc-ai-voc-couverture", "Couverture d'inventaire",
                    "voc.couverture_pct", "% des machines connues", taille=36))
objs.append(dernier("soc-ai-voc-muettes", "Machines sans inventaire",
                    "voc.machines_muettes", "Machines", taille=36))

# Burn-down : la dette par severite dans le temps. `max` par intervalle et non
# `avg` : plusieurs passages par intervalle relevent la meme jauge, la moyenne
# lisserait une variation reelle survenue entre deux scans.
objs.append(vis("soc-ai-voc-burndown", "Dette de vulnerabilites dans le temps", {
    "title": "Dette de vulnerabilites dans le temps",
    "type": "area",
    "aggs": [
        {"id": "1", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "voc.critical", "customLabel": "Critical"}},
        {"id": "3", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "voc.high", "customLabel": "High"}},
        {"id": "4", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "voc.medium", "customLabel": "Medium"}},
        {"id": "5", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "voc.low", "customLabel": "Low"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-90d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {"type": "area", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                  "position": "bottom", "show": True, "style": {},
                                  "scale": {"type": "linear"},
                                  "labels": {"show": True, "filter": True, "truncate": 100},
                                  "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                               "position": "left", "show": True, "style": {},
                               "scale": {"type": "linear", "mode": "normal"},
                               "labels": {"show": True, "rotate": 0, "filter": False,
                                          "truncate": 100},
                               "title": {"text": "Vulnerabilites ouvertes"}}],
               "seriesParams": [
                   {"show": True, "type": "area", "mode": "stacked",
                    "data": {"label": lbl, "id": i}, "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": True, "lineWidth": 2,
                    "showCircles": False, "interpolate": "linear"}
                   for i, lbl in (("1", "Critical"), ("3", "High"),
                                  ("4", "Medium"), ("5", "Low"))],
               "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {"show": False},
               "thresholdLine": {"show": False, "value": 10, "width": 1,
                                  "style": "full", "color": "#E7664C"}},
}, IDX_VOC, query=Q_PARC,
   ui_state={"vis": {"colors": {"Critical": "#BD271E", "High": "#EC7014",
                                "Medium": "#F5C700", "Low": "#6092C0"}}}))

# Capacite de remediation : ce qui arrive contre ce qui part. Une dette stable
# avec un flux eleve des deux cotes n'a pas le meme sens qu'une dette stable
# sans aucun mouvement — la premiere est un parc vivant, la seconde un parc
# abandonne. `sum` ici (et non `max`) : ce sont des DELTAS par passage.
objs.append(vis("soc-ai-voc-flux", "Vulnerabilites apparues / corrigees", {
    "title": "Vulnerabilites apparues / corrigees",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "voc.nouvelles", "customLabel": "Apparues"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "voc.corrigees", "customLabel": "Corrigees"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-90d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "1d", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Vulnerabilites"}}]},
}, IDX_VOC, query=Q_PARC,
   ui_state={"vis": {"colors": {"Apparues": "#E7664C", "Corrigees": "#54B399"}}}))

# MTTR de remediation. `voc.age_jours` porte deux sens selon le statut — age
# tant que c'est ouvert, delai de correction une fois resolu — d'ou le filtre
# `voc.resolue:true`, sans lequel ce chiffre melangerait la dette et la vitesse.
objs.append(vis("soc-ai-voc-mttr", "Delai moyen de correction", {
    "title": "Delai moyen de correction",
    "type": "metric",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "voc.age_jours", "customLabel": "Moyenne (jours)"}},
        {"id": "2", "enabled": True, "type": "percentiles", "schema": "metric",
         "params": {"field": "voc.age_jours", "percents": [50],
                    "customLabel": "Mediane (jours)"}},
        {"id": "3", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Vulnerabilites corrigees"}},
    ],
    "params": {"addTooltip": True, "addLegend": False, "type": "metric",
               "metric": {"percentageMode": False, "useRanges": False,
                          "colorSchema": "Green to Red", "metricColorMode": "None",
                          "colorsRange": [{"from": 0, "to": 10 ** 12}],
                          "labels": {"show": True}, "invertColors": False,
                          "style": {"bgFill": "#000", "bgColor": False,
                                    "labelColor": False, "subText": "",
                                    "fontSize": 36}}},
}, IDX_VOC, query=Q_VULN_CORRIGEE))

objs.append(vis("soc-ai-voc-mttr-severite", "Delai de correction par severite", {
    "title": "Delai de correction par severite",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "voc.age_jours", "customLabel": "Jours (moyenne)"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "vulnerability.severity", "size": 6,
                    "customLabel": "Severite"}},
    ],
    "params": {"type": "histogram", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                  "position": "left", "show": True, "style": {},
                                  "scale": {"type": "linear"},
                                  "labels": {"show": True, "rotate": 0, "filter": False,
                                             "truncate": 200}, "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1", "type": "value",
                               "position": "bottom", "show": True, "style": {},
                               "scale": {"type": "linear", "mode": "normal"},
                               "labels": {"show": True, "rotate": 75, "filter": True,
                                          "truncate": 100},
                               "title": {"text": "Jours"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Jours (moyenne)", "id": "1"},
                                  "valueAxis": "ValueAxis-1",
                                  "drawLinesBetweenPoints": True, "lineWidth": 2,
                                  "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1,
                                  "style": "full", "color": "#E7664C"}},
}, IDX_VOC, query=Q_VULN_CORRIGEE))

# Score d'exposition par machine. `max` sur voc.score et non un compte de
# documents : chaque passage ecrit une ligne par machine, donc un `count` classerait
# les agents par nombre de scans — c'est-a-dire par rien du tout. Le max sur la
# fenetre donne le pire etat de la machine, ce qu'on veut dans une liste de
# priorisation. Trie par la metrique (orderBy "1"), pas alphabetiquement.
objs.append(vis("soc-ai-voc-score-agents",
                "Machines les plus exposees (score /100)", {
    "title": "Machines les plus exposees (score /100)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "voc.score", "customLabel": "Score /100"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "agent.name", "size": 20,
                    "customLabel": "Machine"}},
    ],
    "params": {"type": "histogram", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                  "position": "left", "show": True, "style": {},
                                  "scale": {"type": "linear"},
                                  "labels": {"show": True, "rotate": 0,
                                             "filter": False, "truncate": 200},
                                  "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1",
                               "type": "value", "position": "bottom", "show": True,
                               "style": {}, "scale": {"type": "linear", "mode": "normal"},
                               "labels": {"show": True, "rotate": 75, "filter": True,
                                          "truncate": 100},
                               "title": {"text": "Score d'exposition /100"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Score /100", "id": "1"},
                                  "valueAxis": "ValueAxis-1",
                                  "drawLinesBetweenPoints": True, "lineWidth": 2,
                                  "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1,
                                  "style": "full", "color": "#E7664C"}},
}, IDX_VOC, query=Q_ASSET))

objs.append(vis("soc-ai-voc-risque-priorite",
                "Vulnerabilites ouvertes par priorite d'asset", {
    "title": "Vulnerabilites ouvertes par priorite d'asset",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Vulnerabilites"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "asset.priorite_label", "orderBy": "_key",
                    "order": "asc", "size": 4, "customLabel": "Priorite"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "vulnerability.severity", "size": 6,
                    "customLabel": "Severite"}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Vulnerabilites ouvertes"}}]},
}, IDX_VOC, query=Q_VULN_OUVERTE,
   ui_state={"vis": {"colors": {"critical": "#BD271E", "high": "#EC7014",
                                "medium": "#F5C700", "low": "#6092C0"}}}))

# Top paquets : le meilleur retour sur investissement de patch. Un seul paquet
# (le meta-paquet noyau) porte souvent la moitie de la dette d'un hote Debian —
# ce panneau evite de la traiter CVE par CVE.
objs.append(vis("soc-ai-voc-top-paquets", "Paquets porteurs de la dette", {
    "title": "Paquets porteurs de la dette",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Vulnerabilites"}},
        {"id": "3", "enabled": True, "type": "cardinality", "schema": "metric",
         "params": {"field": "agent.name", "customLabel": "Machines"}},
        {"id": "4", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "vulnerability.score_base",
                    "customLabel": "Pire CVSS"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "package.name", "size": 20,
                    "customLabel": "Paquet"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False,
               "showMetricsAtAllLevels": False, "showTotal": False,
               "totalFunc": "sum", "percentageCol": ""},
}, IDX_VOC, query=Q_VULN_OUVERTE))

# La file d'attente reelle du VOC : ce qui a depasse son delai, trie par retard.
# Une recherche sauvegardee et non une table d'agregation, pour que l'analyste
# puisse ouvrir la ligne, voir le paquet exact et pivoter.
objs.append(saved_search(
    "soc-ai-voc-horssla-liste", "Vulnerabilites hors delai (a traiter)",
    "Vulnerabilites ouvertes dont le SLA (severite x priorite de l'asset) est "
    "depasse, du plus gros retard au plus faible.",
    ["agent.name", "asset.priorite_label", "vulnerability.id",
     "vulnerability.severity", "vulnerability.score_base", "package.name",
     "package.version", "voc.age_jours", "voc.sla_jours", "voc.retard_jours"],
    IDX_VOC, query="event_type:voc_vuln and voc.hors_sla:true",
    sort=[["voc.retard_jours", "desc"]]))

objs.append(dashboard("soc-ai-voc", "VOC",
    "Gestion des vulnerabilites du parc (index wazuh-voc-*, alimente par le "
    "conteneur soc-agent-vulns) : dette, capacite de remediation, respect des "
    "delais, et couverture d'inventaire. La couverture se lit AVANT le "
    "burn-down : une dette qui baisse parce qu'une machine a cesse de repondre "
    "n'est pas une amelioration.",
    [
        ("soc-ai-voc-ouvertes",       0,  0, 12, 10),
        ("soc-ai-voc-critical",      12,  0, 12, 10),
        ("soc-ai-voc-horssla",       24,  0, 12, 10),
        ("soc-ai-voc-score-max",     36,  0, 12, 10),
        ("soc-ai-voc-couverture",     0, 10, 24,  8),
        ("soc-ai-voc-muettes",       24, 10, 24,  8),
        ("soc-ai-voc-burndown",       0, 18, 48, 15),
        ("soc-ai-voc-flux",           0, 33, 32, 14),
        ("soc-ai-voc-mttr",          32, 33, 16, 14),
        ("soc-ai-voc-score-agents",   0, 47, 24, 15),
        ("soc-ai-voc-risque-priorite", 24, 47, 24, 15),
        ("soc-ai-voc-mttr-severite",  0, 62, 16, 14),
        ("soc-ai-voc-top-paquets",   16, 62, 32, 14),
        ("soc-ai-voc-horssla-liste",  0, 76, 48, 20, "search"),
    ],
    # 3 ans : les documents `voc_vuln` sont horodates a leur PREMIERE
    # observation. Une fenetre courte masquerait les vulnerabilites les plus
    # anciennes — donc les plus en retard — et le panneau « hors delai »
    # afficherait le contraire de la verite.
    time_from="now-3y"))

with open(OUT, "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"{len(objs)} objets -> {OUT}")
