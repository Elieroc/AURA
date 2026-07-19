#!/usr/bin/env python3
"""Génère le ndjson des dashboards SOC-AI pour Wazuh dashboard (OSD 2.x).

Dashboards :
- Threat Intel : carte GeoIP, réputation AbuseIPDB, détections VirusTotal
- Global      : timeline des alertes par niveau, compteur global d'événements
- Linux       : top règles, échecs d'auth, top alertes (index wazuh-linux-*)
"""
import json

IDX_ALL = "soc-ai-all-alerts"    # pattern combiné wazuh-alerts-*,wazuh-linux-*,wazuh-windows-*,wazuh-web-*
IDX_LINUX = "wazuh-linux-*"
OUT = "/home/elie/Nextcloud/Documents/IT/Projets/SOC-AI/wazuh/dashboards/soc-ai-dashboards.ndjson"

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

TERMS = {"orderBy": "1", "order": "desc", "otherBucket": False, "otherBucketLabel": "Other",
         "missingBucket": False, "missingBucketLabel": "Missing"}


def vis(vid, title, vis_state, idx, query=""):
    return {
        "attributes": {
            "title": title,
            "uiStateJSON": "{}",
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


def dashboard(did, title, description, layout):
    """layout: liste de (vis_id, x, y, w, h) — grille 48 colonnes"""
    panels, refs = [], []
    for i, (vid, x, y, w, h) in enumerate(layout, 1):
        panels.append({"version": "2.13.0",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                       "panelIndex": str(i), "embeddableConfig": {},
                       "panelRefName": f"panel_{i}"})
        refs.append({"id": vid, "name": f"panel_{i}", "type": "visualization"})
    return {
        "attributes": {
            "title": title,
            "description": description,
            "hits": 0,
            "timeRestore": True,
            "timeFrom": "now-30d",
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

objs.append(vis("soc-ai-alerts-timeline", "Alertes par niveau (timeline)", {
    "title": "Alertes par niveau (timeline)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-30d", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "rule.level", "orderBy": "_key", "size": 15}},
    ],
    "params": HIST_PARAMS,
}, IDX_ALL))

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
}, IDX_LINUX, query="rule.level >= 7"))

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
         "params": {**TERMS, "field": "rule.level", "orderBy": "_key", "size": 3, "customLabel": "Niveau"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 3, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_LINUX, query="rule.level >= 7"))

def hbar_agents(vid, title, metric_label, query=""):
    return vis(vid, title, {
        "title": title,
        "type": "horizontal_bar",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric",
             "params": {"customLabel": metric_label}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {**TERMS, "field": "agent.name", "size": 10, "customLabel": "Agent"}},
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
    }, IDX_LINUX, query=query)


objs.append(hbar_agents("soc-ai-linux-agents-alerts", "Top agents par alertes (niveau ≥ 7)",
                        "Alertes", query="rule.level >= 7"))
objs.append(hbar_agents("soc-ai-linux-agents-logs", "Top agents par volume de logs",
                        "Événements"))

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
    "Vue globale : volume d'événements et répartition des alertes par niveau.",
    [
        ("soc-ai-total-events",     0,  0, 12, 15),
        ("soc-ai-alerts-timeline", 12,  0, 36, 15),
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

with open(OUT, "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"{len(objs)} objets -> {OUT}")
