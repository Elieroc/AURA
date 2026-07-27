#!/usr/bin/env python3
"""Génère le ndjson des dashboards SOC-AI pour Wazuh dashboard (OSD 2.x).

Dashboards :
- Threat Intel : carte GeoIP, réputation AbuseIPDB, détections VirusTotal
- Global      : timeline des alertes par niveau, compteur global d'événements
- Linux       : top règles, échecs d'auth, top alertes (index wazuh-linux-*)
"""
import json

IDX_ALL = "soc-ai-all-alerts"    # pattern combiné wazuh-alerts-*,wazuh-linux-*,wazuh-windows-*,wazuh-web-*,wazuh-firewall-*,wazuh-proxy-*
IDX_LINUX = "wazuh-linux-*"
IDX_WEB = "wazuh-web-*"
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

# Alertes actionnables : sévérité >= Medium (rule.level >= 7)
SEV_ACTIONABLE = 'rule.severity:("Medium" or "High" or "Critical")'

# Couleurs par sévérité (palette Elastic/OSD)
SEV_COLORS = {"vis": {"colors": {
    "Critical": "#BD271E",   # rouge
    "High": "#E7664C",       # orange
    "Medium": "#D6BF57",     # jaune
    "Low": "#54B399",        # vert
    "Info": "#6092C0",       # bleu
}}}

# Tri des buckets sévérité par rule.severity_order (Critical=5 ... Info=1)
SEV_TERMS = {**TERMS, "field": "rule.severity.keyword", "size": 5, "orderBy": "custom", "order": "desc",
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


def dashboard(did, title, description, layout):
    """layout: liste de (obj_id, x, y, w, h[, type]) — grille 48 colonnes.
    type vaut "visualization" (défaut) ou "search"."""
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
         "params": {**TERMS, "field": "data.abuseipdb.srcip.keyword", "size": 20, "customLabel": "IP source"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.abuse_confidence_score", "orderBy": "_key",
                     "size": 5, "customLabel": "Score abus"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.dstip.keyword", "size": 5,
                     "missingBucket": True, "missingBucketLabel": "-", "customLabel": "IP destination"}},
        {"id": "5", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.country_code.keyword", "size": 5, "customLabel": "Pays"}},
        {"id": "6", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.isp.keyword", "size": 5, "customLabel": "ISP"}},
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
         "params": {**TERMS, "field": "data.virustotal.source.file.keyword", "size": 20, "customLabel": "Fichier"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.virustotal.positives", "orderBy": "_key",
                     "size": 5, "customLabel": "Moteurs positifs"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name.keyword", "size": 5, "customLabel": "Machine"}},
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
         "params": {**TERMS, "field": "data.abuseipdb.country_code.keyword", "size": 10, "customLabel": "Pays"}},
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

objs.append(saved_search("soc-ai-latest-alerts", "Dernières alertes (timeline)",
    "Flux chronologique des alertes actionnables (sévérité ≥ Medium), plus récentes en tête.",
    ["agent.name", "rule.severity", "rule.level", "rule.description", "data.srcip"],
    IDX_ALL, query=SEV_ACTIONABLE))

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
         "params": {**TERMS, "field": "rule.description.keyword", "size": 10,
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
         "params": {**TERMS, "field": "agent.name.keyword", "size": 10}},
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
         "params": {**TERMS, "field": "rule.description.keyword", "size": 15, "customLabel": "Alerte"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Sévérité"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name.keyword", "size": 3, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_LINUX, query=SEV_ACTIONABLE))

def hbar_agents(vid, title, metric_label, query=""):
    return vis(vid, title, {
        "title": title,
        "type": "horizontal_bar",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric",
             "params": {"customLabel": metric_label}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {**TERMS, "field": "agent.name.keyword", "size": 10, "customLabel": "Agent"}},
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
         "params": {**TERMS, "field": "rule.description.keyword", "size": 10,
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
         "params": {**TERMS, "field": "rule.description.keyword", "size": 15, "customLabel": "Alerte"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Sévérité"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name.keyword", "size": 3, "customLabel": "Agent"}},
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
         "params": {**TERMS, "field": "agent.name.keyword", "size": 10}},
    ],
    "params": HIST_PARAMS,
}, IDX_WEB))

objs.append(vis("soc-ai-web-top-urls", "Top URLs ciblées", {
    "title": "Top URLs ciblées",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Hits"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.url.keyword", "size": 15, "customLabel": "URL"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.id.keyword", "size": 3, "customLabel": "Code HTTP"}},
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
         "params": {**TERMS, "field": "data.srcip.keyword", "size": 10, "customLabel": "IP source"}},
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
         "params": {**TERMS, "field": "data.id.keyword", "size": 10, "customLabel": "Code HTTP"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}, IDX_WEB))

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
    "Vue globale : volume d'événements, répartition par sévérité, flux des dernières alertes.",
    [
        ("soc-ai-total-events",     0,  0, 12, 15),
        ("soc-ai-alerts-timeline", 12,  0, 36, 15),
        ("soc-ai-latest-alerts",    0, 15, 48, 20, "search"),
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

with open(OUT, "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"{len(objs)} objets -> {OUT}")
