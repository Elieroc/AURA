#!/usr/bin/env python3
"""Génère le ndjson du dashboard SOC-AI Threat Intel pour Wazuh dashboard (OSD 2.x)."""
import json

IDX = "soc-ai-all-alerts"
OUT = "/home/elie/Nextcloud/Documents/IT/Projets/SOC-AI/wazuh/dashboards/soc-ai-threat-intel.ndjson"

def ref(name="kibanaSavedObjectMeta.searchSourceJSON.index"):
    return {"id": IDX, "name": name, "type": "index-pattern"}

def search_source(query="", filters=None):
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": filters or [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })

def vis(vid, title, vis_state, query=""):
    return {
        "attributes": {
            "title": title,
            "uiStateJSON": "{}",
            "visState": json.dumps(vis_state),
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "id": vid,
        "references": [ref()],
        "type": "visualization",
        "version": "1",
    }

objs = []

# 1. Carte GeoIP des alertes
objs.append(vis("soc-ai-geoip-map", "SOC-AI - Carte des IP sources (GeoIP)", {
    "title": "SOC-AI - Carte des IP sources (GeoIP)",
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
}))

# 2. Alertes par niveau dans le temps
objs.append(vis("soc-ai-alerts-timeline", "SOC-AI - Alertes par niveau (timeline)", {
    "title": "SOC-AI - Alertes par niveau (timeline)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-24h", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "rule.level", "orderBy": "_key", "order": "desc", "size": 15,
                     "otherBucket": False, "otherBucketLabel": "Other",
                     "missingBucket": False, "missingBucketLabel": "Missing"}},
    ],
    "params": {"type": "histogram", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                                  "show": True, "style": {}, "scale": {"type": "linear"},
                                  "labels": {"show": True, "filter": True, "truncate": 100},
                                  "title": {}}],
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
               "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}},
}))

# 3. Top IP par score AbuseIPDB
objs.append(vis("soc-ai-abuseipdb-table", "SOC-AI - Réputation IP (AbuseIPDB)", {
    "title": "SOC-AI - Réputation IP (AbuseIPDB)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "data.abuseipdb.srcip", "orderBy": "1", "order": "desc", "size": 20,
                     "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing", "customLabel": "IP source"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "data.abuseipdb.abuse_confidence_score", "orderBy": "_key", "order": "desc",
                     "size": 5, "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing", "customLabel": "Score abus"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "data.abuseipdb.country_code", "orderBy": "1", "order": "desc",
                     "size": 5, "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing", "customLabel": "Pays"}},
        {"id": "5", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "data.abuseipdb.isp", "orderBy": "1", "order": "desc",
                     "size": 5, "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing", "customLabel": "ISP"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, query="data.abuseipdb.srcip:*"))

# 4. Détections VirusTotal
objs.append(vis("soc-ai-virustotal-table", "SOC-AI - Détections VirusTotal", {
    "title": "SOC-AI - Détections VirusTotal",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alertes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "data.virustotal.source.file", "orderBy": "1", "order": "desc", "size": 20,
                     "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing", "customLabel": "Fichier"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "data.virustotal.positives", "orderBy": "_key", "order": "desc", "size": 5,
                     "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing", "customLabel": "Moteurs positifs"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "agent.name", "orderBy": "1", "order": "desc", "size": 5,
                     "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing", "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, query="data.virustotal.positives:*"))

# 5. Top règles déclenchées
objs.append(vis("soc-ai-top-rules", "SOC-AI - Top règles déclenchées", {
    "title": "SOC-AI - Top règles déclenchées",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": "rule.description", "orderBy": "1", "order": "desc", "size": 10,
                     "otherBucket": True, "otherBucketLabel": "Autres", "missingBucket": False,
                     "missingBucketLabel": "Missing"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}))

# 6. Échecs d'authentification par agent
objs.append(vis("soc-ai-auth-failures", "SOC-AI - Échecs d'authentification", {
    "title": "SOC-AI - Échecs d'authentification",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-24h", "to": "now"},
                     "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "agent.name", "orderBy": "1", "order": "desc", "size": 10,
                     "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                     "missingBucketLabel": "Missing"}},
    ],
    "params": {"type": "histogram", "grid": {"categoryLines": False},
               "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                                  "show": True, "style": {}, "scale": {"type": "linear"},
                                  "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                               "position": "left", "show": True, "style": {},
                               "scale": {"type": "linear", "mode": "normal"},
                               "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                               "title": {"text": "Échecs"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                  "data": {"label": "Count", "id": "1"},
                                  "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                  "lineWidth": 2, "showCircles": True}],
               "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {"show": False},
               "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}},
}, query='rule.groups:("authentication_failed" or "authentication_failures" or "invalid_login") or rule.id:(5710 or 5716 or 5760)'))

# Dashboard : grille 48 colonnes, 15 unités de haut par rangée
panels = []
layout = [
    ("soc-ai-geoip-map",        0,  0, 24, 15),
    ("soc-ai-alerts-timeline", 24,  0, 24, 15),
    ("soc-ai-abuseipdb-table",  0, 15, 24, 15),
    ("soc-ai-virustotal-table",24, 15, 24, 15),
    ("soc-ai-top-rules",        0, 30, 24, 15),
    ("soc-ai-auth-failures",   24, 30, 24, 15),
]
dash_refs = []
for i, (vid, x, y, w, h) in enumerate(layout, 1):
    panels.append({
        "version": "2.13.0",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i),
        "embeddableConfig": {},
        "panelRefName": f"panel_{i}",
    })
    dash_refs.append({"id": vid, "name": f"panel_{i}", "type": "visualization"})

objs.append({
    "attributes": {
        "title": "SOC-AI - Threat Intel",
        "description": "Vue d'ensemble threat intel : GeoIP, réputation IP AbuseIPDB, détections VirusTotal, échecs d'authentification.",
        "hits": 0,
        "timeRestore": True,
        "timeFrom": "now-24h",
        "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 60000},
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "id": "soc-ai-threat-intel",
    "references": dash_refs,
    "type": "dashboard",
    "version": "1",
})

with open(OUT, "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"{len(objs)} objets -> {OUT}")
