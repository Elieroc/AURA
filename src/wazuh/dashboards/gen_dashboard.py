#!/usr/bin/env python3
"""Generates the ndjson of the Aura-SOC dashboards for Wazuh dashboard (OSD 2.x).

Dashboards:
- Threat Intel : GeoIP map, AbuseIPDB reputation, VirusTotal detections
- Global      : timeline of alerts by level, global event counter,
                MTTD / MTTR (delays taken from the wazuh-ai-* index)
- Linux       : top rules, auth failures, top alerts (wazuh-linux-* index)
- Windows     : Event IDs, logon types, processes created, files
                dropped, credential access, PowerShell (wazuh-windows-* index)
- AI          : tokens, cost, latency and verdict quality (wazuh-ai-* index,
                fed by the soc-agent-metrics container)
"""
import json
import os

IDX_ALL = "soc-ai-all-alerts"    # combined pattern wazuh-alerts-*,wazuh-linux-*,wazuh-windows-*,wazuh-web-*,wazuh-firewall-*,wazuh-proxy-*
IDX_LINUX = "wazuh-linux-*"
IDX_WINDOWS = "wazuh-windows-*"
IDX_WEB = "wazuh-web-*"
IDX_YARA = "wazuh-yara-*"
IDX_AI = "wazuh-ai-*"      # AI metrics produced by ai/soc_agent/metrics.py
IDX_VOC = "wazuh-voc-*"    # VOC: fleet vulnerabilities, produced by ai/soc_agent/vulns.py
IDX_ARCHIVE = "wazuh-archive-*"  # Archive catalog, produced by ai/soc_agent/archive_metrics.py
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
                    "title": {"text": "Number of alerts"}}],
    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                       "data": {"label": "Count", "id": "1"},
                       "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                       "lineWidth": 2, "showCircles": True}],
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "times": [], "addTimeMarker": False, "labels": {"show": False},
    "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
}

# TRAP (learned the hard way, 3 round-trips): NEVER append `.keyword` to a field here.
# Wazuh declares all its string fields as PURE `keyword` in its template
# (_template/wazuh) — not as `text` + `.keyword` sub-field like OpenSearch's
# default dynamic mapping does. `agent.name.keyword`,
# `rule.description.keyword`, `data.virustotal.source.file.keyword`... therefore
# do not exist, and the visualization silently shows "No results found".
# The custom indices (wazuh-linux-*, wazuh-web-*, wazuh-proxy-*, ...) inherit the
# same mapping via the `soc-ai-routing` template (a clone of Wazuh's own, cf.
# wazuh/README.md) — the rule therefore applies to them too.
# Check before adding a field:
#   curl -sk -u admin:$INDEXER_PASSWORD \
#     "https://localhost:9200/wazuh-alerts-*/_mapping/field/<field>"
TERMS = {"orderBy": "1", "order": "desc", "otherBucket": False, "otherBucketLabel": "Other",
         "missingBucket": False, "missingBucketLabel": "Missing"}

# Actionable alerts: severity >= Medium (rule.level >= 7)
SEV_ACTIONABLE = 'rule.severity:("Medium" or "High" or "Critical")'

# What we LOOK at, as opposed to what we count. Same threshold as the one above
# which the AI pipeline opens an incident (config.MIN_LEVEL = 12 ~ High):
# the Global dashboard's stream therefore shows exactly what the soc-agent could
# take into account, no more, no less.
SEV_HIGH_CRIT = 'rule.severity:("High" or "Critical")'

# Colors by severity (Elastic/OSD palette)
SEV_COLORS = {"vis": {"colors": {
    "Critical": "#BD271E",   # red
    "High": "#E7664C",       # orange
    "Medium": "#D6BF57",     # yellow
    "Low": "#54B399",        # green
    "Info": "#6092C0",       # blue
}}}

# Sort severity buckets by rule.severity_order (Critical=5 ... Info=1)
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
    """Saved search — chronological list of events (dashboard panel)."""
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
    """layout: list of (obj_id, x, y, w, h[, type]) — 48-column grid.
    type is "visualization" (default) or "search".

    `time_from`: window restored on open. Configurable for the VOC, whose
    vulnerability documents are timestamped at their FIRST observation —
    a 30-day window would precisely hide the oldest ones, i.e. the
    most overdue.
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

# ---------- Visualizations: Threat Intel ----------

objs.append(vis("soc-ai-geoip-map", "Source IP map (GeoIP)", {
    "title": "Source IP map (GeoIP)",
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

objs.append(vis("soc-ai-abuseipdb-table", "IP reputation (AbuseIPDB)", {
    "title": "IP reputation (AbuseIPDB)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alerts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.srcip", "size": 20, "customLabel": "Source IP"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.abuse_confidence_score", "orderBy": "_key",
                     "size": 5, "customLabel": "Abuse score"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.dstip", "size": 5,
                     "missingBucket": True, "missingBucketLabel": "-", "customLabel": "Destination IP"}},
        {"id": "5", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.country_code", "size": 5, "customLabel": "Country"}},
        {"id": "6", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.abuseipdb.isp", "size": 5, "customLabel": "ISP"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_ALL, query="data.abuseipdb.srcip:*"))

objs.append(vis("soc-ai-virustotal-table", "VirusTotal detections", {
    "title": "VirusTotal detections",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alerts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.virustotal.source.file", "size": 20, "customLabel": "File"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.virustotal.positives", "orderBy": "_key",
                     "size": 5, "customLabel": "Positive engines"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 5, "customLabel": "Machine"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_ALL, query="data.virustotal.positives:* and not data.virustotal.positives:0"))

objs.append(vis("soc-ai-vt-total", "VirusTotal detections (total)", {
    "title": "VirusTotal detections (total)",
    "type": "metric",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "VT detections"}},
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

objs.append(vis("soc-ai-abuseipdb-countries", "Top countries (AbuseIPDB)", {
    "title": "Top countries (AbuseIPDB)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Detections"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.abuseipdb.country_code", "size": 10, "customLabel": "Country"}},
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
                               "title": {"text": "Detections"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Detections", "id": "1"},
                                  "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                  "lineWidth": 2, "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                                  "color": "#E7664C"}},
}, IDX_ALL, query="data.abuseipdb.srcip:*"))

# ---------- Visualizations: Global ----------

objs.append(vis("soc-ai-alerts-timeline", "Alerts by severity (timeline)", {
    "title": "Alerts by severity (timeline)",
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

objs.append(saved_search("soc-ai-latest-alerts", "Latest alerts (High / Critical)",
    "Chronological stream of High and Critical alerts, most recent first. "
    "The >= Medium threshold drowned this stream under the reverse proxy's scan "
    "noise — tens of thousands of 4xx per day, none of them actionable.",
    ["agent.name", "rule.severity", "rule.level", "rule.description", "data.srcip",
     "rule.mitre.tactic"],
    IDX_ALL, query=SEV_HIGH_CRIT))

objs.append(vis("soc-ai-total-events", "Global event count", {
    "title": "Global event count",
    "type": "metric",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Events"}},
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

# ---------- Visualizations: Linux (wazuh-linux-* index) ----------

objs.append(vis("soc-ai-top-rules", "Top triggered rules", {
    "title": "Top triggered rules",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.description", "size": 10,
                     "otherBucket": True, "otherBucketLabel": "Other"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}, IDX_LINUX, query=SEV_ACTIONABLE))

objs.append(vis("soc-ai-auth-failures", "Authentication failures", {
    "title": "Authentication failures",
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

objs.append(vis("soc-ai-linux-top-alerts", "Top alerts", {
    "title": "Top alerts",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alert"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severity"}},
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


objs.append(hbar_agents("soc-ai-linux-agents-alerts", "Top agents by alerts (severity >= Medium)",
                        "Alerts", query=SEV_ACTIONABLE))
objs.append(hbar_agents("soc-ai-linux-agents-logs", "Top agents by log volume",
                        "Events"))

# ---------- Visualizations: Web (wazuh-web-* index) ----------
# Web rule levels are low (attacks = 6): the relevant filter is the "attack" group.

objs.append(vis("soc-ai-web-top-rules", "Top web rules (attacks)", {
    "title": "Top web rules (attacks)",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.description", "size": 10,
                     "otherBucket": True, "otherBucketLabel": "Other"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}, IDX_WEB, query='rule.groups:"attack"'))

objs.append(vis("soc-ai-web-top-alerts", "Top web alerts", {
    "title": "Top web alerts",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alert"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severity"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 3, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WEB, query='rule.groups:"attack"'))

objs.append(vis("soc-ai-web-timeline", "Web alerts (timeline)", {
    "title": "Web alerts (timeline)",
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

objs.append(vis("soc-ai-web-top-urls", "Top targeted URLs", {
    "title": "Top targeted URLs",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Hits"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.url", "size": 15, "customLabel": "URL"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.id", "size": 3, "customLabel": "HTTP code"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WEB, query='rule.groups:"attack"'))

objs.append(vis("soc-ai-web-top-srcips", "Top web source IPs", {
    "title": "Top web source IPs",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Requests"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.srcip", "size": 10, "customLabel": "Source IP"}},
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
                               "title": {"text": "Requests"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Requests", "id": "1"},
                                  "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                  "lineWidth": 2, "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                                  "color": "#E7664C"}},
}, IDX_WEB))

objs.append(vis("soc-ai-web-http-codes", "HTTP codes", {
    "title": "HTTP codes",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.id", "size": 10, "customLabel": "HTTP code"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
}, IDX_WEB))

# ---------- Visualizations: YARA (wazuh-yara-* index) ----------
# Loki/YARITRUST: loki logs carry their own level in data.level
# (ALERT/WARNING/NOTICE); the scanned machine is in data.yara.scanned_host
# (loki's native hostname field is ALWAYS the scanner, cf. rule 100900).

objs.append(vis("soc-ai-yara-total", "Malicious files detected (total)", {
    "title": "Malicious files detected (total)",
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

objs.append(vis("soc-ai-yara-timeline", "YARA matches by severity (timeline)", {
    "title": "YARA matches by severity (timeline)",
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

objs.append(vis("soc-ai-yara-top-hosts", "Top infected machines", {
    "title": "Top infected machines",
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

objs.append(vis("soc-ai-yara-top-files", "Files detected", {
    "title": "Files detected",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.file_path", "size": 20, "customLabel": "File"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.yara.scanned_host", "size": 3, "customLabel": "Machine"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.sha256", "size": 1, "customLabel": "SHA256"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_YARA))

objs.append(saved_search("soc-ai-yara-latest", "Latest YARA matches",
    "Chronological stream of files detected by Loki/YARITRUST, most recent first.",
    ["data.yara.scanned_host", "data.score", "rule.severity", "data.file_path", "data.sha256"],
    IDX_YARA))


# ---------- Visualizations: AI (wazuh-ai-* index) ----------
#
# Two families of documents in this index, always filter on `event_type`:
#   event_type:llm_call -> consumption (tokens, latency, cost), one doc per call
#   event_type:triage   -> quality (verdict, inconsistencies, guardrails)
# Without this filter, a counter mixes the two and means nothing.

Q_LLM = "event_type:llm_call"
Q_TRIAGE = "event_type:triage"

# Verdict colors: true positive red, false positive green, uncertain yellow.
VERDICT_COLORS = {"vis": {"colors": {
    "true_positive": "#BD271E",
    "false_positive": "#54B399",
    "needs_investigation": "#D6BF57",
}}}


def metric_vis(vid, title, label, idx, query, agg):
    """Single big number. `agg` is the metric aggregation (count, sum...)."""
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


objs.append(metric_vis("soc-ai-ai-tokens-total", "Tokens consumed (total)",
                       "Tokens", IDX_AI, Q_LLM,
                       {"type": "sum", "params": {"field": "ai.total_tokens"}}))

objs.append(metric_vis("soc-ai-ai-calls-total", "Model calls",
                       "Calls", IDX_AI, Q_LLM, {"type": "count"}))

objs.append(metric_vis("soc-ai-ai-cost-total", "Estimated cost (USD, approx.)",
                       "USD (approx.)", IDX_AI, Q_LLM,
                       {"type": "sum", "params": {"field": "ai.cost_usd"}}))

objs.append(metric_vis("soc-ai-ai-latency-avg", "Average latency (ms)",
                       "ms", IDX_AI, Q_LLM,
                       {"type": "avg", "params": {"field": "ai.duration_ms"}}))

# Tokens over time, stacked input/output: it's the ratio between the two
# that explains the cost (output is billed more expensively everywhere), and an
# output spike signals a model that reasons for a long time.
objs.append(vis("soc-ai-ai-tokens-timeline", "Tokens over time (input / output)", {
    "title": "Tokens over time (input / output)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.prompt_tokens", "customLabel": "Input tokens"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.completion_tokens", "customLabel": "Output tokens"}},
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
   ui_state={"vis": {"colors": {"Input tokens": "#6092C0", "Output tokens": "#E7664C"}}}))

# By caller: shows WHERE the budget goes. Triage is only one of the consumers
# — the IRIS report often costs more (4000 tokens of budget vs 3000).
objs.append(vis("soc-ai-ai-tokens-by-usage", "Tokens by usage", {
    "title": "Tokens by usage",
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

# Cost over time. Title explicit about the approximation: the rates come
# from the public pricing grid, not from an invoice (cf. config.LLM_COST_USD_PER_MTOKEN_*).
objs.append(vis("soc-ai-ai-cost-timeline", "Estimated cost over time (USD, approx.)", {
    "title": "Estimated cost over time (USD, approx.)",
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

# Share of the input served by the cache: the main cost lever, since a
# cache hit is billed 50x cheaper than a cache miss.
objs.append(vis("soc-ai-ai-cache", "Input: cache hit vs cache miss", {
    "title": "Input: cache hit vs cache miss",
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
                              "title": {"text": "Input tokens"}}]},
}, IDX_AI, query=Q_LLM,
   ui_state={"vis": {"colors": {"Cache hit": "#54B399", "Cache miss": "#E7664C"}}}))

objs.append(vis("soc-ai-ai-calls-by-model", "Calls by model", {
    "title": "Calls by model",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Calls"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "ai.model", "size": 10, "customLabel": "Model"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_AI, query=Q_LLM))

# Latency: average AND 95th percentile. The average alone hides calls that
# time out, and it's the 95th that tells whether the 5-minute cycle holds.
objs.append(vis("soc-ai-ai-latency-timeline", "Call latency (average / p95)", {
    "title": "Call latency (average / p95)",
    "type": "line",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "ai.duration_ms", "customLabel": "Average (ms)"}},
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
                                 "data": {"label": "Average (ms)", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Milliseconds"}}]},
}, IDX_AI, query=Q_LLM))

# Budget: a completion_tokens that sticks to max_tokens explains empty content
# (finish_reason=length on reasoning models).
objs.append(vis("soc-ai-ai-budget", "Output vs budget by usage", {
    "title": "Output vs budget by usage",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "ai.completion_tokens", "customLabel": "Avg. output"}},
        {"id": "3", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "ai.completion_tokens", "customLabel": "Max output"}},
        {"id": "4", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "ai.max_tokens", "customLabel": "Budget"}},
        {"id": "5", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Calls"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "ai.usage", "size": 10, "customLabel": "Usage"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_AI, query=Q_LLM))

objs.append(vis("soc-ai-ai-errors", "Failed calls", {
    "title": "Failed calls",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Calls"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "ai.error", "size": 10, "customLabel": "Error"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "ai.usage", "size": 5, "customLabel": "Usage"}},
    ],
    "params": {"perPage": 5, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_AI, query="event_type:llm_call and ai.ok:false"))

# ---------- Verdict quality (event_type:triage) ----------

objs.append(vis("soc-ai-ai-verdicts", "Verdict breakdown", {
    "title": "Verdict breakdown",
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

objs.append(vis("soc-ai-ai-verdicts-timeline", "Verdicts over time", {
    "title": "Verdicts over time",
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

objs.append(vis("soc-ai-ai-confidence", "Confidence by verdict", {
    "title": "Confidence by verdict",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Triages"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "triage.verdict", "size": 5,
                    "customLabel": "Verdict"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "triage.confidence", "size": 3,
                    "customLabel": "Confidence"}},
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

# The three degradation signals readable WITHOUT a labelled set. A bar that
# rises here always precedes a problem: a broken prompt, or hostile data.
#
# NB: the producer (soc_agent/metrics.py, `_doc_triage`) writes these counters
# under `triage.guardrail_count` and `triage.inconsistency_count` (English field
# names) — the dashboard used to reference stale French field names
# (`triage.garde_fou_count` / `triage.incoherence_count`) that no field in the
# index ever carried; fixed below to match the actual producer output.
objs.append(vis("soc-ai-ai-quality", "Guardrails, inconsistencies, injections", {
    "title": "Guardrails, inconsistencies, injections",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "triage.guardrail_count", "customLabel": "Guardrails"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "triage.inconsistency_count", "customLabel": "Inconsistencies"}},
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
   ui_state={"vis": {"colors": {"Guardrails": "#E7664C", "Inconsistencies": "#D6BF57"}}}))

objs.append(vis("soc-ai-ai-actions", "Proposed actions", {
    "title": "Proposed actions",
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

objs.append(vis("soc-ai-ai-cost-by-agent", "Cost and tokens by machine", {
    "title": "Cost and tokens by machine",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Triages"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "ai.prompt_tokens", "customLabel": "Input tokens"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "incident.agent_name", "size": 15,
                    "customLabel": "Machine"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_AI, query=Q_TRIAGE))

objs.append(saved_search("soc-ai-ai-latest", "Latest model calls",
    "Chronological stream of DeepSeek calls: usage, tokens, duration, incident.",
    ["ai.usage", "ai.model", "ai.prompt_tokens", "ai.completion_tokens",
     "ai.duration_ms", "ai.ok", "incident.id"],
    IDX_AI, query=Q_LLM))


# ---------- End-to-end delays: MTTD / MTTR (event_type:incident_kpi) ----------
#
# The two numbers every SOC gets asked for. They come from the wazuh-ai-*
# index and NOT from the alerts: the delay is computed between bounds that live
# in three Postgres tables (incidents, triages, mitigations), and OSD doesn't
# know how to subtract two dates from two documents. The computation happens at
# export time (soc_agent/metrics.py, `_doc_kpi`), one document per incident.
#
#   MTTD = first event observed -> incident created by correlation.
#   MTTR = incident created -> first remediation ACTUALLY applied
#          (statuses executed/confirmed/no_effect; neither dry_run nor an
#          unconfirmed 'issued'). The two add up to the total delay.
#
# The average ALONE lies here: a single incident caught up by a delay sweep
# (alert indexed hours after the event) can triple it. Hence the median next to
# it, and the incident count behind the number — an average over
# 3 incidents doesn't carry the same weight as an average over 300.
Q_KPI = "event_type:incident_kpi"


def kpi_delay(vid, title, field, query, account_label):
    return vis(vid, title, {
        "title": title,
        "type": "metric",
        "aggs": [
            {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
             "params": {"field": field, "customLabel": "Average (min)"}},
            {"id": "2", "enabled": True, "type": "percentiles", "schema": "metric",
             "params": {"field": field, "percents": [50],
                        "customLabel": "Median (min)"}},
            {"id": "3", "enabled": True, "type": "count", "schema": "metric",
             "params": {"customLabel": account_label}},
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


objs.append(kpi_delay(
    "soc-ai-mttd", "MTTD — detection delay", "kpi.mttd_minutes",
    Q_KPI, "Incidents detected"))

# Explicit filter on the existence of the delay: the average would ignore
# nulls anyway, but the COUNT would say "11 incidents" where only 3 were
# actually remediated. The denominator shown must be the one behind the
# average shown.
objs.append(kpi_delay(
    "soc-ai-mttr", "MTTR — remediation delay", "kpi.mttr_minutes",
    f"{Q_KPI} and kpi.remediated:true", "Incidents remediated"))


def counter(vid, title, label, query="", idx=IDX_ALL, agg=None):
    """Single big number on the combined index."""
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


objs.append(counter("soc-ai-actionable-events", "Actionable alerts (>= Medium)",
                     "Alerts", query=SEV_ACTIONABLE))

objs.append(counter("soc-ai-highcrit-events", "High + Critical alerts",
                     "Alerts", query=SEV_HIGH_CRIT))

# Cardinality on agent.name: counts the machines that have REALLY emitted,
# not the enrolled agents. A silent agent (sensor down, agent stopped) makes
# this number drop — that's the point.
objs.append(counter("soc-ai-active-agents", "Emitting machines",
                     "Machines",
                     agg={"type": "cardinality", "params": {"field": "agent.name"}}))

objs.append(vis("soc-ai-severity-pie", "Breakdown by severity", {
    "title": "Breakdown by severity",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alerts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": SEV_TERMS},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_ALL, ui_state=SEV_COLORS))

# Events by machine, STACKED by severity: the plain total per host says
# who is chatty, not who is doing badly. A machine with few events but a
# red bar matters more than a machine drowned in level 3.
objs.append(vis("soc-ai-events-by-host", "Events by machine (by severity)", {
    "title": "Events by machine (by severity)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Events"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "agent.name", "size": 20,
                    "customLabel": "Machine"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": SEV_TERMS},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Events", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Events"}}]},
}, IDX_ALL, ui_state=SEV_COLORS))

# By index: measures what EACH sensor produces, and therefore where the
# platform's load goes. `_index` is an OpenSearch meta field, aggregatable as-is
# — it's the only way to see the routing (alerts-pipeline.json) from a
# visualization, since the index name doesn't exist in any field of the document.
objs.append(vis("soc-ai-events-by-index", "Events by index (sensor)", {
    "title": "Events by index (sensor)",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Events"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "_index", "size": 20,
                    "customLabel": "Index"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_ALL))

objs.append(vis("soc-ai-global-top-rules", "Top rules (all sources)", {
    "title": "Top rules (all sources)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alerts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15,
                    "customLabel": "Rule"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.level", "orderBy": "_key", "order": "desc",
                    "size": 3, "customLabel": "Level"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_ALL))

# Restricted to actionable alerts: on an exposed estate, the top IPs across
# all severities is just a ranking of scanners.
objs.append(vis("soc-ai-global-top-srcips", "Top source IPs (>= Medium)", {
    "title": "Top source IPs (>= Medium)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alerts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "data.srcip", "size": 15,
                    "customLabel": "Source IP"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Alerts", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Alerts"}}]},
}, IDX_ALL, query=SEV_ACTIONABLE))

# MITRE tactics: says at what STAGE of an intrusion we are. A swing from
# Reconnaissance to Execution/Persistence is the signal that matters, and it
# doesn't show up on any volume counter.
objs.append(vis("soc-ai-mitre-tactics", "MITRE tactics (>= Medium)", {
    "title": "MITRE tactics (>= Medium)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alerts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.mitre.tactic", "size": 12,
                    "customLabel": "Tactic"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Alerts", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Alerts"}}]},
}, IDX_ALL, query=SEV_ACTIONABLE))

# ---------- Visualizations: Windows (wazuh-windows-* index) ----------
# Windows volume is crushed by 4624/4634 (logon / logoff):
# 32,000 of 43,000 events, all Info. The panels that count the noise (Event
# IDs, logon types, volume per agent) therefore read it RAW, while the ones
# showing a threat filter >= Medium or target a precise behavior. Mixing the
# two would give a dashboard where everything is green because everything is
# drowned out.

# Wazuh's Windows-side groups sometimes arrive with a leading space
# (" powershell", " WEF"): the built-in rules' <group> list is written across
# several lines in the XML, and the indentation space leaks into the value.
# `rule.groups:"powershell"` (exact term on a keyword) therefore matches NOTHING.
# Hence the wildcards: they are what makes these queries reliable, not a comfort choice.
Q_WIN_CRED = ('rule.groups:(*credential_access* or *lsass_dump* or *mimikatz* or '
              '*kerberoasting* or *ntds_dump* or *dcsync*) or rule.id:(100910 or 100915 or 100918)')
Q_WIN_PS = 'rule.groups:*powershell* or data.win.system.eventID:("4103" or "4104")'
Q_WIN_AUTH_FAIL = ('rule.groups:(*authentication_failed* or *win_authentication_failed*) or '
                   'data.win.system.eventID:("4625" or "4771" or "4776" or "4740")')

objs.append(counter("soc-ai-win-total-events", "Windows events",
                     "Events", idx=IDX_WINDOWS))

objs.append(counter("soc-ai-win-actionable", "Actionable alerts (>= Medium)",
                     "Alerts", query=SEV_ACTIONABLE, idx=IDX_WINDOWS))

# Cardinality on data.win.system.computer and not agent.name: it's the name
# seen INSIDE the event, i.e. the machine's real FQDN (WIN-DC.lab.local). An
# agent whose identity was cloned from a template emits under another
# machine's agent name — the two numbers then diverge, and that's the signal.
objs.append(counter("soc-ai-win-hosts", "Emitting Windows machines",
                     "Machines", idx=IDX_WINDOWS,
                     agg={"type": "cardinality",
                          "params": {"field": "data.win.system.computer"}}))

objs.append(counter("soc-ai-win-cred-count", "Credential access",
                     "Events", query=Q_WIN_CRED, idx=IDX_WINDOWS))

objs.append(vis("soc-ai-win-timeline", "Windows alerts by severity (timeline)", {
    "title": "Windows alerts by severity (timeline)",
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

objs.append(vis("soc-ai-win-mitre", "Windows MITRE tactics (>= Medium)", {
    "title": "Windows MITRE tactics (>= Medium)",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alerts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.mitre.tactic", "size": 12,
                    "customLabel": "Tactic"}},
    ],
    "params": {**HIST_PARAMS, "type": "horizontal_bar",
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                 "data": {"label": "Alerts", "id": "1"},
                                 "valueAxis": "ValueAxis-1",
                                 "drawLinesBetweenPoints": True, "lineWidth": 2,
                                 "showCircles": True}],
               "categoryAxes": [{**HIST_PARAMS["categoryAxes"][0], "position": "left",
                                 "labels": {"show": True, "rotate": 0, "filter": False,
                                            "truncate": 200}}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0], "name": "BottomAxis-1",
                              "position": "bottom", "title": {"text": "Alerts"}}],
               "addLegend": False},
}, IDX_WINDOWS, query=SEV_ACTIONABLE))

objs.append(vis("soc-ai-win-top-rules", "Top Windows rules (>= Medium)", {
    "title": "Top Windows rules (>= Medium)",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "rule.description", "size": 10,
                     "otherBucket": True, "otherBucketLabel": "Other"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
               "isDonut": True, "labels": {"show": False, "values": True,
                                            "last_level": True, "truncate": 100}},
}, IDX_WINDOWS, query=SEV_ACTIONABLE))

objs.append(vis("soc-ai-win-top-alerts", "Top Windows alerts", {
    "title": "Top Windows alerts",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Occurrences"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alert"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severity"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 3, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query=SEV_ACTIONABLE))

# RAW volume (no severity filter): the useful reading here is the shape of the
# telemetry, not the threat. An Event ID that disappears from this graph = an
# audit sub-category that went dark on the machine.
objs.append(hbar_agents("soc-ai-win-event-ids", "Top Windows Event IDs",
                        "Events", idx=IDX_WINDOWS,
                        field="data.win.system.eventID", bucket_label="Event ID"))

objs.append(vis("soc-ai-win-logon-types",
                "Logons by type (2 interactive, 3 network, 5 service, 10 RDP)", {
    "title": "Logons by type (2 interactive, 3 network, 5 service, 10 RDP)",
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

objs.append(hbar_agents("soc-ai-win-top-accounts", "Top targeted accounts (logons)",
                        "Sessions", idx=IDX_WINDOWS,
                        field="data.win.eventdata.targetUserName", bucket_label="Account",
                        query='data.win.system.eventID:"4624"'))

objs.append(vis("soc-ai-win-auth-failures", "Windows authentication failures", {
    "title": "Windows authentication failures",
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

# Parent -> child lineage, not the process list: a powershell.exe
# alone says nothing, a powershell.exe launched by winword.exe says everything.
objs.append(vis("soc-ai-win-processes", "Processes created (parent -> child)", {
    "title": "Processes created (parent -> child)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Executions"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.win.eventdata.parentImage", "size": 10,
                     "customLabel": "Parent process"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.win.eventdata.image", "size": 3,
                     "customLabel": "Created process"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS))

objs.append(vis("soc-ai-win-dropped-files", "Files dropped (Sysmon EID 11)", {
    "title": "Files dropped (Sysmon EID 11)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Drops"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "data.win.eventdata.targetFilename", "size": 15,
                     "customLabel": "File"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query='data.win.eventdata.targetFilename:*'))

# In-house rules 100910 / 100915 / 100918 (kerberoasting RC4, DCSync, lsass dump)
# + equivalent built-in groups. This is the panel where an AD compromise
# shows up first, hence its position above the raw stream.
objs.append(vis("soc-ai-win-cred-access", "Credential access (lsass, DCSync, Kerberoasting)", {
    "title": "Credential access (lsass, DCSync, Kerberoasting)",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Events"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alert"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severity"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query=Q_WIN_CRED))

objs.append(vis("soc-ai-win-powershell", "PowerShell activity", {
    "title": "PowerShell activity",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Events"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "rule.description", "size": 15, "customLabel": "Alert"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**SEV_TERMS, "customLabel": "Severity"}},
        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "agent.name", "size": 2, "customLabel": "Agent"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
               "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
}, IDX_WINDOWS, query=Q_WIN_PS))

objs.append(hbar_agents("soc-ai-win-agents-alerts", "Top Windows agents by alerts (>= Medium)",
                        "Alerts", query=SEV_ACTIONABLE, idx=IDX_WINDOWS))
objs.append(hbar_agents("soc-ai-win-agents-logs", "Top Windows agents by log volume",
                        "Events", idx=IDX_WINDOWS))

objs.append(saved_search("soc-ai-win-latest", "Latest Windows alerts (High / Critical)",
    "Chronological stream of Windows High and Critical alerts, most recent first. "
    "Columns chosen to decide without opening the document: who (targetUserName), "
    "on what (computer), with what (commandLine).",
    ["agent.name", "rule.severity", "rule.level", "rule.description",
     "data.win.system.eventID", "data.win.eventdata.targetUserName",
     "data.win.eventdata.commandLine"],
    IDX_WINDOWS, query=SEV_HIGH_CRIT))

# ---------- Dashboards ----------

objs.append(dashboard("soc-ai-threat-intel", "Threat Intel",
    "Threat intel: GeoIP map of source IPs, AbuseIPDB reputation, VirusTotal detections.",
    [
        ("soc-ai-geoip-map",             0,  0, 48, 16),
        ("soc-ai-abuseipdb-table",       0, 16, 24, 14),
        ("soc-ai-virustotal-table",     24, 16, 24, 14),
        ("soc-ai-vt-total",              0, 30, 12, 12),
        ("soc-ai-abuseipdb-countries",  12, 30, 36, 12),
    ]))

objs.append(dashboard("soc-ai-global", "Global",
    "Global view: volume and severity, detection and remediation delays "
    "(MTTD / MTTR), breakdown by machine and by sensor, MITRE tactics, "
    "stream of High/Critical alerts.",
    [
        ("soc-ai-total-events",       0,  0, 12, 10),
        ("soc-ai-actionable-events", 12,  0, 12, 10),
        ("soc-ai-highcrit-events",   24,  0, 12, 10),
        ("soc-ai-active-agents",     36,  0, 12, 10),
        # Second row: what the platform TAKES TIME to do, facing what it sees.
        # Deliberately above the volume curves: a SOC is judged on these two
        # numbers before it's judged on its throughput.
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
    "Linux alerts (wazuh-linux-* index): top rules, top alerts, authentication failures.",
    [
        ("soc-ai-top-rules",        0,  0, 24, 15),
        ("soc-ai-linux-top-alerts",24,  0, 24, 15),
        ("soc-ai-auth-failures",    0, 15, 48, 14),
        ("soc-ai-linux-agents-alerts", 0, 29, 24, 12),
        ("soc-ai-linux-agents-logs",  24, 29, 24, 12),
    ]))

objs.append(dashboard("soc-ai-windows", "Windows",
    "Windows / Active Directory alerts (wazuh-windows-* index): Event IDs, "
    "logons, authentication failures, process lineage, "
    "dropped files, credential access (lsass / DCSync / Kerberoasting), "
    "PowerShell activity.",
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
    "Web alerts (wazuh-web-* index): attacks, targeted URLs, source IPs, HTTP codes.",
    [
        ("soc-ai-web-top-rules",   0,  0, 24, 15),
        ("soc-ai-web-top-alerts", 24,  0, 24, 15),
        ("soc-ai-web-timeline",    0, 15, 48, 12),
        ("soc-ai-web-top-urls",    0, 27, 24, 13),
        ("soc-ai-web-top-srcips", 24, 27, 12, 13),
        ("soc-ai-web-http-codes", 36, 27, 12, 13),
    ]))

objs.append(dashboard("soc-ai-yara", "YARA",
    "Loki YARA/IOC scans (YARITRUST, wazuh-yara-* index): malicious files detected by machine.",
    [
        ("soc-ai-yara-total",     0,  0, 12, 12),
        ("soc-ai-yara-timeline", 12,  0, 36, 12),
        ("soc-ai-yara-top-hosts", 0, 12, 24, 14),
        ("soc-ai-yara-top-files",24, 12, 24, 14),
        ("soc-ai-yara-latest",    0, 26, 48, 20, "search"),
    ]))

objs.append(dashboard("soc-ai-ai", "AI",
    "Model usage (wazuh-ai-* index): tokens, cost, latency, and "
    "quality of the verdicts returned by the triage.",
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

# ---------- Visualizations: VOC (wazuh-voc-* index) ----------
#
# Three kinds of documents in the same index pattern, distinguished by
# event_type (same convention as wazuh-ai-*):
#
#   voc_parc  : one line per scanner pass — counters for the whole fleet.
#               This is the TIME SERIES: burn-down, flow, coverage.
#   voc_asset : one line per machine per pass — exposure score.
#   voc_vuln  : one line per vulnerability, REWRITTEN on each pass, in the
#               STABLE index wazuh-voc-vulns. Timestamped at its first
#               observation, not at run time: that's what allows reading the age.
#
# TRAP, direct consequence: any visualization based on voc_vuln is
# dependent on the dashboard's time window. A 30-day window would hide
# vulnerabilities seen more than 30 days ago — i.e.
# exactly the oldest ones, therefore the most overdue, therefore the only ones
# that matter for a VOC. Hence the 3-year time_from on this dashboard.
#
# NB: the `voc.*` field names below (statut, resolue, ouvertes, critical,
# hors_sla_total, score_max, couverture_pct, machines_muettes, nouvelles,
# corrigees, age_jours, sla_jours, retard_jours...) are kept in French on
# purpose — they are the data schema already written by the producer
# (ai/soc_agent/vulns.py) into the live wazuh-voc-* index. Renaming them here
# would silently break every panel below. Only the surrounding titles/labels
# are translated.

Q_FLEET = "event_type:voc_parc"
Q_ASSET = "event_type:voc_asset"
Q_VULN_OPEN = "event_type:voc_vuln and voc.statut:ouverte"
Q_VULN_FIXED = "event_type:voc_vuln and voc.resolue:true"


def last(vid, title, field, label, query=Q_FLEET, size=48):
    """Single big number = LATEST value recorded, via top_hits.

    Not `max` nor `avg`: these documents are GAUGES, not events. A
    `max` over 30 days would show the month's debt peak while passing it off
    as the current state — exactly the opposite of what a VOC should show.
    """
    return vis(vid, title, {
        "title": title,
        "type": "metric",
        "aggs": [{"id": "1", "enabled": True, "type": "top_hits",
                  "schema": "metric",
                  "params": {"field": field, "aggregate": "concat", "size": 1,
                             "sortField": "timestamp", "sortOrder": "desc",
                             "customLabel": label}}],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "colorsRange": [{"from": 0, "to": 10 ** 12}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgFill": "#000", "bgColor": False,
                                        "labelColor": False, "subText": "",
                                        "fontSize": size}}},
    }, IDX_VOC, query=query)


objs.append(last("soc-ai-voc-ouvertes", "Open vulnerabilities",
                    "voc.ouvertes", "Open"))
objs.append(last("soc-ai-voc-critical", "Of which critical",
                    "voc.critical", "Critical"))
objs.append(last("soc-ai-voc-horssla", "Overdue (SLA exceeded)",
                    "voc.hors_sla_total", "Over SLA"))
objs.append(last("soc-ai-voc-score-max", "Most exposed machine (score)",
                    "voc.score_max", "Score /100"))

# Coverage first, and on the dashboard's first screen. A debt going down
# because machines have stopped responding is not an improvement: without
# this number next to the burn-down, nothing lets you tell the difference. The
# fleet's VOC has already hit this kind of blind spot (auditd absent
# everywhere, cloned agents gone silent) — the lesson is wired in here.
objs.append(last("soc-ai-voc-couverture", "Inventory coverage",
                    "voc.couverture_pct", "% of known machines", size=36))
objs.append(last("soc-ai-voc-muettes", "Machines without inventory",
                    "voc.machines_muettes", "Machines", size=36))

# Burn-down: debt by severity over time. `max` per interval and not
# `avg`: several passes per interval read the same gauge, the average would
# smooth out a real variation that occurred between two scans.
objs.append(vis("soc-ai-voc-burndown", "Vulnerability debt over time", {
    "title": "Vulnerability debt over time",
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
                               "title": {"text": "Open vulnerabilities"}}],
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
}, IDX_VOC, query=Q_FLEET,
   ui_state={"vis": {"colors": {"Critical": "#BD271E", "High": "#EC7014",
                                "Medium": "#F5C700", "Low": "#6092C0"}}}))

# Remediation capacity: what comes in against what goes out. A stable debt
# with a high flow on both sides doesn't mean the same thing as a stable debt
# with no movement at all — the first is a living fleet, the second an
# abandoned one. `sum` here (and not `max`): these are DELTAS per pass.
objs.append(vis("soc-ai-voc-flux", "Vulnerabilities appeared / fixed", {
    "title": "Vulnerabilities appeared / fixed",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "voc.nouvelles", "customLabel": "Appeared"}},
        {"id": "3", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "voc.corrigees", "customLabel": "Fixed"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-90d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "1d", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Vulnerabilities"}}]},
}, IDX_VOC, query=Q_FLEET,
   ui_state={"vis": {"colors": {"Appeared": "#E7664C", "Fixed": "#54B399"}}}))

# Remediation MTTR. `voc.age_jours` carries two meanings depending on
# status — age while it's open, fix delay once resolved — hence the filter
# `voc.resolue:true`, without which this number would mix debt and speed.
objs.append(vis("soc-ai-voc-mttr", "Average fix delay", {
    "title": "Average fix delay",
    "type": "metric",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "voc.age_jours", "customLabel": "Average (days)"}},
        {"id": "2", "enabled": True, "type": "percentiles", "schema": "metric",
         "params": {"field": "voc.age_jours", "percents": [50],
                    "customLabel": "Median (days)"}},
        {"id": "3", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Vulnerabilities fixed"}},
    ],
    "params": {"addTooltip": True, "addLegend": False, "type": "metric",
               "metric": {"percentageMode": False, "useRanges": False,
                          "colorSchema": "Green to Red", "metricColorMode": "None",
                          "colorsRange": [{"from": 0, "to": 10 ** 12}],
                          "labels": {"show": True}, "invertColors": False,
                          "style": {"bgFill": "#000", "bgColor": False,
                                    "labelColor": False, "subText": "",
                                    "fontSize": 36}}},
}, IDX_VOC, query=Q_VULN_FIXED))

objs.append(vis("soc-ai-voc-mttr-severite", "Fix delay by severity", {
    "title": "Fix delay by severity",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric",
         "params": {"field": "voc.age_jours", "customLabel": "Days (average)"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "vulnerability.severity", "size": 6,
                    "customLabel": "Severity"}},
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
                               "title": {"text": "Days"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Days (average)", "id": "1"},
                                  "valueAxis": "ValueAxis-1",
                                  "drawLinesBetweenPoints": True, "lineWidth": 2,
                                  "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1,
                                  "style": "full", "color": "#E7664C"}},
}, IDX_VOC, query=Q_VULN_FIXED))

# Exposure score by machine. `max` on voc.score and not a document count:
# each pass writes one line per machine, so a `count` would rank
# agents by number of scans — i.e. by nothing at all. The max over the
# window gives the machine's worst state, which is what a prioritization
# list wants. Sorted by the metric (orderBy "1"), not alphabetically.
objs.append(vis("soc-ai-voc-score-agents",
                "Most exposed machines (score /100)", {
    "title": "Most exposed machines (score /100)",
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
                               "title": {"text": "Exposure score /100"}}],
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
                "Open vulnerabilities by asset priority", {
    "title": "Open vulnerabilities by asset priority",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Vulnerabilities"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "asset.priorite_label", "orderBy": "_key",
                    "order": "asc", "size": 4, "customLabel": "Priority"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "vulnerability.severity", "size": 6,
                    "customLabel": "Severity"}},
    ],
    "params": {**HIST_PARAMS,
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Open vulnerabilities"}}]},
}, IDX_VOC, query=Q_VULN_OPEN,
   ui_state={"vis": {"colors": {"critical": "#BD271E", "high": "#EC7014",
                                "medium": "#F5C700", "low": "#6092C0"}}}))

# Top packages: the best patching return on investment. A single package
# (the kernel meta-package) often carries half the debt of a Debian host —
# this panel avoids handling it CVE by CVE.
objs.append(vis("soc-ai-voc-top-paquets", "Packages carrying the debt", {
    "title": "Packages carrying the debt",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Vulnerabilities"}},
        {"id": "3", "enabled": True, "type": "cardinality", "schema": "metric",
         "params": {"field": "agent.name", "customLabel": "Machines"}},
        {"id": "4", "enabled": True, "type": "max", "schema": "metric",
         "params": {"field": "vulnerability.score_base",
                    "customLabel": "Worst CVSS"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {**TERMS, "field": "package.name", "size": 20,
                    "customLabel": "Package"}},
    ],
    "params": {"perPage": 10, "showPartialRows": False,
               "showMetricsAtAllLevels": False, "showTotal": False,
               "totalFunc": "sum", "percentageCol": ""},
}, IDX_VOC, query=Q_VULN_OPEN))

# The VOC's real work queue: what has exceeded its deadline, sorted by delay.
# A saved search and not an aggregation table, so the analyst
# can open the row, see the exact package, and pivot.
objs.append(saved_search(
    "soc-ai-voc-horssla-liste", "Overdue vulnerabilities (to handle)",
    "Open vulnerabilities whose SLA (severity x asset priority) is "
    "exceeded, from the biggest delay to the smallest.",
    ["agent.name", "asset.priorite_label", "vulnerability.id",
     "vulnerability.severity", "vulnerability.score_base", "package.name",
     "package.version", "voc.age_jours", "voc.sla_jours", "voc.retard_jours"],
    IDX_VOC, query="event_type:voc_vuln and voc.hors_sla:true",
    sort=[["voc.retard_jours", "desc"]]))

objs.append(dashboard("soc-ai-voc", "VOC",
    "Fleet vulnerability management (wazuh-voc-* index, fed by the "
    "soc-agent-vulns container): debt, remediation capacity, deadline "
    "compliance, and inventory coverage. Coverage is read BEFORE the "
    "burn-down: a debt going down because a machine stopped responding "
    "is not an improvement.",
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
    # 3 years: `voc_vuln` documents are timestamped at their FIRST
    # observation. A short window would hide the oldest vulnerabilities
    # — i.e. the most overdue ones — and the "overdue" panel
    # would show the opposite of the truth.
    time_from="now-3y"))

# ---------- Visualizations: Archive (wazuh-archive-* index) ----------
#
# One document per (index set, month), fed by archive_metrics.py on every
# archiving pass (periodic or on demand via aura_archive_create) — a state
# index, not a time series of events: re-exporting overwrites the same
# document rather than adding one. `@timestamp` is `archived_at`, which never
# changes once written, so the growth-over-time panel is real history, not an
# artifact of the export cadence.

objs.append(metric_vis("soc-ai-archive-count", "Archives",
                       "Index set x month", IDX_ARCHIVE, "",
                       {"type": "count"}))

objs.append(metric_vis("soc-ai-archive-documents", "Documents archived (total)",
                       "Documents", IDX_ARCHIVE, "",
                       {"type": "sum", "params": {"field": "archive.documents"}}))

objs.append(metric_vis("soc-ai-archive-bytes", "Storage used (encrypted, bytes)",
                       "Bytes", IDX_ARCHIVE, "",
                       {"type": "sum", "params": {"field": "archive.object_bytes"}}))

# Estimated cost: B2's published rate applied to the encrypted bytes actually
# stored (config.ARCHIVE_S3_COST_USD_PER_GB_MONTH) — see docs/ARCHIVAGE.md.
# Not an invoice, same caveat as the AI dashboard's cost panels.
objs.append(metric_vis("soc-ai-archive-cost", "Estimated cost (USD/month, approx.)",
                       "USD/month (approx.)", IDX_ARCHIVE, "",
                       {"type": "sum", "params": {"field": "archive.cost_usd_month"}}))

objs.append(metric_vis("soc-ai-archive-ratio", "Average compression ratio",
                       "x (plain / encrypted)", IDX_ARCHIVE, "",
                       {"type": "avg", "params": {"field": "archive.ratio"}}))

# Failures first, on the dashboard's first screen: an archive that doesn't
# read back is not an archive (see archive.py's drill). `ok` in green, every
# other state in red — there is no intermediate state worth a distinct color.
objs.append(vis("soc-ai-archive-verify-state", "Verification state", {
    "title": "Verification state",
    "type": "pie",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Archives"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "archive.verify_state", "size": 10,
                    "missingBucket": True, "missingBucketLabel": "never verified",
                    "customLabel": "State"}},
    ],
    "params": {"type": "pie", "addTooltip": True, "addLegend": True,
               "legendPosition": "right", "isDonut": True,
               "labels": {"show": True, "values": True, "last_level": True,
                          "truncate": 100}},
}, IDX_ARCHIVE, ui_state={"vis": {"colors": {"ok": "#54B399"}}}))

# Growth over time, stacked by index set: shows WHICH source is filling the
# bucket, not just that it's filling. `sum` per interval is correct here
# (unlike VOC's gauge, which needs `max`): each document is a distinct
# month's worth of bytes, not a repeated observation of the same state.
objs.append(vis("soc-ai-archive-growth", "Storage growth over time (by index set)", {
    "title": "Storage growth over time (by index set)",
    "type": "histogram",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "archive.object_bytes", "customLabel": "Bytes"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "timeRange": {"from": "now-3y", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {**TERMS, "field": "archive.index_set", "size": 15,
                    "customLabel": "Index set"}},
    ],
    "params": {**HIST_PARAMS, "seriesParams": [{**HIST_PARAMS["seriesParams"][0],
                                                "mode": "stacked"}],
               "valueAxes": [{**HIST_PARAMS["valueAxes"][0],
                              "title": {"text": "Bytes (encrypted)"}}]},
}, IDX_ARCHIVE))

objs.append(vis("soc-ai-archive-by-index-set", "Storage by index set", {
    "title": "Storage by index set",
    "type": "horizontal_bar",
    "aggs": [
        {"id": "1", "enabled": True, "type": "sum", "schema": "metric",
         "params": {"field": "archive.object_bytes", "customLabel": "Bytes"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {**TERMS, "field": "archive.index_set", "size": 20,
                    "customLabel": "Index set"}},
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
                               "title": {"text": "Bytes (encrypted)"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                  "data": {"label": "Bytes", "id": "1"},
                                  "valueAxis": "ValueAxis-1",
                                  "drawLinesBetweenPoints": True, "lineWidth": 2,
                                  "showCircles": True}],
               "addTooltip": True, "addLegend": False, "legendPosition": "right",
               "times": [], "addTimeMarker": False, "labels": {},
               "thresholdLine": {"show": False, "value": 10, "width": 1,
                                  "style": "full", "color": "#E7664C"}},
}, IDX_ARCHIVE))

# The catalog itself, one row per archive — the working list: what's
# restorable, and whether it's still trustworthy (verify_state).
objs.append(saved_search(
    "soc-ai-archive-catalog", "Archive catalog",
    "One line per (index set, month) archived, with its encrypted size, "
    "estimated monthly cost, and last verification state.",
    ["archive.index_set", "archive.period", "archive.documents",
     "archive.object_bytes", "archive.ratio", "archive.cost_usd_month",
     "archive.verify_state", "archive.verified_at"],
    IDX_ARCHIVE, sort=[["archive.index_set", "asc"]]))

objs.append(dashboard("soc-ai-archive", "Archivage",
    "Cold archiving to B2 (wazuh-archive-* index, fed by archive_metrics.py "
    "on every archiving pass — periodic or on demand via aura_archive_create): "
    "volume, estimated storage cost, verification state, growth by index set, "
    "and the full catalog. See docs/ARCHIVAGE.md.",
    [
        ("soc-ai-archive-count",       0,  0, 10, 10),
        ("soc-ai-archive-documents",  10,  0, 10, 10),
        ("soc-ai-archive-bytes",      20,  0, 10, 10),
        ("soc-ai-archive-cost",       30,  0, 10, 10),
        ("soc-ai-archive-ratio",      40,  0,  8, 10),
        ("soc-ai-archive-verify-state", 0, 10, 16, 15),
        ("soc-ai-archive-by-index-set", 16, 10, 32, 15),
        ("soc-ai-archive-growth",       0, 25, 48, 16),
        ("soc-ai-archive-catalog",      0, 41, 48, 20, "search"),
    ],
    # Archives are timestamped at archived_at, which can be well over a year
    # old (ARCHIVE_RETENTION_MONTHS default 12) — a short window would hide
    # most of the catalog, same reasoning as the VOC dashboard.
    time_from="now-3y"))

with open(OUT, "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"{len(objs)} objects -> {OUT}")
