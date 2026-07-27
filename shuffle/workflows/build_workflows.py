#!/usr/bin/env python3
"""Crée les workflows Shuffle "Wazuh - Host Isolation" et "Wazuh - Kill
Process" par l'API (pas d'export upstream à importer : ces workflows n'ont
jamais existé qu'en tant qu'objets vivants dans une instance Shuffle).

Fixe l'id des triggers webhook sur SHUFFLE_WEBHOOK_ISOLATE / _KILL (mêmes
valeurs que dans ai/.env, cf. README) pour que le soc-agent (mitigate.py)
retrouve la même URL de webhook quelle que soit l'instance Shuffle déployée.

Idempotent au sens : relancer recrée un nouveau workflow (Shuffle n'a pas de
"upsert par nom" via cette API) si l'ancien n'a pas été supprimé — supprimer
d'abord dans l'UI ou via DELETE /api/v1/workflows/<id> avant de relancer.

Usage (depuis shuffle/, avec .env chargé) :
    SHUFFLE_DEFAULT_APIKEY=... \\
    WAZUH_API_USER=wazuh-wui WAZUH_API_PASSWORD=... \\
    WAZUH_HOST=<ip host, PAS 127.0.0.1> \\
    SHUFFLE_WEBHOOK_ISOLATE=webhook_xxx SHUFFLE_WEBHOOK_KILL=webhook_yyy \\
    python3 workflows/build_workflows.py

WAZUH_HOST doit être une IP joignable depuis le réseau docker "shuffle" (le
worker qui exécute l'action HTTP n'est PAS en network_mode: host comme
soc-agent) : l'IP LAN de la machine, pas 127.0.0.1/localhost.
"""
import json
import os
import sys
import urllib.request
import urllib.error

BASE = os.environ.get("SHUFFLE_URL", "http://localhost:5001") + "/api/v1"
APIKEY = os.environ["SHUFFLE_DEFAULT_APIKEY"]
WAZUH_HOST = os.environ["WAZUH_HOST"]
WAZUH_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_PASS = os.environ["WAZUH_API_PASSWORD"]
HTTP_APP_ID = "bcbf2fa9-cddd-4a9b-8955-e38b9b34b213"
HTTP_APP_VERSION = "1.4.0"

# webhook_xxx dans .env -> id nu attendu par l'API triggers/hooks.
WEBHOOK_ISOLATE = os.environ["SHUFFLE_WEBHOOK_ISOLATE"].removeprefix("webhook_")
WEBHOOK_KILL = os.environ["SHUFFLE_WEBHOOK_KILL"].removeprefix("webhook_")


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Authorization", f"Bearer {APIKEY}")
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print("HTTP ERROR", e.code, e.read().decode())
        raise


def param(name, value, multiline=False):
    return {"name": name, "value": value, "multiline": multiline,
            "required": False, "configuration": False}


def http_action(node_id, label, method, url, headers, body, x, y):
    params = [param("url", url), param("headers", headers, multiline=True)]
    if body is not None:
        params.append(param("body", body, multiline=True))
    params += [param("verify", "false"), param("timeout", "10")]
    return {
        "app_name": "http", "app_version": HTTP_APP_VERSION,
        "app_id": HTTP_APP_ID, "id": node_id, "is_valid": True,
        "isStartNode": False, "label": label, "name": method,
        "environment": "Shuffle", "parameters": params,
        "position": {"x": x, "y": y}, "sub_action": False, "priority": 0,
        "execution_variable": {"name": "", "value": ""},
        "category": "", "errors": [],
    }


def webhook_trigger(trig_id, start_node, x, y):
    return {
        "id": trig_id, "label": "Webhook", "app_name": "webhook",
        "trigger_type": "WEBHOOK", "status": "running", "name": "Webhook",
        "tags": None, "parameters": [{"name": "url", "value": f"webhook_{trig_id}"}],
        "position": {"x": x, "y": y}, "isStartNode": True, "is_valid": True,
        "environment": "cloud", "start": start_node, "workflow_id": "",
    }


def branch(src, dst, bid):
    return {"id": bid, "source_id": src, "destination_id": dst,
            "label": "", "has_error": False, "conditions": []}


def register_hook(hook_id, start_node, workflow_id):
    r = call("POST", "/hooks", {
        "id": hook_id, "name": "Webhook", "start": start_node,
        "workflow": workflow_id, "info": {"name": "Webhook", "description": ""},
        "type": "webhook", "status": "running",
    })
    if not r.get("success"):
        print("ECHEC activation hook", hook_id, r)
        sys.exit(1)


def build(name, description, trig_id, extra_arg_in_body):
    wf = call("POST", "/workflows", {"name": name, "description": description})
    wf_id = wf["id"]
    auth_id = f"{trig_id[:8]}-0000-4000-8000-000000000001"
    ar_id = f"{trig_id[:8]}-0000-4000-8000-000000000002"

    auth_node = http_action(auth_id, "auth_wazuh", "POST",
        f"https://{WAZUH_HOST}:55000/security/user/authenticate?raw=true",
        "Content-Type: application/json", None, 300, 300)
    auth_node["parameters"] += [param("username", WAZUH_USER), param("password", WAZUH_PASS)]

    ar_body = '{\n  "command": "$exec.ar_command",\n  "arguments": []\n}'
    if extra_arg_in_body:
        ar_body = '{\n  "command": "$exec.ar_command",\n  "arguments": ["$exec.extra_args"]\n}'
    ar_node = http_action(ar_id, "run_active_response", "PUT",
        f"https://{WAZUH_HOST}:55000/active-response?agents_list=$exec.agent_id",
        "Authorization: Bearer $auth_wazuh.body\nContent-Type: application/json",
        ar_body, 600, 300)

    wf["actions"] = [auth_node, ar_node]
    wf["triggers"] = [webhook_trigger(trig_id, auth_id, 50, 300)]
    wf["branches"] = [branch(trig_id, auth_id, "br1"), branch(auth_id, ar_id, "br2")]
    call("PUT", f"/workflows/{wf_id}", wf)
    register_hook(trig_id, auth_id, wf_id)
    print(f"{name}: workflow {wf_id}, webhook webhook_{trig_id}")


if __name__ == "__main__":
    build("Wazuh - Host Isolation", "webhook -> auth_wazuh -> run_active_response",
          WEBHOOK_ISOLATE, extra_arg_in_body=False)
    build("Wazuh - Kill Process", "webhook -> auth_wazuh -> run_active_response (kill)",
          WEBHOOK_KILL, extra_arg_in_body=True)
