#!/usr/bin/env python3
"""Émet des événements connect/disconnect/endpoint-changed pour les pairs
WireGuard, à partir de la base SQLite de WGDashboard (déjà installé sur
l'hôte, déjà en train de suivre l'état des pairs — pas de raison de
réinventer un second poller de `wg show`).

Tables lues (lecture seule, WGDashboard reste seul écrivain) :
  - `<iface>` (ex "wg0") : état courant par pair (name, status, endpoint,
    allowed_ip) — status "running"/"stopped" est le calcul de WGDashboard
    lui-même (plus fiable qu'un seuil de handshake maison).
  - `<iface>_history_endpoint` : chaque changement d'IP source d'un pair
    (roaming, nouvelle session) — signal plus précis qu'un simple
    "handshake récent", WGDashboard l'enregistre nativement dès qu'il change.

Usage : appelé périodiquement (systemd timer, cf. wg-monitor.timer),
écrit une ligne par événement sur stdout -> redirigé vers WG_LOG_FILE.
État de suivi dans WG_STATE_FILE, pour ne loguer que les transitions.

Premier run (pas de WG_STATE_FILE) : se cale sur l'historique déjà présent
sans rien rejouer — seuls les changements POSTÉRIEURS au démarrage du
monitoring produisent une ligne.
"""
import json
import os
import sqlite3
import time

WG_IFACE = os.environ.get("WG_IFACE", "wg0")
DB_PATH = os.environ.get("WG_DASHBOARD_DB", "/etc/wgdashboard/src/db/wgdashboard.db")
STATE_FILE = os.environ.get("WG_STATE_FILE", "/var/lib/wg-monitor/state.json")


def load_state(conn):
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Premier run : se cale sur le dernier changement déjà connu, pour ne
        # pas rejouer tout l'historique d'un coup.
        row = conn.execute(
            f'SELECT MAX(time) AS t FROM "{WG_IFACE}_history_endpoint"').fetchone()
        return {"peers": {}, "last_endpoint_change": row["t"] or ""}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def main():
    # Lecture seule : WGDashboard reste l'unique écrivain de ce fichier.
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    state = load_state(conn)
    peers_state = state.get("peers", {})
    last_change = state.get("last_endpoint_change", "")

    peers = {r["id"]: r for r in
             conn.execute(f'SELECT id, name, status, endpoint, allowed_ip FROM "{WG_IFACE}"')}

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    # 1) Transitions running/stopped, au sens de WGDashboard.
    for pubkey, row in peers.items():
        name = row["name"] or pubkey[:8]
        prev = peers_state.get(pubkey)
        if prev is not None and prev != row["status"]:
            event = "peer_connected" if row["status"] == "running" else "peer_disconnected"
            lines.append(f"[{ts}] wg-monitor: event={event} peer_name={name} "
                         f"peer_ip={row['allowed_ip']} pubkey={pubkey} endpoint={row['endpoint']}")
        peers_state[pubkey] = row["status"]

    # 2) Changements d'IP source (roaming / nouvelle session), même si le
    #    statut running/stopped n'a pas bougé entre deux checks.
    new_last_change = last_change
    for row in conn.execute(
            f'SELECT id, endpoint, time FROM "{WG_IFACE}_history_endpoint" '
            f'WHERE time > ? ORDER BY time ASC', (last_change,)):
        pubkey, endpoint, t = row["id"], row["endpoint"], row["time"]
        peer = peers.get(pubkey)
        name = (peer["name"] if peer and peer["name"] else pubkey[:8])
        allowed_ip = peer["allowed_ip"] if peer else "?"
        lines.append(f"[{ts}] wg-monitor: event=endpoint_changed peer_name={name} "
                     f"peer_ip={allowed_ip} pubkey={pubkey} endpoint={endpoint}")
        new_last_change = t

    conn.close()

    for line in lines:
        print(line)

    save_state({"peers": peers_state, "last_endpoint_change": new_last_change})


if __name__ == "__main__":
    main()
