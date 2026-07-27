#!/usr/bin/env python3
"""Émet des événements connect/disconnect pour les pairs WireGuard.

WireGuard (module noyau) ne journalise rien par défaut : pas d'audit trail,
seul `wg show` donne un état instantané (dernier handshake, compteurs). Ce
script compare cet état d'un run à l'autre et loggue les TRANSITIONS
(connexion active <-> inactive), pas un snapshot périodique bruyant.

"Actif" = dernier handshake dans les WG_THRESHOLD_S dernières secondes.
WireGuard rekey sous trafic toutes les 120-180s ; un pair réellement inactif
(pas de trafic) n'a simplement pas de handshake récent, ce qui n'est PAS une
déconnexion explicite (WireGuard est sans état de connexion) mais un proxy
raisonnable pour "pair actuellement en train de causer avec nous".

Usage : appelé périodiquement (systemd timer, cf. wg-monitor.timer),
écrit une ligne par transition sur stdout -> redirigé vers WG_LOG_FILE.
Idempotent entre les runs via WG_STATE_FILE (pas de dépendance à un
démon qui tournerait en continu).
"""
import ipaddress
import json
import os
import subprocess
import sys
import time

WG_IFACE = os.environ.get("WG_IFACE", "wg0")
WG_THRESHOLD_S = int(os.environ.get("WG_THRESHOLD_S", "200"))
STATE_FILE = os.environ.get("WG_STATE_FILE", "/var/lib/wg-monitor/state.json")
LOG_FILE = os.environ.get("WG_LOG_FILE", "/var/log/wireguard-events.log")


def peer_ip(allowed_ips):
    # AllowedIPs peut lister plusieurs réseaux ; on garde la première IP hôte
    # (/32) comme identifiant lisible du pair.
    for net in allowed_ips.split(","):
        net = net.strip()
        try:
            n = ipaddress.ip_network(net, strict=False)
            if n.num_addresses == 1:
                return str(n.network_address)
        except ValueError:
            continue
    return allowed_ips


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def main():
    out = subprocess.run(["wg", "show", WG_IFACE, "dump"],
                          capture_output=True, text=True, check=True).stdout
    lines = out.strip().splitlines()
    if not lines:
        return

    now = int(time.time())
    prev_state = load_state()
    new_state = {}

    # Première ligne = l'interface elle-même (privkey, port, fwmark) : ignorée.
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 5:
            continue
        pubkey, _psk, endpoint, allowed_ips, latest_handshake = fields[:5]
        latest_handshake = int(latest_handshake)
        active = latest_handshake > 0 and (now - latest_handshake) < WG_THRESHOLD_S
        ip = peer_ip(allowed_ips)

        was_active = prev_state.get(pubkey, {}).get("active", False)
        new_state[pubkey] = {"active": active, "last_handshake": latest_handshake}

        if active and not was_active:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
            print(f"[{ts}] wg-monitor: event=peer_connected peer_ip={ip} "
                  f"pubkey={pubkey} endpoint={endpoint}")
        elif was_active and not active:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
            print(f"[{ts}] wg-monitor: event=peer_disconnected peer_ip={ip} "
                  f"pubkey={pubkey} endpoint={endpoint}")

    save_state(new_state)


if __name__ == "__main__":
    main()
