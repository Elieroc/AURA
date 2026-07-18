#!/usr/bin/env python3
# Intégration Wazuh -> AbuseIPDB
# Interroge l'API AbuseIPDB pour la réputation de l'IP source (data.srcip)
# d'une alerte, et réinjecte le résultat comme nouvel événement dans
# l'analyseur Wazuh (socket queue), qui matche les règles 100621/100622.
#
# Appelé par wazuh-integratord : custom-abuseipdb <alert_file> <api_key>

import json
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket

import requests

SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = "90"
TIMEOUT = 10


def send_event(event: dict) -> None:
    msg = f"1:custom-abuseipdb:{json.dumps(event)}"
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(msg.encode())
    sock.close()


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(1)

    alert_file, api_key = sys.argv[1], sys.argv[2]

    with open(alert_file) as f:
        alert = json.load(f)

    srcip = alert.get("data", {}).get("srcip")
    if not srcip:
        sys.exit(0)

    # IP privées/locales : pas de sens de requêter AbuseIPDB
    if srcip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.",
                         "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
                         "fe80:", "::1")):
        sys.exit(0)

    try:
        response = requests.get(
            API_URL,
            params={"ipAddress": srcip, "maxAgeInDays": MAX_AGE_DAYS},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()["data"]
    except Exception as exc:
        send_event({
            "integration": "custom-abuseipdb",
            "abuseipdb": {"error": str(exc), "srcip": srcip},
        })
        sys.exit(1)

    send_event({
        "integration": "custom-abuseipdb",
        # srcip à la racine -> data.srcip après décodage JSON -> enrichi en
        # GeoLocation par le pipeline geoip de l'indexer
        "srcip": srcip,
        "abuseipdb": {
            "srcip": srcip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
            "last_reported_at": data.get("lastReportedAt"),
            "source_alert_rule_id": alert.get("rule", {}).get("id"),
            "source_alert_description": alert.get("rule", {}).get("description"),
        },
    })


if __name__ == "__main__":
    main()
