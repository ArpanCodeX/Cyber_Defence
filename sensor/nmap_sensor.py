"""Detect TCP SYN port scans on an authorized local lab host.

This sensor reports telemetry to the existing event API. It deliberately does
not execute firewall commands; the API's temporary block protects the HTTP
gateway while keeping the sensor safe to run in a lab.
"""
from __future__ import annotations

from collections import defaultdict, deque
import json
import os
import threading
import time
from urllib import request
from urllib.error import URLError

from scapy.all import IP, TCP, sniff


EVENT_API_URL = os.getenv("EVENT_API_URL", "")
EVENT_SITE_KEY = os.getenv("EVENT_SITE_KEY", "")
EVENT_SITE_ID = os.getenv("EVENT_SITE_ID", "demo")
SENSOR_INTERFACE = os.getenv("SENSOR_INTERFACE") or None
UNIQUE_PORT_THRESHOLD = int(os.getenv("PORT_SCAN_UNIQUE_PORTS", "10"))
WINDOW_SECONDS = int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "60"))
COOLDOWN_SECONDS = int(os.getenv("PORT_SCAN_COOLDOWN_SECONDS", "60"))

seen: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
last_reported: dict[str, float] = {}
lock = threading.Lock()


def report_scan(source_ip: str, destination_port: int) -> None:
    if not EVENT_API_URL or not EVENT_SITE_KEY:
        return
    payload = {
        "site_id": EVENT_SITE_ID,
        "source_ip": source_ip,
        "path": "/",
        "method": "TCP",
        "event_type": "port_probe",
        "destination_port": destination_port,
        "severity": "medium",
        "rule_id": "network.syn-port-scan",
    }
    req = request.Request(
        EVENT_API_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Site-Key": EVENT_SITE_KEY},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=2):
            pass
    except (URLError, TimeoutError, OSError, ValueError) as error:
        print(f"event report failed: {error}", flush=True)


def handle_packet(packet) -> None:
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return
    tcp = packet[TCP]
    if tcp.flags & 0x02 and not tcp.flags & 0x10:
        source_ip = packet[IP].src
        now = time.monotonic()
        with lock:
            ports = seen[source_ip]
            ports.append((now, int(tcp.dport)))
            while ports and now - ports[0][0] > WINDOW_SECONDS:
                ports.popleft()
            unique_ports = {port for _, port in ports}
            last = last_reported.get(source_ip, 0)
            should_report = (
                len(unique_ports) >= UNIQUE_PORT_THRESHOLD
                and now - last >= COOLDOWN_SECONDS
            )
            if should_report:
                last_reported[source_ip] = now
        report_ports = sorted(unique_ports) if should_report else []
        for port in report_ports:
            report_scan(source_ip, port)


def main() -> None:
    if not EVENT_API_URL or not EVENT_SITE_KEY:
        raise SystemExit("EVENT_API_URL and EVENT_SITE_KEY are required")
    print(
        f"monitoring TCP SYN traffic on {SENSOR_INTERFACE or 'all interfaces'}",
        flush=True,
    )
    sniff(iface=SENSOR_INTERFACE, filter="tcp[tcpflags] & tcp-syn != 0", prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
