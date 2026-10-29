"""Detect common TCP and UDP port scans on an authorized local lab host.

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

from scapy.all import IP, TCP, UDP, sniff


EVENT_API_URL = os.getenv("EVENT_API_URL", "")
EVENT_SITE_KEY = os.getenv("EVENT_SITE_KEY", "")
EVENT_SITE_ID = os.getenv("EVENT_SITE_ID", "demo")
SENSOR_INTERFACE = os.getenv("SENSOR_INTERFACE") or None
UNIQUE_PORT_THRESHOLD = int(os.getenv("PORT_SCAN_UNIQUE_PORTS", "10"))
WINDOW_SECONDS = int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "60"))
COOLDOWN_SECONDS = int(os.getenv("PORT_SCAN_COOLDOWN_SECONDS", "60"))

seen: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
last_reported: dict[tuple[str, str], float] = {}
lock = threading.Lock()


def tcp_scan_type(flags: int) -> str | None:
    """Classify TCP probes using the flag combinations used by common scanners."""
    if flags & 0x02 and not flags & 0x10:
        return "syn"
    if flags == 0:
        return "null"
    if flags == 0x01:
        return "fin"
    if flags == 0x29:
        return "xmas"
    if flags == 0x10:
        return "ack"
    return None


def report_scan(source_ip: str, destination_port: int, scan_type: str) -> None:
    if not EVENT_API_URL or not EVENT_SITE_KEY:
        return
    payload = {
        "site_id": EVENT_SITE_ID,
        "source_ip": source_ip,
        "path": "/",
        "method": "UDP" if scan_type == "udp" else "TCP",
        "event_type": "port_probe",
        "destination_port": destination_port,
        "severity": "medium",
        "scan_type": scan_type,
        "rule_id": f"network.{scan_type}-port-scan",
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
    if not packet.haslayer(IP):
        return
    if packet.haslayer(TCP):
        scan_type = tcp_scan_type(int(packet[TCP].flags))
        destination_port = int(packet[TCP].dport) if scan_type else None
    elif packet.haslayer(UDP):
        scan_type = "udp"
        destination_port = int(packet[UDP].dport)
    else:
        return
    if not scan_type or destination_port is None:
        return

    source_ip = packet[IP].src
    now = time.monotonic()
    key = (source_ip, scan_type)
    with lock:
        ports = seen[key]
        ports.append((now, destination_port))
        while ports and now - ports[0][0] > WINDOW_SECONDS:
            ports.popleft()
        unique_ports = {port for _, port in ports}
        last = last_reported.get(key, 0)
        should_report = (
            len(unique_ports) >= UNIQUE_PORT_THRESHOLD
            and now - last >= COOLDOWN_SECONDS
        )
        if should_report:
            last_reported[key] = now
    report_ports = sorted(unique_ports) if should_report else []
    for port in report_ports:
        report_scan(source_ip, port, scan_type)


def main() -> None:
    if not EVENT_API_URL or not EVENT_SITE_KEY:
        raise SystemExit("EVENT_API_URL and EVENT_SITE_KEY are required")
    print(
        f"monitoring TCP/UDP probe traffic on {SENSOR_INTERFACE or 'all interfaces'}",
        flush=True,
    )
    sniff(
        iface=SENSOR_INTERFACE,
        filter="tcp or udp",
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
