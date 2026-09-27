#!/usr/bin/env python3
"""
Shared nmap "normal format" (-oN) parser. Used by both gen_report.py (for
the HTML/JSON report) and the history-snapshot step in recon.sh (for
diffing between runs), so there's exactly one place that understands
nmap's text output instead of two slightly-different regexes drifting
apart over time.
"""

import argparse
import re
from pathlib import Path

# "Nmap scan report for host.example.com (93.184.216.34)"
# "Nmap scan report for 93.184.216.34"
HOST_RE = re.compile(r"^Nmap scan report for (\S+)(?:\s+\(([0-9a-fA-F:.]+)\))?\s*$")

# "80/tcp   open  http"
# "443/tcp  open  https    nginx"  (extra columns beyond service are ignored)
PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)")


def parse_nmap_text(text):
    """Parse nmap normal-format text into {host: [{"port", "proto", "state", "service"}, ...]}."""
    hosts = {}
    current_host = None

    for raw_line in text.splitlines():
        line = raw_line.strip()

        host_match = HOST_RE.match(line)
        if host_match:
            current_host = host_match.group(1)
            hosts.setdefault(current_host, [])
            continue

        port_match = PORT_RE.match(line)
        if port_match and current_host:
            hosts[current_host].append(
                {
                    "port": int(port_match.group(1)),
                    "proto": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                }
            )

    return hosts


def flatten_for_diff(hosts):
    """Sorted 'host port/proto state service' lines — stable, line-diffable format."""
    lines = []
    for host, ports in hosts.items():
        for p in ports:
            lines.append(f"{host} {p['port']}/{p['proto']} {p['state']} {p['service']}")
    return sorted(lines)


def count_open_ports(hosts):
    return sum(1 for ports in hosts.values() for p in ports if p["state"] == "open")


def main():
    ap = argparse.ArgumentParser(description="Parse nmap normal-format output.")
    ap.add_argument("--input", required=True)
    ap.add_argument(
        "--output",
        required=True,
        help="Flattened 'host port/proto state service' lines, one per line",
    )
    args = ap.parse_args()

    p = Path(args.input)
    if not p.is_file():
        Path(args.output).write_text("")
        return

    hosts = parse_nmap_text(p.read_text())
    lines = flatten_for_diff(hosts)
    Path(args.output).write_text("\n".join(lines) + ("\n" if lines else ""))


if __name__ == "__main__":
    main()
