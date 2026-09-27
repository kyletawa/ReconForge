import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nmap_parser import parse_nmap_text, flatten_for_diff, count_open_ports  # noqa: E402


SAMPLE_NMAP_OUTPUT = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-27 10:00 UTC
Nmap scan report for www.example.com (93.184.216.34)
Host is up (0.012s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
8080/tcp closed http-proxy

Nmap scan report for api.example.com (93.184.216.35)
Host is up (0.020s latency).
PORT    STATE SERVICE
443/tcp open  https

Nmap done: 2 IP addresses (2 hosts up) scanned in 4.21 seconds
"""


class TestParseNmapText:
    def test_parses_multiple_hosts(self):
        hosts = parse_nmap_text(SAMPLE_NMAP_OUTPUT)
        assert set(hosts.keys()) == {"www.example.com", "api.example.com"}

    def test_parses_port_entries_correctly(self):
        hosts = parse_nmap_text(SAMPLE_NMAP_OUTPUT)
        www_ports = {p["port"]: p for p in hosts["www.example.com"]}
        assert www_ports[80]["state"] == "open"
        assert www_ports[80]["service"] == "http"
        assert www_ports[443]["proto"] == "tcp"
        assert www_ports[8080]["state"] == "closed"

    def test_host_with_single_port(self):
        hosts = parse_nmap_text(SAMPLE_NMAP_OUTPUT)
        assert len(hosts["api.example.com"]) == 1
        assert hosts["api.example.com"][0]["port"] == 443

    def test_empty_input_returns_empty_dict(self):
        assert parse_nmap_text("") == {}

    def test_host_with_no_open_ports_still_present(self):
        text = "Nmap scan report for empty.example.com\nHost is up.\n"
        hosts = parse_nmap_text(text)
        assert hosts == {"empty.example.com": []}

    def test_ip_only_host_line(self):
        text = "Nmap scan report for 10.0.0.1\n80/tcp open http\n"
        hosts = parse_nmap_text(text)
        assert "10.0.0.1" in hosts
        assert hosts["10.0.0.1"][0]["port"] == 80


class TestCountOpenPorts:
    def test_counts_only_open_state(self):
        hosts = parse_nmap_text(SAMPLE_NMAP_OUTPUT)
        # 80/open, 443/open on www; 443/open on api; 8080/closed excluded
        assert count_open_ports(hosts) == 3

    def test_zero_for_no_hosts(self):
        assert count_open_ports({}) == 0


class TestFlattenForDiff:
    def test_produces_sorted_stable_lines(self):
        hosts = parse_nmap_text(SAMPLE_NMAP_OUTPUT)
        lines = flatten_for_diff(hosts)
        assert lines == sorted(lines)
        assert any("www.example.com 80/tcp open http" == l for l in lines)

    def test_empty_hosts_produces_empty_list(self):
        assert flatten_for_diff({}) == []
