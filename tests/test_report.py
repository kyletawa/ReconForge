import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gen_report import build_data, render_html  # noqa: E402


def make_args(tmp_path, **overrides):
    """Writes minimal fixture files and returns an argparse.Namespace like
    the one gen_report.main() builds, pointing at them."""
    files = {
        "subdomains": "www.example.com\napi.example.com\nexample.com\n",
        "resolved": "www.example.com\napi.example.com\n",
        "httpx_json": (
            '{"url":"https://www.example.com","status_code":200,"title":"Home",'
            '"webserver":"nginx","tech":["Nginx","React"],"content_length":1234}\n'
            '{"url":"https://api.example.com","status_code":403,"title":"Forbidden",'
            '"webserver":"cloudflare","tech":["Cloudflare"],"content_length":100}\n'
        ),
        "ports_txt": (
            "Nmap scan report for www.example.com (93.184.216.34)\n"
            "80/tcp open http\n443/tcp open https\n"
        ),
        "urls": "https://www.example.com/?id=1\nhttps://www.example.com/app.js\n",
        "params": "https://www.example.com/?id=1\n",
        "js_files": "https://www.example.com/app.js\n",
        "sensitive": "https://www.example.com/.env\n",
        "nuclei_json": (
            '{"template-id":"exposed-env-file","info":{"name":"Exposed .env","severity":"high"},'
            '"host":"https://www.example.com","matched-at":"https://www.example.com/.env"}\n'
        ),
    }
    files.update(overrides)

    paths = {}
    for key, content in files.items():
        p = tmp_path / f"{key}.txt"
        p.write_text(content)
        paths[key] = str(p)

    return argparse.Namespace(
        domain="example.com",
        subdomains=paths["subdomains"],
        resolved=paths["resolved"],
        httpx_json=paths["httpx_json"],
        ports_txt=paths["ports_txt"],
        urls=paths["urls"],
        params=paths["params"],
        js_files=paths["js_files"],
        sensitive=paths["sensitive"],
        nuclei_json=paths["nuclei_json"],
    )


class TestBuildData:
    def test_counts_match_fixture_inputs(self, tmp_path):
        data = build_data(make_args(tmp_path))
        assert data["counts"]["subdomains"] == 3
        assert data["counts"]["resolved"] == 2
        assert data["counts"]["live_http"] == 2
        assert data["counts"]["nuclei_findings"] == 1

    def test_open_ports_parsed_from_nmap_text(self, tmp_path):
        data = build_data(make_args(tmp_path))
        assert data["counts"]["open_ports"] == 2
        assert data["counts"]["hosts_port_scanned"] == 1
        assert "www.example.com" in data["open_ports_by_host"]

    def test_technology_counter_aggregates_across_hosts(self, tmp_path):
        data = build_data(make_args(tmp_path))
        techs = dict(data["top_technologies"])
        assert techs.get("Nginx") == 1
        assert techs.get("Cloudflare") == 1

    def test_severity_breakdown(self, tmp_path):
        data = build_data(make_args(tmp_path))
        assert data["severity_breakdown"] == {"high": 1}

    def test_missing_optional_files_degrade_gracefully(self, tmp_path):
        args = make_args(tmp_path, nuclei_json="", ports_txt="")
        args.nuclei_json = str(tmp_path / "does_not_exist.json")
        args.ports_txt = str(tmp_path / "does_not_exist.txt")
        data = build_data(args)
        assert data["counts"]["nuclei_findings"] == 0
        assert data["counts"]["open_ports"] == 0
        assert data["open_ports_by_host"] == {}

    def test_json_serializable(self, tmp_path):
        data = build_data(make_args(tmp_path))
        # should not raise — this is what recon.sh actually writes to report.json
        json.dumps(data)


class TestRenderHtml:
    def test_produces_html_document(self, tmp_path):
        data = build_data(make_args(tmp_path))
        out = render_html(data)
        assert out.startswith("<!DOCTYPE html>")
        assert "example.com" in out

    def test_escapes_user_controlled_title(self, tmp_path):
        args = make_args(
            tmp_path,
            httpx_json=(
                '{"url":"https://www.example.com","status_code":200,'
                '"title":"<script>alert(1)</script>","tech":[]}\n'
            ),
        )
        data = build_data(args)
        out = render_html(data)
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_empty_data_does_not_crash(self, tmp_path):
        args = make_args(
            tmp_path,
            subdomains="",
            resolved="",
            httpx_json="",
            ports_txt="",
            urls="",
            params="",
            js_files="",
            sensitive="",
            nuclei_json="",
        )
        data = build_data(args)
        out = render_html(data)
        assert "<!DOCTYPE html>" in out
        assert "No changes" not in out  # sanity: this is the report, not the diff
