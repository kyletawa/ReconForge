import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from diff import build_diff, render_text, read_nuclei_set  # noqa: E402


def make_snapshot(tmp_path, name, **files):
    d = tmp_path / name
    d.mkdir()
    for fname, content in files.items():
        (d / fname).write_text(content)
    return d


class TestBuildDiff:
    def test_detects_new_and_removed_subdomains(self, tmp_path):
        old = make_snapshot(tmp_path, "old", **{"subdomains.txt": "a.example.com\nb.example.com\n"})
        new = make_snapshot(tmp_path, "new", **{"subdomains.txt": "b.example.com\nc.example.com\n"})
        d = build_diff(old, new)
        assert d["subdomains"]["new"] == ["c.example.com"]
        assert d["subdomains"]["removed"] == ["a.example.com"]

    def test_no_change_gives_empty_diff(self, tmp_path):
        old = make_snapshot(tmp_path, "old", **{"subdomains.txt": "a.example.com\n"})
        new = make_snapshot(tmp_path, "new", **{"subdomains.txt": "a.example.com\n"})
        d = build_diff(old, new)
        assert d["subdomains"]["new"] == []
        assert d["subdomains"]["removed"] == []

    def test_missing_files_treated_as_empty_sets(self, tmp_path):
        old = make_snapshot(tmp_path, "old")
        new = make_snapshot(tmp_path, "new", **{"live_hosts.txt": "https://new.example.com\n"})
        d = build_diff(old, new)
        assert d["live_hosts"]["new"] == ["https://new.example.com"]
        assert d["live_hosts"]["removed"] == []

    def test_new_nuclei_finding_detected(self, tmp_path):
        old = make_snapshot(tmp_path, "old", **{"nuclei.json": ""})
        new_finding = json.dumps(
            {"template-id": "exposed-env-file", "host": "https://example.com",
             "matched-at": "https://example.com/.env", "info": {"severity": "high"}}
        )
        new = make_snapshot(tmp_path, "new", **{"nuclei.json": new_finding + "\n"})
        d = build_diff(old, new)
        assert len(d["nuclei_findings"]["new"]) == 1
        assert "exposed-env-file" in d["nuclei_findings"]["new"][0]

    def test_ports_diff(self, tmp_path):
        old = make_snapshot(tmp_path, "old", **{"ports.txt": "host.example.com 80/tcp open http\n"})
        new = make_snapshot(
            tmp_path, "new",
            **{"ports.txt": "host.example.com 80/tcp open http\nhost.example.com 8443/tcp open https-alt\n"},
        )
        d = build_diff(old, new)
        assert d["ports"]["new"] == ["host.example.com 8443/tcp open https-alt"]
        assert d["ports"]["removed"] == []


class TestReadNucleiSet:
    def test_parses_jsonl_into_tuples(self, tmp_path):
        p = tmp_path / "nuclei.json"
        p.write_text(
            json.dumps({"template-id": "t1", "host": "h1"}) + "\n"
            + json.dumps({"template-id": "t2", "host": "h2"}) + "\n"
        )
        result = read_nuclei_set(p)
        assert result == {("t1", "h1"), ("t2", "h2")}

    def test_missing_file_returns_empty_set(self, tmp_path):
        assert read_nuclei_set(tmp_path / "missing.json") == set()

    def test_malformed_lines_skipped_not_fatal(self, tmp_path):
        p = tmp_path / "nuclei.json"
        p.write_text("not json\n" + json.dumps({"template-id": "t1", "host": "h1"}) + "\n")
        assert read_nuclei_set(p) == {("t1", "h1")}


class TestRenderText:
    def test_no_changes_message_when_diff_is_empty(self):
        empty_diff = {
            "old_run": "run1", "new_run": "run2",
            "subdomains": {"new": [], "removed": []},
            "live_hosts": {"new": [], "removed": []},
            "technologies": {"new": [], "removed": []},
            "ports": {"new": [], "removed": []},
            "urls": {"new": [], "removed": []},
            "nuclei_findings": {"new": [], "removed": []},
        }
        text = render_text(empty_diff)
        assert "No changes detected" in text

    def test_new_items_prefixed_with_plus(self):
        d = {
            "old_run": "run1", "new_run": "run2",
            "subdomains": {"new": ["dev.example.com"], "removed": []},
            "live_hosts": {"new": [], "removed": []},
            "technologies": {"new": [], "removed": []},
            "ports": {"new": [], "removed": []},
            "urls": {"new": [], "removed": []},
            "nuclei_findings": {"new": [], "removed": []},
        }
        text = render_text(d)
        assert "+ dev.example.com" in text

    def test_removed_items_prefixed_with_minus(self):
        d = {
            "old_run": "run1", "new_run": "run2",
            "subdomains": {"new": [], "removed": ["old.example.com"]},
            "live_hosts": {"new": [], "removed": []},
            "technologies": {"new": [], "removed": []},
            "ports": {"new": [], "removed": []},
            "urls": {"new": [], "removed": []},
            "nuclei_findings": {"new": [], "removed": []},
        }
        text = render_text(d)
        assert "- old.example.com" in text
