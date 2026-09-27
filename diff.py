#!/usr/bin/env python3
"""
ReconForge diff engine — compares two run snapshots and reports what
changed: new/removed subdomains, live hosts, ports, technologies, and
nuclei findings. This is what turns ReconForge from a point-in-time recon
tool into a continuous attack-surface monitor: run it today, run it again
next week, and get told exactly what's new.

Snapshots are plain directories of text files (see recon.sh's history
step), not the HTML/JSON report — keeping this decoupled from the report
schema means the report can change shape without breaking diffing.
"""

import argparse
import json
import sys
from pathlib import Path


def read_set(path):
    p = Path(path)
    if not p.is_file():
        return set()
    return {line.strip() for line in p.read_text().splitlines() if line.strip()}


def read_nuclei_set(path):
    """Returns a set of (template_id, host) tuples from a nuclei -jsonl file."""
    p = Path(path)
    if not p.is_file():
        return set()

    findings = set()
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = record.get("info", {}) or {}
        template_id = record.get("template-id", info.get("name", "unknown"))
        host = record.get("host") or record.get("matched-at", "")
        findings.add((template_id, host))
    return findings


def diff_sets(old, new):
    """Returns (sorted new-only, sorted old-only)."""
    return sorted(new - old), sorted(old - new)


def build_diff(old_dir, new_dir):
    old_dir, new_dir = Path(old_dir), Path(new_dir)

    subs_new, subs_removed = diff_sets(
        read_set(old_dir / "subdomains.txt"), read_set(new_dir / "subdomains.txt")
    )
    live_new, live_removed = diff_sets(
        read_set(old_dir / "live_hosts.txt"), read_set(new_dir / "live_hosts.txt")
    )
    tech_new, tech_removed = diff_sets(
        read_set(old_dir / "tech.txt"), read_set(new_dir / "tech.txt")
    )
    ports_new, ports_removed = diff_sets(
        read_set(old_dir / "ports.txt"), read_set(new_dir / "ports.txt")
    )
    url_new, url_removed = diff_sets(
        read_set(old_dir / "urls.txt"), read_set(new_dir / "urls.txt")
    )

    old_nuclei = read_nuclei_set(old_dir / "nuclei.json")
    new_nuclei = read_nuclei_set(new_dir / "nuclei.json")
    finding_new, finding_removed = diff_sets(old_nuclei, new_nuclei)

    return {
        "old_run": old_dir.name,
        "new_run": new_dir.name,
        "subdomains": {"new": subs_new, "removed": subs_removed},
        "live_hosts": {"new": live_new, "removed": live_removed},
        "technologies": {"new": tech_new, "removed": tech_removed},
        "ports": {"new": ports_new, "removed": ports_removed},
        "urls": {"new": url_new, "removed": url_removed},
        "nuclei_findings": {
            "new": [f"{tid} @ {host}" for tid, host in finding_new],
            "removed": [f"{tid} @ {host}" for tid, host in finding_removed],
        },
    }


def _has_changes(diff):
    return any(v["new"] or v["removed"] for v in diff.values() if isinstance(v, dict))


def render_text(diff):
    lines = ["RECON DIFFERENCE", "=" * 60, f"Comparing: {diff['old_run']}  ->  {diff['new_run']}", ""]

    def section(title, entries, cap=200):
        new, removed = entries["new"], entries["removed"]
        if not new and not removed:
            return
        lines.append(title.upper())
        for item in new[:cap]:
            lines.append(f"+ {item}")
        for item in removed[:cap]:
            lines.append(f"- {item}")
        if len(new) > cap or len(removed) > cap:
            lines.append(f"  ... ({len(new)} new, {len(removed)} removed total — truncated)")
        lines.append("")

    section("New / Removed Subdomains", diff["subdomains"])
    section("New / Removed Live Hosts", diff["live_hosts"])
    section("New / Removed Ports", diff["ports"])
    section("New / Removed Technologies", diff["technologies"])
    section("New / Removed URLs", diff["urls"], cap=50)
    section("New / Removed Nuclei Findings", diff["nuclei_findings"])

    if not _has_changes(diff):
        lines.append("No changes detected since the last run.")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Diff two ReconForge run snapshots.")
    ap.add_argument("--old", required=True, help="Path to the older snapshot directory")
    ap.add_argument("--new", required=True, help="Path to the newer snapshot directory")
    ap.add_argument("--out-json", help="Optional: write the diff as JSON")
    ap.add_argument("--out-text", help="Optional: write the diff as plain text")
    args = ap.parse_args()

    if not Path(args.old).is_dir():
        print(f"[diff error] old snapshot dir not found: {args.old}", file=sys.stderr)
        sys.exit(1)
    if not Path(args.new).is_dir():
        print(f"[diff error] new snapshot dir not found: {args.new}", file=sys.stderr)
        sys.exit(1)

    diff = build_diff(args.old, args.new)
    text = render_text(diff)

    print(text)

    if args.out_json:
        Path(args.out_json).write_text(json.dumps(diff, indent=2))
    if args.out_text:
        Path(args.out_text).write_text(text)


if __name__ == "__main__":
    main()
