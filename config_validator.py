#!/usr/bin/env python3
"""
Validates a ReconForge recon.conf before recon.sh sources it.

Bash will happily `source` a config file with a typo'd key ("THREAD=100"
instead of "THREADS=100") or a non-numeric value and silently do the wrong
thing — or nothing — with it. This catches that upfront instead of letting
it fail quietly three phases later.
"""

import argparse
import re
import sys
from pathlib import Path

# key -> expected type. Keep this in sync with recon.sh's Defaults section.
KNOWN_KEYS = {
    "THREADS": int,
    "RATE_LIMIT": int,
    "RESOLVERS": str,
    "WORDLIST": str,
    "TOP_PORTS": int,
    "URL_TIMEOUT": int,
    "SCOPE_FILE": str,
}

_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def parse_conf(path):
    """Returns (dict of key -> raw string value, list of error strings)."""
    values, errors = {}, []
    p = Path(path)

    if not p.is_file():
        return values, [f"config file not found: {path}"]

    for lineno, raw in enumerate(p.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        match = _LINE_RE.match(line)
        if not match:
            errors.append(f"line {lineno}: not a valid KEY=VALUE line: {raw!r}")
            continue

        key, val = match.group(1), match.group(2).strip()
        val = val.strip('"').strip("'")

        if key not in KNOWN_KEYS:
            errors.append(f"line {lineno}: unknown config key '{key}' (typo?)")
            continue

        expected_type = KNOWN_KEYS[key]
        if expected_type is int and not re.fullmatch(r"-?\d+", val):
            errors.append(f"line {lineno}: {key} must be an integer, got {val!r}")
            continue

        values[key] = val

    return values, errors


def main():
    ap = argparse.ArgumentParser(description="Validate a ReconForge recon.conf file.")
    ap.add_argument("path")
    args = ap.parse_args()

    values, errors = parse_conf(args.path)

    if errors:
        for e in errors:
            print(f"[config error] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[config] OK — {len(values)} known key(s) set")


if __name__ == "__main__":
    main()
