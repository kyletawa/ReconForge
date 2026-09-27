#!/usr/bin/env python3
"""
ReconForge scope engine.

Loads a YAML scope definition and filters a list of hosts against it.
Exclusions always win over inclusions, and anything not explicitly allowed
is dropped by default — scope creep should require an edit to the scope
file, never a gap in the matching logic.

Example scope.yaml:

    target: example.com

    scope:
      allowed:
        - "example.com"
        - "*.example.com"
      excluded:
        - "admin.example.com"
        - "*.internal.example.com"
"""

import argparse
import fnmatch
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only when PyYAML is missing
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


class ScopeError(ValueError):
    """Raised for a malformed or missing scope file."""


class Scope:
    def __init__(self, target, allowed, excluded):
        self.target = target
        self.allowed = list(allowed or [])
        self.excluded = list(excluded or [])

    @classmethod
    def from_file(cls, path):
        p = Path(path)
        if not p.is_file():
            raise ScopeError(f"scope file not found: {path}")

        try:
            data = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as e:
            raise ScopeError(f"invalid YAML in {path}: {e}") from e

        if not isinstance(data, dict):
            raise ScopeError(f"{path} must contain a YAML mapping at the top level")

        target = data.get("target")
        if not target:
            raise ScopeError("scope file missing required 'target' field")

        scope_block = data.get("scope") or {}
        if not isinstance(scope_block, dict):
            raise ScopeError("'scope' must be a mapping with 'allowed'/'excluded' lists")

        allowed = scope_block.get("allowed") or []
        excluded = scope_block.get("excluded") or []

        if not allowed:
            raise ScopeError("scope.allowed must list at least one pattern")

        return cls(target=target, allowed=allowed, excluded=excluded)

    @staticmethod
    def _normalize(host):
        return host.strip().lower().rstrip(".")

    @classmethod
    def _matches_any(cls, host, patterns):
        host = cls._normalize(host)
        for pattern in patterns:
            if fnmatch.fnmatch(host, cls._normalize(pattern)):
                return True
        return False

    def is_allowed(self, host):
        """Excluded patterns always win. Default is deny."""
        if not host:
            return False
        if self._matches_any(host, self.excluded):
            return False
        return self._matches_any(host, self.allowed)

    def filter_hosts(self, hosts):
        allowed, rejected = [], []
        for h in hosts:
            (allowed if self.is_allowed(h) else rejected).append(h)
        return allowed, rejected


def main():
    parser = argparse.ArgumentParser(
        description="Filter a list of hosts against a ReconForge scope file."
    )
    parser.add_argument("--scope", required=True, help="Path to scope YAML file")
    parser.add_argument("--input", required=True, help="File with one host per line")
    parser.add_argument("--output", required=True, help="Where to write in-scope hosts")
    parser.add_argument("--rejected", help="Optional: write out-of-scope hosts here")
    args = parser.parse_args()

    try:
        scope = Scope.from_file(args.scope)
    except ScopeError as e:
        print(f"[scope error] {e}", file=sys.stderr)
        sys.exit(1)

    in_path = Path(args.input)
    if not in_path.is_file():
        print(f"[scope error] input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    hosts = [l.strip() for l in in_path.read_text().splitlines() if l.strip()]
    allowed, rejected = scope.filter_hosts(hosts)

    Path(args.output).write_text("\n".join(allowed) + ("\n" if allowed else ""))
    if args.rejected:
        Path(args.rejected).write_text("\n".join(rejected) + ("\n" if rejected else ""))

    print(
        f"[scope] {len(allowed)}/{len(hosts)} hosts in scope ({len(rejected)} rejected)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
