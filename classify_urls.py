#!/usr/bin/env python3
"""
URL classifier — slices a list of collected URLs into buckets useful for
attack-surface triage: URLs carrying query parameters, JavaScript files, and
URLs whose extension often indicates an exposed sensitive file.

Pulled out of recon.sh's inline grep patterns so the matching logic has one
source of truth and is actually testable.
"""

import argparse
import re
from pathlib import Path
from urllib.parse import urlsplit

SENSITIVE_EXTENSIONS = {
    "env", "bak", "old", "sql", "zip", "tar", "gz", "log",
    "config", "yml", "yaml", "json", "conf", "ini", "swp", "db",
}

_EXTENSION_RE = re.compile(r"\.([a-z0-9]{1,6})$")


def has_params(url):
    return bool(urlsplit(url).query)


def is_js_file(url):
    return urlsplit(url).path.lower().endswith(".js")


def sensitive_extension(url):
    """Returns the matched extension if the URL's path ends in one we flag, else None."""
    path = urlsplit(url).path.lower()
    match = _EXTENSION_RE.search(path)
    if match and match.group(1) in SENSITIVE_EXTENSIONS:
        return match.group(1)
    return None


def classify(urls):
    params, js_files, sensitive = [], [], []
    for url in urls:
        if has_params(url):
            params.append(url)
        if is_js_file(url):
            js_files.append(url)
        if sensitive_extension(url):
            sensitive.append(url)
    return params, js_files, sensitive


def main():
    ap = argparse.ArgumentParser(description="Classify URLs into attack-surface buckets.")
    ap.add_argument("--input", required=True)
    ap.add_argument("--params-out", required=True)
    ap.add_argument("--js-out", required=True)
    ap.add_argument("--sensitive-out", required=True)
    args = ap.parse_args()

    p = Path(args.input)
    urls = [l.strip() for l in p.read_text().splitlines() if l.strip()] if p.is_file() else []

    params, js_files, sensitive = classify(urls)

    Path(args.params_out).write_text("\n".join(params) + ("\n" if params else ""))
    Path(args.js_out).write_text("\n".join(js_files) + ("\n" if js_files else ""))
    Path(args.sensitive_out).write_text("\n".join(sensitive) + ("\n" if sensitive else ""))

    print(
        f"[classify] {len(params)} param'd URLs, {len(js_files)} JS files, "
        f"{len(sensitive)} sensitive-extension hits"
    )


if __name__ == "__main__":
    main()
