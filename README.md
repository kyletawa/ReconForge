<div align="center">

# ReconForge

**Point it at a domain. Get subdomains, live hosts, tech stacks, open ports, crawled URLs, and vuln hits — back as one clean report.**

[![Bash](https://img.shields.io/badge/bash-5.0%2B-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/kyletawa/ReconForge/actions/workflows/ci.yml/badge.svg)](https://github.com/kyletawa/ReconForge/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)
[![Status](https://img.shields.io/badge/status-active-success)](#)

</div>

---

Most recon "pipelines" are a single messy shell one-liner someone pasted into a
gist three years ago. ReconForge isn't that. It's eight clear phases, each
one logged, resumable, and independently debuggable — glued around the same
tools you already trust (`subfinder`, `httpx`, `nmap`, `katana`, `nuclei`,
etc.), ending in a report you'd actually be comfortable handing to a client.

```
domain.com
   │
   ▼
 subdomain enum ──▶ dns resolution ──▶ live host probing ──▶ tech fingerprint
   │                                                              │
   ▼                                                              ▼
 port scanning ◀── url collection ◀── attack surface slicing ◀────┘
   │
   ▼
 nuclei scan ──▶ HTML / JSON report
```

## Why this exists

I built this while moving from IT support into offensive security :I wanted
a recon tool that didn't just dump 10,000 lines of subdomains into a
terminal and call it a day. ReconForge is the tool I wanted on day one of a
bug bounty program: run one command, walk away, come back to a report that
tells you where to actually start looking.

## Features

- 🔍 **Eight-phase pipeline** — subdomain enum → DNS resolution → live host
  detection → HTTP probing & tech fingerprinting → port scanning → URL
  collection → vuln scanning → reporting
- 🧠 **Smart output slicing** — auto-buckets collected URLs into
  parameterized endpoints, JS files, and sensitive-extension hits
  (`.env`, `.sql`, `.git`-adjacent, etc.) so you're not grepping manually
- ⚡ **Resumable runs** — `--skip-existing` picks up where a killed or
  interrupted scan left off, phase by phase
- 🛡️ **Active steps are opt-in** — port scanning and nuclei only fire with
  `--active` / `--nuclei`, so a default run stays passive-only
- 📊 **One-file HTML dashboard** — dark, readable, shareable — plus a
  structured JSON export for feeding into your own tooling
- 🧩 **Graceful degradation** — missing an optional tool like `amass` or
  `nuclei`? That phase just gets skipped with a warning, nothing crashes
- ⏱️ **Timeout-guarded URL collection** — `gau`/`waybackurls`/`katana` each
  get a configurable wall-clock limit so one slow upstream API can't stall
  the whole pipeline on a large target
- ⚙️ **Config file support** — set your defaults once in `recon.conf`,
  override per-run with flags, with a validator that catches typo'd keys
  before bash silently ignores them
- 🎯 **Scope engine** — define allowed/excluded host patterns in a YAML
  file and every phase after discovery only ever touches what's in scope;
  fails closed if the scope file itself is broken
- 📈 **Continuous monitoring, not just point-in-time recon** — every run
  snapshots itself, and from the second run onward you get a diff: new
  subdomains, new open ports, new tech, new URLs, new nuclei findings —
  exactly what changed since last time
- ✅ **Tested, with CI** — 70+ unit tests covering the scope engine, URL
  classifier, config validator, nmap parser, report generator, and diff
  engine, plus a GitHub Actions pipeline running ShellCheck, syntax checks,
  and an end-to-end smoke test on every push

## Quick start

```bash
git clone https://github.com/kyletawa/ReconForge.git
cd ReconForge
chmod +x recon.sh

./recon.sh -d example.com
```

That's it : passive recon only, report lands at
`recon_output/example.com/report/report.html`.

Want the full engagement pass?

```bash
./recon.sh -d example.com --active --nuclei -t 100
```

Running against a big target and URL collection is dragging? Slow upstream
APIs (Common Crawl especially) are wrapped in a 5-minute timeout per tool by
default so they can't stall the whole run — bump it with `--url-timeout 600`
or disable it with `--url-timeout 0`.

Only want ReconForge touching hosts you've actually confirmed are in scope?

```bash
cp scope.example.yaml scope.yaml   # edit to your target's allowed/excluded patterns
./recon.sh -d example.com --scope scope.yaml
```

Anything that doesn't match an allowed pattern — or matches an excluded one
— never reaches DNS resolution, httpx, nmap, katana, or nuclei.

Run it again next week and it tells you what changed:

```bash
./recon.sh -d example.com
# ...
# RECON DIFFERENCE
# ================
# NEW SUBDOMAINS
# + dev.example.com
# NEW PORTS
# + 8443/tcp
# NEW FINDINGS
# + 1
```

## What you get

```
recon_output/example.com/
├── subdomains/subdomains.txt       # scope-filtered, if --scope was used
├── dns/resolved.txt
├── httpx/live_hosts.txt
├── ports/nmap_scan.txt
├── urls/urls.txt, urls_with_params.txt, js_files.txt, interesting_extensions.txt
├── nuclei/nuclei_results.json
├── history/<timestamp>/            # snapshot from every run, kept for diffing
└── report/
    ├── report.html                 ← start here
    ├── report.json
    └── diff.txt                    # vs. the previous run, from the 2nd run onward
```

## Stack

| Phase | Tool(s) |
|---|---|
| Subdomain enum | `subfinder`, `amass`, `puredns` (optional brute-force) |
| DNS resolution | `dnsx` |
| Live host + fingerprinting | `httpx` |
| Port scanning | `nmap` |
| URL collection | `gau`, `waybackurls`, `katana` |
| Vuln scanning | `nuclei` |
| Scope enforcement | `scope.py` (PyYAML) |
| Reporting & diffing | Python 3, `jq`, `gen_report.py`, `diff.py`, `nmap_parser.py` |

Full install commands, every flag, config file options, and output schema
are in **[docs/USAGE.md](docs/USAGE.md)**.

## Extending it

Each phase is a self-contained block in `recon.sh` — add a tool's call,
pipe its output into that phase's file, and wire a new field into
`gen_report.py` if you want it in the dashboard. No framework to fight,
just bash and a bit of Python. See [docs/USAGE.md](docs/USAGE.md#extending-it)
for the specifics.

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
shellcheck recon.sh
```

70+ tests cover the scope engine, URL classifier, config validator, nmap
parser, report generator, and diff engine. Every push and PR runs the same
checks in CI — ShellCheck, bash/Python syntax, the full test suite, and an
end-to-end smoke test that actually runs every CLI tool against fixture
data and checks the output.

## Legal

Only run this against assets you're explicitly authorized to test — your
own infrastructure, or a program's published scope with a valid rules of
engagement. Unauthorized scanning is illegal in most jurisdictions and will
get you kicked off every bounty platform that matters.

## License

MIT: use it, fork it, break it, improve it.

---

<div align="center">

Built by **Kyle** ([Kyle.exe](https://tawandachihata.netlify.app)) — CoreSec Group
· [blog](https://tawandablog.netlify.app) · [portfolio](https://tawandachihata.netlify.app)

</div>
