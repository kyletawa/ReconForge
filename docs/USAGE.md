# ReconForge — Full Usage Guide


A modular, staged reconnaissance pipeline for bug bounty and external attack
surface mapping. It wraps well-known open-source recon tools with consistent
logging, resumability, and a single styled HTML/JSON report at the end.

```
Domain
  ↓ subfinder / amass
Subdomain enumeration
  ↓ scope.py (only if --scope is given)
Scope filtering
  ↓ dnsx
DNS resolution
  ↓ httpx
Live host detection + HTTP/HTTPS probing + tech fingerprinting
  ↓ nmap (opt-in)
Port scanning
  ↓ gau / waybackurls / katana
URL collection
  ↓ nuclei (opt-in)
Vulnerability scanning
  ↓ gen_report.py
HTML / JSON report
  ↓ diff.py (from the 2nd run onward)
Diff against the previous run
```

## ⚠️ Legal

Only run this against assets you are explicitly authorized to test: your own
infrastructure, or a target covered by a signed engagement letter or a bug
bounty program's published scope and rules of engagement. Unauthorized
scanning of third-party systems is illegal in most jurisdictions and will get
you banned from bounty platforms at minimum.

## Requirements

Core (required):

| Tool      | Purpose                        | Install |
|-----------|---------------------------------|---------|
| subfinder | Passive subdomain enumeration   | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| dnsx      | Fast DNS resolution              | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx     | HTTP probing + tech-detect       | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nmap      | Port scanning                    | `apt install nmap` / `brew install nmap` |
| gau       | Historical URL collection        | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| katana    | Active crawling                  | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| jq        | JSON parsing in the pipeline      | `apt install jq` / `brew install jq` |
| python3   | Report generation, scope engine, diffing | usually preinstalled |
| PyYAML    | Parsing scope.yaml files          | `pip install -r requirements.txt` |

Optional (pipeline degrades gracefully if missing):

| Tool         | Purpose                            | Install |
|--------------|--------------------------------------|---------|
| amass        | Deeper passive subdomain enum        | `go install github.com/owasp-amass/amass/v4/...@master` |
| waybackurls  | Wayback Machine URL collection       | `go install github.com/tomnomnom/waybackurls@latest` |
| nuclei       | Template-based vulnerability scanning| `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| puredns      | Wordlist-based subdomain brute force | `go install github.com/d3mondev/puredns/v2@latest` |

Make sure `$GOPATH/bin` (usually `~/go/bin`) is on your `$PATH`, and run
`nuclei -update-templates` once before first use.

Make the script executable once:

```bash
chmod +x recon.sh
```

## Usage

```bash
./recon.sh -d example.com
```

Common flags:

```bash
# Faster pass, subfinder only, no amass
./recon.sh -d example.com --no-amass

# Full active engagement: port scan + vuln templates
./recon.sh -d example.com --active --nuclei -t 100 -r 200

# Custom resolvers + wordlist brute force + custom output location
./recon.sh -d example.com --resolvers resolvers.txt --wordlist subs-large.txt -o /data/engagements/acme

# Re-run after adding more scope without redoing finished phases
./recon.sh -d example.com --active --nuclei --skip-existing

# Big target: give slow upstream APIs more time before URL collection gives up
./recon.sh -d example.com --url-timeout 600

# Disable the timeout entirely and let gau/waybackurls/katana run to completion
./recon.sh -d example.com --url-timeout 0

# Only touch hosts your scope file explicitly allows
./recon.sh -d example.com --scope scope.yaml
```

Run `./recon.sh -h` for the full flag list.

### URL collection timeouts

`gau`, `waybackurls`, and `katana` each depend on external APIs (Wayback
Machine, Common Crawl, OTX) that can be slow or rate-limited — especially on
large targets with a long crawl history. By default, each of those three
tools is wrapped in a **300-second timeout**: if one hangs, ReconForge logs a
warning, moves on with whatever it collected, and the pipeline keeps going
instead of stalling indefinitely.

- `--url-timeout <seconds>` — change the per-tool limit (e.g. `600` for a
  large target you're willing to wait longer on)
- `--url-timeout 0` — disable the timeout entirely, let each tool run to
  completion no matter how long it takes

This only wraps the URL-collection phase — subdomain enum, DNS resolution,
httpx probing, port scanning, and nuclei are unaffected.

### Scope engine

Every host discovered during subdomain enumeration is checked against a
scope file before **any** downstream phase touches it — DNS resolution,
httpx probing, port scanning, URL crawling, and nuclei all only ever see
hosts that passed the check. Nothing out of scope gets an HTTP request,
a port scan, or a crawl.

```bash
cp scope.example.yaml scope.yaml   # then edit it for your target
./recon.sh -d example.com --scope scope.yaml
```

`scope.yaml` format:

```yaml
target: example.com

scope:
  allowed:
    - "example.com"
    - "*.example.com"

  excluded:
    - "admin.example.com"
    - "*.internal.example.com"
```

Matching rules:

- **Exclusions always win.** A host matching both an `allowed` and an
  `excluded` pattern is dropped.
- **Default is deny.** A host matching neither list is dropped — it has
  to be explicitly allowed, not merely "not excluded".
- Patterns are glob-style (`fnmatch`), case-insensitive, and a trailing
  dot is ignored. `*.example.com` matches `www.example.com` but not the
  bare apex `example.com` — list both if you want the apex included.
- If the scope file is missing, malformed, or has an empty `allowed`
  list, the whole run **aborts** rather than silently scanning everything.
  Fail closed, not open.

Rejected hosts are written to
`subdomains/subdomains.rejected.txt` so you can see what got filtered out
and why (check it against your scope file if something you expected is
missing).

### Continuous monitoring (diff against the previous run)

Every run saves a snapshot of itself under
`recon_output/<domain>/history/<timestamp>/`. From the second run onward,
ReconForge automatically diffs the new snapshot against the most recent
previous one and prints — and saves — what changed:

```
RECON DIFFERENCE
============================================================
Comparing: 20260927T090000Z  ->  20260928T090000Z

NEW / REMOVED SUBDOMAINS
+ dev.example.com
+ api2.example.com
- old.example.com

NEW / REMOVED PORTS
+ www.example.com 8443/tcp open https-alt

NEW / REMOVED TECHNOLOGIES
+ Next.js

NEW / REMOVED NUCLEI FINDINGS
+ exposed-env-file @ https://api2.example.com
```

This is what turns ReconForge from a point-in-time recon tool into a
lightweight continuous attack-surface monitor: schedule it (cron, a
GitHub Actions workflow, whatever) and the diff tells you exactly what
appeared or disappeared since last time, instead of re-reading the whole
report to spot it yourself.

- Diffs cover subdomains, live hosts, open ports, detected technologies,
  collected URLs, and nuclei findings.
- The last 10 snapshots are kept automatically; older ones are pruned.
- Run `python3 diff.py --old <dir> --new <dir>` directly to compare any
  two snapshots by hand, or `--out-json` for a machine-readable diff.
- The very first run has nothing to diff against — it's the baseline.

### Config file

Instead of typing flags every time, drop a `recon.conf` next to `recon.sh`
(or point to one with `-c`):

```bash
THREADS=100
RATE_LIMIT=200
RESOLVERS=/opt/wordlists/resolvers.txt
TOP_PORTS=2000
URL_TIMEOUT=600
```

`recon.conf` is validated (`config_validator.py`) before it's sourced — an
unknown key (a typo like `THREAD=100`) or a non-numeric value for a
numeric key fails the run immediately with a clear error, instead of bash
silently ignoring the typo and running with defaults.

## Output layout

```
recon_output/<domain>/
├── recon.log                       # full run log, every phase
├── subdomains/
│   ├── all_raw.txt                 # unfiltered tool output
│   ├── subdomains.txt              # deduped, validated (and scope-filtered, if used)
│   ├── subdomains.scoped.txt       # only present if --scope was used
│   └── subdomains.rejected.txt     # only present if --scope was used
├── dns/
│   ├── resolved.json               # dnsx raw JSON
│   └── resolved.txt                # resolved hostnames
├── httpx/
│   ├── httpx.json                  # full probe data (status, title, tech, server)
│   └── live_hosts.txt              # live URLs
├── ports/
│   ├── nmap_scan.xml
│   └── nmap_scan.txt
├── urls/
│   ├── urls.txt                    # all collected URLs (gau+wayback+katana)
│   ├── urls_with_params.txt        # candidate injection points
│   ├── js_files.txt                # JS for endpoint/secret mining
│   └── interesting_extensions.txt  # .env, .bak, .sql, .git-adjacent hits, etc.
├── nuclei/
│   └── nuclei_results.json
├── history/
│   └── <timestamp>/                # one snapshot per run, kept for diffing (last 10)
│       ├── subdomains.txt
│       ├── live_hosts.txt
│       ├── urls.txt
│       ├── ports.txt               # flattened "host port/proto state service" lines
│       ├── tech.txt
│       └── nuclei.json
└── report/
    ├── report.json                 # structured summary, for further tooling
    ├── report.html                 # human-readable dashboard
    ├── diff.json                   # vs. the previous run — only from the 2nd run onward
    └── diff.txt                    # same, human-readable
```

## Extending it

- **Add a new tool to a phase**: each phase is a self-contained block in
  `recon.sh` — append the tool's invocation and pipe its output into the
  existing `*_raw.txt` / final file for that phase, or add a new output file
  and wire it into `gen_report.py`'s `build_data()` + `render_html()`.
- **Add a new report section**: extend `build_data()` in `gen_report.py` to
  compute the new field, then add a `<section>` block in `render_html()`.
- **Add something to the diff**: pick a new snapshot file to save in
  `recon.sh`'s history step, read it as a set in `diff.py`'s `build_diff()`,
  and add a `section(...)` call in `render_text()`.
- **Change scope matching behavior**: `scope.py`'s `Scope.is_allowed()` is
  the single place that decides in/out — everything else just calls it.
- **JS secret-mining / param fuzzing**: `urls/js_files.txt` and
  `urls/urls_with_params.txt` are meant as hand-off points into tools like
  `trufflehog`, `secretfinder`, or a fuzzing pass with `ffuf` — deliberately
  left as a separate step rather than baked in, since those need
  target-specific tuning.
- **Scheduled monitoring runs**: point cron, a systemd timer, or a separate
  scheduled GitHub Actions workflow at `./recon.sh -d example.com --scope
  scope.yaml --skip-existing` on a fixed `-o` output directory — the
  built-in history/diff step handles the "what's new" part on its own.

Whatever you change, `pytest tests/ -v` and `shellcheck recon.sh` should
both stay green — see the main [README](../README.md#testing) for how CI
runs the same checks on every push.
