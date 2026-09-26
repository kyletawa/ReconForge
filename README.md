# ReconForge

A modular, staged reconnaissance pipeline for bug bounty and external attack
surface mapping. It wraps well-known open-source recon tools with consistent
logging, resumability, and a single styled HTML/JSON report at the end.

```
Domain
  ↓ subfinder / amass
Subdomain enumeration
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
| python3   | Report generation                | usually preinstalled |

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
```

Run `./recon.sh -h` for the full flag list.

### Config file

Instead of typing flags every time, drop a `recon.conf` next to `recon.sh`
(or point to one with `-c`):

```bash
THREADS=100
RATE_LIMIT=200
RESOLVERS=/opt/wordlists/resolvers.txt
TOP_PORTS=2000
```

## Output layout

```
recon_output/<domain>/
├── recon.log                       # full run log, every phase
├── subdomains/
│   ├── all_raw.txt                 # unfiltered tool output
│   └── subdomains.txt              # deduped, validated candidates
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
└── report/
    ├── report.json                 # structured summary, for further tooling
    └── report.html                 # human-readable dashboard
```

## Extending it

- **Add a new tool to a phase**: each phase is a self-contained block in
  `recon.sh` — append the tool's invocation and pipe its output into the
  existing `*_raw.txt` / final file for that phase, or add a new output file
  and wire it into `gen_report.py`'s `build_data()` + `render_html()`.
- **Add a new report section**: extend `build_data()` in `gen_report.py` to
  compute the new field, then add a `<section>` block in `render_html()`.
- **CI / scheduled runs**: `--skip-existing` plus a fixed `-o` directory lets
  you re-run against a growing scope list without repeating finished phases;
  diff `subdomains.txt` or `report.json` between runs to catch newly
  appearing assets.
- **JS secret-mining / param fuzzing**: `urls/js_files.txt` and
  `urls/urls_with_params.txt` are meant as hand-off points into tools like
  `trufflehog`, `secretfinder`, or a fuzzing pass with `ffuf` — deliberately
  left as a separate step rather than baked in, since those need
  target-specific tuning.
