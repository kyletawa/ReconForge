#!/usr/bin/env bash
###############################################################################
#
#   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
#   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
#   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
#   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
#   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
#   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
#
#   ReconForge — Modular Bug Bounty / External Attack Surface Recon Pipeline
#   Author:  Kyle.exe / CoreSec Group
#   Usage:   ./recon.sh -d example.com [options]
#
#   LEGAL: Run this only against assets you are explicitly authorized to test
#   (your own infrastructure, or scope you hold written permission / a bug
#   bounty program's rules of engagement for). Unauthorized scanning of
#   third-party systems is illegal in most jurisdictions.
#
###############################################################################

set -uo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
START_TIME=$(date +%s)
SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" &>/dev/null && pwd)"

###############################################################################
# Defaults (overridable via CLI flags or recon.conf)
###############################################################################
DOMAIN=""
OUT_ROOT="./recon_output"
THREADS=50
RATE_LIMIT=150
RESOLVERS=""
WORDLIST=""
DO_ACTIVE_SCAN=false        # nmap port scan
DO_NUCLEI=false             # active vuln templates — opt-in, noisy
DO_AMASS=true
SKIP_EXISTING=false
NUCLEI_SEVERITY="info,low,medium,high,critical"
TOP_PORTS=1000
CONFIG_FILE="${SCRIPT_DIR}/recon.conf"
URL_TIMEOUT=300   # seconds, per URL-collection tool (gau/waybackurls/katana). 0 = no timeout.
SCOPE_FILE=""     # path to a scope.yaml — when set, every phase after subdomain enum only touches in-scope hosts

###############################################################################
# Colors / logging
###############################################################################
if [[ -t 1 ]]; then
    C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'
    C_YELLOW='\033[0;33m'; C_BLUE='\033[0;34m'; C_CYAN='\033[0;36m'; C_BOLD='\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_BOLD=''
fi

LOG_FILE=""
log()      { echo -e "${C_CYAN}[*]${C_RESET} $*"      | tee -a "$LOG_FILE"; }
ok()       { echo -e "${C_GREEN}[+]${C_RESET} $*"     | tee -a "$LOG_FILE"; }
warn()     { echo -e "${C_YELLOW}[!]${C_RESET} $*"    | tee -a "$LOG_FILE"; }
err()      { echo -e "${C_RED}[-]${C_RESET} $*"       | tee -a "$LOG_FILE" >&2; }
section()  { echo -e "\n${C_BOLD}${C_BLUE}==> $*${C_RESET}" | tee -a "$LOG_FILE"; }

# run_with_timeout <label> -- <command...>
# Wraps a command in `timeout` (if URL_TIMEOUT > 0) so one slow upstream API
# (looking at you, Common Crawl) can't stall the whole pipeline. Exit code
# 124 from `timeout` means it hit the wall clock, not a real tool failure —
# we warn distinctly for that so it's not mistaken for a crash.
run_with_timeout() {
    local label="$1"; shift
    if [[ "$URL_TIMEOUT" -gt 0 ]]; then
        timeout "${URL_TIMEOUT}s" "$@"
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            warn "$label timed out after ${URL_TIMEOUT}s — moving on with partial results"
        fi
        return $rc
    else
        "$@"
    fi
}

banner() {
cat <<'EOF'
   ____                    _____                    
  |  _ \ ___  ___ ___  _ __|  ___|__  _ __ __ _  ___ 
  | |_) / _ \/ __/ _ \| '_ \ |_ / _ \| '__/ _` |/ _ \
  |  _ <  __/ (_| (_) | | | |  _| (_) | | | (_| |  __/
  |_| \_\___|\___\___/|_| |_|_|  \___/|_|  \__, |\___|
                                            |___/      
EOF
echo "        Modular Recon Pipeline  |  v${VERSION}  |  Kyle.exe / CoreSec Group"
}

usage() {
cat <<EOF
Usage: $0 -d <domain> [options]

Required:
  -d, --domain <domain>       Target root domain (e.g. example.com)

Options:
  -o, --output <dir>          Output root directory   (default: ./recon_output)
  -t, --threads <n>           Threads for httpx/dnsx   (default: $THREADS)
  -r, --rate <n>              Requests/sec for nuclei  (default: $RATE_LIMIT)
      --resolvers <file>      Custom DNS resolvers list for dnsx/amass
      --wordlist <file>       Wordlist for brute-force subdomain enum (optional)
      --top-ports <n>         nmap top-ports count     (default: $TOP_PORTS)
      --url-timeout <sec>     Per-tool timeout for gau/waybackurls/katana (default: ${URL_TIMEOUT}s, 0 = no timeout)
      --scope <file>          Scope YAML file — filters discovered hosts before any downstream
                               phase touches them (see scope.example.yaml)
      --active                Enable nmap port scanning (active — noisier)
      --nuclei                Enable nuclei template scanning (active — noisy)
      --no-amass               Skip amass (subfinder only, faster)
      --skip-existing          Skip a phase if its output file already exists
  -c, --config <file>         Path to a recon.conf (default: alongside this script)
  -h, --help                   Show this help

Examples:
  $0 -d example.com
  $0 -d example.com --active --nuclei -t 100
  $0 -d example.com -o /data/engagements/acme --resolvers resolvers.txt
  $0 -d example.com --url-timeout 600      # give slow upstreams (Common Crawl etc.) more room on a big target
  $0 -d example.com --url-timeout 0        # disable timeouts entirely, let URL collection run to completion
  $0 -d example.com --scope scope.yaml     # only touch hosts your scope file explicitly allows

Every run also records a snapshot under recon_output/<domain>/history/ and,
from the second run onward, diffs it against the previous one — new/removed
subdomains, live hosts, ports, technologies and nuclei findings — printed at
the end and saved to report/diff.txt.

Config file (recon.conf) can pre-set any of the above as KEY=VALUE, e.g.:
  THREADS=100
  RATE_LIMIT=200
  RESOLVERS=/opt/resolvers.txt
EOF
}

###############################################################################
# Argument parsing
###############################################################################
[[ -f "$CONFIG_FILE" ]] && {
    if command -v python3 &>/dev/null && [[ -f "${SCRIPT_DIR}/config_validator.py" ]]; then
        if ! python3 "${SCRIPT_DIR}/config_validator.py" "$CONFIG_FILE"; then
            echo "[-] recon.conf failed validation (see above) — fix it or remove it before running." >&2
            exit 1
        fi
    fi
    log "Loading config: $CONFIG_FILE"; source "$CONFIG_FILE"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)     DOMAIN="$2"; shift 2 ;;
        -o|--output)      OUT_ROOT="$2"; shift 2 ;;
        -t|--threads)     THREADS="$2"; shift 2 ;;
        -r|--rate)        RATE_LIMIT="$2"; shift 2 ;;
        --resolvers)      RESOLVERS="$2"; shift 2 ;;
        --wordlist)       WORDLIST="$2"; shift 2 ;;
        --top-ports)      TOP_PORTS="$2"; shift 2 ;;
        --url-timeout)    URL_TIMEOUT="$2"; shift 2 ;;
        --scope)          SCOPE_FILE="$2"; shift 2 ;;
        --active)         DO_ACTIVE_SCAN=true; shift ;;
        --nuclei)         DO_NUCLEI=true; shift ;;
        --no-amass)       DO_AMASS=false; shift ;;
        --skip-existing)  SKIP_EXISTING=true; shift ;;
        -c|--config)      CONFIG_FILE="$2";
                           if command -v python3 &>/dev/null && [[ -f "${SCRIPT_DIR}/config_validator.py" ]]; then
                               python3 "${SCRIPT_DIR}/config_validator.py" "$CONFIG_FILE" || exit 1
                           fi
                           source "$CONFIG_FILE"; shift 2 ;;
        -h|--help)        banner; usage; exit 0 ;;
        *) err "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

banner

if [[ -z "$DOMAIN" ]]; then
    err "No target domain supplied."
    usage
    exit 1
fi

# Basic sanity check on domain format
if ! [[ "$DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
    err "'$DOMAIN' doesn't look like a valid domain."
    exit 1
fi

###############################################################################
# Output layout
###############################################################################
OUT_DIR="${OUT_ROOT}/${DOMAIN}"
DIR_SUBS="${OUT_DIR}/subdomains"
DIR_DNS="${OUT_DIR}/dns"
DIR_HTTP="${OUT_DIR}/httpx"
DIR_PORTS="${OUT_DIR}/ports"
DIR_URLS="${OUT_DIR}/urls"
DIR_VULN="${OUT_DIR}/nuclei"
DIR_REPORT="${OUT_DIR}/report"

mkdir -p "$DIR_SUBS" "$DIR_DNS" "$DIR_HTTP" "$DIR_PORTS" "$DIR_URLS" "$DIR_VULN" "$DIR_REPORT"
LOG_FILE="${OUT_DIR}/recon.log"
: > "$LOG_FILE"

log "Target:        ${C_BOLD}${DOMAIN}${C_RESET}"
log "Output dir:    ${OUT_DIR}"
log "Threads:       ${THREADS}   Rate limit: ${RATE_LIMIT}"
log "Active scan:   ${DO_ACTIVE_SCAN}   Nuclei: ${DO_NUCLEI}"
log "URL timeout:   $([[ "$URL_TIMEOUT" -gt 0 ]] && echo "${URL_TIMEOUT}s per tool" || echo "disabled")"
log "Scope file:    $([[ -n "$SCOPE_FILE" ]] && echo "$SCOPE_FILE" || echo "none — all discovered hosts are in play")"

###############################################################################
# Dependency check
###############################################################################
REQUIRED_TOOLS=(subfinder dnsx httpx nmap gau katana jq)
OPTIONAL_TOOLS=(amass waybackurls nuclei)
MISSING=()

section "Checking dependencies"
for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool found"
    else
        err "$tool NOT found (required)"
        MISSING+=("$tool")
    fi
done
for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool found (optional)"
    else
        warn "$tool NOT found (optional — related phase will be skipped)"
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    err "Missing required tools: ${MISSING[*]}"
    err "Install them (most are Go-based, e.g.: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest) and re-run."
    exit 1
fi

if [[ "$URL_TIMEOUT" -gt 0 ]] && ! command -v timeout &>/dev/null; then
    warn "'timeout' (coreutils) not found — --url-timeout has no effect on this system"
    URL_TIMEOUT=0
fi

skip_if_present() {
    # $1 = filepath; returns 0 (skip) if SKIP_EXISTING and file has content
    [[ "$SKIP_EXISTING" == true && -s "$1" ]]
}

###############################################################################
# Phase 1 — Subdomain enumeration
###############################################################################
section "Phase 1/8 — Subdomain enumeration"
SUBS_RAW="${DIR_SUBS}/all_raw.txt"
SUBS_FINAL="${DIR_SUBS}/subdomains.txt"

if skip_if_present "$SUBS_FINAL"; then
    warn "Skipping (already exists): $SUBS_FINAL"
else
    : > "$SUBS_RAW"

    log "Running subfinder..."
    subfinder -d "$DOMAIN" -all -silent 2>>"$LOG_FILE" >> "$SUBS_RAW" || warn "subfinder exited non-zero"

    if [[ "$DO_AMASS" == true ]] && command -v amass &>/dev/null; then
        log "Running amass (passive)..."
        amass enum -passive -d "$DOMAIN" -silent 2>>"$LOG_FILE" >> "$SUBS_RAW" || warn "amass exited non-zero"
    fi

    if [[ -n "$WORDLIST" && -f "$WORDLIST" ]] && command -v puredns &>/dev/null; then
        log "Running puredns brute-force with $WORDLIST..."
        RESOLVER_ARGS=()
        [[ -n "$RESOLVERS" ]] && RESOLVER_ARGS=(-r "$RESOLVERS")
        puredns bruteforce "$WORDLIST" "$DOMAIN" "${RESOLVER_ARGS[@]}" -q 2>>"$LOG_FILE" >> "$SUBS_RAW" || warn "puredns exited non-zero"
    elif [[ -n "$WORDLIST" ]]; then
        warn "Wordlist given but 'puredns' not installed — skipping brute-force step"
    fi

    # Always include the bare apex
    echo "$DOMAIN" >> "$SUBS_RAW"

    sort -u "$SUBS_RAW" | grep -E "^[a-zA-Z0-9.*_-]+\.${DOMAIN//./\\.}$|^${DOMAIN//./\\.}$" > "$SUBS_FINAL"
    ok "Collected $(wc -l < "$SUBS_FINAL") unique candidate subdomains -> $SUBS_FINAL"
fi

###############################################################################
# Scope engine — filters discovered hosts before ANY downstream phase touches
# them. This runs right after discovery and before DNS resolution, so a
# misconfigured target never gets probed, ported, crawled, or nuclei'd.
###############################################################################
if [[ -n "$SCOPE_FILE" ]]; then
    section "Scope engine — enforcing $SCOPE_FILE"

    if ! command -v python3 &>/dev/null; then
        err "python3 not found — cannot enforce scope. Refusing to continue without it."
        exit 1
    fi

    SCOPED_SUBS="${DIR_SUBS}/subdomains.scoped.txt"
    REJECTED_SUBS="${DIR_SUBS}/subdomains.rejected.txt"

    if ! python3 "${SCRIPT_DIR}/scope.py" \
            --scope "$SCOPE_FILE" \
            --input "$SUBS_FINAL" \
            --output "$SCOPED_SUBS" \
            --rejected "$REJECTED_SUBS" \
            2>>"$LOG_FILE"; then
        err "Scope engine failed to load or apply $SCOPE_FILE — see $LOG_FILE."
        err "Aborting rather than risk scanning a host that was never confirmed in scope."
        exit 1
    fi

    ok "$(wc -l < "$SCOPED_SUBS" 2>/dev/null || echo 0) hosts in scope, $(wc -l < "$REJECTED_SUBS" 2>/dev/null || echo 0) rejected -> $SCOPED_SUBS"
    if [[ -s "$REJECTED_SUBS" ]]; then
        warn "Out-of-scope hosts were discovered and excluded — see $REJECTED_SUBS"
    fi
    SUBS_FINAL="$SCOPED_SUBS"
fi

###############################################################################
# Phase 2 — DNS resolution
###############################################################################
section "Phase 2/8 — DNS resolution"
DNS_RESOLVED="${DIR_DNS}/resolved.txt"
DNS_JSON="${DIR_DNS}/resolved.json"

if skip_if_present "$DNS_RESOLVED"; then
    warn "Skipping (already exists): $DNS_RESOLVED"
else
    RESOLVER_ARGS=()
    [[ -n "$RESOLVERS" ]] && RESOLVER_ARGS=(-r "$RESOLVERS")
    log "Resolving with dnsx..."
    dnsx -l "$SUBS_FINAL" "${RESOLVER_ARGS[@]}" -silent -a -resp -json -t "$THREADS" \
        2>>"$LOG_FILE" > "$DNS_JSON" || warn "dnsx exited non-zero"
    jq -r 'select(.host != null) | .host' "$DNS_JSON" 2>>"$LOG_FILE" | sort -u > "$DNS_RESOLVED"
    ok "$(wc -l < "$DNS_RESOLVED") hosts resolved -> $DNS_RESOLVED"
fi

###############################################################################
# Phase 3 — Live host detection + Phase 4 — HTTP/HTTPS probing & tech fingerprint
# (httpx does both in one efficient pass)
###############################################################################
section "Phase 3-4/8 — Live host detection, HTTP probing & tech fingerprinting"
HTTPX_JSON="${DIR_HTTP}/httpx.json"
HTTPX_LIVE="${DIR_HTTP}/live_hosts.txt"

if skip_if_present "$HTTPX_LIVE"; then
    warn "Skipping (already exists): $HTTPX_LIVE"
else
    log "Probing resolved hosts with httpx (status, title, tech-detect, server)..."
    httpx -l "$DNS_RESOLVED" -silent -json -t "$THREADS" \
        -status-code -title -tech-detect -server -content-length -follow-redirects \
        2>>"$LOG_FILE" > "$HTTPX_JSON" || warn "httpx exited non-zero"
    jq -r 'select(.url != null) | .url' "$HTTPX_JSON" 2>>"$LOG_FILE" | sort -u > "$HTTPX_LIVE"
    ok "$(wc -l < "$HTTPX_LIVE") live HTTP(S) services -> $HTTPX_LIVE"
fi

###############################################################################
# Phase 5 — Port scanning (opt-in, active)
###############################################################################
section "Phase 5/8 — Port scanning"
PORTS_XML="${DIR_PORTS}/nmap_scan.xml"
PORTS_TXT="${DIR_PORTS}/nmap_scan.txt"

if [[ "$DO_ACTIVE_SCAN" == true ]]; then
    if skip_if_present "$PORTS_TXT"; then
        warn "Skipping (already exists): $PORTS_TXT"
    else
        log "Running nmap top-${TOP_PORTS} ports against resolved hosts (this can take a while)..."
        nmap -iL "$DNS_RESOLVED" --top-ports "$TOP_PORTS" -T4 -Pn \
            -oX "$PORTS_XML" -oN "$PORTS_TXT" 2>>"$LOG_FILE" >> "$LOG_FILE" \
            || warn "nmap exited non-zero"
        ok "Port scan complete -> $PORTS_TXT"
    fi
else
    warn "Active scan disabled (pass --active to enable nmap port scanning)"
fi

###############################################################################
# Phase 6 — URL collection
###############################################################################
section "Phase 6/8 — URL collection"
URLS_RAW="${DIR_URLS}/all_raw.txt"
URLS_FINAL="${DIR_URLS}/urls.txt"

if skip_if_present "$URLS_FINAL"; then
    warn "Skipping (already exists): $URLS_FINAL"
else
    : > "$URLS_RAW"

    log "Running gau (timeout: $([[ "$URL_TIMEOUT" -gt 0 ]] && echo "${URL_TIMEOUT}s" || echo "none"))..."
    run_with_timeout "gau" gau --subs "$DOMAIN" 2>>"$LOG_FILE" >> "$URLS_RAW" \
        || [[ $? -eq 124 ]] || warn "gau exited non-zero"

    if command -v waybackurls &>/dev/null; then
        log "Running waybackurls (timeout: $([[ "$URL_TIMEOUT" -gt 0 ]] && echo "${URL_TIMEOUT}s" || echo "none"))..."
        echo "$DOMAIN" | run_with_timeout "waybackurls" waybackurls 2>>"$LOG_FILE" >> "$URLS_RAW" \
            || [[ $? -eq 124 ]] || warn "waybackurls exited non-zero"
    fi

    log "Running katana — active crawl (timeout: $([[ "$URL_TIMEOUT" -gt 0 ]] && echo "${URL_TIMEOUT}s" || echo "none"))..."
    run_with_timeout "katana" katana -list "$HTTPX_LIVE" -silent -jc -kf all -d 3 -c "$THREADS" \
        2>>"$LOG_FILE" >> "$URLS_RAW" \
        || [[ $? -eq 124 ]] || warn "katana exited non-zero"

    sort -u "$URLS_RAW" > "$URLS_FINAL"
    ok "$(wc -l < "$URLS_FINAL") unique URLs collected -> $URLS_FINAL"

    # Attack-surface slicing: params, JS files, likely-sensitive extensions.
    # Handled by classify_urls.py (proper URL parsing) rather than grep, so
    # the same matching logic is testable and shared with any future tooling.
    if command -v python3 &>/dev/null; then
        python3 "${SCRIPT_DIR}/classify_urls.py" \
            --input "$URLS_FINAL" \
            --params-out "${DIR_URLS}/urls_with_params.txt" \
            --js-out "${DIR_URLS}/js_files.txt" \
            --sensitive-out "${DIR_URLS}/interesting_extensions.txt" \
            2>>"$LOG_FILE" | tee -a "$LOG_FILE" || warn "classify_urls.py exited non-zero"
    else
        warn "python3 not found — falling back to basic grep for URL slicing"
        grep -E '\?.+=' "$URLS_FINAL" > "${DIR_URLS}/urls_with_params.txt" 2>/dev/null || true
        grep -E '\.js($|\?)' "$URLS_FINAL" > "${DIR_URLS}/js_files.txt" 2>/dev/null || true
        grep -E '\.(env|bak|old|sql|zip|tar|gz|log|config|yml|yaml|json)($|\?)' "$URLS_FINAL" \
            > "${DIR_URLS}/interesting_extensions.txt" 2>/dev/null || true
    fi
fi

###############################################################################
# Phase 7 — Vulnerability scanning (opt-in, active)
###############################################################################
section "Phase 7/8 — Nuclei scanning"
NUCLEI_OUT="${DIR_VULN}/nuclei_results.json"

if [[ "$DO_NUCLEI" == true ]]; then
    if command -v nuclei &>/dev/null; then
        if skip_if_present "$NUCLEI_OUT"; then
            warn "Skipping (already exists): $NUCLEI_OUT"
        else
            log "Running nuclei (severity: $NUCLEI_SEVERITY, rate: $RATE_LIMIT)..."
            nuclei -l "$HTTPX_LIVE" -silent -jsonl -severity "$NUCLEI_SEVERITY" \
                -rl "$RATE_LIMIT" -c "$THREADS" \
                2>>"$LOG_FILE" > "$NUCLEI_OUT" || warn "nuclei exited non-zero"
            ok "Nuclei findings -> $NUCLEI_OUT ($(wc -l < "$NUCLEI_OUT") hits)"
        fi
    else
        warn "nuclei requested but not installed — skipping"
    fi
else
    warn "Nuclei disabled (pass --nuclei to enable — noisy, only run with authorization)"
fi

###############################################################################
# Phase 8 — Report generation
###############################################################################
section "Phase 8/8 — Report generation"

REPORT_JSON="${DIR_REPORT}/report.json"
REPORT_HTML="${DIR_REPORT}/report.html"

if command -v python3 &>/dev/null; then
    if python3 "${SCRIPT_DIR}/gen_report.py" \
        --domain "$DOMAIN" \
        --subdomains "$SUBS_FINAL" \
        --resolved "$DNS_RESOLVED" \
        --httpx-json "$HTTPX_JSON" \
        --ports-txt "$PORTS_TXT" \
        --urls "$URLS_FINAL" \
        --params "${DIR_URLS}/urls_with_params.txt" \
        --js-files "${DIR_URLS}/js_files.txt" \
        --sensitive "${DIR_URLS}/interesting_extensions.txt" \
        --nuclei-json "$NUCLEI_OUT" \
        --out-json "$REPORT_JSON" \
        --out-html "$REPORT_HTML" \
        2>>"$LOG_FILE"
    then
        ok "Report written -> $REPORT_HTML"
    else
        err "Report generation failed — check $LOG_FILE"
    fi
else
    err "python3 not found — cannot generate report. Raw phase outputs remain in $OUT_DIR"
fi

###############################################################################
# History snapshot + diff against the previous run
###############################################################################
section "Recording snapshot & diffing against the previous run"

HISTORY_DIR="${OUT_DIR}/history"
SNAPSHOT_DIR="${HISTORY_DIR}/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$SNAPSHOT_DIR"

cp -f "$SUBS_FINAL" "$SNAPSHOT_DIR/subdomains.txt" 2>/dev/null || true
cp -f "$HTTPX_LIVE" "$SNAPSHOT_DIR/live_hosts.txt" 2>/dev/null || true
cp -f "$URLS_FINAL" "$SNAPSHOT_DIR/urls.txt" 2>/dev/null || true
[[ -f "$NUCLEI_OUT" ]] && cp -f "$NUCLEI_OUT" "$SNAPSHOT_DIR/nuclei.json"

if [[ -f "$HTTPX_JSON" ]] && command -v jq &>/dev/null; then
    jq -r '.tech[]?' "$HTTPX_JSON" 2>/dev/null | sort -u > "$SNAPSHOT_DIR/tech.txt"
fi

if [[ -f "$PORTS_TXT" ]] && command -v python3 &>/dev/null; then
    python3 "${SCRIPT_DIR}/nmap_parser.py" --input "$PORTS_TXT" --output "$SNAPSHOT_DIR/ports.txt" \
        2>>"$LOG_FILE" || warn "nmap_parser.py failed — ports won't appear in this snapshot's diff"
fi

# Keep only the last 10 snapshots so history/ doesn't grow unbounded
mapfile -t OLD_SNAPSHOTS < <(ls -1dt "$HISTORY_DIR"/*/ 2>/dev/null | tail -n +11)
[[ ${#OLD_SNAPSHOTS[@]} -gt 0 ]] && rm -rf "${OLD_SNAPSHOTS[@]}"

PREV_SNAPSHOT=$(ls -1dt "$HISTORY_DIR"/*/ 2>/dev/null | sed -n '2p')
DIFF_TXT="${DIR_REPORT}/diff.txt"

if [[ -n "$PREV_SNAPSHOT" ]] && command -v python3 &>/dev/null; then
    ok "Previous snapshot found ($(basename "$PREV_SNAPSHOT")) — computing diff"
    python3 "${SCRIPT_DIR}/diff.py" \
        --old "$PREV_SNAPSHOT" --new "$SNAPSHOT_DIR" \
        --out-json "${DIR_REPORT}/diff.json" \
        --out-text "$DIFF_TXT" \
        2>>"$LOG_FILE" | tee -a "$LOG_FILE"
else
    log "No previous snapshot yet — this is the baseline. Run again later to see what changed."
fi

###############################################################################
# Summary
###############################################################################
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

section "Recon complete — ${DOMAIN}"
ok "Elapsed:        $((ELAPSED / 60))m $((ELAPSED % 60))s"
ok "Subdomains:     $(wc -l < "$SUBS_FINAL" 2>/dev/null || echo 0)"
ok "Resolved:       $(wc -l < "$DNS_RESOLVED" 2>/dev/null || echo 0)"
ok "Live HTTP(S):   $(wc -l < "$HTTPX_LIVE" 2>/dev/null || echo 0)"
ok "URLs:           $(wc -l < "$URLS_FINAL" 2>/dev/null || echo 0)"
ok "Full log:       $LOG_FILE"
ok "Report:         $REPORT_HTML"
[[ -f "$DIFF_TXT" ]] && ok "Diff:           $DIFF_TXT"
echo
