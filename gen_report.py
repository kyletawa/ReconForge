#!/usr/bin/env python3
"""
ReconForge report generator.
Consumes the raw phase outputs from recon.sh and produces:
  - report.json  (machine-readable, structured)
  - report.html  (styled, single-file, shareable summary)
"""

import argparse
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

# nmap_parser.py lives alongside this script — import it directly rather than
# re-implementing nmap text parsing here, so report.json and the diff engine
# never drift apart on what "a port" means.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nmap_parser import parse_nmap_text, count_open_ports  # noqa: E402


def read_text(path):
    if not path or not os.path.isfile(path):
        return ""
    with open(path, "r", errors="ignore") as f:
        return f.read()


def read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def read_jsonl(path):
    records = []
    if not path or not os.path.isfile(path):
        return records
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--domain", required=True)
    p.add_argument("--subdomains")
    p.add_argument("--resolved")
    p.add_argument("--httpx-json")
    p.add_argument("--ports-txt")
    p.add_argument("--urls")
    p.add_argument("--params")
    p.add_argument("--js-files")
    p.add_argument("--sensitive")
    p.add_argument("--nuclei-json")
    p.add_argument("--out-json", required=True)
    p.add_argument("--out-html", required=True)
    return p.parse_args()


def build_data(args):
    subdomains = read_lines(args.subdomains)
    resolved = read_lines(args.resolved)
    httpx_records = read_jsonl(args.httpx_json)
    urls = read_lines(args.urls)
    params = read_lines(args.params)
    js_files = read_lines(args.js_files)
    sensitive = read_lines(args.sensitive)
    nuclei_hits = read_jsonl(args.nuclei_json)

    status_counter = Counter()
    tech_counter = Counter()
    httpx_clean = []
    for r in httpx_records:
        url = r.get("url")
        if not url:
            continue
        status = r.get("status_code")
        title = r.get("title", "")
        server = r.get("webserver") or r.get("server", "")
        techs = r.get("tech", []) or []
        for t in techs:
            tech_counter[t] += 1
        if status is not None:
            status_counter[str(status)] += 1
        httpx_clean.append({
            "url": url, "status": status, "title": title,
            "server": server, "tech": techs,
            "length": r.get("content_length"),
        })

    severity_counter = Counter()
    nuclei_clean = []
    for h in nuclei_hits:
        info = h.get("info", {})
        sev = info.get("severity", "unknown")
        severity_counter[sev] += 1
        nuclei_clean.append({
            "template": h.get("template-id", info.get("name", "unknown")),
            "severity": sev,
            "host": h.get("host") or h.get("matched-at", ""),
            "matched": h.get("matched-at", ""),
        })

    open_ports_by_host = parse_nmap_text(read_text(args.ports_txt))
    open_ports_count = count_open_ports(open_ports_by_host)

    data = {
        "domain": args.domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "subdomains": len(subdomains),
            "resolved": len(resolved),
            "live_http": len(httpx_clean),
            "urls": len(urls),
            "urls_with_params": len(params),
            "js_files": len(js_files),
            "sensitive_extension_hits": len(sensitive),
            "nuclei_findings": len(nuclei_clean),
            "hosts_port_scanned": len(open_ports_by_host),
            "open_ports": open_ports_count,
        },
        "status_code_breakdown": dict(status_counter),
        "top_technologies": tech_counter.most_common(20),
        "severity_breakdown": dict(severity_counter),
        "subdomains": subdomains,
        "live_hosts": httpx_clean,
        "open_ports_by_host": open_ports_by_host,
        "urls_with_params": params[:500],
        "js_files": js_files[:500],
        "sensitive_extension_hits": sensitive,
        "nuclei_findings": nuclei_clean,
    }
    return data


def sev_color(sev):
    return {
        "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
        "low": "#65a30d", "info": "#0891b2", "unknown": "#6b7280",
    }.get(sev, "#6b7280")


def render_html(d):
    c = d["counts"]

    def esc(x):
        return html.escape(str(x))

    stat_cards = "".join(
        f'<div class="card"><div class="num">{esc(v)}</div><div class="label">{esc(k.replace("_", " "))}</div></div>'
        for k, v in c.items()
    )

    tech_rows = "".join(
        f'<tr><td>{esc(t)}</td><td>{esc(n)}</td></tr>' for t, n in d["top_technologies"]
    ) or '<tr><td colspan="2" class="muted">No technology fingerprints captured</td></tr>'

    sev_rows = "".join(
        f'<tr><td><span class="badge" style="background:{sev_color(s)}">{esc(s)}</span></td><td>{esc(n)}</td></tr>'
        for s, n in sorted(d["severity_breakdown"].items(), key=lambda x: -x[1])
    ) or '<tr><td colspan="2" class="muted">No nuclei findings (or nuclei not run)</td></tr>'

    live_rows = "".join(
        f'<tr><td>{esc(h["url"])}</td><td>{esc(h.get("status",""))}</td>'
        f'<td>{esc(h.get("title","") or "")}</td><td>{esc(h.get("server","") or "")}</td>'
        f'<td>{esc(", ".join(h.get("tech") or []))}</td></tr>'
        for h in d["live_hosts"][:1000]
    ) or '<tr><td colspan="5" class="muted">No live HTTP services recorded</td></tr>'

    finding_rows = "".join(
        f'<tr><td><span class="badge" style="background:{sev_color(f["severity"])}">{esc(f["severity"])}</span></td>'
        f'<td>{esc(f["template"])}</td><td>{esc(f["matched"] or f["host"])}</td></tr>'
        for f in sorted(d["nuclei_findings"], key=lambda x: x["severity"])
    ) or '<tr><td colspan="3" class="muted">No findings</td></tr>'

    port_rows = "".join(
        f'<tr><td>{esc(host)}</td><td>{esc(p["port"])}/{esc(p["proto"])}</td>'
        f'<td>{esc(p["state"])}</td><td>{esc(p["service"])}</td></tr>'
        for host, ports in sorted(d.get("open_ports_by_host", {}).items())
        for p in ports
    ) or '<tr><td colspan="4" class="muted">No port scan data (run with --active to enable nmap)</td></tr>'

    sensitive_rows = "".join(f'<li>{esc(u)}</li>' for u in d["sensitive_extension_hits"][:200]) \
        or '<li class="muted">None found</li>'

    params_rows = "".join(f'<li>{esc(u)}</li>' for u in d["urls_with_params"][:300]) \
        or '<li class="muted">None found</li>'

    subs_rows = "".join(f'<li>{esc(s)}</li>' for s in d["subdomains"][:2000])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconForge Report — {esc(d['domain'])}</title>
<style>
  :root {{
    --bg: #0b0f17; --panel: #121826; --panel2: #171f30; --border: #232c40;
    --text: #e5e9f0; --muted: #8b95a8; --accent: #22d3ee; --accent2: #a78bfa;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    line-height: 1.5;
  }}
  header {{
    padding: 32px 24px 20px; border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, var(--panel2), var(--bg));
  }}
  header h1 {{
    margin: 0 0 4px; font-size: 1.6rem; letter-spacing: 0.5px;
    color: var(--accent); font-family: 'Courier New', monospace;
  }}
  header .sub {{ color: var(--muted); font-size: 0.9rem; }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 32px; }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }}
  .card .num {{ font-size: 1.8rem; font-weight: 700; color: var(--accent2); }}
  .card .label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
  section {{ margin-bottom: 36px; }}
  h2 {{
    font-size: 1.05rem; color: var(--text); border-left: 3px solid var(--accent);
    padding-left: 10px; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.5px;
  }}
  table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.85rem; word-break: break-all; }}
  th {{ background: var(--panel2); color: var(--muted); text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.5px; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ padding: 2px 10px; border-radius: 999px; font-size: 0.72rem; font-weight: 600; color: #0b0f17; text-transform: uppercase; }}
  .muted {{ color: var(--muted); font-style: italic; }}
  .scroll-box {{ max-height: 360px; overflow-y: auto; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; }}
  .scroll-box ul {{ margin: 0; padding-left: 18px; }}
  .scroll-box li {{ font-size: 0.82rem; word-break: break-all; padding: 3px 0; border-bottom: 1px dashed var(--border); }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.75rem; padding: 20px; border-top: 1px solid var(--border); }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  @media (max-width: 700px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<header>
  <h1>&gt; ReconForge_</h1>
  <div class="sub">Target: <strong>{esc(d['domain'])}</strong> &nbsp;|&nbsp; Generated: {esc(d['generated_at'])}</div>
</header>
<main>

  <div class="stats">
    {stat_cards}
  </div>

  <section>
    <h2>Nuclei Severity Breakdown</h2>
    <table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{sev_rows}</tbody></table>
  </section>

  <section>
    <h2>Vulnerability Findings</h2>
    <div class="scroll-box"><table><thead><tr><th>Severity</th><th>Template</th><th>Matched At</th></tr></thead>
    <tbody>{finding_rows}</tbody></table></div>
  </section>

  <section>
    <h2>Open Ports</h2>
    <div class="scroll-box"><table><thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th></tr></thead>
    <tbody>{port_rows}</tbody></table></div>
  </section>

  <section>
    <h2>Technology Fingerprints (top 20)</h2>
    <table><thead><tr><th>Technology</th><th>Occurrences</th></tr></thead><tbody>{tech_rows}</tbody></table>
  </section>

  <section>
    <h2>Live HTTP(S) Services</h2>
    <div class="scroll-box">
    <table><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Tech</th></tr></thead>
    <tbody>{live_rows}</tbody></table>
    </div>
  </section>

  <div class="two-col">
    <section>
      <h2>Sensitive Extension Hits</h2>
      <div class="scroll-box"><ul>{sensitive_rows}</ul></div>
    </section>
    <section>
      <h2>URLs With Parameters</h2>
      <div class="scroll-box"><ul>{params_rows}</ul></div>
    </section>
  </div>

  <section>
    <h2>All Enumerated Subdomains</h2>
    <div class="scroll-box"><ul>{subs_rows}</ul></div>
  </section>

</main>
<footer>ReconForge v1.0.0 — for authorized security testing only. Kyle.exe / CoreSec Group.</footer>
</body>
</html>"""


def main():
    args = parse_args()
    data = build_data(args)

    with open(args.out_json, "w") as f:
        json.dump(data, f, indent=2)

    with open(args.out_html, "w") as f:
        f.write(render_html(data))

    print(f"Wrote {args.out_json} and {args.out_html}")


if __name__ == "__main__":
    main()
