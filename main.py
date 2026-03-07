#!/usr/bin/env python3
"""Daily Experiments — NIST NVD security scanner with threat visualization."""
import json, os, datetime, hashlib, urllib.request, ssl, glob
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_COLORS = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#2ecc71", "UNKNOWN": "#95a5a6"}

def fetch_recent_cves(days_back=2, max_results=20):
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    end = now.strftime("%Y-%m-%dT23:59:59.999")
    url = f"{NVD_API}?pubStartDate={start}&pubEndDate={end}&resultsPerPage={max_results}"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "daily-experiments-bot/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return json.loads(resp.read().decode()).get("vulnerabilities", [])
    except Exception as e:
        print(f"[WARN] NVD fetch failed: {e}")
        return []

def parse_cve(vuln):
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")
    metrics = cve.get("metrics", {})
    severity, score = "UNKNOWN", 0.0
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            m = metrics[version][0]
            cvss = m.get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))
            break
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])
    return {"id": cve_id, "description": desc[:300], "severity": severity, "score": score,
            "cwes": cwes, "references": [r.get("url", "") for r in cve.get("references", [])[:3]],
            "published": cve.get("published", "")}

def analyze_trends(parsed):
    severity_counts = {}
    cwe_counts = {}
    for p in parsed:
        severity_counts[p["severity"]] = severity_counts.get(p["severity"], 0) + 1
        for c in p["cwes"]:
            cwe_counts[c] = cwe_counts.get(c, 0) + 1
    threat_score = sum(SEVERITY_WEIGHTS.get(p["severity"], 0) * p["score"] for p in parsed)
    return {"total_cves": len(parsed), "severity_distribution": severity_counts,
            "top_cwes": sorted(cwe_counts.items(), key=lambda x: -x[1])[:5],
            "threat_index": round(threat_score, 2), "critical_count": severity_counts.get("CRITICAL", 0)}

def load_yesterday(date_str):
    yesterday = (datetime.datetime.strptime(date_str, "%Y-%m-%d") - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    path = f"logs/{yesterday}.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def compute_delta(today_trends, yesterday_data):
    if not yesterday_data:
        return {"status": "no_previous_data"}
    y_trends = yesterday_data.get("trends", {})
    deltas = {}
    for key in ["total_cves", "threat_index", "critical_count"]:
        t_val = today_trends.get(key, 0)
        y_val = y_trends.get(key, 0)
        if y_val:
            deltas[key] = {"today": t_val, "yesterday": y_val, "change_pct": round(((t_val - y_val) / y_val) * 100, 1)}
        else:
            deltas[key] = {"today": t_val, "yesterday": y_val, "change_pct": 0}
    return {"status": "compared", "deltas": deltas}

def generate_charts(parsed, trends, date_str):
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle(f"Security Threat Dashboard — {date_str}", fontsize=14, fontweight="bold")

    # 1: Severity distribution
    sev_labels = list(trends["severity_distribution"].keys())
    sev_values = list(trends["severity_distribution"].values())
    sev_colors = [SEVERITY_COLORS.get(s, "#95a5a6") for s in sev_labels]
    axes[0].pie(sev_values, labels=sev_labels, autopct="%1.0f%%", colors=sev_colors, startangle=90)
    axes[0].set_title("Severity Distribution")

    # 2: Top CVEs by score
    top_cves = sorted(parsed, key=lambda x: x["score"], reverse=True)[:10]
    cve_ids = [c["id"][-8:] for c in top_cves]
    scores = [c["score"] for c in top_cves]
    bar_colors = [SEVERITY_COLORS.get(c["severity"], "#95a5a6") for c in top_cves]
    axes[1].barh(cve_ids[::-1], scores[::-1], color=bar_colors[::-1])
    axes[1].set_xlabel("CVSS Score")
    axes[1].set_title("Top 10 CVEs by Score")
    axes[1].set_xlim(0, 10)

    # 3: CWE frequency
    if trends["top_cwes"]:
        cwe_labels = [c[0] for c in trends["top_cwes"]]
        cwe_counts = [c[1] for c in trends["top_cwes"]]
        axes[2].bar(cwe_labels, cwe_counts, color="#3498db")
        axes[2].set_ylabel("Count")
        axes[2].tick_params(axis="x", rotation=45)
    else:
        axes[2].text(0.5, 0.5, "No CWE Data", ha="center", va="center", fontsize=14)
    axes[2].set_title("Top Weakness Categories")

    plt.tight_layout()
    path = f"logs/{date_str}_dashboard.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()

    # Historical trend
    history_files = sorted(glob.glob("logs/*.json"))[-14:]
    if len(history_files) >= 2:
        fig2, ax = plt.subplots(figsize=(12, 4))
        dates, threats, crit = [], [], []
        for hf in history_files:
            with open(hf) as f:
                h = json.load(f)
            dates.append(os.path.basename(hf).replace(".json", ""))
            threats.append(h.get("trends", {}).get("threat_index", 0))
            crit.append(h.get("trends", {}).get("critical_count", 0))
        ax.fill_between(range(len(dates)), threats, alpha=0.3, color="#e74c3c")
        ax.plot(range(len(dates)), threats, "o-", color="#e74c3c", label="Threat Index", linewidth=2)
        ax.set_xticks(range(len(dates)))
        ax.set_xticklabels(dates, rotation=45, fontsize=8)
        ax.set_ylabel("Threat Index")
        ax.set_title("14-Day Threat Trend")
        ax.legend()
        plt.tight_layout()
        plt.savefig(f"logs/{date_str}_trend.png", dpi=150, bbox_inches="tight")
        plt.close()

    return path

def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    print(f"[daily-experiments] Fetching CVEs from NVD...")
    vulns = fetch_recent_cves()
    parsed = [parse_cve(v) for v in vulns]
    parsed.sort(key=lambda x: x["score"], reverse=True)
    trends = analyze_trends(parsed)

    yesterday = load_yesterday(date_str)
    delta = compute_delta(trends, yesterday)

    report = {"timestamp": now.isoformat(), "scan_id": hashlib.sha256(now.isoformat().encode()).hexdigest()[:10],
              "trends": trends, "delta": delta, "cves": parsed}

    os.makedirs("logs", exist_ok=True)
    with open(f"logs/{date_str}.json", "w") as f:
        json.dump(report, f, indent=2)

    chart_path = generate_charts(parsed, trends, date_str)

    md = [f"# Security Scan Report — {date_str}\n"]
    md.append(f"**Scan ID:** `{report['scan_id']}` | **CVEs:** {trends['total_cves']} | **Threat Index:** {trends['threat_index']}\n")
    md.append(f"![Dashboard]({os.path.basename(chart_path)})\n")
    if os.path.exists(f"logs/{date_str}_trend.png"):
        md.append(f"![Trend]({date_str}_trend.png)\n")
    md.append("## Threat Overview\n")
    md.append("| Metric | Value |")
    md.append("|--------|-------|")
    md.append(f"| Threat Index | {trends['threat_index']} |")
    md.append(f"| Critical CVEs | {trends['critical_count']} |")
    for sev, count in trends["severity_distribution"].items():
        md.append(f"| {sev} | {count} |")
    if delta.get("status") == "compared":
        md.append("\n## Delta vs Yesterday\n")
        md.append("| Metric | Today | Yesterday | Change |")
        md.append("|--------|-------|-----------|--------|")
        for k, d in delta["deltas"].items():
            arrow = "📈" if d["change_pct"] > 0 else "📉" if d["change_pct"] < 0 else "➡️"
            md.append(f"| {k} | {d['today']} | {d['yesterday']} | {arrow} {d['change_pct']}% |")
    if trends["top_cwes"]:
        md.append("\n## Top Weakness Categories\n")
        md.append("| CWE | Count |")
        md.append("|-----|-------|")
        for cwe, count in trends["top_cwes"]:
            md.append(f"| {cwe} | {count} |")
    md.append("\n## CVE Details\n")
    md.append("| CVE ID | Score | Severity | Description |")
    md.append("|--------|-------|----------|-------------|")
    for p in parsed[:15]:
        md.append(f"| {p['id']} | {p['score']} | {p['severity']} | {p['description'][:80].replace('|','/')}... |")

    with open(f"logs/{date_str}.md", "w") as f:
        f.write("\n".join(md))
    print(f"[daily-experiments] v2.0 report + charts generated ({trends['total_cves']} CVEs)")

if __name__ == "__main__":
    main()
