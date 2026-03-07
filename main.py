#!/usr/bin/env python3
"""Daily Experiments — Automated security scanning & NIST NVD parsing."""
import json, os, datetime, hashlib, urllib.request, ssl

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

def fetch_recent_cves(days_back=2, max_results=20):
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    end = now.strftime("%Y-%m-%dT23:59:59.999")

    url = f"{NVD_API}?pubStartDate={start}&pubEndDate={end}&resultsPerPage={max_results}"

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "daily-experiments-bot/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"[WARN] NVD fetch failed: {e}")
        return []

def parse_cve(vuln):
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")

    metrics = cve.get("metrics", {})
    severity = "UNKNOWN"
    score = 0.0

    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            m = metrics[version][0]
            cvss = m.get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))
            break

    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

    return {
        "id": cve_id,
        "description": desc[:300],
        "severity": severity,
        "score": score,
        "cwes": cwes,
        "references": refs,
        "published": cve.get("published", ""),
    }

def analyze_trends(parsed):
    severity_counts = {}
    cwe_counts = {}
    for p in parsed:
        sev = p["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for c in p["cwes"]:
            cwe_counts[c] = cwe_counts.get(c, 0) + 1

    threat_score = sum(SEVERITY_WEIGHTS.get(p["severity"], 0) * p["score"] for p in parsed)
    top_cwes = sorted(cwe_counts.items(), key=lambda x: -x[1])[:5]

    return {
        "total_cves": len(parsed),
        "severity_distribution": severity_counts,
        "top_cwes": top_cwes,
        "threat_index": round(threat_score, 2),
        "critical_count": severity_counts.get("CRITICAL", 0),
    }

def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    date_str = now.strftime("%Y-%m-%d")

    print(f"[daily-experiments] Fetching CVEs from NVD...")
    vulns = fetch_recent_cves()
    parsed = [parse_cve(v) for v in vulns]
    parsed.sort(key=lambda x: x["score"], reverse=True)
    trends = analyze_trends(parsed)

    report = {
        "timestamp": now.isoformat(),
        "scan_id": hashlib.sha256(now.isoformat().encode()).hexdigest()[:10],
        "trends": trends,
        "cves": parsed,
    }

    os.makedirs("logs", exist_ok=True)
    with open(f"logs/{date_str}.json", "w") as f:
        json.dump(report, f, indent=2)

    md = [f"# Security Scan Report — {date_str}\n"]
    md.append(f"**Scan ID:** `{report['scan_id']}` | **CVEs Analyzed:** {trends['total_cves']}\n")
    md.append(f"## Threat Overview\n")
    md.append(f"| Metric | Value |")
    md.append(f"|--------|-------|")
    md.append(f"| Threat Index | {trends['threat_index']} |")
    md.append(f"| Critical CVEs | {trends['critical_count']} |")
    for sev, count in trends["severity_distribution"].items():
        md.append(f"| {sev} | {count} |")
    if trends["top_cwes"]:
        md.append(f"\n## Top Weakness Categories\n")
        md.append(f"| CWE | Count |")
        md.append(f"|-----|-------|")
        for cwe, count in trends["top_cwes"]:
            md.append(f"| {cwe} | {count} |")
    md.append(f"\n## CVE Details\n")
    md.append(f"| CVE ID | Score | Severity | Description |")
    md.append(f"|--------|-------|----------|-------------|")
    for p in parsed[:15]:
        desc_short = p["description"][:100].replace("|", "/")
        md.append(f"| {p['id']} | {p['score']} | {p['severity']} | {desc_short}... |")

    with open(f"logs/{date_str}.md", "w") as f:
        f.write("\n".join(md))

    print(f"[daily-experiments] Report generated: logs/{date_str}.md ({trends['total_cves']} CVEs)")

if __name__ == "__main__":
    main()
