#!/usr/bin/env python3
"""Generate professional forensic investigation reports.

Usage:
    python 09_forensic_report.py [--dataset FILE] [--output FILE]

Produces:
  - Executive summary
  - Key findings & IOCs (Indicators of Compromise)
  - Evidence chain
  - Recommendations
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import Any

def load_dataset(file: Path) -> dict[str, Any]:
    """Load cleaned dataset."""
    with open(file, encoding='utf-8') as f:
        return json.load(f)

def extract_iocs(data: dict) -> dict[str, list]:
    """Extract IOCs (suspicious IPs, files, domains, etc)."""
    records = data.get("records", [])
    iocs = {
        "suspicious_ips": [],
        "suspicious_files": [],
        "suspicious_domains": [],
        "suspicious_processes": [],
        "suspicious_urls": [],
    }
    
    for record in records:
        details = record.get("details", {})
        
        # Extract IPs
        if ip := details.get("ip") or details.get("remote_ip"):
            if ip not in iocs["suspicious_ips"]:
                iocs["suspicious_ips"].append(ip)
        
        # Extract files
        if file := details.get("file") or details.get("filepath"):
            if file not in iocs["suspicious_files"]:
                iocs["suspicious_files"].append(file)
        
        # Extract domains
        if domain := details.get("domain") or details.get("host"):
            if domain and "." in domain and domain not in iocs["suspicious_domains"]:
                iocs["suspicious_domains"].append(domain)
        
        # Extract processes
        if proc := details.get("process") or details.get("executable"):
            if proc not in iocs["suspicious_processes"]:
                iocs["suspicious_processes"].append(proc)
        
        # Extract URLs
        if url := details.get("url"):
            if url not in iocs["suspicious_urls"]:
                iocs["suspicious_urls"].append(url)
    
    return {k: v[:20] for k, v in iocs.items() if v}  # Top 20 each

def analyze_findings(data: dict) -> list[dict[str, Any]]:
    """Extract key findings from the dataset."""
    records = data.get("records", [])
    problems = data.get("collection_problems", [])
    summary = data.get("summary", {})
    
    findings = []
    
    # Finding 1: Collection Issues
    if problems:
        findings.append({
            "severity": "HIGH",
            "title": "Data Collection Issues Detected",
            "description": f"Found {len(problems)} collection problems that may affect analysis completeness.",
            "details": problems[:5],
            "impact": "Results may be incomplete or inconclusive"
        })
    
    # Finding 2: Record Distribution
    event_types = Counter(r.get("event_type", "unknown") for r in records)
    if event_types:
        findings.append({
            "severity": "INFO",
            "title": "Evidence Distribution",
            "description": f"Analyzed {len(records)} forensic records across {len(event_types)} event types.",
            "top_events": dict(event_types.most_common(5)),
            "impact": "Evidence comes from diverse sources"
        })
    
    # Finding 3: Data Quality
    total = len(records)
    with_details = sum(1 for r in records if r.get("details"))
    quality_pct = (with_details / total * 100) if total else 0
    
    findings.append({
        "severity": "MEDIUM" if quality_pct < 70 else "LOW",
        "title": "Data Quality Assessment",
        "description": f"{quality_pct:.1f}% of records have detailed metadata.",
        "quality_percentage": quality_pct,
        "impact": "Analysis confidence level"
    })
    
    # Finding 4: Identified Entities
    users = set(r.get("user") for r in records if r.get("user"))
    hosts = set(r.get("host") for r in records if r.get("host"))
    apps = set(r.get("application") for r in records if r.get("application"))
    
    if users or hosts or apps:
        findings.append({
            "severity": "INFO",
            "title": "Investigation Scope",
            "description": f"Evidence spans {len(users)} users, {len(hosts)} hosts, {len(apps)} applications.",
            "user_count": len(users),
            "host_count": len(hosts),
            "app_count": len(apps),
            "impact": "Broader investigation scope indicates more complex incident"
        })
    
    return findings

def generate_markdown_report(data: dict, iocs: dict, findings: list) -> str:
    """Generate markdown forensic report."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    records = data.get("records", [])
    summary = data.get("summary", {})
    
    report = f"""# Forensic Investigation Report

**Generated:** {timestamp}  
**Total Records Analyzed:** {len(records)}  
**Collection Status:** {"Complete" if not data.get("collection_problems") else "With Issues"}

---

## Executive Summary

This forensic investigation analyzed {len(records)} records from Velociraptor collection data. The analysis identified key findings that require attention and actionable indicators of compromise (IOCs).

---

## Key Findings

"""
    
    for i, finding in enumerate(findings, 1):
        severity = finding["severity"]
        color = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
        
        report += f"""### {i}. {finding['title']} {color}

**Severity:** {severity}

{finding['description']}

"""
        if "top_events" in finding:
            report += "**Event Distribution:**\n"
            for event, count in finding["top_events"].items():
                report += f"- {event}: {count} records\n"
            report += "\n"
        
        if "quality_percentage" in finding:
            report += f"**Quality Score:** {finding['quality_percentage']:.1f}%\n\n"
        
        if "user_count" in finding:
            report += f"- **Users:** {finding['user_count']}\n"
            report += f"- **Hosts:** {finding['host_count']}\n"
            report += f"- **Applications:** {finding['app_count']}\n\n"
        
        report += f"**Impact:** {finding.get('impact', 'N/A')}\n\n"
    
    # IOCs Section
    report += """---

## Indicators of Compromise (IOCs)

"""
    
    if not iocs:
        report += "No suspicious indicators extracted from current dataset.\n\n"
    else:
        if iocs.get("suspicious_ips"):
            report += f"""### Suspicious IP Addresses ({len(iocs['suspicious_ips'])})

```
{chr(10).join(iocs['suspicious_ips'])}
```

"""
        
        if iocs.get("suspicious_domains"):
            report += f"""### Suspicious Domains ({len(iocs['suspicious_domains'])})

```
{chr(10).join(iocs['suspicious_domains'])}
```

"""
        
        if iocs.get("suspicious_files"):
            report += f"""### Suspicious Files ({len(iocs['suspicious_files'])})

```
{chr(10).join(iocs['suspicious_files'])}
```

"""
        
        if iocs.get("suspicious_processes"):
            report += f"""### Suspicious Processes ({len(iocs['suspicious_processes'])})

```
{chr(10).join(iocs['suspicious_processes'])}
```

"""
        
        if iocs.get("suspicious_urls"):
            report += f"""### Suspicious URLs ({len(iocs['suspicious_urls'])})

```
{chr(10).join(iocs['suspicious_urls'])}
```

"""
    
    # Recommendations
    report += """---

## Recommendations

1. **Immediate Actions**
   - Isolate affected hosts from the network if malware is suspected
   - Preserve all evidence for legal proceedings
   - Block extracted IOCs at perimeter (firewall, proxy)

2. **Investigation Next Steps**
   - Cross-reference IOCs with threat intelligence feeds
   - Analyze process execution chains for attack progression
   - Interview system owners about suspicious activity
   - Check backups for earlier compromise indicators

3. **Prevention**
   - Deploy EDR (Endpoint Detection & Response) solution
   - Implement network segmentation
   - Enable detailed logging on critical systems
   - Conduct staff security awareness training

---

## Evidence Chain

All evidence was extracted from the Velociraptor forensic collection:
- **Source:** Velociraptor automated collection
- **Dataset:** cleaned_dataset.json
- **Total Records:** {len(records)}
- **Analysis Date:** {timestamp}

This report serves as a forensic artifact documenting the investigation timeline and findings.

---

*Report generated by AI Investigation Platform*
"""
    
    return report

def main():
    dataset_file = Path("data/processed/cleaned_dataset.json")
    output_file = Path("data/processed/forensic_report.md")
    
    if not dataset_file.exists():
        print(f"Error: {dataset_file} not found")
        sys.exit(1)
    
    print(f"Loading {dataset_file}...")
    data = load_dataset(dataset_file)
    
    print("Extracting IOCs...")
    iocs = extract_iocs(data)
    
    print("Analyzing findings...")
    findings = analyze_findings(data)
    
    print(f"Generating report ({len(findings)} findings, {sum(len(v) for v in iocs.values())} IOCs)...")
    report = generate_markdown_report(data, iocs, findings)
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(report, encoding='utf-8')
    
    print(f"\nReport saved to {output_file}")
    # The report contains emoji; a cp1252 console cannot encode them, so drop
    # anything unprintable from the preview rather than crashing after the
    # file has already been written successfully.
    encoding = sys.stdout.encoding or "utf-8"
    preview = report[:800].encode(encoding, errors="replace").decode(encoding)
    print(f"\nPreview:\n{preview}...\n")

if __name__ == "__main__":
    main()