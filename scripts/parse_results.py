#!/usr/bin/env python3
"""
parse_results.py — Parse Trivy JSON scan output and print a summary table.

Usage:
    trivy fs . --format json --output trivy.json
    python scripts/parse_results.py --input trivy.json

    trivy image myimage:latest --format json --output trivy.json
    python scripts/parse_results.py --input trivy.json --fail-on CRITICAL
"""

import json
import sys
import argparse
from collections import defaultdict
from datetime import datetime

SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[92m",  # green
    "UNKNOWN":  "\033[90m",  # grey
}
RESET = "\033[0m"


def color(text: str, severity: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def parse_trivy_json(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def extract_vulnerabilities(data: dict) -> list[dict]:
    vulns = []
    results = data.get("Results", [])
    for result in results:
        target = result.get("Target", "unknown")
        for v in result.get("Vulnerabilities") or []:
            vulns.append({
                "target":      target,
                "pkg":         v.get("PkgName", "-"),
                "installed":   v.get("InstalledVersion", "-"),
                "fixed":       v.get("FixedVersion", "-"),
                "severity":    v.get("Severity", "UNKNOWN"),
                "cve":         v.get("VulnerabilityID", "-"),
                "title":       v.get("Title", "-")[:60],
            })
    return vulns


def extract_misconfigs(data: dict) -> list[dict]:
    misconfigs = []
    for result in data.get("Results", []):
        target = result.get("Target", "unknown")
        for m in result.get("Misconfigurations") or []:
            misconfigs.append({
                "target":   target,
                "id":       m.get("ID", "-"),
                "severity": m.get("Severity", "UNKNOWN"),
                "title":    m.get("Title", "-")[:60],
                "status":   m.get("Status", "-"),
            })
    return misconfigs


def print_summary(vulns: list, misconfigs: list):
    counts = defaultdict(int)
    for v in vulns:
        counts[v["severity"]] += 1

    print("\n" + "═" * 70)
    print("  🔐 TRIVY SCAN SUMMARY")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 70)

    print("\n  VULNERABILITIES BY SEVERITY:")
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        bar = "█" * min(count, 40)
        print(f"  {color(f'{sev:<10}', sev)} {color(bar, sev)} {count}")

    print(f"\n  Total vulnerabilities : {len(vulns)}")
    print(f"  Total misconfigurations: {len(misconfigs)}")

    if vulns:
        print("\n" + "─" * 70)
        print("  TOP 20 VULNERABILITIES")
        print("─" * 70)
        print(f"  {'SEVERITY':<10} {'CVE':<20} {'PACKAGE':<20} {'FIXED':<15} TITLE")
        print("  " + "─" * 66)
        sorted_vulns = sorted(vulns, key=lambda x: SEVERITY_ORDER.index(x["severity"]))
        for v in sorted_vulns[:20]:
            sev   = color(f"{v['severity']:<10}", v["severity"])
            cve   = f"{v['cve']:<20}"
            pkg   = f"{v['pkg']:<20}"
            fixed = f"{v['fixed']:<15}"
            print(f"  {sev} {cve} {pkg} {fixed} {v['title']}")

    if misconfigs:
        print("\n" + "─" * 70)
        print("  MISCONFIGURATIONS")
        print("─" * 70)
        for m in misconfigs[:15]:
            sev = color(f"{m['severity']:<10}", m["severity"])
            print(f"  {sev} {m['id']:<15} {m['title']}")

    print("\n" + "═" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Parse Trivy JSON output")
    parser.add_argument("--input",    "-i", required=True, help="Path to Trivy JSON output file")
    parser.add_argument("--fail-on",  "-f", default=None,
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Exit code 1 if any vuln of this severity or higher is found")
    parser.add_argument("--output",   "-o", default=None,
                        help="Save summary to text file")
    args = parser.parse_args()

    try:
        data       = parse_trivy_json(args.input)
        vulns      = extract_vulnerabilities(data)
        misconfigs = extract_misconfigs(data)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON: {e}")
        sys.exit(1)

    print_summary(vulns, misconfigs)

    # Fail on severity threshold
    if args.fail_on:
        threshold_idx = SEVERITY_ORDER.index(args.fail_on)
        for v in vulns:
            if SEVERITY_ORDER.index(v["severity"]) <= threshold_idx:
                print(f"[FAIL] Found vulnerabilities at or above {args.fail_on} severity.")
                sys.exit(1)

    print("[PASS] Scan complete.")


if __name__ == "__main__":
    main()
