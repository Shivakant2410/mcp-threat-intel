#!/usr/bin/env python3
"""
mcp-check — CLI tool to check MCP server trust score.
Free tier: query before connecting any MCP server.

Usage:
    python mcp_check.py @modelcontextprotocol/server-filesystem
    python mcp_check.py @modelcontextprotocol/server-filesystem --verbose
    python mcp_check.py --list-top-risks
"""

import json
import sys
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
SANDBOX_DIR = DATA_DIR / "sandbox_results"
INDEX_FILE = DATA_DIR / "index.json"
REPORTS_DIR = DATA_DIR / "reports"


def safe_load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Failed to load {path}: {e}")
        return None


def load_index():
    return safe_load_json(INDEX_FILE) or []


def load_analysis(package_name):
    safe_name = package_name.replace("/", "_").replace("@", "")
    result_file = SANDBOX_DIR / f"{safe_name}.json"
    return safe_load_json(result_file)


def load_threat_report():
    reports = sorted(REPORTS_DIR.glob("threat_report_*.json"), reverse=True)
    if reports:
        return safe_load_json(reports[0])
    return None


def display_trust_score(package_name, verbose=False):
    analysis = load_analysis(package_name)
    index = load_index()

    pkg_meta = next((pkg for pkg in index if pkg["name"] == package_name), None)

    if not analysis and not pkg_meta:
        print(f"❌ {package_name} — NOT FOUND in index or sandbox results")
        print(f"   Run: python crawler.py and python sandbox.py {package_name}")
        return

    if not analysis:
        print(f"⚠️  {package_name} — IN INDEX but NOT YET ANALYZED")
        if pkg_meta:
            print(f"   Description: {pkg_meta.get('description', 'N/A')}")
            print(f"   Version: {pkg_meta.get('version', 'N/A')}")
            print(f"   Source: {pkg_meta.get('source', 'N/A')}")
        print(f"   Run: python sandbox.py {package_name} to analyze")
        return

    score = analysis["score"]
    risk = score["risk_level"]
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "MINIMAL": "✅"}

    print(f"\n{'=' * 50}")
    print(f"  MCP TRUST SCORE: {package_name}")
    print(f"{'=' * 50}")
    print(f"  Risk Level:  {risk_emoji.get(risk, '❓')} {risk}")
    print(f"  Score:       {score['score']}")
    print(f"  Version:     {analysis.get('version', 'N/A')}")
    print(f"  Analyzed:    {analysis.get('analyzed_at', 'N/A')[:10]}")
    print()

    s = score["summary"]
    print(f"  FINDINGS:")
    for k, v in s.items():
        print(f"  {k.replace('_',' ').title():<20} {v}")

    if verbose and score.get("details"):
        print(f"\n  DETAILS:")
        for detail in score["details"]:
            print(f"  {detail}")

    threat_report = load_threat_report()
    if threat_report:
        for pkg in threat_report.get("packages", []):
            if pkg["package"] == package_name:
                dev = pkg["deviation_analysis"]
                print(f"\n  DEVIATION ANALYSIS:")
                print(f"  Risk Assessment: {dev['risk_assessment']}")
                print(f"  Deviations:      {dev['deviation_count']}")
                print(f"  Critical:        {dev['critical_count']}")
                print(f"  High:            {dev['high_count']}")
                if verbose and dev.get("deviations"):
                    print(f"\n  DEVIATIONS:")
                    for d in dev["deviations"]:
                        print(f"    [{d['severity']}] {d['type']}")
                        print(f"         {d['description']}")
                break
    print()


def list_top_risks(limit=10):
    """List top risk MCP servers from sandbox_results or threat report."""
    results = []

    # Always scan sandbox_results first
    for f in SANDBOX_DIR.glob("*.json"):
        if f.name == "batch_results.json":
            continue
        data = safe_load_json(f)
        if data:
            results.append(data)

    # If threat report exists, merge its results
    threat_report = load_threat_report()
    if threat_report:
        for pkg in threat_report.get("packages", []):
            results.append({
                "package": pkg["package"],
                "score": {
                    "score": pkg["deviation_analysis"]["deviation_score"],
                    "risk_level": pkg["deviation_analysis"]["risk_assessment"],
                }
            })

    if not results:
        print("❌ No analysis results found. Run crawler.py and sandbox.py first.")
        return

    risk_emoji = {"CRITICAL": "🔴", "EXPLOITABLE": "🔴", "HIGH": "🟠", "SUSPICIOUS": "🟠",
                  "MEDIUM": "🟡", "MODERATE": "🟡", "LOW": "🟢", "LOW_RISK": "🟢", "MINIMAL": "✅"}

    print(f"\n{'=' * 60}")
    print(f"  MCP THREAT INTELLIGENCE — TOP RISKS")
    print(f"{'=' * 60}\n")

    # Sort by score descending
    results.sort(key=lambda r: r["score"]["score"], reverse=True)

    for i, r in enumerate(results[:limit], 1):
        s = r["score"]
        risk = s.get("risk_level", "UNKNOWN")
        emoji = risk_emoji.get(risk, "❓")
        print(f"  {i:2d}. {emoji} {r.get('package','N/A')}")
        print(f"      Score: {s['score']} | Risk: {risk}")
    print()


def main():
    if "--list-top-risks" in sys.argv:
        list_top_risks()
        return

    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]

    if not args:
        print("Usage: python mcp_check.py <package-name> [--verbose]")
        print("       python mcp_check.py --list-top-risks")
        return

    display_trust_score(args[0], verbose=verbose)


if __name__ == "__main__":
    main()
