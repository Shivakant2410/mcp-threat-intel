"""
MCP Behavioral Deviation Analyzer
Compares what an MCP server CLAIMS to do (tool descriptions, README)
vs what it ACTUALLY does (network calls, file access, env reads).

The gap between claim and behavior = the exploit surface.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
REPORTS_DIR = DATA_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def extract_claimed_capabilities(findings, package_meta=None):
    """
    Extract what the MCP server CLAIMS to do from:
    - Tool descriptions in code
    - Package description
    - README content (if available)
    """
    claimed = {
        "tool_names": [],
        "tool_descriptions": [],
        "declared_network": False,
        "declared_fs_access": False,
        "declared_env_access": False,
        "declared_exec": False,
        "package_description": "",
    }

    # From tool descriptions in code
    for td in findings.get("tool_descriptions", []):
        claimed["tool_names"].extend(td.get("tool_names", []))
        claimed["tool_descriptions"].extend(td.get("descriptions", []))

    # From declared capabilities in package.json
    for cap in findings.get("declared_capabilities", []):
        deps = cap.get("dependencies", [])
        if any("fetch" in d or "axios" in d or "request" in d or "http" in d for d in deps):
            claimed["declared_network"] = True
        if any("fs" in d or "file" in d or "path" in d for d in deps):
            claimed["declared_fs_access"] = True

        scripts = cap.get("scripts", {})
        if "preinstall" in scripts or "postinstall" in scripts:
            claimed["declared_exec"] = True

    # From package metadata
    if package_meta:
        claimed["package_description"] = package_meta.get("description", "")
        desc_lower = claimed["package_description"].lower()

        # Heuristic: does the description mention network, files, env?
        if any(w in desc_lower for w in ["api", "http", "url", "webhook", "request", "fetch", "remote"]):
            claimed["declared_network"] = True
        if any(w in desc_lower for w in ["file", "read", "write", "directory", "path", "filesystem"]):
            claimed["declared_fs_access"] = True
        if any(w in desc_lower for w in ["environment", "env", "config", "variable", "secret"]):
            claimed["declared_env_access"] = True
        if any(w in desc_lower for w in ["exec", "spawn", "shell", "command", "run", "process"]):
            claimed["declared_exec"] = True

    return claimed


def extract_observed_behaviors(findings):
    """
    Extract what the MCP server ACTUALLY does based on static analysis findings.
    """
    observed = {
        "network_calls": [],
        "external_domains": [],
        "env_reads": [],
        "fs_operations": [],
        "exec_calls": [],
        "eval_usage": [],
        "encoded_strings": [],
        "suspicious_patterns": [],
    }

    # Network calls
    for item in findings.get("network_indicators", []):
        observed["network_calls"].append({
            "file": item["file"],
            "pattern": item["pattern"],
            "count": item["count"],
        })
        # Extract domains from examples
        for ex in item.get("examples", []):
            urls = re.findall(r'https?://([^\s/\'"<>]+)', ex.get("code", ""))
            for domain in urls:
                if domain not in observed["external_domains"]:
                    observed["external_domains"].append(domain)

    # Env reads
    for item in findings.get("env_access", []):
        observed["env_reads"].append({
            "file": item["file"],
            "pattern": item["pattern"],
            "count": item["count"],
        })

    # File system operations
    for item in findings.get("file_system_ops", []):
        observed["fs_operations"].append({
            "file": item["file"],
            "pattern": item["pattern"],
            "count": item["count"],
        })

    # Exec calls
    for item in findings.get("child_process", []):
        observed["exec_calls"].append({
            "file": item["file"],
            "pattern": item["pattern"],
            "count": item["count"],
        })

    # Eval usage
    for item in findings.get("eval_usage", []):
        observed["eval_usage"].append({
            "file": item["file"],
            "pattern": item["pattern"],
            "count": item["count"],
        })

    # Encoded strings
    for item in findings.get("encoded_strings", []):
        observed["encoded_strings"].append({
            "file": item["file"],
            "pattern": item["pattern"],
            "count": item["count"],
        })

    # Suspicious patterns
    for item in findings.get("suspicious_patterns", []):
        observed["suspicious_patterns"].append({
            "file": item["file"],
            "pattern": item["pattern"],
            "count": item["count"],
        })

    return observed


def compute_deviation(claimed, observed):
    """
    Compute the gap between claimed capabilities and observed behaviors.
    This is the core intelligence — the exploit surface.
    """
    deviations = []

    # Network deviation
    has_network = len(observed["network_calls"]) > 0
    if has_network and not claimed["declared_network"]:
        deviations.append({
            "type": "UNDECLARED_NETWORK_ACCESS",
            "severity": "HIGH",
            "description": f"Package makes network calls but doesn't declare network capability in description",
            "evidence": observed["network_calls"][:3],
            "domains": observed["external_domains"][:5],
        })

    # External domain analysis
    internal_patterns = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    external_domains = [d for d in observed["external_domains"]
                        if not any(p in d for p in internal_patterns)]
    if external_domains:
        deviations.append({
            "type": "EXTERNAL_COMMUNICATION",
            "severity": "MEDIUM",
            "description": f"Package communicates with {len(external_domains)} external domain(s)",
            "domains": external_domains[:10],
        })

    # Env access deviation
    has_env = len(observed["env_reads"]) > 0
    if has_env and not claimed["declared_env_access"]:
        deviations.append({
            "type": "UNDECLARED_ENV_ACCESS",
            "severity": "HIGH",
            "description": "Package reads environment variables but doesn't declare env access",
            "evidence": observed["env_reads"][:3],
        })

    # Exec deviation
    has_exec = len(observed["exec_calls"]) > 0
    if has_exec and not claimed["declared_exec"]:
        deviations.append({
            "type": "UNDECLARED_COMMAND_EXECUTION",
            "severity": "CRITICAL",
            "description": "Package executes system commands but doesn't declare this capability",
            "evidence": observed["exec_calls"][:3],
        })

    # Eval usage — always a deviation for MCP servers
    if observed["eval_usage"]:
        deviations.append({
            "type": "DYNAMIC_CODE_EXECUTION",
            "severity": "CRITICAL",
            "description": "Package uses eval/Function constructor — can execute arbitrary code",
            "evidence": observed["eval_usage"][:3],
        })

    # Encoded strings — obfuscation indicator
    if observed["encoded_strings"]:
        deviations.append({
            "type": "OBFUSCATED_CONTENT",
            "severity": "MEDIUM",
            "description": "Package contains encoded/obfuscated strings that may hide behavior",
            "evidence": observed["encoded_strings"][:3],
        })

    # Suspicious patterns
    for sp in observed["suspicious_patterns"]:
        severity = "HIGH"
        if "CREDENTIAL" in sp["pattern"]:
            severity = "CRITICAL"
        elif "PROTOTYPE" in sp["pattern"]:
            severity = "CRITICAL"
        elif "DESTRUCTIVE" in sp["pattern"]:
            severity = "CRITICAL"

        deviations.append({
            "type": sp["pattern"],
            "severity": severity,
            "description": f"Suspicious pattern detected: {sp['pattern']} in {sp['file']}",
            "count": sp["count"],
        })

    # Compute overall deviation score
    severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
    deviation_score = sum(severity_weights.get(d["severity"], 1) for d in deviations)

    return {
        "deviations": deviations,
        "deviation_count": len(deviations),
        "deviation_score": deviation_score,
        "critical_count": sum(1 for d in deviations if d["severity"] == "CRITICAL"),
        "high_count": sum(1 for d in deviations if d["severity"] == "HIGH"),
        "risk_assessment": "EXPLOITABLE" if deviation_score >= 20 else
                          "SUSPICIOUS" if deviation_score >= 10 else
                          "MODERATE" if deviation_score >= 5 else
                          "LOW_RISK",
    }


def analyze_package(analysis_result, package_meta=None):
    """
    Full behavioral deviation analysis for a single package.
    Takes the output from sandbox.py analysis.
    """
    findings = analysis_result.get("findings", {})

    claimed = extract_claimed_capabilities(findings, package_meta)
    observed = extract_observed_behaviors(findings)
    deviation = compute_deviation(claimed, observed)

    report = {
        "package": analysis_result.get("package", ""),
        "version": analysis_result.get("version", ""),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "claimed_capabilities": claimed,
        "observed_behaviors": observed,
        "deviation_analysis": deviation,
    }

    return report


def generate_threat_report(reports, output_file=None):
    """
    Generate a consolidated threat intelligence report from all analyses.
    This is the output that becomes the LinkedIn post, the HackerNews submission,
    the thing that establishes authority.
    """
    if output_file is None:
        output_file = REPORTS_DIR / f"threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"

    # Sort by deviation score
    sorted_reports = sorted(
        reports,
        key=lambda r: r["deviation_analysis"]["deviation_score"],
        reverse=True
    )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_analyzed": len(sorted_reports),
        "exploitable": sum(1 for r in sorted_reports if r["deviation_analysis"]["risk_assessment"] == "EXPLOITABLE"),
        "suspicious": sum(1 for r in sorted_reports if r["deviation_analysis"]["risk_assessment"] == "SUSPICIOUS"),
        "moderate": sum(1 for r in sorted_reports if r["deviation_analysis"]["risk_assessment"] == "MODERATE"),
        "low_risk": sum(1 for r in sorted_reports if r["deviation_analysis"]["risk_assessment"] == "LOW_RISK"),
        "total_critical_deviations": sum(r["deviation_analysis"]["critical_count"] for r in sorted_reports),
        "total_high_deviations": sum(r["deviation_analysis"]["high_count"] for r in sorted_reports),
    }

    report = {
        "summary": summary,
        "packages": sorted_reports,
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return report


if __name__ == "__main__":
    import sys

    # Load results — try batch file first, then scan individual files
    sandbox_dir = Path(__file__).parent / "data" / "sandbox_results"
    results = []

    # Option 1: batch_results.json
    batch_file = sandbox_dir / "batch_results.json"
    if batch_file.exists():
        with open(batch_file) as f:
            results = json.load(f)
        print(f"Loaded {len(results)} results from batch_results.json")
    else:
        # Option 2: scan individual result files
        seen = set()
        for sf in sandbox_dir.glob("*.json"):
            if sf.name == "batch_results.json":
                continue
            try:
                with open(sf) as f:
                    data = json.load(f)
                pkg_name = data.get("package", "")
                if pkg_name and pkg_name not in seen:
                    results.append(data)
                    seen.add(pkg_name)
            except (json.JSONDecodeError, IOError):
                pass
        if results:
            print(f"Loaded {len(results)} results from individual sandbox files")

    if not results:
        print("No sandbox results found. Run: python sandbox.py --batch")
        sys.exit(1)

    # Load index for package metadata
    index_file = Path(__file__).parent / "data" / "index.json"
    meta_lookup = {}
    if index_file.exists():
        with open(index_file) as f:
            index = json.load(f)
        for pkg in index:
            meta_lookup[pkg["name"]] = pkg

    # Run deviation analysis
    reports = []
    for result in results:
        meta = meta_lookup.get(result.get("package", ""), None)
        report = analyze_package(result, meta)
        reports.append(report)

    threat_report = generate_threat_report(reports)

    s = threat_report["summary"]
    print(f"\nTHREAT INTELLIGENCE REPORT")
    print(f"{'=' * 50}")
    print(f"Total analyzed: {s['total_analyzed']}")
    print(f"Exploitable:    {s['exploitable']}")
    print(f"Suspicious:     {s['suspicious']}")
    print(f"Moderate:       {s['moderate']}")
    print(f"Low risk:       {s['low_risk']}")
    print(f"Critical devs:  {s['total_critical_deviations']}")
    print(f"High devs:      {s['total_high_deviations']}")

    # Also save a human-readable summary
    summary_file = Path(__file__).parent / "data" / "reports" / "summary.txt"
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_file, "w") as f:
        f.write(f"MCP THREAT INTELLIGENCE REPORT\n")
        f.write(f"{'=' * 50}\n")
        f.write(f"Generated: {s['generated_at'][:10]}\n")
        f.write(f"Total analyzed: {s['total_analyzed']}\n")
        f.write(f"Exploitable:    {s['exploitable']} ({s['exploitable']*100//s['total_analyzed']}%)\n")
        f.write(f"Suspicious:     {s['suspicious']}\n")
        f.write(f"Moderate:       {s['moderate']}\n")
        f.write(f"Low risk:       {s['low_risk']}\n\n")
        f.write(f"TOP RISKS:\n")
        for pkg in threat_report["packages"][:10]:
            dev = pkg["deviation_analysis"]
            f.write(f"  {pkg['package']}: {dev['deviation_score']} ({dev['risk_assessment']})\n")
            for d in dev["deviations"][:3]:
                f.write(f"    [{d['severity']}] {d['type']}\n")
    print(f"\nSummary saved to {summary_file}")
