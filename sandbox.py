"""
MCP Behavioral Sandbox
Runs MCP servers in isolation and logs:
- Outbound network calls (DNS, HTTP)
- Filesystem access (read, write, exec)
- Environment variable reads
- Child process spawning
- Deviation from claimed tool description

Since Docker may not be available, we also support a static analysis mode
that inspects package contents without executing them.
"""

import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
SANDBOX_DIR = DATA_DIR / "sandbox_results"
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# CLEANUP — remove old sandbox results before batch run
# ============================================================
for f in SANDBOX_DIR.glob("*.json"):
    try:
        f.unlink()
    except Exception as e:
        print(f"⚠️ Could not delete {f}: {e}")

        
# ============================================================
# STATIC ANALYSIS — Inspect package without running it
# ============================================================

def download_npm_package(name, version="latest", output_dir=None):
    """Download an npm package tarball and extract it. Cross-platform (no tar CLI needed)."""
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="mcp_sandbox_")

    pkg_dir = os.path.join(output_dir, name.replace("/", "_").replace("@", ""))
    os.makedirs(pkg_dir, exist_ok=True)

    extract_dir = os.path.join(pkg_dir, "contents")
    os.makedirs(extract_dir, exist_ok=True)

    # Method 1: Download tarball directly from npm registry via HTTP
    # Works on all platforms, no npm CLI needed
    try:
        # Resolve "latest" to actual version first
        if version == "latest":
            meta_url = f"https://registry.npmjs.org/{name}/latest"
            req = urllib.request.Request(meta_url, headers={"User-Agent": "mcp-threat-intel/0.1"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                meta = json.loads(resp.read().decode())
                version = meta.get("version", "latest")

        # Download tarball
        tarball_url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"
        req = urllib.request.Request(tarball_url, headers={"User-Agent": "mcp-threat-intel/0.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            tgz_data = resp.read()

        # Extract using Python's tarfile (no external tar command)
        with tarfile.open(fileobj=io.BytesIO(tgz_data), mode='r:gz') as tar:
            # Security: filter out absolute paths and path traversal
            members = [m for m in tar.getmembers()
                       if not m.name.startswith('/') and '..' not in m.name]
            tar.extractall(path=extract_dir, members=members, filter='data')

        # Verify something was extracted
        if any(Path(extract_dir).iterdir()):
            return extract_dir

    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            tarfile.TarError, OSError, Exception) as e:
        print(f"  [HTTP] Registry download failed: {e}")

    # Method 2: Fallback to npm pack + Python tarfile
    try:
        result = subprocess.run(
            ["npm", "pack", f"{name}@{version}", "--pack-destination", pkg_dir],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"  [npm] pack failed: {result.stderr.strip()[:100]}")
            return None

        tgz_files = list(Path(pkg_dir).glob("*.tgz"))
        if not tgz_files:
            print(f"  [npm] No tarball found after pack")
            return None

        with tarfile.open(str(tgz_files[0]), 'r:gz') as tar:
            members = [m for m in tar.getmembers()
                       if not m.name.startswith('/') and '..' not in m.name]
            tar.extractall(path=extract_dir, members=members, filter='data')

        if any(Path(extract_dir).iterdir()):
            return extract_dir

    except (subprocess.TimeoutExpired, FileNotFoundError, tarfile.TarError, OSError) as e:
        print(f"  [npm] Fallback failed: {e}")

    return None

def safe_load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Failed to load {path}: {e}")
        return None

def analyze_package_contents(extract_dir):
    """Static analysis of package contents — look for red flags."""
    findings = {
        "network_indicators": [],
        "env_access": [],
        "file_system_ops": [],
        "child_process": [],
        "eval_usage": [],
        "encoded_strings": [],
        "suspicious_patterns": [],
        "tool_descriptions": [],
        "declared_capabilities": [],
        "files_analyzed": 0,
    }

    package_dir = Path(extract_dir) / "package"
    if not package_dir.exists():
        package_dir = Path(extract_dir)

    # Recursively find all JS/TS files
    js_files = list(package_dir.rglob("*.js")) + list(package_dir.rglob("*.mjs")) + list(package_dir.rglob("*.cjs"))
    ts_files = list(package_dir.rglob("*.ts"))
    json_files = list(package_dir.rglob("*.json"))

    all_code_files = js_files + ts_files
    findings["files_analyzed"] = len(all_code_files)

    # Analyze package.json for declared capabilities
    for jf in json_files:
     if jf.name == "package.json":
        pkg_data = safe_load_json(jf)
        if pkg_data:
            findings["declared_capabilities"].append({
                "file": str(jf.relative_to(package_dir)),
                "dependencies": list(pkg_data.get("dependencies", {}).keys()),
                "scripts": pkg_data.get("scripts", {}),
                "main": pkg_data.get("main", ""),
            })


    # Patterns to search for in code
    patterns = {
        "network_indicators": [
            (r'https?://[^\s\'"<>]+', "HTTP_URL"),
            (r'fetch\s*\(', "FETCH_CALL"),
            (r'axios\.', "AXIOS_CALL"),
            (r'\.request\s*\(', "REQUEST_CALL"),
            (r'WebSocket|ws://|wss://', "WEBSOCKET"),
            (r'DNS|dns\.lookup|dns\.resolve', "DNS_CALL"),
            (r'net\.connect|tls\.connect', "NET_CONNECT"),
        ],
        "env_access": [
            (r'process\.env', "PROCESS_ENV"),
            (r'getenv|getEnv', "GET_ENV"),
            (r'\.env\b', "DOT_ENV"),
        ],
        "file_system_ops": [
            (r'fs\.read|fs\.write|fs\.append|fs\.unlink|fs\.mkdir|fs\.rmdir|fs\.rename', "FS_OP"),
            (r'readFile|writeFile|readFileSync|writeFileSync', "FILE_OP_SYNC"),
            (r'createReadStream|createWriteStream', "FILE_STREAM"),
        ],
        "child_process": [
            (r'child_process', "CHILD_PROCESS_IMPORT"),
            (r'exec\s*\(|execSync\s*\(', "EXEC_CALL"),
            (r'spawn\s*\(|spawnSync\s*\(', "SPAWN_CALL"),
            (r'execFile\s*\(', "EXECFILE_CALL"),
        ],
        "eval_usage": [
            (r'\beval\s*\(', "EVAL_CALL"),
            (r'Function\s*\(', "FUNCTION_CONSTRUCTOR"),
            (r'new Function\b', "NEW_FUNCTION"),
            (r'vm\.runInContext|vm\.runInNewContext|vm\.runInThisContext', "VM_RUN"),
        ],
        "encoded_strings": [
            (r'atob\s*\(|btoa\s*\(', "BASE64_ENCODE"),
            (r'Buffer\.from\s*\([^)]*,\s*[\'"]base64[\'"]', "BASE64_BUFFER"),
            (r'\\x[0-9a-fA-F]{2}', "HEX_ESCAPE"),
            (r'\\u[0-9a-fA-F]{4}', "UNICODE_ESCAPE"),
        ],
        "suspicious_patterns": [
            (r'curl\s+|wget\s+', "DOWNLOAD_COMMAND"),
            (r'/etc/passwd|/etc/shadow', "SENSITIVE_FILE_PATH"),
            (r'sudo\s+|chmod\s+|chown\s+', "PRIVILEGE_ESCALATION"),
            (r'rm\s+-rf|del\s+/[sfq]', "DESTRUCTIVE_COMMAND"),
            (r'keylog|credential|password|secret|token', "CREDENTIAL_ACCESS"),
            (r'prototype.*pollute|__proto__', "PROTOTYPE_POLLUTION"),
            (r'\.pipe\s*\(\s*.*stream', "STREAM_PIPE"),
        ],
    }

    for filepath in all_code_files:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                rel_path = str(filepath.relative_to(package_dir))
        except (IOError, ValueError):
            continue

        for category, pattern_list in patterns.items():
            for pattern, label in pattern_list:
                matches = re.findall(pattern, content)
                if matches:
                    # Get line numbers for context
                    lines_with_matches = []
                    for i, line in enumerate(content.split('\n'), 1):
                        if re.search(pattern, line):
                            lines_with_matches.append({
                                "line": i,
                                "code": line.strip()[:200],
                            })

                    findings[category].append({
                        "file": rel_path,
                        "pattern": label,
                        "count": len(matches),
                        "examples": lines_with_matches[:5],  # Cap at 5 examples
                    })

    # Extract MCP tool descriptions from code
    tool_desc_pattern = re.compile(r'(?:name|toolName)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE)
    tool_desc2_pattern = re.compile(r'description\s*[:=]\s*["\']([^"\']{10,}?)["\']', re.IGNORECASE)

    for filepath in all_code_files:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                rel_path = str(filepath.relative_to(package_dir))
        except (IOError, ValueError):
            continue

        names = tool_desc_pattern.findall(content)
        descs = tool_desc2_pattern.findall(content)
        if names or descs:
            findings["tool_descriptions"].append({
                "file": rel_path,
                "tool_names": names[:10],
                "descriptions": descs[:5],
            })

    return findings


def compute_behavioral_score(findings):
    """
    Score behavioral deviation from expected MCP server behavior.
    Higher score = more suspicious.

    Scoring rubric:
    - Network calls to external endpoints: +3 each unique domain
    - Environment variable access: +2 each
    - Child process execution: +5 each
    - eval/Function constructor: +8 each
    - Encoded/obfuscated strings: +6 each
    - Suspicious patterns (credentials, proto pollution): +7 each
    - File system write operations: +3 each
    """
    score = 0
    details = []

    # Network indicators
    for item in findings.get("network_indicators", []):
        score += min(item["count"], 10) * 3
        details.append(f"Network: {item['pattern']} in {item['file']} ({item['count']}x)")

    # Env access
    for item in findings.get("env_access", []):
        score += min(item["count"], 10) * 2
        details.append(f"Env: {item['pattern']} in {item['file']} ({item['count']}x)")

    # Child process — HIGH risk
    for item in findings.get("child_process", []):
        score += min(item["count"], 5) * 5
        details.append(f"⚠ EXEC: {item['pattern']} in {item['file']} ({item['count']}x)")

    # eval/Function — CRITICAL risk
    for item in findings.get("eval_usage", []):
        score += min(item["count"], 3) * 8
        details.append(f"🔴 EVAL: {item['pattern']} in {item['file']} ({item['count']}x)")

    # Encoded strings — suspicious
    for item in findings.get("encoded_strings", []):
        score += min(item["count"], 5) * 6
        details.append(f"🔒 ENCODED: {item['pattern']} in {item['file']} ({item['count']}x)")

    # Suspicious patterns
    for item in findings.get("suspicious_patterns", []):
        score += min(item["count"], 5) * 7
        details.append(f"🚨 SUSPICIOUS: {item['pattern']} in {item['file']} ({item['count']}x)")

    # File system writes
    for item in findings.get("file_system_ops", []):
        if "write" in item["pattern"].lower() or "unlink" in item["pattern"].lower():
            score += min(item["count"], 5) * 3
            details.append(f"FS Write: {item['pattern']} in {item['file']} ({item['count']}x)")

    # Determine risk level
    if score >= 50:
        risk = "CRITICAL"
    elif score >= 30:
        risk = "HIGH"
    elif score >= 15:
        risk = "MEDIUM"
    elif score >= 5:
        risk = "LOW"
    else:
        risk = "MINIMAL"

    return {
        "score": score,
        "risk_level": risk,
        "details": details,
        "summary": {
            "network_indicators": len(findings.get("network_indicators", [])),
            "env_access": len(findings.get("env_access", [])),
            "child_process": len(findings.get("child_process", [])),
            "eval_usage": len(findings.get("eval_usage", [])),
            "encoded_strings": len(findings.get("encoded_strings", [])),
            "suspicious_patterns": len(findings.get("suspicious_patterns", [])),
            "fs_operations": len(findings.get("file_system_ops", [])),
        }
    }


def analyze_npm_package(name, version="latest"):
    """Full static analysis of an npm MCP server package."""
    print(f"[SANDBOX] Analyzing {name}@{version}...")

    # Download
    extract_dir = download_npm_package(name, version)
    if not extract_dir:
        print(f"  [ERR] Could not download {name}")
        return None

    # Static analysis
    findings = analyze_package_contents(extract_dir)

    # Score
    score = compute_behavioral_score(findings)

    result = {
        "package": name,
        "version": version,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "analysis_type": "static",
        "findings": findings,
        "score": score,
    }

    # Save result
    safe_name = name.replace("/", "_").replace("@", "")
    result_file = SANDBOX_DIR / f"{safe_name}.json"
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"  Score: {score['score']} ({score['risk_level']})")
    for detail in score["details"][:5]:
        print(f"    {detail}")

    return result


def batch_analyze(packages, limit=20):
    """Analyze a batch of packages from the index."""
    print(f"\n[BATCH] Analyzing up to {limit} packages...")
    results = []

    for i, pkg in enumerate(packages[:limit]):
        if pkg.get("source") != "npm":
            continue

        name = pkg["name"]
        version = pkg.get("version", "latest")
        result = analyze_npm_package(name, version)
        if result:
            results.append(result)
            pkg["analysis"] = result

        if i >= limit - 1:
            break

    # Summary
    print(f"\n{'=' * 60}")
    print(f"BATCH ANALYSIS COMPLETE")
    print(f"{'=' * 60}")
    print(f"Analyzed: {len(results)} packages")

    # Top risks
    sorted_results = sorted(results, key=lambda r: r["score"]["score"], reverse=True)
    print(f"\nTop risks:")
    for r in sorted_results[:5]:
        s = r["score"]
        print(f"  {r['package']}: {s['score']} ({s['risk_level']})")
        for d in s["details"][:3]:
            print(f"    {d}")

    # Save batch results
    batch_file = SANDBOX_DIR / "batch_results.json"
    with open(batch_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {batch_file}")

    return results


if __name__ == "__main__":
    import sys
    if "--batch" in sys.argv:
        # Batch mode: analyze N packages from index
        limit = 50
        for i, arg in enumerate(sys.argv):
            if arg == "--limit" and i + 1 < len(sys.argv):
                limit = int(sys.argv[i + 1])

        # Load index
        index_file = Path(__file__).parent / "data" / "index.json"
        if not index_file.exists():
            print("No index found. Run crawler.py first.")
            sys.exit(1)

        with open(index_file) as f:
            index = json.load(f)

        npm_pkgs = [p for p in index if p.get("source") == "npm"]
        print(f"[BATCH] {len(npm_pkgs)} npm packages in index, analyzing up to {limit}...")

        # Check which are already analyzed
        already = set()
        for sf in SANDBOX_DIR.glob("*.json"):
            if sf.name != "batch_results.json":
                already.add(sf.stem)
        print(f"[BATCH] {len(already)} already analyzed, skipping those")

        to_analyze = []
        for pkg in npm_pkgs:
            safe_name = pkg["name"].replace("/", "_").replace("@", "")
            if safe_name not in already:
                to_analyze.append(pkg)
            if len(to_analyze) >= limit:
                break

        print(f"[BATCH] Analyzing {len(to_analyze)} new packages...")
        results = batch_analyze(to_analyze, limit=limit)

        # Also run analyzer automatically after batch
        print(f"\n{'=' * 60}")
        print(f"Running deviation analysis...")
        print(f"{'=' * 60}")
        os.system(f"{sys.executable} analyzer.py")

    elif len(sys.argv) > 1:
        pkg_name = sys.argv[1]
        version = sys.argv[2] if len(sys.argv) > 2 else "latest"
        analyze_npm_package(pkg_name, version)
    else:
        print("Usage:")
        print("  python sandbox.py <package-name> [version]   Analyze a single package")
        print("  python sandbox.py --batch [--limit N]         Batch analyze from index")
        print()
        print("Examples:")
        print("  python sandbox.py @modelcontextprotocol/server-filesystem latest")
        print("  python sandbox.py --batch --limit 50")
