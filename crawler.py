"""
MCP Threat Intelligence Crawler
Pulls MCP server metadata from npm, GitHub, Smithery, Glama.
Builds the initial index — every public MCP server, its metadata, and claims.
"""

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

DATA_DIR = Path(__file__).parent / "data"
RAW_DIR = DATA_DIR / "raw"
INDEX_FILE = DATA_DIR / "index.json"

# Ensure dirs
RAW_DIR.mkdir(parents=True, exist_ok=True)


def fetch_json(url, timeout=30):
    """Fetch JSON from a URL with error handling."""
    try:
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "MCP-ThreatIntel/0.1 (research)"
        })
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"  [ERR] {url}: {e}")
        return None


def fetch_html(url, timeout=30):
    """Fetch HTML from a URL."""
    try:
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "MCP-ThreatIntel/0.1 (research)"
        })
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"  [ERR] {url}: {e}")
        return None


# ============================================================
# NPM CRAWLER — @modelcontextprotocol/* and MCP-related packages
# ============================================================

def crawl_npm_scoped():
    """Crawl all packages under @modelcontextprotocol scope on npm."""
    print("[NPM] Crawling @modelcontextprotocol scope...")
    packages = []

    # Get all packages in the scope
    url = "https://registry.npmjs.org/-/v1/search?text=@modelcontextprotocol&size=250"
    data = fetch_json(url)
    if not data:
        return packages

    for obj in data.get("objects", []):
        pkg = obj.get("package", {})
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        description = pkg.get("description", "")
        links = pkg.get("links", {})
        repo = links.get("repository", "")
        npm_url = links.get("npm", "")
        date = pkg.get("date", "")
        keywords = pkg.get("keywords", [])
        author = pkg.get("author", {})

        entry = {
            "source": "npm",
            "name": name,
            "version": version,
            "description": description,
            "repository": repo,
            "npm_url": npm_url,
            "published_date": date,
            "keywords": keywords,
            "author": author.get("name", "") if isinstance(author, dict) else str(author),
            "crawled_at": datetime.now(timezone.utc).isoformat(),
        }
        packages.append(entry)

    print(f"  [NPM] Found {len(packages)} @modelcontextprotocol packages")
    return packages


def crawl_npm_keyword(keyword="mcp-server", size=250):
    """Crawl npm for packages matching a keyword."""
    print(f"[NPM] Crawling keyword '{keyword}'...")
    packages = []

    url = f"https://registry.npmjs.org/-/v1/search?text={keyword}&size={size}"
    data = fetch_json(url)
    if not data:
        return packages

    for obj in data.get("objects", []):
        pkg = obj.get("package", {})
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        description = pkg.get("description", "")
        links = pkg.get("links", {})
        repo = links.get("repository", "")
        npm_url = links.get("npm", "")
        date = pkg.get("date", "")
        keywords = pkg.get("keywords", [])

        entry = {
            "source": "npm",
            "name": name,
            "version": version,
            "description": description,
            "repository": repo,
            "npm_url": npm_url,
            "published_date": date,
            "keywords": keywords,
            "crawled_at": datetime.now(timezone.utc).isoformat(),
        }
        packages.append(entry)

    print(f"  [NPM] Found {len(packages)} packages for '{keyword}'")
    return packages


def get_npm_package_detail(name):
    """Get full metadata for a specific npm package including all versions."""
    url = f"https://registry.npmjs.org/{name}"
    data = fetch_json(url)
    if not data:
        return None

    versions = list(data.get("versions", {}).keys())
    latest = data.get("dist-tags", {}).get("latest", "")
    time_info = data.get("time", {})

    # Get dependencies and scripts for latest version
    latest_data = data.get("versions", {}).get(latest, {})
    deps = list(latest_data.get("dependencies", {}).keys())
    scripts = latest_data.get("scripts", {})
    main_file = latest_data.get("main", "")
    license = latest_data.get("license", "")

    # Count maintainers
    maintainers = data.get("maintainers", [])

    return {
        "all_versions": versions,
        "latest_version": latest,
        "dependencies": deps,
        "scripts": scripts,
        "main_file": main_file,
        "license": license,
        "maintainers": [m.get("name", "") if isinstance(m, dict) else str(m) for m in maintainers],
        "created": time_info.get("created", ""),
        "modified": time_info.get("modified", ""),
        "version_count": len(versions),
    }


# ============================================================
# GITHUB CRAWLER — MCP server repositories
# ============================================================

def crawl_github_topics():
    """Crawl GitHub for repositories tagged with MCP-related topics."""
    print("[GITHUB] Crawling MCP-related repositories...")
    packages = []

    queries = [
        "mcp-server",
        "model-context-protocol",
        "mcp-tool",
    ]

    for query in queries:
        url = f"https://api.github.com/search/repositories?q={query}+in:name,description&sort=stars&order=desc&per_page=100"
        data = fetch_json(url)
        if not data:
            continue

        for repo in data.get("items", []):
            entry = {
                "source": "github",
                "name": repo.get("full_name", ""),
                "description": repo.get("description", "") or "",
                "repository": repo.get("html_url", ""),
                "stars": repo.get("stargazers_count", 0),
                "forks": repo.get("forks_count", 0),
                "language": repo.get("language", ""),
                "topics": repo.get("topics", []),
                "created_at": repo.get("created_at", ""),
                "updated_at": repo.get("updated_at", ""),
                "license": (repo.get("license") or {}).get("spdx_id", "") if repo.get("license") else "",
                "open_issues": repo.get("open_issues_count", 0),
                "crawled_at": datetime.now(timezone.utc).isoformat(),
            }
            packages.append(entry)

        time.sleep(2)  # Rate limit

    # Deduplicate by repo full_name
    seen = set()
    unique = []
    for p in packages:
        if p["name"] not in seen:
            seen.add(p["name"])
            unique.append(p)

    print(f"  [GITHUB] Found {len(unique)} unique repositories")
    return unique


# ============================================================
# SMITHERY CRAWLER — MCP server registry
# ============================================================

def crawl_smithery():
    """Crawl Smithery.ai MCP server registry."""
    print("[SMITHERY] Crawling registry...")
    packages = []

    # Smithery has an API endpoint
    url = "https://registry.smithery.ai/servers"
    data = fetch_json(url)
    if data:
        if isinstance(data, list):
            for server in data:
                entry = {
                    "source": "smithery",
                    "name": server.get("name", server.get("qualifiedName", "")),
                    "description": server.get("description", ""),
                    "repository": server.get("repository", {}).get("url", "") if isinstance(server.get("repository"), dict) else server.get("repository", ""),
                    "downloads": server.get("downloads", 0),
                    "crawled_at": datetime.now(timezone.utc).isoformat(),
                }
                packages.append(entry)
        elif isinstance(data, dict):
            servers = data.get("servers", data.get("results", []))
            for server in servers:
                entry = {
                    "source": "smithery",
                    "name": server.get("name", server.get("qualifiedName", "")),
                    "description": server.get("description", ""),
                    "repository": server.get("repository", {}).get("url", "") if isinstance(server.get("repository"), dict) else server.get("repository", ""),
                    "downloads": server.get("downloads", 0),
                    "crawled_at": datetime.now(timezone.utc).isoformat(),
                }
                packages.append(entry)

    # Fallback: try HTML scraping if API fails
    if not packages:
        print("  [SMITHERY] API failed, trying web scrape...")
        html = fetch_html("https://smithery.ai/explore")
        if html:
            soup = BeautifulSoup(html, "html.parser")
            # Look for server cards/links
            links = soup.find_all("a", href=re.compile(r"/servers/"))
            for link in links:
                name = link.get_text(strip=True)
                href = link.get("href", "")
                if name and href:
                    packages.append({
                        "source": "smithery",
                        "name": name,
                        "smithery_url": f"https://smithery.ai{href}",
                        "crawled_at": datetime.now(timezone.utc).isoformat(),
                    })

    print(f"  [SMITHERY] Found {len(packages)} servers")
    return packages


# ============================================================
# GLAMA CRAWLER — MCP server registry
# ============================================================

def crawl_glama():
    """Crawl Glama.ai MCP server registry."""
    print("[GLAMA] Crawling registry...")
    packages = []

    url = "https://glama.ai/mcp/servers"
    html = fetch_html(url)
    if not html:
        return packages

    soup = BeautifulSoup(html, "html.parser")
    # Glama lists servers in cards/table
    # Look for JSON-LD or structured data
    scripts = soup.find_all("script", type="application/ld+json")
    for script in scripts:
        try:
            data = json.loads(script.string)
            if isinstance(data, list):
                for item in data:
                    packages.append({
                        "source": "glama",
                        "name": item.get("name", ""),
                        "description": item.get("description", ""),
                        "url": item.get("url", ""),
                        "crawled_at": datetime.now(timezone.utc).isoformat(),
                    })
        except (json.JSONDecodeError, TypeError):
            pass

    # Also try finding server links
    links = soup.find_all("a", href=re.compile(r"/mcp/servers/"))
    seen_names = {p["name"] for p in packages}
    for link in links:
        name = link.get_text(strip=True)
        href = link.get("href", "")
        if name and name not in seen_names and href:
            packages.append({
                "source": "glama",
                "name": name,
                "glama_url": f"https://glama.ai{href}",
                "crawled_at": datetime.now(timezone.utc).isoformat(),
            })
            seen_names.add(name)

    print(f"  [GLAMA] Found {len(packages)} servers")
    return packages


# ============================================================
# INDEX BUILDER — Merge all sources into unified index
# ============================================================

def build_index(all_packages):
    """Merge all crawled packages into a unified index, deduplicating by name+source."""
    index = {}
    for pkg in all_packages:
        key = f"{pkg['source']}:{pkg['name']}"
        if key not in index:
            index[key] = pkg
        else:
            # Merge — prefer richer data
            existing = index[key]
            for k, v in pkg.items():
                if v and not existing.get(k):
                    existing[k] = v

    return list(index.values())


def enrich_npm_packages(packages, detail_limit=50):
    """Enrich npm packages with detailed metadata (deps, scripts, versions)."""
    print(f"[ENRICH] Getting details for up to {detail_limit} npm packages...")
    enriched = 0
    for pkg in packages:
        if pkg["source"] != "npm" or enriched >= detail_limit:
            continue
        name = pkg["name"]
        print(f"  [ENRICH] {name}...")
        detail = get_npm_package_detail(name)
        if detail:
            pkg.update(detail)
            enriched += 1
        time.sleep(0.5)  # Be gentle on npm registry
    print(f"  [ENRICH] Enriched {enriched} packages")
    return packages


def run_full_crawl(enrich=True):
    """Run the complete crawl across all sources."""
    print("=" * 60)
    print("MCP THREAT INTELLIGENCE — FULL CRAWL")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    all_packages = []

    # NPM
    all_packages.extend(crawl_npm_scoped())
    all_packages.extend(crawl_npm_keyword("mcp-server", size=250))
    all_packages.extend(crawl_npm_keyword("mcp tool", size=100))

    # GitHub
    all_packages.extend(crawl_github_topics())

    # Smithery
    all_packages.extend(crawl_smithery())

    # Glama
    all_packages.extend(crawl_glama())

    # Build unified index
    print(f"\n[BUILD] Total raw entries: {len(all_packages)}")
    index = build_index(all_packages)
    print(f"[BUILD] Deduplicated index: {len(index)}")

    # Enrich npm packages with details
    if enrich:
        index = enrich_npm_packages(index, detail_limit=30)

    # Save raw index
    INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2, default=str)
    print(f"\n[SAVE] Index saved to {INDEX_FILE}")
    print(f"[SAVE] {len(index)} entries")

    return index


def run_quick_crawl():
    """Quick crawl — just npm scoped packages + keyword, no enrichment.
    For the 'tonight' validation test."""
    print("=" * 60)
    print("MCP THREAT INTELLIGENCE — QUICK CRAWL (validation)")
    print("=" * 60)

    all_packages = []
    all_packages.extend(crawl_npm_scoped())
    all_packages.extend(crawl_npm_keyword("mcp-server", size=50))

    index = build_index(all_packages)

    # Quick enrich top 20
    index = enrich_npm_packages(index, detail_limit=20)

    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2, default=str)
    print(f"\n[SAVE] Quick index: {len(index)} entries → {INDEX_FILE}")

    return index


if __name__ == "__main__":
    import sys
    if "--quick" in sys.argv:
        run_quick_crawl()
    else:
        run_full_crawl()
