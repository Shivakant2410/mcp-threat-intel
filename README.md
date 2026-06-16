# mcp-threat-intel

**Behavioral reputation layer for MCP servers.**

MCP servers connect AI agents to your filesystem, credentials, APIs, and production systems. They run with elevated permissions and minimal vetting. We built a static behavioral analyzer to find out what they actually do versus what they claim.

**882 servers indexed. 50 analyzed. 64% contact domains not mentioned in their description.**

---

## Why this exists

When you connect an MCP server, you're trusting it with everything your AI agent can touch. There is no VirusTotal for MCP. No reputation database. No behavioral history. You're flying blind.

We're building the map.

---

## Quick start

```bash
git clone https://github.com/shivakant2410/mcp-threat-intel
cd mcp-threat-intel
pip install -r requirements.txt

# Check a single package
python mcp_check.py @atomicmail/mcp-modelcontextprotocol

# Run the full crawler
python crawler.py

# Analyze a batch
python sandbox.py

# Score behavioral deviation
python analyzer.py
```

---

## What's in this repo

| File | What it does |
|---|---|
| `crawler.py` | Pulls MCP servers from npm, GitHub, Smithery, Glama |
| `sandbox.py` | Static behavioral analysis — network calls, credential access, eval usage, child process execution |
| `analyzer.py` | Scores deviation between declared capabilities and observed behavior |
| `mcp_check.py` | CLI trust score tool — run before connecting anything |
| `data/index.json` | Full 882-server index |
| `data/reports/threat_report_20260616.json` | Today's threat report |

Sandbox results (per-package JSON) are excluded to keep the repo lean. They regenerate from the index when you re-run `sandbox.py`.

---

## How scoring works

We analyze four behavioral categories and weight by severity:

| Category | Examples | Weight |
|---|---|---|
| **CRITICAL** | `eval()`, `new Function()`, `exec()`, prototype pollution, credential file access | ×10 |
| **HIGH** | Undeclared network calls, undeclared env variable access | ×5 |
| **MEDIUM** | Base64 encoded strings (obfuscation indicator) | ×2 |
| **LOW** | Standard filesystem access | ×1 |

Final score = sum of weighted hits. Threshold classification:

- **EXPLOITABLE** — score > 50
- **SUSPICIOUS** — score 20–50
- **MODERATE** — score 5–20
- **LOW RISK** — score < 5

---

## Key findings (June 16, 2026)

### @atomicmail/mcp-modelcontextprotocol — Score: 1421

Description: *"MCP server for email"*

Observed behavior:
- Connects to **14 external domains** including `eu.posthog.com` (PostHog analytics — a third party, undeclared)
- Reads and writes `credentials.json`, `session.jwt`, `capability.jwt` to `~/.atomicmail/`
- Spawns child processes — undeclared
- Uses `eval`/`new Function()` — dynamic code execution at runtime

None of this is declared in the package description.

> We notified the maintainer via responsible disclosure email on June 16, 2026 before publishing.

### mcp-use (1.32.0) — Score: 3726

Highest-scoring package in our dataset:
- WebSocket connections to external servers
- Extensive undeclared network infrastructure
- Credential access patterns
- Prototype pollution vectors

An MCP orchestration library with a wide undeclared behavioral surface.

### @iflow-mcp/matthewdailey-mcp-starter — Score: 206

It's called "mcp-starter." It ships prototype pollution and eval.

---

## What "undeclared" means

We're not claiming malice. PostHog telemetry in an email MCP server might be a lazy developer decision or intentional data harvesting. Our scoring doesn't distinguish intent — only behavior.

The gap between what an MCP server claims and what it does is the security boundary that matters. AI agents operating autonomously with elevated permissions have no way to audit this themselves.

---

## Roadmap

- [ ] Scale static analysis to full 882-server index
- [ ] Runtime sandboxing (Docker execution environment — observe live network calls)
- [ ] Rug-pull detection (behavioral diff between package versions)
- [ ] `npx mcp-check` — zero-install CLI
- [ ] API endpoint for real-time trust score queries
- [ ] Weekly threat report publication

---

## Contributing

Found a malicious MCP server? Open an issue with the package name and behavioral evidence. We'll analyze it and add it to the dataset.

Security researchers: the full sandbox analysis JSON is available on request. Email: work.shiva08@gmail.com.

---

## Responsible disclosure

If you find a package in our dataset that warrants direct disclosure, we follow standard 90-day coordinated disclosure. We notified @atomicmail before publishing this report.

---

## License

MIT. The data is yours. Use it.

---

*Built June 16, 2026 — the same day OX Security disclosed an RCE in the MCP protocol itself affecting 150M+ downloads. The timing is not a coincidence. The ecosystem needed this yesterday.*
