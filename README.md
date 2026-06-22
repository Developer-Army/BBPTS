# BBPTS v1.4.0

[![Build Status](https://github.com/Developer-Army/BBPTS/actions/workflows/ci.yml/badge.svg)](https://github.com/Developer-Army/BBPTS/actions)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Developer-Army/BBPTS)](https://golang.org)
[![Latest Release](https://img.shields.io/github/v/release/Developer-Army/BBPTS)](https://github.com/Developer-Army/BBPTS/releases)
[![License](https://img.shields.io/github/license/Developer-Army/BBPTS)](LICENSE)

> **Bug Bounty Recon on Autopilot.** Point it at target domains, gather intelligence, and get prioritized, actionable findings instantly.

BBPTS automates the execution of **25+ elite penetration testing and reconnaissance tools** in a highly structured pipeline. It correlates, cleans, and deduplicates the results into a unified interactive report, scoring findings by risk severity so you know exactly where to start testing.

![BBPTS TUI Dashboard](docs/terminal.png)

---

## Key Features

* **Automated Pipeline**: Orchestrates recon stages sequentially (Subdomains ➔ DNS/Ports ➔ Web Probing ➔ Vuln Scanning).
* **CI/CD Gating (`-ci`)**: Run headlessly in CI environments with non-zero exit code enforcement (`-fail-on`) upon finding critical items.
* **Continuous Monitoring (`-cron`)**: Execute recurring scans at custom intervals to track target changes and generate diff reports.
* **Strict Scope Control (`-scope-file`)**: Input target scope wildcard rules to filter target domains and prevent out-of-scope scanning.
* **Attack Paths**: Graph-based asset relationship visualization displaying findings and attack vectors as connected nodes.
* **CVSS 3.1 Risk Scoring**: Native implementation of CVSS 3.1 base scoring to mathematically rate and prioritize exposures.
* **Direct Platform Submission (`-submit`)**: Automatically upload verified vulnerabilities directly to HackerOne or Bugcrowd bug bounty portals.
* **Setup Profiles**: Choose between **User Mode** (core tools) and **Developer Mode** (full suite + dev environments).
* **Unified Reporting**: Generates interactive HTML dashboards, structured JSON/CSV logs, and XML templates ready for Burp Suite, OWASP ZAP, and Caido.
* **Live Notifications**: Connect webhooks to receive real-time alerts via Discord, Slack, or Telegram.

---

## Installation & Setup

BBPTS uses a profile-based setup to let you customize your environment.

### Linux / macOS

```bash
# Clone the repository
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS

# Run the setup script with your preferred profile
# Options: --user (minimal footprint) or --dev (full scan capabilities)
bash scripts/setup.sh --user

# Build the main executable
go build -o bbpts ./cmd/bbpts
sudo cp bbpts /usr/local/bin/    # System-wide installation
```

### Windows

```batch
# Clone the repository
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS

# Run the setup script with your preferred profile
# Options: --user or --dev
scripts\setup.bat --user

# Build the executable
go build -o bbpts.exe .\cmd\bbpts
```

### Docker (Containerized)

```bash
# Build the Docker image
docker build -t bbpts .

# Run a scan inside the container
docker run --rm -v $(pwd)/results:/app/results bbpts -i targets.txt
```

---

## Quick Start

### 1. Create a targets file (`targets.txt`)
```text
example.com
app.example.com
https://api.example.com
```

### 2. Execute a scan
```bash
# Run a default medium-mode scan
bbpts -i targets.txt
```

### 3. Review Results
Your scan reports are saved under the `./results/` directory:
* `report.html` — Interactive visual dashboard
* `report.json` — Structured machine-readable findings
* `summary.csv` — Tabular spreadsheet-friendly summary

---

## Scan Profiles

| Profile / Mode | Setup CLI Flag | Go Tools Installed | Additional Dependencies Checked |
| :--- | :--- | :--- | :--- |
| **User Mode** | `--user` / `-u` | All Go recon tools (Subfinder, Nuclei, HTTPX...) | None (No warnings for Docker, GCC, Make) |
| **Developer Mode** | `--dev` / `-d` | All Go recon tools | Dev environments checked (Docker, GCC, Make, Git) |

---

## Integrated Recon Stages (25+ Tools)

```
                     [ targets.txt ]
                            │
                            ▼
┌───────────────────────────────────────────────────────┐
│                    BBPTS ENGINE                       │
├───────────────────────────────────────────────────────┤
│  Stage 1: Subdomain Discovery                         │
│  └─ subfinder, amass, assetfinder, chaos, crtsh       │
├───────────────────────────────────────────────────────┤
│  Stage 2: DNS Resolving & Port Scanning               │
│  └─ dnsx, puredns, massdns, naabu                     │
├───────────────────────────────────────────────────────┤
│  Stage 3: Web Probing & Crawling                      │
│  └─ httpx, katana, gau, hakrawler, shodan, wafw00f    │
├───────────────────────────────────────────────────────┤
│  Stage 4: Fuzzing & Vulnerability Scanning            │
│  └─ nuclei, dalfox, ffuf, gobuster, feroxbuster       │
└───────────────────────────────────────────────────────┘
                            │
                            ▼
                    [ Scan Reports ]
             (HTML, JSON, CSV, Burp XML)
```

---

## CLI Flag Reference

### Core CLI Flags

| Flag | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `-input` | `-i` | Target domains file or single URL | |
| `-tools` | `-t` | Comma-separated list of specific tools to run | |
| `-exclude-tools` | `-x` | Comma-separated list of tools to skip | |
| `-output` | `-o` | Output file path for markdown report | `results/<input_name>_report.md` |
| `-summary` | `-s` | Output file path for CSV summary | `results/<input_name>_summary.csv` |
| `-light` | | Fast passive-only scan mode | `false` |
| `-full` | | Full mode: maximum coverage, heavier optional tools | `false` |
| `-mode` | | Scan mode: `light`, `medium`, or `full` | `medium` |
| `-threads` | | Go worker threads | `inherits 32 from config` |
| `-rate-limit` | | Max requests per second limit | `inherits 50 from config` |
| `-batch-size` | `-b` | Parallel domain scan count | `inherits 1 from config` |
| `-tui` | | Enable interactive TUI dashboard | `true` |
| `-web` | `-w` | Launch local web dashboard | `false` |
| `-port` | | Dashboard port | `8080` |
| `-doctor` | | Verify external tool availability & paths | `false` |
| `-resume` | `-r` | Resume scan from last recorded checkpoint | `false` |
| `-version` | `-v` | Print version information and exit | `false` |

### Advanced CLI Flags

| Flag | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `-config` | | Path to BBPTS config JSON file | `./configs/config.json` |
| `-rules` | | Path to BBPTS rules JSON file | `./configs/rules.json` |
| `-scope-file` | | Enforce target matching against wildcard scope rules | |
| `-scope` | | Scope identifier for state tracking | |
| `-diff` | | Show only new findings compared to last run | `false` |
| `-timeout` | | Overall recon timeout per tool group (0 to disable) | `0` |
| `-debug` | | Enable debug logging | `false` |
| `-log-level` | | Log level: `debug`, `info`, `warn`, `error` | `info` |
| `-log-file` | | Path to write logs | `bbpts.log` |
| `-cron` | | Continuous monitoring interval (minutes) | `0` (disabled) |
| `-obsidian` | | Destination directory for Obsidian notes | |
| `-evidence` | | Write compact JSON evidence bundle for top insights | |
| `-evidence-top` | | Max insights in evidence bundle | `25` |
| `-worker` | | Run as a distributed worker listening to the event bus | `false` |
| `-submit` | | Submit high-priority findings to configured bug bounty platform | `false` |
| `-tls`/`-https` | | Start dashboard with HTTPS/TLS | `false` |
| `-tls-cert` | | Path to TLS certificate file | |
| `-tls-key` | | Path to TLS key file | |
| `-web-ender` | | Custom research identifier tag (e.g. `H1{username}`) | |
| `-low-resource` | | Optimize CPU/memory usage for weak hardware | `false` |
| `-max-cpu-percent`| | Max CPU percentage limit | `90` |
| `-max-cpu-cores`  | | Max CPU cores limit | |
| `-max-memory-mb`  | | Max memory limit in MB | |
| `-gc-percent`     | | Go garbage collection target percentage | |
| `-preset`         | | Named tool preset from config `tool_presets` | |
| `-profile`        | | Named program profile from config `program_profiles` | |
| `-json` | `-j` | Output results in JSON format to stdout | `false` |
| `-auto-update` | | Auto-update Nuclei templates before scan | `false` |
| `-report-template`| | Path to custom Go HTML report template | |
| `-metrics` | | Enable Prometheus metrics endpoint | `false` |
| `-metrics-port` | | Prometheus metrics port | `9090` |
| `-ci` | | Run in CI mode (non-zero exit on finding discovery) | `false` |
| `-fail-on` | | Minimum severity to trigger non-zero exit in CI mode | `medium` |
| `-passive` | | Passive-only stealth mode: skips active probing | `false` |
| `-cookie` | | Custom session Cookie header to inject into 16/33 HTTP-active tools | |
| `-dry-run` | | Dry-run mode: prints CLI commands that would run without execution | `false` |
| `-asset-store`| | Path to stream live JSONL asset discoveries in real time | |
| `-export-burp` | | Export findings to Burp Suite XML format | |
| `-export-h1` | | Export HackerOne CSV format findings | |
| `-export-bc` | | Export Bugcrowd CSV format findings | |

---

## Security & Safety Notes

> **Warning**: Active scanning generates substantial network traffic. Do not run intensive scans from shared CI/CD runners (like GitHub Actions free runners) to avoid platform bans. Use a dedicated VPS.

> **Scope Control**: Ensure you have explicit authorization to scan target networks. Keep scan targets strictly within your bounty program scope.

---

## Enterprise (CTEM/ASM) Modules (Beta)

BBPTS includes production-ready components of an enterprise-grade **Continuous Threat Exposure Management (CTEM)** and **Attack Surface Management (ASM)** platform:
* **Domain Assets & Finding Nodes**: Evolved database schemas that represent assets and vulnerability nodes in a connected graph model.
* **Asset Ownership & Teams**: Structures for tracking asset custodianship and managing security escalation contacts.
* **SLA Compliance Escalations**: Tickers and rules to track SLA compliance and automatically dispatch alerts (webhooks, email, tickets) on breaches.
* **CTEM State Machine**: Native state transition validation (e.g. Open ➔ Assigned ➔ SLA Exception ➔ Remediated ➔ Verified) consolidated inside the storage engine (`ctem.go`).
* **CVSS 3.1 Calculator**: Automated base score and severity rating calculations according to the CVSS 3.1 specification.

For architecture details and to contribute to the enterprise features, see the [Developer Guide](docs/developer_guide.md).

---

## Additional Documentation

* [User Guide](docs/user_guide.md) — Detailed configuration and usage walkthroughs.
* [Developer Guide](docs/developer_guide.md) — Code architecture and contribution guidelines.
* [Containerization Roadmap](docs/CONTAINERIZATION.md) — Deploying BBPTS in Docker environments.

---

## License & Credits

* **License**: Licensed under the [MIT License](LICENSE).
* **Credits**: Built with respect for the incredible open-source creations from Project Discovery, OWASP, and the security community.
