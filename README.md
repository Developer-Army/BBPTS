# BBPTS — Bug Bounty Penetration Testing Suite

<p align="center">
  <img src="docs/terminal.gif" alt="BBPTS TUI Dashboard" width="800px" style="max-width: 100%; border-radius: 8px;" />
</p>

<p align="center">
  <a href="https://github.com/Developer-Army/BBPTS/actions"><img src="https://github.com/Developer-Army/BBPTS/actions/workflows/ci.yml/badge.svg" alt="Build Status" /></a>
  <a href="https://golang.org"><img src="https://img.shields.io/github/go-mod/go-version/Developer-Army/BBPTS" alt="Go Version" /></a>
  <a href="https://github.com/Developer-Army/BBPTS/releases"><img src="https://img.shields.io/github/v/release/Developer-Army/BBPTS" alt="Latest Release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Developer-Army/BBPTS" alt="License" /></a>
  <a href="https://github.com/Developer-Army/BBPTS"><img src="https://img.shields.io/badge/Coverage-60%25%2B-green" alt="Coverage" /></a>
</p>

> **The only recon pipeline that thinks for itself.** Point it at target domains, gather intelligence, and get prioritized, actionable findings instantly.

> **Contributing:** Want to help build or extend BBPTS? Start with [CONTRIBUTING.md](CONTRIBUTING.md). If you want proof that it finds real-world issues, read the [case study walkthrough](docs/case_study.md).

```bash
brew install developer-army/bbpts/bbpts
```

---

## What Makes BBPTS Different

| Feature | BBPTS (Go) | ReconFTW (Bash) | BBOT (Python) |
| :--- | :--- | :--- | :--- |
| **Runtime** | Single compiled binary, no interpreter | Heavy dependencies, shell scripts | Python interpreter, virtualenvs |
| **Interface** | Live TUI + Local Web Dashboard | Raw terminal stdout logs | Terminal CLI / JSON outputs |
| **FP Filtering** | Body-fingerprinted active filtering | Grep/heuristic-based | Signature-based checks |
| **Bounty Native** | Direct H1/Bugcrowd program & scope loader | Manual text file list input | Text files / custom integrations |

---

## Install in 30 Seconds

### macOS
```bash
brew tap developer-army/bbpts
brew install bbpts
```

### Linux
```bash
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS && go build -o bbpts ./cmd/bbpts
```

### Docker
```bash
docker pull ghcr.io/developer-army/bbpts:latest
docker run --rm -v $(pwd)/results:/app/results ghcr.io/developer-army/bbpts -i targets.txt
```

---

## Quick Start

### 1. Create a Target List (`targets.txt`)
```text
example.com
https://api.example.com
```

### 2. Run the Suite
```bash
bbpts -i targets.txt
```

### 3. Output
Your reports are automatically generated under the `./results/` folder:
- `report.html` — Interactive visual dashboard
- `report.json` — Structured machine-readable findings

---

## Visual Pipeline Diagram

```
[ Targets Input ] ➔ [ Stage 1: Subdomain Discovery ] (subfinder, amass, assetfinder, chaos)
                          │
                          ▼
                    [ Stage 2: DNS & Port Scanning ] (dnsx, puredns, naabu)
                          │
                          ▼
                    [ Stage 3: HTTP & Web Probing ] (httpx, katana, gau, shodan)
                          │
                          ▼
                    [ Stage 4: Fuzzing & Vuln Scanning ] (nuclei, dalfox, cors, default_creds)
                          │
                          ▼
                    [ Interactive HTML/JSON Reports ]
```

---

## Integrated Tools

BBPTS aggregates and correlates output from the best open-source security tools:
* **Asset Discovery**: `subfinder`, `amass`, `assetfinder`, `chaos`, `crtsh`, `github`
* **Network Scan**: `naabu`, `dnsx`, `puredns`, `massdns`
* **Web Recon**: `httpx`, `katana`, `gau`, `hakrawler`, `shodan`, `wafw00f`, `gowitness`
* **Vuln Checkers**: `nuclei`, `dalfox`, `ffuf`, `gobuster`, `feroxbuster`, `trufflehog`, `cors`, `jwt_analyzer`, `bypass403`, `firebase_recon`, `mass_assignment`, `source_map`, `default_creds`

---

## CLI Flag Reference

### Core CLI Flags

| Flag | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `-input` | `-i` | Target domains file or single URL | |
| `-tools` | `-t` | Comma-separated list of specific tools to run | |
| `-mode` | | Scan mode: `light`, `medium`, or `full` | `medium` |
| `-threads` | | Go worker threads | `32` |
| `-rate-limit` | | Max requests per second limit | `50` |
| `-tui` | | Enable interactive TUI dashboard | `true` |
| `-web` | `-w` | Launch local web dashboard | `false` |
| `-port` | | Dashboard port | `8080` |
| `-doctor` | | Verify external tool availability & paths | `false` |

---

## Security & Safety Notes

> [!WARNING]
> Active scanning generates substantial network traffic. Ensure you have explicit authorization to scan target networks and keep targets strictly within program scope boundaries.
