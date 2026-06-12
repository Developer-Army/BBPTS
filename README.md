# BBPTS v1.4.0
> **Bug Bounty Recon on Autopilot.** Point it at target domains, gather intelligence, and get prioritized, actionable findings instantly.

BBPTS automates the execution of **25+ elite penetration testing and reconnaissance tools** in a highly structured pipeline. It correlates, cleans, and deduplicates the results into a unified interactive report, scoring findings by risk severity so you know exactly where to start testing.

---

## Key Features

* **Automated Pipeline**: Orchestrates recon stages sequentially (Subdomains ➔ DNS/Ports ➔ Web Probing ➔ Vuln Scanning).
* **Setup Profiles**: Choose between **User Mode** (core tools) and **Developer Mode** (full suite + dev environments).
* **Unified Reporting**: Generates interactive HTML dashboards, structured JSON/CSV logs, and XML templates ready for Burp Suite, OWASP ZAP, and Caido.
* **Smart Scoring**: Prioritizes findings using an internal risk analyzer to highlight high-value targets.
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

| Flag | Short | Description |
| :--- | :--- | :--- |
| `-input` | `-i` | Target domains file or single URL |
| `-tools` | `-t` | Comma-separated list of specific tools to run |
| `-exclude-tools` | `-x` | Comma-separated list of tools to skip |
| `-output` | `-o` | Output file path for report |
| `-summary` | `-s` | Output file path for CSV summary |
| `--light` | | Fast passive-only scan |
| `-batch-size` | `-b` | Parallel domain scan count (default 1) |
| `-threads` | | Go worker threads (default 32) |
| `-rate-limit` | | Max requests per second limit |
| `-resume` | `-r` | Resume scan from last recorded checkpoint |
| `-doctor` | | Verify external tool availability & paths |
| `-web` | `-w` | Launch the local web dashboard |

---

## Security & Safety Notes

> **Warning**: Active scanning generates substantial network traffic. Do not run intensive scans from shared CI/CD runners (like GitHub Actions free runners) to avoid platform bans. Use a dedicated VPS.

> **Scope Control**: Ensure you have explicit authorization to scan target networks. Keep scan targets strictly within your bounty program scope.

---

## Experimental Enterprise (CTEM/ASM) Modules

BBPTS includes preview components of an enterprise-grade **Continuous Threat Exposure Management (CTEM)** and **Attack Surface Management (ASM)** platform:
* **Domain Assets & Finding Nodes**: Evolved database schemas that represent assets and vulnerability nodes in a connected graph model.
* **Asset Ownership & Teams**: Structures for tracking asset custodianship and managing security escalation contacts.
* **SLA Compliance Escalations**: Tickers and rules to track SLA compliance and automatically dispatch alerts (webhooks, email, tickets) on breaches.
* **Experimental State Machine**: The state transition logic in `internal/domain/workflows` models complete lifecycle paths (e.g. Open ➔ Assigned ➔ SLA Exception ➔ Remediated ➔ Verified) but is not yet fully integrated into CLI/TUI workflows.

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
