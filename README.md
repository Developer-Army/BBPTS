# BBPTS v1.1.2

> **Bug Bounty recon on autopilot.** Point it at targets, get prioritized findings.

[![Version](https://img.shields.io/badge/version-1.1.2-blue.svg)](https://github.com/Developer-Army/BBPTS)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://golang.org/)
[![Build Status](https://github.com/Developer-Army/BBPTS/workflows/CI/badge.svg)](https://github.com/Developer-Army/BBPTS/actions)

![BBPTS TUI Demo](docs/terminal.png)

---

## What Is This?

BBPTS runs **25+ recon tools** automatically, in the right order, and gives you a **prioritized report** — no bash scripts, no manual piping.

**You give it domains → It gives you findings ranked by severity.**

### Why Use BBPTS?

| Problem                           | BBPTS Solution                              |
| --------------------------------- | ------------------------------------------- |
| Running tools one by one          | Runs 25+ tools in parallel, automatically   |
| Forgetting which tools to run     | Pre-built scan modes (light / full)         |
| Messy output from different tools | Unified reports (HTML, JSON, Burp/ZAP/Caido XML) |
| No idea what to test first        | Scores and ranks findings by risk           |
| Alerts for critical stuff         | Discord / Slack / Telegram notifications    |

---

## Install

### 🐧 Linux / macOS

```bash
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS
bash scripts/setup.sh
go build -o bbpts ./cmd/bbpts
sudo cp bbpts /usr/local/bin/    # system-wide
# OR
cp bbpts ~/.local/bin/            # user-only (add ~/.local/bin to PATH)

bbpts -doctor    # verify everything works
```

### 🪟 Windows

```batch
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS
scripts\setup.bat
go build -o bbpts.exe .\cmd\bbpts
.\bbpts.exe -doctor
```

> **Need:** Go 1.22+, Git, and Npcap (for network scanning)

### 🐳 Docker

```bash
docker build -t bbpts .
docker run --rm -v $(pwd)/results:/app/results bbpts -i targets.txt
```

### Other Methods

```bash
# Using Make
make install-user    # builds + copies to ~/.local/bin
make install         # builds + copies to /usr/local/bin (needs sudo)

# Using go install
go install github.com/Developer-Army/BBPTS/cmd/bbpts@latest
git clone https://github.com/Developer-Army/BBPTS.git && cd BBPTS && bash scripts/setup.sh
```

---

## Quick Start

### 1. Create a targets file

```
example.com
app.example.com
https://api.example.com
```

### 2. Run a scan

```bash
bbpts -i targets.txt              # default scan (medium mode)
```

### 3. Check results

Reports land in `./results/`:

- `report.html` — full interactive report
- `summary.csv` — spreadsheet-friendly
- `report.json` — machine-readable

**That's it.** Three steps.

---

## Common Commands

```bash
# Light scan (fast, passive only)
bbpts -i targets.txt --light

# Full scan (everything, takes longer)
bbpts -i targets.txt --full

# Pick specific tools
bbpts -i targets.txt -t subfinder,httpx,nuclei

# Skip specific tools
bbpts -i targets.txt -x nuclei,dalfox

# Scan multiple domains in parallel
bbpts -i targets.txt -b 5

# Custom report output
bbpts -i targets.txt -o results/report.md -s results/summary.csv

# Export for Burp Suite
bbpts -i targets.txt -export-burp burp-import.xml

# Continuous monitoring (re-scan every 60 min)
bbpts -i targets.txt -scope my-program -cron 60

# Resume interrupted scan
bbpts -i targets.txt -resume

# JSON output (pipe to jq, scripts, etc.)
bbpts -i targets.txt -json | jq '.[] | select(.priority == "high")'

# Only show changes since last scan
bbpts -i targets.txt -scope my-program -diff

# Interactive config wizard
bbpts init

# Check tool health
bbpts -doctor
```

---

## Scan Modes

| Mode       | Flag        | What It Does                                | Speed   |
| ---------- | ----------- | ------------------------------------------- | ------- |
| **Light**  | `--light`   | Passive recon only (subdomains, DNS, WHOIS) | ⚡ Fast |
| **Normal** | _(default)_ | Passive + active probing + crawling         |

---

## Supported Tools (25+)

### Stage 1 — Subdomain Discovery

`subfinder` · `amass` · `assetfinder` · `findomain` · `chaos` · `crtsh` · `whois` · `tlsx` · `github`

### Stage 2 — DNS & Ports

`dnsx` · `puredns` · `massdns` · `naabu`

### Stage 3 — Web Probing & Crawling

`httpx` · `katana` · `gau` · `hakrawler` · `shodan` · `wafw00f` · `gowitness` · `trufflehog` · `uro` · `graphql` · `browser`

### Stage 4 — Vuln Scanning & Fuzzing

`nuclei` · `dalfox` · `ffuf` · `gobuster` · `feroxbuster` · `interactsh` · `secrets` · `js_analyzer`

---

## Configuration

### Config Wizard (easiest)

```bash
bbpts init
```

Walks you through setting up API keys, rate limits, and notifications interactively.

### Manual Config

Edit `configs/config.json`:

```jsonc
{
  "api_keys": {
    "shodan": "YOUR_KEY", // get from shodan.io
    "github": "YOUR_TOKEN", // GitHub personal access token
    "chaos": "YOUR_KEY", // projectdiscovery.io
    "virustotal": "YOUR_KEY", // virustotal.com
  },
  "rate_limit": 50, // global max requests/sec
  "threads": 32, // parallel workers
  "ports": "", // custom naabu ports (empty = defaults)
  "batch_size": 1, // domains scanned in parallel (1 = sequential)
  "auto_update": false, // auto-update nuclei templates
  "notify": {
    "discord_webhook": "", // get from Discord server settings
    "slack_webhook": "", // get from Slack app config
    "telegram_bot_token": "", // @BotFather on Telegram
    "telegram_chat_id": "", // your chat ID
  },
}
```

### Environment Variables (alternative)

```bash
export BBPTS_SHODAN_API_KEY=your_key
export BBPTS_GITHUB_TOKEN=your_token
export BBPTS_RATE_LIMIT=30
```

---

## Output Formats

| Format         | File                | Use Case                     |
| -------------- | ------------------- | ---------------------------- |
| **HTML**       | `report.html`       | Visual report with charts    |
| **Markdown**   | `report.md`         | Documentation / notes        |
| **CSV**        | `summary.csv`       | Spreadsheets / data analysis |
| **JSON**       | `report.json`       | Scripts / automation         |
| **Burp XML**   | `burp_export.xml`   | Import into Burp Suite       |
| **ZAP XML**    | `zap_export.xml`    | Import into OWASP ZAP        |
| **Caido JSON** | `caido_export.json` | Import into Caido            |

---

## CLI Flags Reference

| Flag               | Short | Description                                              |
| ------------------ | ----- | -------------------------------------------------------- |
| `-input`           | `-i`  | Target file or URL                                       |
| `-tools`           | `-t`  | Comma-separated tools to run                             |
| `-exclude-tools`   | `-x`  | Tools to skip                                            |
| `-output`          | `-o`  | Report output path                                       |
| `-summary`         | `-s`  | CSV summary path                                         |
| `--light`          |       | Fast passive scan                                        |
| `-batch-size`      | `-b`  | Parallel domain batches                                  |
| `-threads`         |       | Worker threads (default 32)                              |
| `-rate-limit`      |       | Max requests/sec                                         |
| `-log-level`       |       | `debug` / `info` / `warn` / `error`                      |
| `-resume`          | `-r`  | Resume scan from checkpoint (tracks targets by `-scope`) |
| `-json`            | `-j`  | JSON output to stdout                                    |
| `-auto-update`     |       | Update nuclei templates first                            |
| `-report-template` |       | Custom Go template file                                  |
| `-scope`           |       | Scope ID for state & checkpoint tracking                 |
| `-diff`            |       | Show only new findings                                   |
| `-cron`            |       | Re-scan interval (minutes)                               |
| `-doctor`          |       | Check tool health                                        |
| `-submit`          |       | Submit findings to platform                              |
| `-https`           |       | Start dashboard with HTTPS/TLS                           |
| `-tls-cert`        |       | Path to TLS certificate file                             |
| `-tls-key`         |       | Path to TLS key file                                     |
| `-web-ender`       |       | Custom research identifier tag (e.g. H1{username})       |
| `-export-burp`     |       | Export Burp Suite XML                                    |
| `-web`             | `-w`  | Start web dashboard                                      |
| `-debug`           |       | Debug logging                                            |
| `-version`         | `-v`  | Print version                                            |

---

## Architecture

```
targets.txt
    │
    ▼
┌─────────────────────────────────────┐
│           BBPTS Engine              │
│                                     │
│  Stage 1: Subdomain Discovery       │
│  Stage 2: DNS + Port Scanning       │
│  Stage 3: Web Probing + Crawling    │
│  Stage 4: Vuln Scanning + Fuzzing   │
│                                     │
│  ┌──────────┐  ┌──────────┐        │
│  │ Analyzer │  │ Reporter │        │
│  └──────────┘  └──────────┘        │
└─────────────────────────────────────┘
    │
    ▼
results/
├── report.html
├── summary.csv
├── report.json
└── burp_export.xml
```

---

## Safety Notes

> ⚠️ **Don't run from GitHub Actions shared runners.** Active scanning tools generate real network traffic. Use a VPS or self-hosted runner.

> ⚠️ **Submission is off by default.** Use the `-submit` flag to submit high-priority findings to configured platforms.

---

## Docs

| Document                                     | What It Covers                   |
| -------------------------------------------- | -------------------------------- |
| [User Guide](docs/user_guide.md)             | Setup, examples, troubleshooting |
| [Developer Guide](docs/developer_guide.md)   | Architecture, contributing       |
| [Configuration](docs/configuration.md)       | All config options explained     |
| [Containerization](docs/CONTAINERIZATION.md) | Docker usage + roadmap           |
| [Changelog](CHANGELOG.md)                    | Version history                  |

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [Developer Guide](docs/developer_guide.md).

## License

MIT — see [LICENSE](LICENSE).

## Credits

Built on top of amazing open-source tools by Project Discovery, OWASP, Tom Hudson, and the bug bounty community. 🙏
