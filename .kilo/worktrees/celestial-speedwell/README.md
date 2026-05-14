# BBPTS v1.0 (Bug Bounty Program Tool Set)

**Reconnaissance & Target Prioritization Toolkit**

BBPTS is a Go application for automating the early phases of bug bounty reconnaissance. It focuses on structured target ingestion, staged tool orchestration, prioritization, and export into manual testing workflows like Burp Suite.

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/Developer-Army/BBPTS)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Key Features

- **Robust Concurrency**: Built with a panic-recovered, semaphore-backed orchestrator capable of parallelizing 15+ external security tools safely.
- **Alerting Engine**: Notifications for **Discord, Slack, and Telegram** on higher-priority findings.
- **Distributed Fleet Support**: Optional **Axiom** integration for running supported tools across a fleet.
- **Advanced Fingerprinting**: Correlates assets using **JARM fingerprints**, favicon hashes, and SSL pattern analysis to find hidden infrastructure.
- **Structured Logging**: Native `log/slog` integration ready for CI/CD pipelines and log aggregators.
- **Intelligent Prioritization**: Computes scores, tags, and suggested tests from reconnaissance events.
- **Continuous Monitoring**: Database-backed differential scanning to identify new assets and changes between runs.
- **Scope-Aware CSV Input**: Header-based CSV imports respect `scope` metadata so out-of-scope rows are not scanned.
- **Pipeline URL Preservation**: Web URLs discovered by earlier stages remain usable by URL-dependent tools like `ffuf` and `gobuster`.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [Supported Tools](#supported-tools)
- [Output Formats](#output-formats)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

BBPTS is cross-platform and supports **Linux (Debian/RPM), macOS, and Windows**.

### linux and Mac Installation

```bash
# Clone the repository
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS

# Run the cross-platform setup (installs deps, tools, wordlists, and builds the binary)
bash scripts/setup.sh

# Alternatively, if you have 'make':
make setup

# Build the binary manually if needed 
go build -o bbpts ./cmd/bbpts

# Run diagnostics to verify your environment
./bbpts -doctor

# Verify installation
./bbpts -help
```

### Windows Installation

```batch
# Clone the repository
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS

# Run the Windows setup (installs deps, tools, and wordlists)
scripts\setup.bat

# Build the binary
go build -o bbpts.exe .\cmd\bbpts

# Run diagnostics to verify your environment
.\bbpts.exe -doctor
```

**Windows Prerequisites:**
- **Go 1.22+** (add to PATH)
- **Git Bash** or **PowerShell** for running scripts
- **Npcap/WinPcap** for network scanning tools (naabu, etc.)

**Note:** Ensure `%USERPROFILE%\go\bin` is in your PATH to access installed tools.

### Docker Installation

```bash
# Build the Docker image
docker build -t bbpts .

# Run BBPTS in Docker
docker run -v $(pwd)/results:/app/results bbpts -i targets.txt
```

---

## Quick Start

1. **Prepare your targets**: Create a `targets.txt` file with domains or URLs.

2. **Run reconnaissance**:
   ```bash
   ./bbpts -i targets.txt
   ```

3. **Generate reports**:
   ```bash
   ./bbpts -i targets.txt -output report.md -summary summary.csv
   ```

4. **Continuous monitoring**:
   ```bash
   ./bbpts -i targets.txt -scope my-program -cron 60
   ```

---

## Usage

### Command Line Options

```
Usage of ./bbpts:
  -config string
        Path to BBPTS config file (default "configs/config.json")
  -cron int
        Continuous monitoring interval (minutes)
  -debug
        Enable debug logging
  -diff
        Show only new findings
  -doctor
        Run environment diagnostics
  -export-burp string
        Export Burp Suite XML findings
  -i string
        Short for -input
  -input string
        Input file path
  -low-resource
        Optimize for weak hardware
  -obsidian string
        Obsidian note directory
  -output string
        Markdown report output path
  -port int
        Dashboard port (default 8080)
  -rate-limit int
        Max requests/second (default 20)
  -rules string
        Path to BBPTS rules file (default "configs/rules.json")
  -scope string
        Scope identifier for state tracking
  -summary string
        CSV summary output path
  -t string
        Comma-separated recon tools to run (short for -tools)
  -threads int
        Number of concurrent threads (default 32)
  -timeout duration
        Recon timeout per tool (default 30s)
  -tool string
        Comma-separated recon tools to run (short for -tools)
  -tools string
        Comma-separated recon tools to run (leave empty to run all tools)
  -tui
        Enable interactive TUI dashboard
  -w    Short for -web
  -web
        Enable local web dashboard
```

### Input Formats

BBPTS supports multiple input formats:

- **Simple list**: One domain/URL per line
- **CSV with headers**: `url,scope,priority,tags,notes`
- **JSON**: Structured target definitions

### Examples

```bash
# Basic reconnaissance
./bbpts -i targets.txt

# Generate reports
./bbpts -i targets.txt -output results/report.md -summary results/summary.csv

# Run specific tools
./bbpts -i targets.txt -tools subfinder,httpx,nuclei

# Continuous monitoring
./bbpts -i targets.txt -scope example-com -cron 60

# Export to Burp Suite
./bbpts -i targets.txt -export-burp burp-import.xml

# Enable web dashboard
./bbpts -i targets.txt -web -port 8080
```

---

## Configuration

BBPTS uses two main configuration files:

- `configs/config.json`: Main application settings
- `configs/rules.json`: Custom event-matching rules

### Config File Structure

```json
{
  "api_keys": {
    "shodan": "",
    "censys": "",
    "securitytrails": "",
    "github": "",
    "chaos": "",
    "virustotal": "",
    "passivetotal": "",
    "binaryedge": ""
  },
  "proxies": [],
  "rate_limit": 20,
  "state_dir": "./results/state",
  "wordlists_dir": "./wordlists",
  "wordlists": {
    "dns": "dns-5k.txt",
    "directory": "raft-small-files.txt",
    "subdomain": "subdomains-top1million-5000.txt",
    "api": "api-endpoints.txt"
  },
  "threads": 32,
  "timeout": "30s",
  "notify": {
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "discord_webhook": "",
    "slack_webhook": ""
  },
  "fleet": {
    "enabled": false,
    "fleet_name": "bbpts-fleet",
    "fleet_size": 10,
    "delete_after": true
  }
}
```

---

## Supported Tools

BBPTS orchestrates 15+ industry-standard reconnaissance tools:

### Subdomain Enumeration
- **Subfinder**: Passive subdomain discovery
- **Amass**: Comprehensive subdomain enumeration
- **Assetfinder**: Rapid subdomain finding
- **Puredns**: High-speed DNS resolution

### Port Scanning & Probing
- **Httpx**: Fast HTTP probing
- **Dnsx**: DNS record enumeration
- **Naabu**: Port scanning

### Content Discovery
- **Katana**: Web crawling
- **Gau**: URL collection from archives
- **Waybackurls**: Historical URL discovery
- **Hakrawler**: Fast web crawling

### Vulnerability Scanning
- **Nuclei**: Template-based vulnerability scanning
- **Dalfox**: XSS detection

### Other
- **Interactsh**: Out-of-band interaction testing
- **Anew**: Deduplication utilities
- **Gf**: Pattern matching
- **Ffuf**: Fuzzing

---

## Output Formats

BBPTS supports multiple output formats:

- **Markdown Reports**: Detailed analysis with prioritization
- **CSV Summaries**: Structured data for further processing
- **Burp Suite XML**: Direct import into Burp Scanner
- **Obsidian Notes**: Knowledge base integration
- **JSON**: Programmatic access

### Sample Markdown Report

```markdown
# BBPTS Reconnaissance Report
Generated: Mon, 01 Jan 2024 12:00:00 UTC

## Summary
- Total Hosts Analyzed: 5
- High Priority Findings: 2

| Host | Score | Priority | Tags | Suggested Tests |
|------|-------|----------|------|-----------------|
| example.com | 45 | high | api,parameterized | Test for SQL injection; Parameter tampering |
```

---

## Architecture

BBPTS follows a staged pipeline architecture:

1. **Preprocessing**: Input normalization and deduplication
2. **Passive Recon**: Subdomain enumeration, DNS analysis
3. **Active Probing**: Port scanning, HTTP fingerprinting
4. **Content Discovery**: Web crawling, URL collection
5. **Vulnerability Scanning**: Template-based testing
6. **Analysis & Reporting**: Risk scoring, prioritization

### Key Components

- **Orchestrator**: Manages tool execution and concurrency
- **Bus**: Internal event system for reactive processing
- **Analyzers**: Intelligence extraction from recon events
- **Reporters**: Multi-format output generation

---

## Documentation

For detailed documentation, see the [docs/](docs/) directory:

- **[Quick Start Guide](docs/QUICKSTART.md)**: Step-by-step setup and usage
- **[Development Guide](docs/DEVELOPMENT.md)**: Architecture, testing, and development setup
- **[Configuration Guide](docs/CONFIG.md)**: Detailed configuration options and API keys
- **[CSV Format Guide](docs/CSV_FORMAT.md)**: Input format specifications and examples
- **[Testing Guide](docs/TESTING.md)**: Testing strategy and guidelines
- **[Changelog](docs/CHANGELOG.md)**: Version history and updates

### Additional Resources

- **[Burp Suite Integration](docs/Burp_integration.md)**: Import findings into Burp Scanner
- **[Sandboxing Guide](docs/SANDBOXING.md)**: Running BBPTS in isolated environments
- **[Tools Integration](docs/tools.md)**: External tool setup and configuration

---

## Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) for details.

---

## License

BBPTS is released under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

BBPTS builds upon the excellent work of the security community:

- Project Discovery tools (subfinder, httpx, nuclei, etc.)
- OWASP Amass
- Tom Hudson's assetfinder
- And many others...

Special thanks to the bug bounty community for inspiration and feedback.

---

## Changelog

See [CHANGELOG.md](docs/CHANGELOG.md) for version history and updates.
./bbpts -help
```

### Testing

Run the test suite before using the tool in production workflows:

```bash
# Quick test (30 seconds)
make test

# Full test with race detection (2-3 minutes)
go test -v -race ./...

# See detailed testing guide
# cat TESTING.md
```

**What gets tested:**
- ✅ CSV input parsing with metadata
- ✅ Report generation (JSON, Markdown, HTML)
- ✅ Tool integrations (Burp, Caido, ZAP)
- ✅ Orchestration and concurrency
- ✅ State management and persistence
- ✅ Analysis and scoring

For comprehensive test recommendations, see [TESTING.md](TESTING.md)

### Running with Docker

For a consistent experience across all devices without installing local dependencies:

```bash
# Build the image
docker build -t bbpts .

# Run a scan
docker run --rm -v $(pwd):/app bbpts -input targets.txt -summary results/summary.csv
```

> **Note for Windows Users:** You may need to run the setup command in a terminal with administrative privileges to install system dependencies via `choco` or `scoop`. Ensure Npcap/WinPcap is installed for network scanning tools.

---

## Quick Start

### Basic Passive Scan
Run a fast, silent scan outputting to the `results` folder:
```bash
./bbpts \
  -input targets.txt \
  -tools subfinder,httpx,crtsh \
  -summary results/summary.csv
```

### Comprehensive Pipeline
Run a broader pipeline with debug logging:
```bash
./bbpts \
  -input scope.txt \
  -tools subfinder,assetfinder,crtsh,dnsx,httpx,katana,ffuf \
  -summary results/prioritized.csv \
  -output results/detailed_report.md \
  -debug \
  -threads 10
```

### Structured CSV Input
Header-based CSV files support metadata like `scope`, `priority`, `tags`, and `notes`. Rows marked `out` are skipped during scanning.

```csv
url,scope,priority,tags,notes
api.example.com,in,critical,api;auth,Primary API
staging.example.com,out,low,staging,Do not scan
```

### Configuration Files
BBPTS can read both a runtime config file and a rules file.

- `configs/config.json`: Runtime settings such as API keys, rate limit, thread count, `state_dir`, `wordlists_dir`, notifications, and fleet settings.
- `configs/rules.json`: Custom event-matching rules used for tagging and tool-trigger suggestions.

When you run BBPTS from this repository:

- If `-config` is not provided and `configs/config.json` exists, BBPTS uses that file.
- If `-rules` is not provided and `configs/rules.json` exists, BBPTS uses that file.
- Otherwise it falls back to `~/.bbpts/config.json` for runtime config and built-in default rules for rule evaluation.
- `threads` comes from the loaded config by default. The CLI only overrides it when you pass `-threads <number>`.

You can also set them explicitly:

```bash
./bbpts \
  -input targets.txt \
  -config configs/config.json \
  -rules configs/rules.json
```

Environment variables still override file-based config for supported values like API keys, proxies, rate limit, and state directory.

---

## Documentation

For deep-dive usage and advanced workflows, refer to the official documentation:
- [**Tool Integration Guide**](docs/tools.md): Details on the 15+ supported tools, API key configurations, and how to write your own Go adapters.
- [**Burp Suite Integration**](docs/Burp_integration.md): A step-by-step masterclass on piping BBPTS intelligence directly into Burp Suite Professional.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
