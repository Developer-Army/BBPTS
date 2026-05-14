# BBPTS Usage Guide

## Quick Start

```bash
# Build
make build

# Check your environment
make doctor

# Validate config
make validate

# Basic scan
./bbpts -input targets.txt -tools subfinder,httpx,nuclei
```

## Common Workflows

### 1. Light Mode Recon (Fast, Minimal)
```bash
./bbpts -input targets.txt -light
```
This automatically selects passive tools (subfinder, crtsh, httpx) and writes
organized pipeline artifacts to `results/`.

### 2. Full Recon Pipeline
```bash
./bbpts -input targets.txt \
  -tools subfinder,assetfinder,crtsh,httpx,naabu,katana,gau,ffuf,nuclei \
  -threads 20 \
  -rate 50 \
  -output results/full_report.md
```

### 3. Continuous Monitoring
```bash
./bbpts -input targets.txt \
  -tools subfinder,httpx,nuclei \
  -scope hackerone-program \
  -cron 60 \
  -diff
```
Runs every 60 minutes and only reports **new** findings compared to the last run.

### 4. Low Resource Mode
```bash
./bbpts -input targets.txt \
  -tools subfinder,httpx \
  -low-resource \
  -threads 2
```
Batches targets in groups of 20, limits threads, and forces garbage collection
between batches.

### 5. Distributed Worker Mode
```bash
# Start NATS server
nats-server -js

# Start worker nodes
./bbpts -worker

# Run orchestrator
./bbpts -input targets.txt -tools subfinder,httpx,nuclei
```

### 6. With TUI Dashboard
```bash
./bbpts -input targets.txt \
  -tools subfinder,httpx,nuclei \
  -tui
```

### 7. With Web Dashboard
```bash
./bbpts -input targets.txt \
  -tools subfinder,httpx,nuclei \
  -dashboard -dashboard-port 8080
```

## Configuration

### Config File (`configs/config.json`)
```json
{
  "api_keys": {
    "shodan": "YOUR_SHODAN_KEY",
    "chaos": "YOUR_CHAOS_KEY"
  },
  "proxies": ["socks5://127.0.0.1:9050"],
  "rate_limit": 50,
  "threads": 32,
  "wordlists_dir": "./wordlists",
  "notify": {
    "discord_webhook": "https://discord.com/api/webhooks/..."
  },
  "event_bus": {
    "type": "in-memory"
  }
}
```

### Environment Variables
```bash
export BBPTS_SHODAN_API_KEY=your_key
export BBPTS_CHAOS_API_KEY=your_key
export BBPTS_PROXIES=socks5://127.0.0.1:9050
export BBPTS_RATE_LIMIT=100
```

## Tool Presets

| Preset    | Tools                                        | Use Case            |
|-----------|----------------------------------------------|---------------------|
| `light`   | subfinder, crtsh, httpx                      | Quick passive recon |
| `passive` | subfinder, assetfinder, crtsh, chaos, whois  | Full passive enum   |
| `web`     | httpx, katana, gau, ffuf, nuclei             | Web app testing     |
| `full`    | All available tools                          | Comprehensive scan  |

## Output Formats

BBPTS automatically generates multiple report formats in the `results/` directory:

| Format          | File                    | Use Case                    |
|-----------------|-------------------------|-----------------------------|
| Markdown        | `report.md`             | Human-readable findings     |
| HTML            | `report.html`           | Browser-viewable report     |
| JSON            | `report.json`           | API integration             |
| CSV             | `summary.csv`           | Spreadsheet analysis        |
| Burp Suite XML  | `burp_export.xml`       | Import into Burp            |
| Caido Targets   | `caido_targets.txt`     | Import into Caido           |
| ZAP Report      | `zap_report.xml`        | Import into OWASP ZAP       |

## Diagnostics

### Doctor Command
```bash
make doctor
# or
./bbpts -doctor
```
Checks:
- All recon tool binaries available in PATH
- Tool versions
- DNS resolution
- System resources (CPU, memory)
- Required dependencies (git, curl, python3)

### Config Validation
```bash
make validate
# or
./bbpts -validate-config
```
Validates:
- Thread count ranges
- Rate limit sanity
- Proxy URL formats
- API key presence
- Fleet configuration
- Event bus settings
- Database configuration
- Notification settings

## Performance Tuning

### For Large Target Lists (1000+)
```bash
./bbpts -input large_targets.txt \
  -tools subfinder,httpx \
  -threads 50 \
  -rate 200 \
  -low-resource
```

### For Stealthy Scanning
```bash
./bbpts -input targets.txt \
  -tools subfinder,httpx,nuclei \
  -threads 5 \
  -rate 10
```
Uses built-in browser fingerprinting, proxy rotation, and human-like timing
to minimize WAF detection.

## Architecture

```
bbpts
├── cmd/bbpts/          # CLI entrypoint
├── internal/
│   ├── application/    # Business logic (tools, orchestrator, cache, retry)
│   ├── domain/         # Domain models (events, rules, analysis)
│   ├── infrastructure/ # External concerns (network, storage, telemetry)
│   ├── interfaces/     # Adapters (CLI, TUI, workers, web dashboard)
│   └── shared/         # Cross-cutting (config, input parsing, normalization)
├── configs/            # Configuration files
├── scripts/            # Setup and utility scripts
└── results/            # Scan output directory
```
