# Quick Start Guide - BBPTS v1.1

Get up and running with BBPTS in minutes. This guide covers installation, basic usage, and common workflows.

## Prerequisites

- Go 1.22 or later
- Git

## Installation

### Option 1: Quick Setup (Recommended)

```bash
# Clone and setup in one command
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS
bash scripts/setup.sh
go build -o bbpts ./cmd/bbpts
```

### Option 2: Manual Setup

```bash
# Clone repository
git clone https://github.com/Developer-Army/BBPTS.git
cd BBPTS

# Install Go dependencies
go mod download

# Install external tools (optional, for full functionality)
bash scripts/setup.sh

# Build binary
go build -o bbpts ./cmd/bbpts

# Verify installation
./bbpts -doctor
```

## Basic Usage

### 1. Prepare Targets

Create a `targets.txt` file with your domains:

```
example.com
api.example.com
subdomain.example.com
```

Or use CSV format for metadata:

```csv
url,scope,priority,tags,notes
example.com,in,high,web,Main target
api.example.com,in,medium,api,REST API
```

### 2. Run Basic Scan

```bash
# Simple reconnaissance
./bbpts -i targets.txt

# With output files
./bbpts -i targets.txt -output report.md -summary summary.csv
```

### 3. View Results

The scan generates:
- **Terminal Output**: Real-time progress and findings
- **Markdown Report**: Detailed analysis with prioritization
- **CSV Summary**: Structured data for import

## Common Workflows

### Bug Bounty Recon

```bash
# Full reconnaissance suite
./bbpts -i targets.txt -output results/report.md

# Focus on specific tools
./bbpts -i targets.txt -tools subfinder,httpx,nuclei

# Export to Burp Suite
./bbpts -i targets.txt -export-burp burp-import.xml
```

### Continuous Monitoring

```bash
# Monitor for new assets every hour
./bbpts -i targets.txt -scope my-program -cron 60

# Show only new findings
./bbpts -i targets.txt -scope my-program -diff
```

### Large-Scale Scanning

```bash
# Optimize for performance
./bbpts -i targets.txt -threads 50 -rate-limit 50

# Low-resource mode
./bbpts -i targets.txt -low-resource
```

## Output Examples

### Markdown Report

```markdown
# BBPTS Reconnaissance Report

## Summary
- Total Hosts Analyzed: 3
- High Priority Findings: 1

| Host | Score | Priority | Tags | Suggested Tests |
|------|-------|----------|------|-----------------|
| example.com | 25 | medium | api,parameterized | Test for SQL injection; Parameter tampering |
```

### CSV Summary

```csv
host,severity,score,tags,reasons,suggested_tests,evidence_count
example.com,medium,25,api;parameterized,API surface detected; Query string detected,Test for SQL injection; Parameter tampering,3
```

## Configuration

### Basic Configuration

Edit `configs/config.json`:

```json
{
  "rate_limit": 20,
  "threads": 32,
  "notify": {
    "discord_webhook": "https://discord.com/api/webhooks/...",
    "slack_webhook": "https://hooks.slack.com/services/..."
  }
}
```

The `-timeout` CLI flag defaults to `0`, which disables the global timeout. Set a value such as `-timeout 30m` when you want a hard run limit.

### API Keys (Optional)

Add API keys for enhanced reconnaissance:

```json
{
  "api_keys": {
    "shodan": "your-shodan-key",
    "github": "your-github-token",
    "chaos": "your-chaos-key"
  }
}
```

## Troubleshooting

### Common Issues

**"Command not found" errors:**
- Run `bash scripts/setup.sh` to install external tools
- Or use Docker: `docker run -it bbpts -doctor`

**Slow scanning:**
- Reduce threads: `-threads 10`
- Increase timeout: `-timeout 60s`
- Use low-resource mode: `-low-resource`

**No findings:**
- Check target format (should be domains or URLs)
- Verify internet connectivity
- Some tools require API keys

**Memory issues:**
- Use low-resource mode
- Reduce concurrent tools
- Process targets in batches

### Getting Help

- Check the [full documentation](README.md)
- Run `./bbpts -help` for all options
- Open an issue on GitHub
- Join our community Discord

## Next Steps

- Read the [full README](README.md) for advanced features
- Explore [configuration options](docs/CONFIG.md)
- Learn about [supported tools](docs/TOOLS.md)
- Check [development guide](docs/DEVELOPMENT.md) for contributions
```

**Report Generation:**
```bash
# Verify report output formats
go test -v ./internal/ui/report/
# Tests verify: JSON, Markdown, HTML, filtering, statistics
```

**Tool Integration:**
```bash
# Verify tool exports work
go test -v ./internal/engine/integration/
# Tests verify: Burp, Caido, ZAP, proxy rotation, webhooks
```

**Orchestration & Analysis:**
```bash
# Verify core scanning engine
go test -v ./internal/engine/recon/
go test -v ./internal/analysis/analyze/
# Tests verify: execution, concurrency, prioritization, scoring
```

### Pre-Deployment Checklist

Before using BBPTS in production:

- [ ] Run full test suite: `go test -v -race ./...`
- [ ] Check environment: `./bbpts -doctor`
- [ ] Test with example CSV: `./bbpts -input targets-example.csv`
- [ ] Verify report generation: Check `results/` directory
- [ ] Test tool export: Try `-export-burp`, `-export-caido`, `-export-zap`
- [ ] Verify notifications: Configure and test Discord/Slack/Telegram
- [ ] Test with proxy: Try `-proxies "http://localhost:8080"`

### Enhanced CSV Format

Create a `targets.csv` with rich metadata:

```csv
url,scope,priority,tags,notes
example.com,in,high,api;critical,Main API target - high priority
api.example.com,in,critical,api;internal,Critical internal API
admin.example.com,in,high,admin,Administrative panel
staging.example.com,out,low,staging;test,Staging environment - out of scope
dev.example.com,out,medium,dev;internal,Development server
```

**CSV Columns:**
- `url` (required): Target domain or URL
- `scope` (in/out): Include in scope or out of scope
- `priority` (critical/high/medium/low): Prioritization level
- `tags`: Semicolon-separated tags for organization
- `notes`: Additional context about the target

### New Features in This Release

#### 1. **Enhanced CSV Input with Metadata**
```bash
# Parse targets with metadata
./bbpts -input targets.csv
```

- Supports rich metadata fields
- Automatic scope filtering
- Priority-based targeting
- Custom tag organization

#### 2. **World-Class Report Generation**
```bash
# Generate comprehensive reports
./bbpts -input targets.csv -report-all
```

Generates:
- `report.md` - Markdown report for documentation
- `report.html` - Professional HTML report
- `report.json` - Structured JSON for integration
- `burp-import.xml` - Burp Suite compatible format
- `caido-import.json` - Caido compatible format
- `zap-import.xml` - OWASP ZAP compatible format

#### 3. **Tool Integrations**
```bash
# Export for specific tools
./bbpts -export-burp burp_config.json
./bbpts -export-caido caido_targets.txt
./bbpts -export-zap zap_report.xml
```

#### 4. **Advanced Filtering**
```bash
# Filter results by minimum risk score
./bbpts -input targets.csv -min-score 70

# Differential scanning (only show new findings)
./bbpts -input targets.csv -diff-only
```

#### 5. **Proxy and Fleet Configuration**
```bash
# With proxy rotation
./bbpts -proxies "http://proxy1:8080,http://proxy2:8080"

# With Axiom fleet (distributed scanning)
./bbpts -enable-fleet -fleet-name myfleet -fleet-size 5
```

---

## Comprehensive Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with verbose output
go test -v ./...

# Run specific test package
go test -v ./internal/core/input/...

# Run with coverage
go test -cover ./...
```

### Test Coverage

The project now includes comprehensive tests for:

- **Orchestrator** (`orchestrator_test.go`)
  - Initialization and configuration
  - Execution with timeouts
  - Concurrent tool execution
  - Rate limiting

- **State Management** (`state_test.go`)
  - Asset persistence
  - Differential scanning
  - Multi-target support

- **Input Parsing** (`parser_test.go`)
  - CSV parsing with metadata
  - Newline-separated format
  - Comment handling
  - Whitespace normalization
  - Quoted field support

- **Analysis & Insights** (`insights_integration_test.go`)
  - Insight generation
  - Priority assignment
  - Tag generation
  - Evidence accumulation

- **Tool Runners** (`tool_runner_test.go`)
  - Tool execution
  - Timeout handling
  - Concurrent operation
  - Error handling

- **Integration** (`integration_test.go`)
  - Burp Suite export
  - Caido export
  - OWASP ZAP export
  - Proxy rotation
  - Webhook notifications

- **Report Generation** (`report_generation_test.go`)
  - JSON reports
  - Markdown reports
  - HTML reports
  - Statistics calculation
  - Severity filtering

---

## Advanced Configuration

### Tool Customization

Configure tool behavior in `configs/rules.json`:

```json
{
  "tools": {
    "subfinder": {
      "timeout": 300,
      "threads": 10,
      "sources": ["all"]
    },
    "httpx": {
      "timeout": 30,
      "threads": 50,
      "verify": true
    },
    "ffuf": {
      "timeout": 60,
      "threads": 40,
      "wordlist": "custom.txt"
    }
  }
}
```

### API Key Configuration

Set API keys via environment or config:

```bash
export SHODAN_API_KEY="your_key"
export CENSYS_API_KEY="your_key"
export HUNTER_API_KEY="your_key"
```

Or in `configs/config.json`:

```json
{
  "api_keys": {
    "shodan": "your_key",
    "censys": "your_key",
    "hunter": "your_key"
  }
}
```

### Notification Configuration

Configure real-time alerts:

```json
{
  "notifications": {
    "discord": {
      "webhook_url": "https://discord.com/api/webhooks/...",
      "enabled": true,
      "min_severity": "high"
    },
    "slack": {
      "webhook_url": "https://hooks.slack.com/...",
      "enabled": true
    },
    "telegram": {
      "bot_token": "...",
      "chat_id": "...",
      "enabled": true
    }
  }
}
```

---

## Integration Workflows

### Burp Suite Integration

```bash
# Export findings for manual testing in Burp
./bbpts -input targets.csv -export-burp burp_findings.xml

# Import in Burp Suite:
# 1. Open Burp Suite
# 2. Go to Burp Menu → Import
# 3. Select burp_findings.xml
# 4. Findings will be loaded into your project
```

### Caido Integration

```bash
# Export targets for Caido
./bbpts -input targets.csv -export-caido caido_targets.json

# Import in Caido:
# 1. Open Caido
# 2. Go to Settings → Import
# 3. Select caido_targets.json
# 4. Begin manual testing
```

### OWASP ZAP Integration

```bash
# Export findings for ZAP
./bbpts -input targets.csv -export-zap zap_report.xml

# Import in ZAP:
# 1. Open OWASP ZAP
# 2. Go to File → Import Report
# 3. Select zap_report.xml
# 4. Analyze findings
```

---

## Performance Optimization

### Concurrency Settings

```bash
# High concurrency (for powerful hardware)
./bbpts -input targets.csv -threads 50

# Low concurrency (for limited resources)
./bbpts -input targets.csv -threads 5 -low-resource
```

### Rate Limiting

```bash
# 100 requests per second
./bbpts -input targets.csv -rate-limit 100

# Unlimited (use with caution)
./bbpts -input targets.csv -rate-limit 0
```

### Fleet Distribution

```bash
# Distribute across Axiom fleet
./bbpts -input targets.csv \
  -enable-fleet \
  -fleet-name bbpts-scan \
  -fleet-size 10 \
  -delete-after
```

This reduces a 10-hour scan to approximately 10 minutes across 10 instances.

---

## Troubleshooting

### No Results Found

1. Verify target format
2. Check tool installation: `./bbpts -doctor`
3. Review logs: `./bbpts -input targets.csv -debug`

### High Memory Usage

1. Reduce thread count: `-threads 5`
2. Enable low-resource mode: `-low-resource`
3. Implement rate limiting: `-rate-limit 50`

### Tool Failures

```bash
# Run diagnostics
./bbpts -doctor

# Check specific tool
go run ./cmd/bbpts -test-tool subfinder
```

---

## Best Practices

### Target Prioritization

1. **Critical**: API endpoints, admin panels, user data
2. **High**: Authentication flows, payment systems
3. **Medium**: Public-facing services
4. **Low**: Development/staging environments

### Scanning Strategy

1. Start with subdomain enumeration (subfinder, assetfinder)
2. Run web technology detection (httpx, wappalyzer)
3. Enumerate endpoints (ffuf, feroxbuster)
4. Analyze JavaScript for secrets (js_analyzer)
5. Run specialized nuclei templates
6. Manual testing in Burp/Caido

### Report Best Practices

1. Always verify findings before submission
2. Include steps to reproduce
3. Provide evidence and screenshots
4. Suggest remediation where possible
5. Format for target platform (H1, Intigriti, BugCrowd, etc.)

---

## Contributing & Development

### Adding New Tools

1. Create tool handler in `internal/engine/recon/`
2. Implement `Tool` interface
3. Add tests in `tool_test.go`
4. Register in `registry.go`

### Adding Report Exporters

1. Extend `ReportGenerator` in `internal/ui/report/`
2. Implement export method
3. Add tests in `report_generation_test.go`

---

## Documentation Structure

```
docs/
├── tools.md              # Individual tool documentation
├── Burp_integration.md   # Burp Suite integration guide
├── QUICKSTART.md         # This file
├── ARCHITECTURE.md       # System architecture
└── API.md               # API documentation
```

---

## License

BBPTS is provided as-is for authorized security testing only. Ensure you have proper authorization before testing any targets.

---

## Support

For issues, feature requests, or contributions, please refer to the project documentation and GitHub repository.
