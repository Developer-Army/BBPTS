# BBPTS Tool Integration Guide

The BBPTS (Bug Bounty Program Tool Set) utilizes a modular adapter pattern (`internal/recon/registry.go`) to interface with industry-standard security tools. Each tool runs within an isolated, panic-recovered goroutine to guarantee orchestrator stability in production.

## Core Integrations

### Passive Discovery (OSINT & Historical)
These tools are safe to run against any in-scope target without generating significant traffic to the target infrastructure.

| Tool | Focus Area | Registry Key |
|------|------------|--------------|
| **Subfinder** | Subdomain discovery via passive sources | `subfinder` |
| **Assetfinder** | GitHub and source code reconnaissance | `assetfinder` |
| **Amass** | Deep subdomain mapping | `amass` |
| **Crt.sh** | Certificate Transparency log parsing | `crtsh` |
| **Waybackurls** | Historical endpoint and parameter mining | `waybackurls` |
| **Gau** | Get All URLs (AlienVault, Wayback, CommonCrawl) | `gau` |

### Active Probing (Network & Web)
These tools interact directly with the target infrastructure. Use with caution and respect rate limits.

| Tool | Focus Area | Registry Key |
|------|------------|--------------|
| **HTTPX** | Live service fingerprinting & status checks | `httpx` |
| **DNSx** | Bulk DNS resolution and record extraction | `dnsx` |
| **Katana** | Modern JavaScript web crawling | `katana` |
| **Naabu** | Fast port scanning | `naabu` |
| **FFUF** | Advanced web fuzzing | `ffuf` |
| **Hakrawler**| Lightweight web crawling | `hakrawler` |

---

## Configuration & Tuning

### Enterprise Logging
BBPTS uses `log/slog` for structured logging. When integrating BBPTS into automated scanning pipelines (e.g., GitHub Actions, Jenkins), use the `-json` flag:

```bash
./bbpts -input scope.txt -tools httpx,dnsx -json 2> scan_logs.json
```

### Concurrency Management
Control the thread pool utilizing the `-threads` flag. For environments with strict resource limits, drop threads down to `1` or `2`. For high-throughput cloud environments, scale up to `16+`.

```bash
# High-performance cloud scan
./bbpts -input scope.txt -tools all -threads 16
```

---

## Developing Custom Tool Adapters

BBPTS is designed to be easily extensible. To integrate a new internal or custom open-source tool, you must implement the `Tool` interface.

1. **Create the Adapter:** Create a file in `internal/engine/recon/mytool.go`.
2. **Implement the Interface:**
   ```go
   package recon

   import "context"

   type MyTool struct{}

   func (m *MyTool) Name() string {
       return "mytool"
   }

   func (m *MyTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
       // Your execution logic here
       // 'threads' is passed from the global config
       return []Event{}, nil
   }
   ```
3. **Register the Tool:** Add your tool to the `toolRegistry` map in `internal/engine/recon/registry.go`.
4. **Recompile:** Run `go build -o bbpts ./cmd/bbpts`.
