# BBPTS Tool Integration Guide

The BBPTS (Bug Bounty Program Tool Set) utilizes a modular adapter pattern (`internal/application/services/registry.go`) to interface with industry-standard security tools. Each tool runs within an isolated, panic-recovered goroutine to guarantee orchestrator stability in production.

## Core Integrations

### Passive Discovery (OSINT & Historical)

These tools are safe to run against any in-scope target without generating significant traffic to the target infrastructure.

> [!NOTE]
> DNS/OSINT passive discovery tools (like `subfinder`, `amass`, `assetfinder`, and `chaos`) operate at the DNS/registry level and do not perform direct HTTP requests to target application endpoints. Therefore, HTTP headers and session cookies (`-cookie`) are not propagated to these tools.


| Tool            | Focus Area                                      | Registry Key  |
| --------------- | ----------------------------------------------- | ------------- |
| **Subfinder**   | Subdomain discovery via passive sources         | `subfinder`   |
| **Assetfinder** | GitHub and source code reconnaissance           | `assetfinder` |
| **Amass**       | Deep subdomain mapping                          | `amass`       |
| **Crt.sh**      | Certificate Transparency log parsing            | `crtsh`       |
| **Gau**         | Get All URLs (AlienVault, Wayback, CommonCrawl) | `gau`         |
| **Chaos**       | Subdomain discovery from ProjectDiscovery Chaos | `chaos`       |
| **Whois**       | Whois lookup for domain ownership details       | `whois`       |
| **TLSX**        | SSL/TLS certificate parsing and extraction     | `tlsx`        |
| **GitHub**      | GitHub repository credential scanning           | `github`      |

### Active Probing & Resolution (Network & Web)

These tools interact directly with the target infrastructure to resolve hosts, ports, and identify live web services.

| Tool          | Focus Area                                  | Registry Key |
| ------------- | ------------------------------------------- | ------------ |
| **HTTPX**     | Live service fingerprinting & status checks | `httpx`      |
| **DNSx**      | Bulk DNS resolution and record extraction   | `dnsx`       |
| **Puredns**   | Fast resolver capable of resolving millions | `puredns`    |
| **Massdns**   | High-performance DNS stub resolver          | `massdns`    |
| **Naabu**     | Fast port scanning                          | `naabu`      |
| **Shodan**    | Internet-wide port and service scanning API | `shodan`     |
| **Wafw00f**   | Web Application Firewall fingerprinting     | `wafw00f`    |

### Web Crawling & Discovery

These tools crawl pages or fetch historical URLs to build the site's surface map.

| Tool            | Focus Area                                  | Registry Key  |
| --------------- | ------------------------------------------- | ------------- |
| **Katana**      | Modern JavaScript web crawling              | `katana`      |
| **Hakrawler**   | Lightweight web crawling                    | `hakrawler`   |
| **Browser**     | Built-in headless browser crawler           | `browser`     |
| **Gowitness**   | Headless screenshot taker for web assets    | `gowitness`   |
| **Uro**         | URL sanitization and parameter cleaner      | `uro`         |
| **GraphQL**     | Built-in GraphQL endpoint scanner           | `graphql`     |
| **Trufflehog**  | Secret scanning in git/files                | `trufflehog`  |

### Vulnerability Scanning & Fuzzing

These tools perform active payloads testing to identify specific vulnerabilities.

| Tool          | Focus Area                                  | Registry Key |
| ------------- | ------------------------------------------- | ------------ |
| **Nuclei**    | Template-based vulnerability scanner        | `nuclei`     |
| **Dalfox**    | Parameterized XSS scanner                   | `dalfox`     |
| **FFUF**      | Advanced web fuzzing                        | `ffuf`       |
| **Gobuster**  | Directory and file brute-forcing            | `gobuster`   |
| **Feroxbuster**| High-speed recursive directory fuzzing      | `feroxbuster`|
| **Interactsh**| Out-of-band vulnerability checking          | `interactsh` |
| **Secrets**   | Built-in static secret scanning             | `secrets`    |
| **JS Analyzer**| Built-in client-side JS vulnerability analyzer| `js_analyzer`|

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

1. **Create the Adapter:** Create a file in `internal/application/services/mytool.go`.
2. **Implement the Interface:**

   ```go
   package services

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

3. **Register the Tool:** Add your tool to the `toolFactories` map in `internal/application/services/registry.go`.
4. **Recompile:** Run `go build -o bbpts ./cmd/bbpts`.
