package services

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

type ToolHealth struct {
	Name       string `json:"name"`
	Available  bool   `json:"available"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
	Required   bool   `json:"required"`
	CheckedAt  string `json:"checked_at"`
	InstallCmd string `json:"install_cmd,omitempty"`
}

type SystemHealth struct {
	Tools       []ToolHealth      `json:"tools"`
	System      SystemInfo        `json:"system"`
	Summary     HealthSummary     `json:"summary"`
	Diagnostics []DiagnosticCheck `json:"diagnostics"`
	Mode        string            `json:"mode"`
}

type SystemInfo struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	NumCPU        int    `json:"num_cpu"`
	GoVersion     string `json:"go_version"`
	MaxGoroutines int    `json:"max_goroutines"`
}

type HealthSummary struct {
	TotalTools     int `json:"total_tools"`
	AvailableTools int `json:"available_tools"`
	MissingTools   int `json:"missing_tools"`
}

type DiagnosticCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "pass", "warn", "fail"
	Message string `json:"message"`
}

var toolVersionFlags = map[string][]string{
	"amass":       {"version"},
	"subfinder":   {"-version"},
	"httpx":       {"-version"},
	"naabu":       {"-version"},
	"nuclei":      {"-version"},
	"katana":      {"-version"},
	"dalfox":      {"version"},
	"ffuf":        {"-V"},
	"gobuster":    {"version"},
	"feroxbuster": {"--version"},
	"gau":         {"--version"},
	"hakrawler":   {"--version"},
	"massdns":     {"--version"},
	"dnsx":        {"-version"},
	"puredns":     {"version"},
	"wafw00f":     {"--version"},
	"trufflehog":  {"--version"},
	"chaos":       {"-version"},
	"uro":         {"--help"},
	"interactsh":  {"-v"},
	"shodan":      {"version"},
}

var builtInDoctorTools = map[string]string{
	"browser":                "built-in browser recon module",
	"crtsh":                  "built-in crt.sh HTTP client",
	"github":                 "built-in GitHub API code search tool",
	"graphql":                "built-in GraphQL scanner",
	"oauth":                  "built-in OAuth 2.0 flow tester",
	"proto_pollution":        "built-in Prototype Pollution detector",
	"websocket":              "built-in WebSocket security tester",
	"smuggling":              "built-in HTTP request smuggling detector",
	"race":                   "built-in race condition tester",
	"cache_poisoning":        "built-in cache poisoning detector",
	"js_analyzer":            "built-in JavaScript analyzer",
	"secrets":                "built-in secret scanner",
	"shodan":                 "built-in Shodan API client",
	"cloud_buckets":          "built-in AWS/GCS/Azure cloud bucket scanner",
	"takeover":               "built-in subdomain takeover scanner",
	"ai_vuln":                "built-in AI/LLM vulnerability and prompt injection tester",
	"idor_assist":            "built-in semi-automated IDOR assistant",
	"bypass403":              "built-in 403/401 bypass tester",
	"cors":                   "built-in CORS policy misconfiguration scanner",
	"default_creds":          "built-in default credentials brute-forcer",
	"source_map":             "built-in JS source map exposure scanner",
	"firebase_recon":         "built-in Firebase database exposure scanner",
	"mass_assignment":        "built-in HTTP mass assignment tester",
	"cve_correlate":          "built-in service version CVE correlator",
	"git_exposure":           "built-in git directory exposure scanner",
	"price_logic":            "built-in e-commerce price logic tester",
	"dep_audit":              "built-in software dependency auditor",
	"soap_probe":             "built-in SOAP/XML API endpoints probe",
	"web3_recon":             "built-in Web3/smart contract exposure scanner",
	"cloud_exposure":         "built-in cloud storage & server exposure scanner",
	"cert_monitor":           "built-in SSL/TLS certificate transparency monitor",
	"mobile_recon":           "built-in mobile app backend recon module",
	"auth_matrix":            "built-in authentication matrix tester",
	"ratelimit_bypass":       "built-in rate limit bypass tester",
	"blind_inject":           "built-in blind SQL/NoSQL injection tester",
	"business_logic":         "built-in business logic vulnerability scanner",
	"second_order":           "built-in second-order vulnerability tracker",
	"redos":                  "built-in Regular Expression DoS tester",
	"supply_chain":           "built-in package supply chain dependency scanner",
	"tenant_isolate":         "built-in SaaS multi-tenant isolation tester",
	"wordlist_gen":           "built-in smart custom wordlist generator",
	"mobile_api_discovery":   "built-in mobile application API discovery tool",
	"mobile_dynamic":         "built-in mobile dynamic instrumentation module",
	"mobile_static":          "built-in mobile static analysis engine",
	"app_store_recon":        "built-in App Store/Play Store intelligence harvester",
	"github_actions":         "built-in GitHub Actions CI workflow security scanner",
	"github_vuln_scanning":   "built-in GitHub vulnerability scanning analyzer",
	"github_org_discovery":   "built-in GitHub organization public assets harvester",
	"github_private_repos":   "built-in GitHub private repository scanner",
	"github_dorker":          "built-in GitHub dorker",
	"email_enum":             "built-in email enumerator",
	"crlf":                   "built-in CRLF injection & response splitting tester",
	"email_header_injection": "built-in SMTP/email header injection probe",
	"api_version_probe":      "built-in API version & routing structure scanner",
	"jsonp":                  "built-in JSONP endpoint data leak scanner",
	"jwt_analyzer":           "built-in JWT token analyzer",
	"webdav":                 "built-in WebDAV server scanning module",
	"dns_zone_transfer":      "built-in DNS zone transfer vulnerability tester",
	"http2_downgrade":        "built-in HTTP/2 downgrade & smuggling scanner",
	"tls_misconfig":          "built-in TLS/SSL configuration validator",
	"paste_leaks":            "built-in paste leak threat intelligence monitor",
	"grpc_probe":             "built-in gRPC service probe",
	"asn_recon":              "built-in ASN and IP range discovery tool",
	"ssrf":                   "built-in Server-Side Request Forgery checker",
	"open_redirect":          "built-in open redirect scanner",
	"permutation":            "built-in subdomain permutation generator",
}

var toolBinaryNames = map[string]string{
	"interactsh": "interactsh-client",
}

var toolInstallInstructions = map[string]string{
	"amass":       "CGO_ENABLED=0 go install github.com/owasp-amass/amass/v4/cmd/amass@latest",
	"subfinder":   "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
	"chaos":       "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
	"dnsx":        "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
	"tlsx":        "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
	"puredns":     "go install github.com/d3mondev/puredns/v2@latest",
	"assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
	"httpx":       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
	"naabu":       "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
	"katana":      "go install github.com/projectdiscovery/katana/cmd/katana@latest",
	"gau":         "go install github.com/lc/gau/v2/cmd/gau@latest",
	"ffuf":        "go install github.com/ffuf/ffuf/v2@latest",
	"hakrawler":   "go install github.com/hakluke/hakrawler@latest",
	"gobuster":    "go install github.com/OJ/gobuster/v3@latest",
	"nuclei":      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
	"interactsh":  "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
	"dalfox":      "go install github.com/hahwul/dalfox/v2@latest",
	"gowitness":   "go install github.com/sensepost/gowitness@latest",
	"anew":        "go install github.com/tomnomnom/anew@latest",
	"uro":         "go install github.com/szybnev/uro-go/cmd/uro@latest",
	"feroxbuster": "curl -sLo install-feroxbuster.sh https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh && chmod +x install-feroxbuster.sh && ./install-feroxbuster.sh",
	"massdns":     "git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo cp bin/massdns /usr/local/bin/",
	"trufflehog":  "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
	"whois":       "sudo apt-get install -y whois || brew install whois",
	"wafw00f":     "pip install wafw00f",
	"shodan":      "pip install shodan",
}

func RunHealthChecks(ctx context.Context) *SystemHealth {
	return RunHealthChecksForTools(ctx, AvailableToolNames(), nil, "all")
}

func RunHealthChecksForTools(ctx context.Context, requiredTools, optionalTools []string, mode string) *SystemHealth {
	health := &SystemHealth{
		Mode: mode,
		System: SystemInfo{
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			NumCPU:    runtime.NumCPU(),
			GoVersion: runtime.Version(),
		},
	}

	required := make(map[string]struct{}, len(requiredTools))
	toolNames := make([]string, 0, len(requiredTools)+len(optionalTools))
	seen := make(map[string]struct{}, len(requiredTools)+len(optionalTools))
	for _, name := range requiredTools {
		name = normalizeToolName(name)
		if name == "" {
			continue
		}
		required[name] = struct{}{}
		if _, ok := seen[name]; !ok {
			toolNames = append(toolNames, name)
			seen[name] = struct{}{}
		}
	}
	for _, name := range optionalTools {
		name = normalizeToolName(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; !ok {
			toolNames = append(toolNames, name)
			seen[name] = struct{}{}
		}
	}
	health.Tools = make([]ToolHealth, 0, len(toolNames))

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10)

	for _, name := range toolNames {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			th := checkToolHealth(ctx, name)
			_, th.Required = required[name]
			mu.Lock()
			health.Tools = append(health.Tools, th)
			mu.Unlock()
		}()
	}

	wg.Wait()
	sort.Slice(health.Tools, func(i, j int) bool {
		if health.Tools[i].Required != health.Tools[j].Required {
			return health.Tools[i].Required
		}
		return health.Tools[i].Name < health.Tools[j].Name
	})

	available := 0
	missingRequired := 0
	for _, t := range health.Tools {
		if t.Available {
			available++
		} else if t.Required {
			missingRequired++
		}
	}
	health.Summary = HealthSummary{
		TotalTools:     len(health.Tools),
		AvailableTools: available,
		MissingTools:   missingRequired,
	}

	health.Diagnostics = runDiagnostics(ctx)

	return health
}

func checkToolHealth(ctx context.Context, name string) ToolHealth {
	th := ToolHealth{
		Name:      name,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if desc, ok := builtInDoctorTools[name]; ok {
		th.Available = true
		th.Version = desc
		return th
	}

	binaryName := name
	if mapped, ok := toolBinaryNames[name]; ok {
		binaryName = mapped
	}

	// Find the binary using GetSecurePaths first
	var path string
	var err error
	foundSecure := false
	for _, p := range utils.GetSecurePaths() {
		fullPath := filepath.Join(p, binaryName)
		if info, errStat := os.Stat(fullPath); errStat == nil && !info.IsDir() {
			path = fullPath
			foundSecure = true
			break
		}
	}
	if !foundSecure {
		path, err = exec.LookPath(binaryName)
	}

	if !foundSecure && err != nil {
		th.Available = false
		th.Error = fmt.Sprintf("binary not found in PATH: %v", err)
		if inst, ok := toolInstallInstructions[name]; ok {
			th.InstallCmd = inst
		}
		return th
	}
	th.Path = path
	th.Available = true

	versionArgs, ok := toolVersionFlags[name]
	if !ok {
		versionArgs = []string{"--version"}
	}

	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := tools.PrepareCommand(versionCtx, binaryName, versionArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {

		th.Version = "unknown"
		slog.Debug("Tool version check failed", "tool", name, "error", err)
	} else {
		version := strings.TrimSpace(string(output))

		if idx := strings.IndexByte(version, '\n'); idx > 0 {
			version = version[:idx]
		}

		if len(version) > 120 {
			version = version[:120] + "..."
		}
		th.Version = version
		if name == "httpx" {
			versionLower := strings.ToLower(version)
			if strings.Contains(versionLower, "python") || strings.Contains(versionLower, "usage: httpx") {
				th.Available = false
				th.Error = "Python httpx detected; ProjectDiscovery httpx is required"
			}
		}
	}

	return th
}

func runDiagnostics(ctx context.Context) []DiagnosticCheck {
	var checks []DiagnosticCheck

	checks = append(checks, checkBinaryExists("git", "Git is required for version control and some tool integrations"))

	checks = append(checks, checkBinaryExists("curl", "curl is used for API interactions"))

	checks = append(checks, checkDNSResolution(ctx))

	checks = append(checks, checkSystemResources())

	checks = append(checks, checkBinaryExists("go", "Go compiler is needed for installing Go-based tools"))

	checks = append(checks, checkBinaryExists("python3", "Python 3 is needed for some tools (uro, wafw00f)"))

	checks = append(checks, checkPlaywrightBrowsers(ctx))

	configPath := filepath.Join("configs", "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, ".bbpts", "config.json")
	}
	cfg, err := config.LoadFromFile(configPath)
	if err == nil {
		cfg.LoadFromEnv()
		providers := []string{"shodan", "securitytrails", "github", "chaos", "virustotal", "passivetotal", "binaryedge"}
		for _, provider := range providers {
			key := cfg.APIKeys[provider]
			name := fmt.Sprintf("api-key-%s", provider)
			if key != "" {
				checks = append(checks, DiagnosticCheck{
					Name:    name,
					Status:  "pass",
					Message: fmt.Sprintf("API key for %s is configured", provider),
				})
			} else {
				checks = append(checks, DiagnosticCheck{
					Name:    name,
					Status:  "warn",
					Message: fmt.Sprintf("API key for %s is empty (passive recon capability may be limited)", provider),
				})
			}
		}
	}

	return checks
}

func checkPlaywrightBrowsers(_ context.Context) DiagnosticCheck {
	var cacheDir string
	home, err := os.UserHomeDir()
	if err == nil {
		switch runtime.GOOS {
		case "darwin":
			cacheDir = filepath.Join(home, "Library", "Caches", "ms-playwright")
		case "windows":
			cacheDir = filepath.Join(home, "AppData", "Local", "ms-playwright")
		default:
			cacheDir = filepath.Join(home, ".cache", "ms-playwright")
		}
	}
	if cacheDir != "" {
		if _, err := os.Stat(cacheDir); err == nil {
			return DiagnosticCheck{
				Name:    "playwright-browsers",
				Status:  "pass",
				Message: fmt.Sprintf("Playwright browsers found in cache: %s", cacheDir),
			}
		}
	}
	return DiagnosticCheck{
		Name:    "playwright-browsers",
		Status:  "warn",
		Message: "Playwright browser binaries not found in standard cache path. Run 'go run github.com/playwright-community/playwright-go/cmd/playwright@latest install chromium --with-deps' to install them.",
	}
}

func checkBinaryExists(name, description string) DiagnosticCheck {
	foundSecure := false
	for _, p := range utils.GetSecurePaths() {
		fullPath := filepath.Join(p, name)
		if info, errStat := os.Stat(fullPath); errStat == nil && !info.IsDir() {
			foundSecure = true
			break
		}
	}
	var err error
	if !foundSecure {
		_, err = exec.LookPath(name)
	}

	if !foundSecure && err != nil {
		return DiagnosticCheck{
			Name:    name,
			Status:  "warn",
			Message: fmt.Sprintf("%s: not found in PATH. %s", name, description),
		}
	}
	return DiagnosticCheck{
		Name:    name,
		Status:  "pass",
		Message: fmt.Sprintf("%s: available", name),
	}
}

func checkDNSResolution(ctx context.Context) DiagnosticCheck {
	dnsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := tools.PrepareCommand(dnsCtx, "dig", "+short", "google.com")
	output, err := cmd.CombinedOutput()
	if err != nil {

		cmd2 := tools.PrepareCommand(dnsCtx, "nslookup", "google.com")
		_, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return DiagnosticCheck{
				Name:    "dns-resolution",
				Status:  "fail",
				Message: "DNS resolution failed — network connectivity issues may impact recon tools",
			}
		}
	}
	if len(strings.TrimSpace(string(output))) == 0 {
		return DiagnosticCheck{
			Name:    "dns-resolution",
			Status:  "warn",
			Message: "DNS resolution returned empty result",
		}
	}

	return DiagnosticCheck{
		Name:    "dns-resolution",
		Status:  "pass",
		Message: "DNS resolution working",
	}
}

func checkSystemResources() DiagnosticCheck {
	numCPU := runtime.NumCPU()
	if numCPU < 2 {
		return DiagnosticCheck{
			Name:    "system-resources",
			Status:  "warn",
			Message: fmt.Sprintf("Low CPU count (%d). Performance may be limited for parallel tool execution", numCPU),
		}
	}
	return DiagnosticCheck{
		Name:    "system-resources",
		Status:  "pass",
		Message: fmt.Sprintf("%d CPUs available for parallel recon", numCPU),
	}
}

func FormatHealthReport(health *SystemHealth) string {
	var b strings.Builder

	b.WriteString("\n╔══════════════════════════════════════════════╗\n")
	b.WriteString("║           BBPTS Doctor Report                ║\n")
	b.WriteString("╚══════════════════════════════════════════════╝\n\n")

	b.WriteString(fmt.Sprintf("  Mode: %s\n", health.Mode))
	b.WriteString(fmt.Sprintf("  System: %s/%s (%d CPUs, %s)\n\n",
		health.System.OS, health.System.Arch, health.System.NumCPU, health.System.GoVersion))

	b.WriteString(fmt.Sprintf("  Tools: %d/%d available, %d required missing\n\n",
		health.Summary.AvailableTools, health.Summary.TotalTools, health.Summary.MissingTools))

	b.WriteString("  ┌──────────────────┬────────┬──────────────────────────────────┐\n")
	b.WriteString("  │ Tool             │ Status │ Info                             │\n")
	b.WriteString("  ├──────────────────┼────────┼──────────────────────────────────┤\n")

	for _, tool := range health.Tools {
		status := "  ✓  "
		info := tool.Version
		if !tool.Available {
			status = "  ✗  "
			info = tool.Error
		}
		if !tool.Required && !tool.Available {
			status = "    "
		}
		if !tool.Required {
			tool.Name += " (opt)"
		}
		if len(info) > 30 {
			info = info[:30] + "..."
		}
		b.WriteString(fmt.Sprintf("  │ %-16s │%s │ %-32s │\n", tool.Name, status, info))
	}
	b.WriteString("  └──────────────────┴────────┴──────────────────────────────────┘\n\n")

	b.WriteString("  Diagnostics:\n")
	for _, d := range health.Diagnostics {
		icon := "✓"
		switch d.Status {
		case "warn":
			icon = ""
		case "fail":
			icon = "✗"
		}
		b.WriteString(fmt.Sprintf("    %s %s: %s\n", icon, d.Name, d.Message))
	}

	var missingInstructions []string
	for _, tool := range health.Tools {
		if !tool.Available && tool.InstallCmd != "" {
			missingInstructions = append(missingInstructions, fmt.Sprintf("    * %s: %s", strings.TrimSuffix(tool.Name, " (opt)"), tool.InstallCmd))
		}
	}
	if len(missingInstructions) > 0 {
		b.WriteString("\n  How to install missing tools:\n")
		for _, inst := range missingInstructions {
			b.WriteString(inst)
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	return b.String()
}
