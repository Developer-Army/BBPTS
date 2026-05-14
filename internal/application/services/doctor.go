package services

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ToolHealth represents the health status of a single recon tool.
type ToolHealth struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
	Required  bool   `json:"required"`
	CheckedAt string `json:"checked_at"`
}

// SystemHealth represents overall system health metrics.
type SystemHealth struct {
	Tools       []ToolHealth      `json:"tools"`
	System      SystemInfo        `json:"system"`
	Summary     HealthSummary     `json:"summary"`
	Diagnostics []DiagnosticCheck `json:"diagnostics"`
	Mode        string            `json:"mode"`
}

// SystemInfo holds system-level info for the doctor report.
type SystemInfo struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	NumCPU        int    `json:"num_cpu"`
	GoVersion     string `json:"go_version"`
	MaxGoroutines int    `json:"max_goroutines"`
}

// HealthSummary provides a quick overview of tool availability.
type HealthSummary struct {
	TotalTools     int `json:"total_tools"`
	AvailableTools int `json:"available_tools"`
	MissingTools   int `json:"missing_tools"`
}

// DiagnosticCheck represents a system diagnostic.
type DiagnosticCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "pass", "warn", "fail"
	Message string `json:"message"`
}

// toolVersionFlags maps tool names to version flag arguments.
var toolVersionFlags = map[string][]string{
	"amass":       {"-version"},
	"subfinder":   {"-version"},
	"findomain":   {"--version"},
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
	"interactsh":  {"-version"},
	"shodan":      {"version"},
}

var builtInDoctorTools = map[string]string{
	"browser":     "built-in browser recon module",
	"cloudenum":   "built-in cloud enum module",
	"crtsh":       "built-in crt.sh HTTP client",
	"graphql":     "built-in GraphQL scanner",
	"js_analyzer": "built-in JavaScript analyzer",
	"secrets":     "built-in secret scanner",
	"shodan":      "built-in Shodan API client",
}

var toolBinaryNames = map[string]string{
	"interactsh": "interactsh-client",
}

// RunHealthChecks performs health checks on all registered recon tools.
// Returns a SystemHealth report with tool availability and system diagnostics.
func RunHealthChecks(ctx context.Context) *SystemHealth {
	return RunHealthChecksForTools(ctx, AvailableToolNames(), nil, "all")
}

// RunHealthChecksForTools checks required tools and optional tools separately.
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
	sem := make(chan struct{}, 10) // max 10 concurrent checks

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

	// Summary
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

	// System diagnostics
	health.Diagnostics = runDiagnostics(ctx)

	return health
}

// checkToolHealth checks if a single tool binary is available and functional.
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

	// Find the binary
	path, err := exec.LookPath(binaryName)
	if err != nil {
		th.Available = false
		th.Error = fmt.Sprintf("binary not found in PATH: %v", err)
		return th
	}
	th.Path = path
	th.Available = true

	// Try to get version
	versionArgs, ok := toolVersionFlags[name]
	if !ok {
		versionArgs = []string{"--version"}
	}

	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(versionCtx, binaryName, versionArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Tool exists but version check failed — still available
		th.Version = "unknown"
		slog.Debug("Tool version check failed", "tool", name, "error", err)
	} else {
		version := strings.TrimSpace(string(output))
		// Take only the first line of version output
		if idx := strings.IndexByte(version, '\n'); idx > 0 {
			version = version[:idx]
		}
		// Truncate overly long version strings
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

// runDiagnostics performs system-level health diagnostics.
func runDiagnostics(ctx context.Context) []DiagnosticCheck {
	var checks []DiagnosticCheck

	// Check if git is available (needed for some tools)
	checks = append(checks, checkBinaryExists("git", "Git is required for version control and some tool integrations"))

	// Check if curl is available
	checks = append(checks, checkBinaryExists("curl", "curl is used for API interactions"))

	// Check DNS resolution
	checks = append(checks, checkDNSResolution(ctx))

	// Check available memory
	checks = append(checks, checkSystemResources())

	// Check if Go is available for tools that compile from source
	checks = append(checks, checkBinaryExists("go", "Go compiler is needed for installing Go-based tools"))

	// Check Python for Python-based tools
	checks = append(checks, checkBinaryExists("python3", "Python 3 is needed for some tools (uro, wafw00f)"))

	return checks
}

func checkBinaryExists(name, description string) DiagnosticCheck {
	_, err := exec.LookPath(name)
	if err != nil {
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

	cmd := exec.CommandContext(dnsCtx, "dig", "+short", "google.com")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try nslookup as fallback
		cmd2 := exec.CommandContext(dnsCtx, "nslookup", "google.com")
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

// FormatHealthReport returns a human-readable health report string.
func FormatHealthReport(health *SystemHealth) string {
	var b strings.Builder

	b.WriteString("\n╔══════════════════════════════════════════════╗\n")
	b.WriteString("║           BBPTS Doctor Report                ║\n")
	b.WriteString("╚══════════════════════════════════════════════╝\n\n")

	// System Info
	b.WriteString(fmt.Sprintf("  Mode: %s\n", health.Mode))
	b.WriteString(fmt.Sprintf("  System: %s/%s (%d CPUs, %s)\n\n",
		health.System.OS, health.System.Arch, health.System.NumCPU, health.System.GoVersion))

	// Tool Summary
	b.WriteString(fmt.Sprintf("  Tools: %d/%d available, %d required missing\n\n",
		health.Summary.AvailableTools, health.Summary.TotalTools, health.Summary.MissingTools))

	// Tool Details
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
			status = "  ⚠  "
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

	// Diagnostics
	b.WriteString("  Diagnostics:\n")
	for _, d := range health.Diagnostics {
		icon := "✓"
		if d.Status == "warn" {
			icon = "⚠"
		} else if d.Status == "fail" {
			icon = "✗"
		}
		b.WriteString(fmt.Sprintf("    %s %s: %s\n", icon, d.Name, d.Message))
	}

	b.WriteString("\n")
	return b.String()
}
