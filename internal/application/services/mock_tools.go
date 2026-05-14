package services

import (
	"context"
	"fmt"
	"strings"
)

// MockTool is a test double that returns pre-configured events.
// It implements the Tool interface for use in integration tests
// without requiring external tool binaries.
type MockTool struct {
	ToolName    string
	MockEvents []Event
	MockError   error
	CallCount   int
	LastTargets []string
	LastThreads int
}

// Name returns the mock tool's name.
func (m *MockTool) Name() string {
	return m.ToolName
}

// Run returns the pre-configured events and error.
func (m *MockTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	m.CallCount++
	m.LastTargets = targets
	m.LastThreads = threads

	if m.MockError != nil {
		return nil, m.MockError
	}

	return m.MockEvents, nil
}

// NewMockTool creates a mock tool with the given name and output events.
func NewMockTool(name string, events []Event) *MockTool {
	return &MockTool{
		ToolName:   name,
		MockEvents: events,
	}
}

// NewFailingMockTool creates a mock tool that always returns an error.
func NewFailingMockTool(name string, err error) *MockTool {
	return &MockTool{
		ToolName:  name,
		MockError: err,
	}
}

// MockToolOutputs provides realistic mock outputs for common recon tools.
// Use these in tests to avoid needing actual tool binaries installed.
var MockToolOutputs = map[string][]Event{
	"subfinder": {
		NewEvent("api.example.com", "subfinder", "discovery", nil),
		NewEvent("mail.example.com", "subfinder", "discovery", nil),
		NewEvent("dev.example.com", "subfinder", "discovery", nil),
		NewEvent("staging.example.com", "subfinder", "discovery", nil),
		NewEvent("cdn.example.com", "subfinder", "discovery", nil),
	},
	"assetfinder": {
		NewEvent("www.example.com", "assetfinder", "discovery", nil),
		NewEvent("api.example.com", "assetfinder", "discovery", nil),
		NewEvent("blog.example.com", "assetfinder", "discovery", nil),
	},
	"httpx": {
		NewEvent("https://api.example.com", "httpx", "discovery", map[string]string{
			"status_code": "200", "content_type": "application/json", "server": "nginx",
		}),
		NewEvent("https://www.example.com", "httpx", "discovery", map[string]string{
			"status_code": "200", "content_type": "text/html", "server": "cloudflare",
		}),
		NewEvent("http://dev.example.com", "httpx", "discovery", map[string]string{
			"status_code": "403", "server": "Apache",
		}),
	},
	"naabu": {
		NewEvent("api.example.com:80", "naabu", "port_open", map[string]string{"port": "80"}),
		NewEvent("api.example.com:443", "naabu", "port_open", map[string]string{"port": "443"}),
		NewEvent("api.example.com:8080", "naabu", "port_open", map[string]string{"port": "8080"}),
		NewEvent("mail.example.com:25", "naabu", "port_open", map[string]string{"port": "25"}),
		NewEvent("mail.example.com:993", "naabu", "port_open", map[string]string{"port": "993"}),
	},
	"nuclei": {
		NewEvent("https://api.example.com", "nuclei", "vulnerability", map[string]string{
			"template": "cves/2023/CVE-2023-1234", "severity": "high",
			"name": "SQL Injection in API", "matcher": "error-based",
		}),
		NewEvent("https://dev.example.com", "nuclei", "vulnerability", map[string]string{
			"template": "exposures/configs/phpinfo", "severity": "info",
			"name": "PHP Info Disclosure",
		}),
	},
	"katana": {
		NewEvent("https://api.example.com/v1/users", "katana", "discovery", nil),
		NewEvent("https://api.example.com/v1/auth/login", "katana", "discovery", nil),
		NewEvent("https://api.example.com/v2/admin", "katana", "discovery", nil),
		NewEvent("https://www.example.com/robots.txt", "katana", "discovery", nil),
		NewEvent("https://www.example.com/sitemap.xml", "katana", "discovery", nil),
	},
	"gau": {
		NewEvent("https://api.example.com/api/v1/users?id=1", "gau", "discovery", nil),
		NewEvent("https://api.example.com/api/v1/search?q=test", "gau", "discovery", nil),
		NewEvent("https://www.example.com/login", "gau", "discovery", nil),
	},
	"ffuf": {
		NewEvent("https://api.example.com/admin", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "1234",
		}),
		NewEvent("https://api.example.com/.env", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "456",
		}),
		NewEvent("https://api.example.com/debug", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "789",
		}),
	},
	"crtsh": {
		NewEvent("cert.example.com", "crtsh", "discovery", nil),
		NewEvent("internal.example.com", "crtsh", "discovery", nil),
	},
	"whois": {
		NewEvent("example.com", "whois", "discovery", map[string]string{
			"registrar": "MarkMonitor", "org": "Example Inc.",
			"created": "1995-08-14", "expires": "2030-08-13",
		}),
	},
	"shodan": {
		NewEvent("93.184.216.34", "shodan", "discovery", map[string]string{
			"os": "Linux", "ports": "80,443,8080",
			"org": "Edgecast",
		}),
	},
	"dalfox": {
		NewEvent("https://api.example.com/search?q=test", "dalfox", "vulnerability", map[string]string{
			"type": "reflected-xss", "param": "q",
			"payload": "<script>alert(1)</script>",
		}),
	},
}

// GetMockTool returns a MockTool pre-loaded with realistic output for the given tool name.
func GetMockTool(toolName string) *MockTool {
	events, ok := MockToolOutputs[toolName]
	if !ok {
		return NewMockTool(toolName, nil)
	}
	return NewMockTool(toolName, events)
}

// GetAllMockTools returns MockTools for all registered tools.
func GetAllMockTools() []*MockTool {
	var tools []*MockTool
	for name := range MockToolOutputs {
		tools = append(tools, GetMockTool(name))
	}
	return tools
}

// NewMockPipeline creates a full mock recon pipeline for testing.
// Returns events simulating a complete recon flow against the given target.
func NewMockPipeline(target string) []Event {
	var events []Event

	// Stage 1: Passive recon
	for _, sub := range []string{"api", "mail", "dev", "staging", "cdn", "blog"} {
		events = append(events, NewEvent(
			fmt.Sprintf("%s.%s", sub, target),
			"subfinder",
			"discovery",
			nil,
		))
	}

	// Stage 2: Active probing
	for _, sub := range []string{"api", "mail", "dev"} {
		host := fmt.Sprintf("%s.%s", sub, target)
		events = append(events,
			NewEvent(fmt.Sprintf("https://%s", host), "httpx", "discovery",
				map[string]string{"status_code": "200"}),
		)
	}

	// Stage 3: Web crawling
	for _, path := range []string{"/api/v1/users", "/login", "/admin", "/robots.txt"} {
		events = append(events, NewEvent(
			fmt.Sprintf("https://api.%s%s", target, path),
			"katana",
			"discovery",
			nil,
		))
	}

	// Stage 5: Vulnerability scanning
	events = append(events, NewEvent(
		fmt.Sprintf("https://api.%s", target),
		"nuclei",
		"vulnerability",
		map[string]string{"severity": "high", "template": "cves/test"},
	))

	return events
}

// MockCommandOutput provides mock command-line output strings for testing
// tool parsers without running the actual commands.
var MockCommandOutput = map[string]string{
	"subfinder": strings.Join([]string{
		"api.example.com",
		"mail.example.com",
		"dev.example.com",
		"staging.example.com",
	}, "\n"),
	"httpx": strings.Join([]string{
		"https://api.example.com [200] [application/json] [nginx]",
		"https://www.example.com [200] [text/html] [cloudflare]",
		"http://dev.example.com [403] [] [Apache]",
	}, "\n"),
	"naabu": strings.Join([]string{
		"api.example.com:80",
		"api.example.com:443",
		"api.example.com:8080",
	}, "\n"),
	"nuclei": strings.Join([]string{
		`[2024-01-15T10:30:00] [CVE-2023-1234] [high] https://api.example.com`,
		`[2024-01-15T10:31:00] [phpinfo] [info] https://dev.example.com/phpinfo.php`,
	}, "\n"),
}
