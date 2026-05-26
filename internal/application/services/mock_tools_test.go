// Package services — mock_tools_test.go
//
// MockTool implements the Tool interface for use in unit and integration tests.
// All fixtures use the fictional domain "acme-corp.io". This domain is not a
// real bug-bounty target; it exists solely to make test output readable.
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
	Events      []Event
	Err         error
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

	if m.Err != nil {
		return nil, m.Err
	}

	return m.Events, nil
}

// NewMockTool creates a mock tool with the given name and output events.
func NewMockTool(name string, events []Event) *MockTool {
	return &MockTool{
		ToolName: name,
		Events:   events,
	}
}

// NewFailingMockTool creates a mock tool that always returns an error.
func NewFailingMockTool(name string, err error) *MockTool {
	return &MockTool{
		ToolName: name,
		Err:      err,
	}
}

// MockToolOutputs provides realistic mock outputs for common recon tools.
// Use these in tests to avoid needing actual tool binaries installed.
var MockToolOutputs = map[string][]Event{
	"subfinder": {
		NewEvent("api.acme-corp.io", "subfinder", "discovery", nil),
		NewEvent("mail.acme-corp.io", "subfinder", "discovery", nil),
		NewEvent("dev.acme-corp.io", "subfinder", "discovery", nil),
		NewEvent("staging.acme-corp.io", "subfinder", "discovery", nil),
		NewEvent("cdn.acme-corp.io", "subfinder", "discovery", nil),
	},
	"assetfinder": {
		NewEvent("www.acme-corp.io", "assetfinder", "discovery", nil),
		NewEvent("api.acme-corp.io", "assetfinder", "discovery", nil),
		NewEvent("blog.acme-corp.io", "assetfinder", "discovery", nil),
	},
	"httpx": {
		NewEvent("https://api.acme-corp.io", "httpx", "discovery", map[string]string{
			"status_code": "200", "content_type": "application/json", "server": "nginx",
		}),
		NewEvent("https://www.acme-corp.io", "httpx", "discovery", map[string]string{
			"status_code": "200", "content_type": "text/html", "server": "cloudflare",
		}),
		NewEvent("http://dev.acme-corp.io", "httpx", "discovery", map[string]string{
			"status_code": "403", "server": "Apache",
		}),
	},
	"naabu": {
		NewEvent("api.acme-corp.io:80", "naabu", "port_open", map[string]string{"port": "80"}),
		NewEvent("api.acme-corp.io:443", "naabu", "port_open", map[string]string{"port": "443"}),
		NewEvent("api.acme-corp.io:8080", "naabu", "port_open", map[string]string{"port": "8080"}),
		NewEvent("mail.acme-corp.io:25", "naabu", "port_open", map[string]string{"port": "25"}),
		NewEvent("mail.acme-corp.io:993", "naabu", "port_open", map[string]string{"port": "993"}),
	},
	"nuclei": {
		NewEvent("https://api.acme-corp.io", "nuclei", "vulnerability", map[string]string{
			"template": "cves/2023/CVE-2023-1234", "severity": "high",
			"name": "SQL Injection in API", "matcher": "error-based",
		}),
		NewEvent("https://dev.acme-corp.io", "nuclei", "vulnerability", map[string]string{
			"template": "exposures/configs/phpinfo", "severity": "info",
			"name": "PHP Info Disclosure",
		}),
	},
	"katana": {
		NewEvent("https://api.acme-corp.io/api/v1/users", "katana", "discovery", nil),
		NewEvent("https://api.acme-corp.io/api/v1/auth/login", "katana", "discovery", nil),
		NewEvent("https://api.acme-corp.io/api/v2/admin", "katana", "discovery", nil),
		NewEvent("https://www.acme-corp.io/robots.txt", "katana", "discovery", nil),
		NewEvent("https://www.acme-corp.io/sitemap.xml", "katana", "discovery", nil),
	},
	"gau": {
		NewEvent("https://api.acme-corp.io/api/v1/users?user_id=1", "gau", "discovery", nil),
		NewEvent("https://api.acme-corp.io/api/v1/search?q=test", "gau", "discovery", nil),
		NewEvent("https://www.acme-corp.io/login", "gau", "discovery", nil),
	},
	"ffuf": {
		NewEvent("https://api.acme-corp.io/admin", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "1234",
		}),
		NewEvent("https://api.acme-corp.io/.env", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "456",
		}),
		NewEvent("https://api.acme-corp.io/debug", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "789",
		}),
	},
	"crtsh": {
		NewEvent("cert.acme-corp.io", "crtsh", "discovery", nil),
		NewEvent("internal.acme-corp.io", "crtsh", "discovery", nil),
	},
	"whois": {
		NewEvent("acme-corp.io", "whois", "discovery", map[string]string{
			"registrar": "CSC Corporate Domains", "org": "Acme Corp Ltd.",
			"created": "1995-08-14", "expires": "2030-08-13",
		}),
	},
	"shodan": {
		NewEvent("104.21.0.1", "shodan", "discovery", map[string]string{
			"os": "Linux", "ports": "80,443,8080",
			"org": "Cloudflare, Inc.",
		}),
	},
	"dalfox": {
		NewEvent("https://api.acme-corp.io/search?q=test", "dalfox", "vulnerability", map[string]string{
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

	// Stage 4: Port scanning
	for _, sub := range []string{"api", "mail"} {
		host := fmt.Sprintf("%s.%s", sub, target)
		events = append(events,
			NewEvent(fmt.Sprintf("%s:80", host), "naabu", "port_open", map[string]string{"port": "80"}),
			NewEvent(fmt.Sprintf("%s:443", host), "naabu", "port_open", map[string]string{"port": "443"}),
		)
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
		"api.acme-corp.io",
		"mail.acme-corp.io",
		"dev.acme-corp.io",
		"staging.acme-corp.io",
	}, "\n"),
	"httpx": strings.Join([]string{
		"https://api.acme-corp.io [200] [application/json] [nginx]",
		"https://www.acme-corp.io [200] [text/html] [cloudflare]",
		"http://dev.acme-corp.io [403] [] [Apache]",
	}, "\n"),
	"naabu": strings.Join([]string{
		"api.acme-corp.io:80",
		"api.acme-corp.io:443",
		"api.acme-corp.io:8080",
	}, "\n"),
	"nuclei": strings.Join([]string{
		`[2024-01-15T10:30:00] [CVE-2023-1234] [high] https://api.acme-corp.io`,
		`[2024-01-15T10:31:00] [phpinfo] [info] https://dev.acme-corp.io/phpinfo.php`,
	}, "\n"),
}
