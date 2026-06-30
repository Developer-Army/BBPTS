// Package services — mock_tools_test.go
//
// MockTool implements the Tool interface for use in unit and integration tests.
// All fixtures use the fictional domain "acme-corp.io". This domain is not a
// real bug-bounty target; it exists solely to make test output readable.
package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"strings"
)

type MockTool struct {
	ToolName    string
	Events      []recon.Event
	Err         error
	CallCount   int
	LastTargets []string
	LastThreads int
}

func (m *MockTool) Name() string {
	return m.ToolName
}

func (m *MockTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	m.CallCount++
	m.LastTargets = targets
	m.LastThreads = threads

	if m.Err != nil {
		return nil, m.Err
	}

	return m.Events, nil
}

func NewMockTool(name string, events []recon.Event) *MockTool {
	return &MockTool{
		ToolName: name,
		Events:   events,
	}
}

func NewFailingMockTool(name string, err error) *MockTool {
	return &MockTool{
		ToolName: name,
		Err:      err,
	}
}

var MockToolOutputs = map[string][]recon.Event{
	"subfinder": {
		recon.NewEvent("api.acme-corp.io", "subfinder", "discovery", nil),
		recon.NewEvent("mail.acme-corp.io", "subfinder", "discovery", nil),
		recon.NewEvent("dev.acme-corp.io", "subfinder", "discovery", nil),
		recon.NewEvent("staging.acme-corp.io", "subfinder", "discovery", nil),
		recon.NewEvent("cdn.acme-corp.io", "subfinder", "discovery", nil),
	},
	"assetfinder": {
		recon.NewEvent("www.acme-corp.io", "assetfinder", "discovery", nil),
		recon.NewEvent("api.acme-corp.io", "assetfinder", "discovery", nil),
		recon.NewEvent("blog.acme-corp.io", "assetfinder", "discovery", nil),
	},
	"httpx": {
		recon.NewEvent("https://api.acme-corp.io", "httpx", "discovery", map[string]string{
			"status_code": "200", "content_type": "application/json", "server": "nginx",
		}),
		recon.NewEvent("https://www.acme-corp.io", "httpx", "discovery", map[string]string{
			"status_code": "200", "content_type": "text/html", "server": "cloudflare",
		}),
		recon.NewEvent("http://dev.acme-corp.io", "httpx", "discovery", map[string]string{
			"status_code": "403", "server": "Apache",
		}),
	},
	"naabu": {
		recon.NewEvent("api.acme-corp.io:80", "naabu", "port_open", map[string]string{"port": "80"}),
		recon.NewEvent("api.acme-corp.io:443", "naabu", "port_open", map[string]string{"port": "443"}),
		recon.NewEvent("api.acme-corp.io:8080", "naabu", "port_open", map[string]string{"port": "8080"}),
		recon.NewEvent("mail.acme-corp.io:25", "naabu", "port_open", map[string]string{"port": "25"}),
		recon.NewEvent("mail.acme-corp.io:993", "naabu", "port_open", map[string]string{"port": "993"}),
	},
	"nuclei": {
		recon.NewEvent("https://api.acme-corp.io", "nuclei", "vulnerability", map[string]string{
			"template": "cves/2023/CVE-2023-1234", "severity": "high",
			"name": "SQL Injection in API", "matcher": "error-based",
		}),
		recon.NewEvent("https://dev.acme-corp.io", "nuclei", "vulnerability", map[string]string{
			"template": "exposures/configs/phpinfo", "severity": "info",
			"name": "PHP Info Disclosure",
		}),
	},
	"katana": {
		recon.NewEvent("https://api.acme-corp.io/api/v1/users", "katana", "discovery", nil),
		recon.NewEvent("https://api.acme-corp.io/api/v1/auth/login", "katana", "discovery", nil),
		recon.NewEvent("https://api.acme-corp.io/api/v2/admin", "katana", "discovery", nil),
		recon.NewEvent("https://www.acme-corp.io/robots.txt", "katana", "discovery", nil),
		recon.NewEvent("https://www.acme-corp.io/sitemap.xml", "katana", "discovery", nil),
	},
	"gau": {
		recon.NewEvent("https://api.acme-corp.io/api/v1/users?user_id=1", "gau", "discovery", nil),
		recon.NewEvent("https://api.acme-corp.io/api/v1/search?q=test", "gau", "discovery", nil),
		recon.NewEvent("https://www.acme-corp.io/login", "gau", "discovery", nil),
	},
	"ffuf": {
		recon.NewEvent("https://api.acme-corp.io/admin", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "1234",
		}),
		recon.NewEvent("https://api.acme-corp.io/.env", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "456",
		}),
		recon.NewEvent("https://api.acme-corp.io/debug", "ffuf", "discovery", map[string]string{
			"status": "200", "size": "789",
		}),
	},
	"crtsh": {
		recon.NewEvent("cert.acme-corp.io", "crtsh", "discovery", nil),
		recon.NewEvent("internal.acme-corp.io", "crtsh", "discovery", nil),
	},
	"whois": {
		recon.NewEvent("acme-corp.io", "whois", "discovery", map[string]string{
			"registrar": "CSC Corporate Domains", "org": "Acme Corp Ltd.",
			"created": "1995-08-14", "expires": "2030-08-13",
		}),
	},
	"shodan": {
		recon.NewEvent("104.21.0.1", "shodan", "discovery", map[string]string{
			"os": "Linux", "ports": "80,443,8080",
			"org": "Cloudflare, Inc.",
		}),
	},
	"dalfox": {
		recon.NewEvent("https://api.acme-corp.io/search?q=test", "dalfox", "vulnerability", map[string]string{
			"type": "reflected-xss", "param": "q",
			"payload": "<script>alert(1)</script>",
		}),
	},
}

func GetMockTool(toolName string) *MockTool {
	events, ok := MockToolOutputs[toolName]
	if !ok {
		return NewMockTool(toolName, nil)
	}
	return NewMockTool(toolName, events)
}

func GetAllMockTools() []*MockTool {
	var tools []*MockTool
	for name := range MockToolOutputs {
		tools = append(tools, GetMockTool(name))
	}
	return tools
}

func NewMockPipeline(target string) []recon.Event {
	var events []recon.Event

	for _, sub := range []string{"api", "mail", "dev", "staging", "cdn", "blog"} {
		events = append(events, recon.NewEvent(
			fmt.Sprintf("%s.%s", sub, target),
			"subfinder",
			"discovery",
			nil,
		))
	}

	for _, sub := range []string{"api", "mail", "dev"} {
		host := fmt.Sprintf("%s.%s", sub, target)
		events = append(events,
			recon.NewEvent(fmt.Sprintf("https://%s", host), "httpx", "discovery",
				map[string]string{"status_code": "200"}),
		)
	}

	for _, path := range []string{"/api/v1/users", "/login", "/admin", "/robots.txt"} {
		events = append(events, recon.NewEvent(
			fmt.Sprintf("https://api.%s%s", target, path),
			"katana",
			"discovery",
			nil,
		))
	}

	for _, sub := range []string{"api", "mail"} {
		host := fmt.Sprintf("%s.%s", sub, target)
		events = append(events,
			recon.NewEvent(fmt.Sprintf("%s:80", host), "naabu", "port_open", map[string]string{"port": "80"}),
			recon.NewEvent(fmt.Sprintf("%s:443", host), "naabu", "port_open", map[string]string{"port": "443"}),
		)
	}

	events = append(events, recon.NewEvent(
		fmt.Sprintf("https://api.%s", target),
		"nuclei",
		"vulnerability",
		map[string]string{"severity": "high", "template": "cves/test"},
	))

	return events
}

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
