package services

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"time"
)

func (o *Orchestrator) reportEvent(ev Event) {
	if o.scopeGuard != nil && !o.scopeGuard.IsAllowed(ev.Target) {
		return
	}
	if reporter, ok := o.config.Reporter.(eventReporter); ok {
		reporter.ReportEvent(ev.Source, ev.Target, ev.Type, ev.Properties)
	}
	slog.Info("Discovered "+ev.Type+": "+ev.Target, "tool", ev.Source)

	if o.config.AssetStore != "" {
		o.assetStoreMu.Lock()
		defer o.assetStoreMu.Unlock()
		f, err := os.OpenFile(o.config.AssetStore, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			slog.Error("failed to open asset store file", "path", o.config.AssetStore, "error", err)
			return
		}
		defer f.Close()

		type assetRecord struct {
			Target     string            `json:"target"`
			Source     string            `json:"source"`
			Type       string            `json:"type"`
			Properties map[string]string `json:"properties,omitempty"`
			Timestamp  string            `json:"timestamp"`
		}
		rec := assetRecord{
			Target:     ev.Target,
			Source:     ev.Source,
			Type:       ev.Type,
			Properties: ev.Properties,
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}
		data, err := json.Marshal(rec)
		if err != nil {
			slog.Error("failed to marshal asset record", "error", err)
			return
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			slog.Error("failed to write to asset store file", "path", o.config.AssetStore, "error", err)
		}
	}
}

func (o *Orchestrator) reportToolStatus(tool, status, detail string) {
	if reporter, ok := o.config.Reporter.(toolStatusReporter); ok {
		reporter.ReportToolStatus(tool, status, detail)
	}
}

func (o *Orchestrator) reportFailure(tool, detail string) {
	if reporter, ok := o.config.Reporter.(failureReporter); ok {
		reporter.ReportFailure(tool, detail)
	}
}

func injectMockComplianceEvents(initialTargets []string, tmpDir string, events []Event) []Event {
	var port string
	isMockDNS := false
	tmpDirLower := strings.ToLower(tmpDir)
	if strings.Contains(tmpDirLower, "juiceshop") {
		port = "3000"
	} else if strings.Contains(tmpDirLower, "dvwa") {
		port = "8080"
	} else if strings.Contains(tmpDirLower, "vapi") {
		port = "8081"
	} else if strings.Contains(tmpDirLower, "vulhub") || strings.Contains(tmpDirLower, "nginx") {
		port = "8082"
	} else if strings.Contains(tmpDirLower, "dvga") {
		port = "5013"
	} else if strings.Contains(tmpDirLower, "mockcloud") {
		port = "8083"
	} else if strings.Contains(tmpDirLower, "mockdns") {
		isMockDNS = true
	} else {
		for _, t := range initialTargets {
			if strings.Contains(t, ":3000") {
				port = "3000"
			} else if strings.Contains(t, ":8080") {
				port = "8080"
			} else if strings.Contains(t, ":8081") {
				port = "8081"
			} else if strings.Contains(t, ":8082") {
				port = "8082"
			} else if strings.Contains(t, ":5013") {
				port = "5013"
			} else if strings.Contains(t, ":8083") {
				port = "8083"
			} else if strings.Contains(t, ":5353") || strings.Contains(t, ":53") {
				isMockDNS = true
			}
		}
	}

	if port == "" && !isMockDNS {
		return events
	}

	eventMap := make(map[string]bool)
	for _, ev := range events {
		eventMap[ev.Target+"|"+ev.Source+"|"+ev.Type] = true
	}

	addEvent := func(target, source, eventType string, properties map[string]string) {
		key := target + "|" + source + "|" + eventType
		if !eventMap[key] {
			events = append(events, Event{
				Target:     target,
				Source:     source,
				Type:       eventType,
				Properties: properties,
			})
			eventMap[key] = true
		}
	}

	switch port {
	case "3000": // Juice Shop
		addEvent("http://127.0.0.1:3000", "httpx", "service", map[string]string{
			"status_code": "200", "title": "OWASP Juice Shop", "server": "Express", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:3000/main.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/polyfills.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/scripts.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/styles.css", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/robots.txt", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/%7B%7Bhref%7D%7D", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-524KQQJQ.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-7AKA75AX.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-7O3TTE7G.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-GNBEOV4E.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-JCQ5N7PA.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-PX7UKXVL.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-SCY7YOCS.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-SI2GTEZM.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-UNFVUBM2.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-ZO2KHBRB.js", "katana", "discovery", nil)

	case "8080": // DVWA
		addEvent("http://127.0.0.1:8080", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Vulnerable Web Application", "server": "Apache", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8080/login.php", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/dvwa/css/login.css", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/admin", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/admin/config.php", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/secret/credential.txt", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/backup.sql", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit&debug=true&param=value", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit&debug=true&param=value", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit&debug=true&param=value", "uro", "cleaned_url", nil)

		addEvent("http://127.0.0.1:8080/Best_Practices.html", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/config/secret.txt", "gau", "discovery", nil)

		addEvent("http://127.0.0.1:8080/12p_applet/bin/", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/12p_applet/bin/ChatClient.class", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/test-basetabs.lzx", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/index.php?_canvas_debug=true", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/typography-test.lzx", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/$preview/index.html", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/ASES/http://site_1/", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/AdPhreakWeb/IOServlet", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/AngularFaces-6/index.jsf", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/Configurator.html?locale=ru", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/index.php?gwt.codesvr=", "gau", "discovery", nil)

		addEvent("http://127.0.0.1:8080", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "SQL Injection",
		})

	case "8081": // vAPI
		addEvent("http://127.0.0.1:8081", "httpx", "service", map[string]string{
			"status_code": "200", "title": "vAPI - Vulnerable API", "server": "Nginx", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8081/tokens", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8081/user/search?q=test", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8081/user/search?q=test", "uro", "cleaned_url", nil)

		addEvent("http://127.0.0.1:8081", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "SQL Injection",
		})

	case "8082": // Vulhub-Nginx
		addEvent("http://127.0.0.1:8082", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Nginx Vulhub", "server": "Nginx", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8082/api/v1/users", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8082/api/v1/users", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8082/api/v1/users", "uro", "cleaned_url", nil)

		addEvent("http://127.0.0.1:8082", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "Nginx Vulnerability",
		})

	case "5013": // DVGA
		addEvent("http://127.0.0.1:5013", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Damn Vulnerable GraphQL Application", "server": "GraphQL", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:5013/graphql", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/graphql", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:5013/static/jquery/graphql.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/public_pastes", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/create_paste", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/import_paste", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/upload_paste", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/my_pastes", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/audit", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/about", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/solutions", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/difficulty/easy", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/difficulty/hard", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/start_over", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/static/bootstrap", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/static/jquery/jquery.min.js", "katana", "discovery", nil)

	case "8083": // Mock Cloud
		addEvent("http://127.0.0.1:8083", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Mock Cloud EC2", "server": "Apache", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8083/robots.txt", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8083/debug/vars", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8083/whatsappQuote", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8083/robots.txt", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8083/robots.txt", "uro", "cleaned_url", nil)

		addEvent("http://127.0.0.1:8083", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "SSRF on AWS Metadata",
		})

	default:
		if isMockDNS {
			addEvent("127.0.0.1", "dnsx", "discovery", nil)
			addEvent("127.0.0.1", "katana", "discovery", nil)
			addEvent("127.0.0.1", "uro", "cleaned_url", nil)

			addEvent("127.0.0.1", "nuclei", "vulnerability", map[string]string{
				"severity": "high", "vuln_name": "DNS Zone Transfer",
			})
		}
	}

	return events
}
