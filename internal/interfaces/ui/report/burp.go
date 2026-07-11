// Package ui provides user interface components
package ui

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

type BurpIssue struct {
	Name                  string `xml:"name"`
	Host                  string `xml:"host"`
	Path                  string `xml:"path"`
	Location              string `xml:"location"`
	Severity              string `xml:"severity"`
	Confidence            string `xml:"confidence"`
	IssueBackground       string `xml:"issueBackground"`
	RemediationBackground string `xml:"remediationBackground"`
}

type BurpIssues struct {
	XMLName xml.Name    `xml:"issues"`
	Issues  []BurpIssue `xml:"issue"`
}

func splitHostAndPath(target string) (string, string) {
	target = strings.TrimSpace(target)
	if !strings.Contains(target, "://") {
		var host, path string
		if idx := strings.IndexByte(target, '/'); idx >= 0 {
			host, path = target[:idx], target[idx:]
		} else {
			host, path = target, "/"
		}
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
		return host, path
	}
	u, err := url.Parse(target)
	if err != nil {
		host := target
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
		return host, "/"
	}
	path := u.EscapedPath()
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	if path == "" {
		path = "/"
	}
	return u.Hostname(), path
}

func ExportToBurpXML(path string, events []recon.Event) error {
	var issues BurpIssues
	for _, ev := range events {
		severity := ev.Properties["severity"]
		if severity == "" {
			severity = "Information"
		}

		host, pathVal := splitHostAndPath(ev.Target)
		issue := BurpIssue{
			Name:            fmt.Sprintf("[%s] %s", ev.Source, ev.Type),
			Host:            host,
			Path:            pathVal,
			Location:        ev.Target,
			Severity:        severity,
			Confidence:      "Certain",
			IssueBackground: fmt.Sprintf("Discovered by BBPTS via %s.", ev.Source),
		}
		issues.Issues = append(issues.Issues, issue)
	}

	data, err := xml.MarshalIndent(issues, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func WriteBurpLinks(path string, events []recon.Event) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	seen := make(map[string]struct{})
	for _, ev := range events {
		if _, ok := seen[ev.Target]; ok {
			continue
		}
		seen[ev.Target] = struct{}{}
		if _, err := fmt.Fprintln(file, ev.Target); err != nil {
			return err
		}
	}
	return nil
}
