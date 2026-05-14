// Package report — burp.go provides integration utilities for Burp Suite.
package report

import (
	"encoding/xml"
	"fmt"
	"os"

	"github.com/Developer-Army/BBPTS/internal/engine/recon"
)

// BurpIssue represents a finding in Burp Suite's XML export format.
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

// ExportToBurpXML generates an XML file that can be imported into Burp Suite.
func ExportToBurpXML(path string, events []recon.Event) error {
	var issues BurpIssues
	for _, ev := range events {
		severity := ev.Properties["severity"]
		if severity == "" {
			severity = "Information"
		}

		issue := BurpIssue{
			Name:            fmt.Sprintf("[%s] %s", ev.Source, ev.Type),
			Host:            ev.Target,
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

// WriteBurpLinks exports all discovered URLs to a text file for easy pasting into Burp.
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
		fmt.Fprintln(file, ev.Target)
	}
	return nil
}
