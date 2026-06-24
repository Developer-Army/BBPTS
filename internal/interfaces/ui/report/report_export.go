package ui

import (
	"encoding/json"
	"encoding/xml"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (rg *ReportGenerator) exportForBurp(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "burp-import.xml")
	issues := BurpIssues{Issues: make([]BurpIssue, 0, len(report.Findings))}
	for _, finding := range report.Findings {
		host, pathVal := splitHostAndPath(finding.Target)
		issues.Issues = append(issues.Issues, BurpIssue{
			Name:            finding.Title,
			Host:            host,
			Path:            pathVal,
			Location:        finding.Target,
			Severity:        finding.Severity,
			Confidence:      "Certain",
			IssueBackground: finding.Description,
		})
	}

	data, err := xml.MarshalIndent(issues, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// exportForCaido exports findings for Caido import
func (rg *ReportGenerator) exportForCaido(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "caido-import.json")
	type caidoFinding struct {
		Title       string   `json:"title"`
		Target      string   `json:"target"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Evidence    string   `json:"evidence"`
		Tags        []string `json:"tags,omitempty"`
	}

	out := make([]caidoFinding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		out = append(out, caidoFinding{
			Title:       finding.Title,
			Target:      finding.Target,
			Severity:    strings.ToLower(finding.Severity),
			Description: finding.Description,
			Evidence:    finding.Evidence,
			Tags:        finding.Tags,
		})
	}

	caidoRoot := struct {
		GeneratedAt string         `json:"generated_at"`
		Findings    []caidoFinding `json:"findings"`
	}{
		GeneratedAt: report.GeneratedAt.UTC().Format(time.RFC3339),
		Findings:    out,
	}

	data, err := json.MarshalIndent(caidoRoot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// exportForZAP exports findings for ZAP import
func (rg *ReportGenerator) exportForZAP(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "zap-import.xml")
	type zapAlertItem struct {
		Name     string `xml:"name"`
		Risk     string `xml:"riskdesc"`
		Desc     string `xml:"desc"`
		URI      string `xml:"uri"`
		Evidence string `xml:"evidence"`
	}
	type zapSite struct {
		Name       string         `xml:"name,attr"`
		Host       string         `xml:"host,attr"`
		Port       string         `xml:"port,attr"`
		SSL        string         `xml:"ssl,attr"`
		AlertItems []zapAlertItem `xml:"alerts>alertitem"`
	}
	type zapReport struct {
		XMLName xml.Name `xml:"OWASPZAPReport"`
		Version string   `xml:"version,attr"`
		Site    zapSite  `xml:"site"`
	}

	items := make([]zapAlertItem, 0, len(report.Findings))
	for _, finding := range report.Findings {
		items = append(items, zapAlertItem{
			Name:     finding.Title,
			Risk:     strings.ToUpper(strings.ToLower(finding.Severity)[:1]) + strings.ToLower(finding.Severity)[1:],
			Desc:     finding.Description,
			URI:      finding.Target,
			Evidence: finding.Evidence,
		})
	}

	targetHost := "bbpts.local"
	if len(report.Findings) > 0 {
		targetHost = report.Findings[0].Target
		if strings.Contains(targetHost, "://") {
			if u, err := url.Parse(targetHost); err == nil {
				targetHost = u.Host
			}
		}
		if idx := strings.IndexByte(targetHost, ':'); idx >= 0 {
			targetHost = targetHost[:idx]
		}
	}

	zap := zapReport{
		Version: "2.0",
		Site: zapSite{
			Name:       "bbpts",
			Host:       targetHost,
			Port:       "443",
			SSL:        "true",
			AlertItems: items,
		},
	}
	data, err := xml.MarshalIndent(zap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}
