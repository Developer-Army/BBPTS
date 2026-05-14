// Package report provides comprehensive report generation for BBPTS.
// It exports findings to multiple formats: Markdown, HTML, JSON, and integrates
// with security tools like Burp Suite, Caido, and OWASP ZAP for seamless workflow.
package ui

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// ReportConfig holds configuration for report generation
type ReportConfig struct {
	OutputPath    string
	IncludeBurp   bool
	IncludeCaido  bool
	IncludeZAP    bool
	IncludeHTML   bool
	IncludeJSON   bool
	Verbose       bool
	MinimumScore  int
	BugBountyType string // "standard", "h1", "intigriti", "bugcrowd", etc.
}

// Report represents a comprehensive vulnerability report
type Report struct {
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	GeneratedAt     time.Time         `json:"generated_at"`
	ScanDuration    string            `json:"scan_duration"`
	TargetCount     int               `json:"target_count"`
	FindingCount    int               `json:"finding_count"`
	CriticalCount   int               `json:"critical_count"`
	HighCount       int               `json:"high_count"`
	MediumCount     int               `json:"medium_count"`
	LowCount        int               `json:"low_count"`
	Findings        []DetailedFinding `json:"findings"`
	Statistics      ReportStatistics  `json:"statistics"`
	Recommendations []string          `json:"recommendations"`
	Executive       ExecutiveSummary  `json:"executive_summary"`
}

// DetailedFinding represents a single finding with comprehensive details
type DetailedFinding struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Severity     string    `json:"severity"`
	Score        int       `json:"score"`
	Target       string    `json:"target"`
	Evidence     string    `json:"evidence"`
	Impact       string    `json:"impact"`
	Remediation  string    `json:"remediation"`
	References   []string  `json:"references"`
	Tags         []string  `json:"tags"`
	Sources      []string  `json:"sources"`
	DiscoveredAt time.Time `json:"discovered_at"`
	Effort       string    `json:"effort"` // "low", "medium", "high"
	Priority     string    `json:"priority"`
}

// ReportStatistics holds statistical information about the scan
type ReportStatistics struct {
	TotalTargets      int            `json:"total_targets"`
	TotalSubdomains   int            `json:"total_subdomains"`
	TotalEndpoints    int            `json:"total_endpoints"`
	TotalFindings     int            `json:"total_findings"`
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	TopTools          map[string]int `json:"top_tools"`
	TopTargets        map[string]int `json:"top_targets_by_findings"`
	DiscoveryTimeline map[string]int `json:"discovery_timeline"`
}

// ExecutiveSummary provides a high-level overview
type ExecutiveSummary struct {
	OverallRisk      string          `json:"overall_risk"`
	KeyFindings      []string        `json:"key_findings"`
	ImmediateActions []string        `json:"immediate_actions"`
	LongTermActions  []string        `json:"long_term_actions"`
	ComplianceStatus map[string]bool `json:"compliance_status"`
}

// ReportGenerator generates comprehensive security reports
type ReportGenerator struct {
	config ReportConfig
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(config ReportConfig) *ReportGenerator {
	return &ReportGenerator{config: config}
}

// GenerateFullReport creates comprehensive reports in all configured formats
func (rg *ReportGenerator) GenerateFullReport(insights []analyze.Insight, events []recon.Event) error {
	report := rg.buildReport(insights, events)

	// Generate JSON report
	if rg.config.IncludeJSON {
		if err := rg.generateJSONReport(report); err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}
	}

	// Generate Markdown report
	if err := rg.generateMarkdownReport(report); err != nil {
		return fmt.Errorf("failed to generate Markdown report: %w", err)
	}

	// Generate HTML report
	if rg.config.IncludeHTML {
		if err := rg.generateHTMLReport(report); err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}
	}

	// Generate tool-specific exports
	if rg.config.IncludeBurp {
		if err := rg.exportForBurp(report); err != nil {
			return fmt.Errorf("failed to export for Burp: %w", err)
		}
	}

	if rg.config.IncludeCaido {
		if err := rg.exportForCaido(report); err != nil {
			return fmt.Errorf("failed to export for Caido: %w", err)
		}
	}

	if rg.config.IncludeZAP {
		if err := rg.exportForZAP(report); err != nil {
			return fmt.Errorf("failed to export for ZAP: %w", err)
		}
	}

	// Always generate the interactive Attack Surface Graph if HTML is enabled
	if rg.config.IncludeHTML {
		if err := rg.generateAttackSurfaceGraph(events); err != nil {
			return fmt.Errorf("failed to generate attack surface graph: %w", err)
		}
	}

	return nil
}

// buildReport constructs the report structure from insights and events
func (rg *ReportGenerator) buildReport(insights []analyze.Insight, events []recon.Event) *Report {
	findings := rg.convertInsightsToFindings(insights, events)

	// Count severities
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}

	// Sort findings by severity and score
	sort.Slice(findings, func(i, j int) bool {
		severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
		if severityOrder[findings[i].Severity] != severityOrder[findings[j].Severity] {
			return severityOrder[findings[i].Severity] > severityOrder[findings[j].Severity]
		}
		return findings[i].Score > findings[j].Score
	})

	report := &Report{
		Title:           fmt.Sprintf("BBPTS Security Assessment Report - %s", time.Now().Format("2006-01-02")),
		Description:     "Comprehensive reconnaissance and vulnerability assessment report",
		GeneratedAt:     time.Now(),
		TargetCount:     len(insights),
		FindingCount:    len(findings),
		CriticalCount:   criticalCount,
		HighCount:       highCount,
		MediumCount:     mediumCount,
		LowCount:        lowCount,
		Findings:        findings,
		Statistics:      rg.buildStatistics(insights, events),
		Recommendations: rg.buildRecommendations(findings),
		Executive:       rg.buildExecutiveSummary(findings),
	}

	return report
}

// convertInsightsToFindings converts analyze.Insight to DetailedFinding
func (rg *ReportGenerator) convertInsightsToFindings(insights []analyze.Insight, events []recon.Event) []DetailedFinding {
	findings := []DetailedFinding{}
	eventMap := make(map[string][]recon.Event)

	for _, ev := range events {
		eventMap[ev.Target] = append(eventMap[ev.Target], ev)
	}

	for _, insight := range insights {
		if insight.Score < rg.config.MinimumScore {
			continue
		}

		relatedEvents := eventMap[insight.Host]
		var sourceList []string
		if len(insight.Sources) > 0 {
			sourceList = append(sourceList, insight.Sources...)
		} else {
			sources := make(map[string]bool)
			for _, ev := range relatedEvents {
				sources[ev.Source] = true
			}
			sourceList = make([]string, 0, len(sources))
			for source := range sources {
				sourceList = append(sourceList, source)
			}
			sort.Strings(sourceList)
		}

		// Filter out internal "source: xxx" tokens from reasons before building the report.
		cleanReasons := filterSourceReasons(insight.Reasons)

		finding := DetailedFinding{
			ID:           fmt.Sprintf("FINDING-%d", len(findings)+1),
			Title:        fmt.Sprintf("Reconnaissance finding on %s", insight.Host),
			Description:  strings.Join(cleanReasons, "; "),
			Severity:     insight.Priority,
			Score:        insight.Score,
			Target:       insight.Host,
			Evidence:     fmt.Sprintf("Found through: %s", strings.Join(sourceList, ", ")),
			Tags:         insight.Tags,
			Sources:      sourceList,
			DiscoveredAt: time.Now(),
			Priority:     insight.Priority,
		}

		// Store suggested tests directly as structured data for checklist rendering.
		if len(insight.SuggestedTests) > 0 {
			finding.Remediation = "Suggested security tests: " + strings.Join(insight.SuggestedTests, "\x00")
		}

		findings = append(findings, finding)
	}

	return findings
}

// buildStatistics creates statistical summary
func (rg *ReportGenerator) buildStatistics(insights []analyze.Insight, events []recon.Event) ReportStatistics {
	stats := ReportStatistics{
		TotalTargets:      len(insights),
		TotalFindings:     len(insights),
		SeverityBreakdown: make(map[string]int),
		TopTools:          make(map[string]int),
		TopTargets:        make(map[string]int),
		DiscoveryTimeline: make(map[string]int),
	}

	for _, insight := range insights {
		stats.SeverityBreakdown[insight.Priority]++
		for _, source := range insight.Reasons {
			if strings.Contains(source, "source:") {
				tool := strings.TrimPrefix(source, "source: ")
				stats.TopTools[tool]++
			}
		}
	}

	return stats
}

// buildRecommendations creates actionable recommendations
func (rg *ReportGenerator) buildRecommendations(findings []DetailedFinding) []string {
	recommendations := []string{
		"Prioritize remediation of critical severity findings immediately",
		"Implement Web Application Firewall (WAF) for discovered endpoints",
		"Conduct manual penetration testing on high-value targets",
		"Establish continuous monitoring for new subdomain discoveries",
		"Implement security headers on all discovered assets",
		"Regular security patching and vulnerability management",
		"Multi-factor authentication for administrative interfaces",
	}

	return recommendations
}

// buildExecutiveSummary creates an executive summary
func (rg *ReportGenerator) buildExecutiveSummary(findings []DetailedFinding) ExecutiveSummary {
	critical := 0
	high := 0

	for _, f := range findings {
		if strings.ToLower(f.Severity) == "critical" {
			critical++
		} else if strings.ToLower(f.Severity) == "high" {
			high++
		}
	}

	riskLevel := "Low"
	if critical > 0 {
		riskLevel = "Critical"
	} else if high > 0 {
		riskLevel = "High"
	}

	summary := ExecutiveSummary{
		OverallRisk: riskLevel,
		KeyFindings: []string{
			fmt.Sprintf("Identified %d critical vulnerabilities requiring immediate attention", critical),
			fmt.Sprintf("Discovered %d high-severity issues", high),
			"Multiple reconnaissance data points confirm active services",
		},
		ImmediateActions: []string{
			"Address critical findings within 24 hours",
			"Notify security team of findings",
			"Begin triage and impact assessment",
		},
		LongTermActions: []string{
			"Establish continuous monitoring program",
			"Implement infrastructure hardening",
			"Develop incident response procedures",
		},
		ComplianceStatus: map[string]bool{
			"OWASP": true,
			"CWE":   true,
			"CVE":   false,
		},
	}

	return summary
}

// generateJSONReport exports report as JSON
func (rg *ReportGenerator) generateJSONReport(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// generateMarkdownReport exports report as Markdown
func (rg *ReportGenerator) generateMarkdownReport(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.md")

	content := fmt.Sprintf("# 🛡️ %s\n\n", report.Title)
	content += fmt.Sprintf("> **Generated:** %s  \n", report.GeneratedAt.Format(time.RFC1123))
	content += fmt.Sprintf("> **Risk Level:** %s | **Targets:** %d | **Findings:** %d\n\n",
		report.Executive.OverallRisk, report.TargetCount, report.FindingCount)

	content += "---\n\n## 📊 Executive Summary\n\n"
	content += fmt.Sprintf("| Critical | High | Medium | Low |\n| :---: | :---: | :---: | :---: |\n| %d | %d | %d | %d |\n\n",
		report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)

	content += "### Key Highlights\n"
	for _, highlight := range report.Executive.KeyFindings {
		content += fmt.Sprintf("- %s\n", highlight)
	}

	content += "\n---\n\n## 🎯 Detailed Findings\n\n"

	for _, finding := range report.Findings {
		severityEmoji := "⚪"
		switch strings.ToLower(finding.Severity) {
		case "critical":
			severityEmoji = "🔴"
		case "high":
			severityEmoji = "🟠"
		case "medium":
			severityEmoji = "🟡"
		case "low":
			severityEmoji = "🔵"
		}

		content += fmt.Sprintf("<details>\n<summary><b>%s %s</b> (Score: %d)</summary>\n\n",
			severityEmoji, finding.Target, finding.Score)

		content += "### 🔍 Security Analysis\n"
		for _, reason := range strings.Split(finding.Description, "; ") {
			content += fmt.Sprintf("- %s\n", reason)
		}
		content += "\n"

		if finding.Evidence != "" {
			content += "### 🔗 Discovery Context\n"
			content += finding.Evidence + "\n\n"
		}

		if finding.Remediation != "" {
			content += "### 📝 Recommended Testing Checklist\n"
			if strings.HasPrefix(finding.Remediation, "Suggested security tests: ") {
				tests := strings.TrimPrefix(finding.Remediation, "Suggested security tests: ")
				// Each test is separated by NUL; this preserves commas/parens inside test names.
				for _, test := range strings.Split(tests, "\x00") {
					test = strings.TrimSpace(test)
					if test != "" {
						content += fmt.Sprintf("- [ ] %s\n", test)
					}
				}
			} else {
				content += finding.Remediation + "\n"
			}
			content += "\n"
		}

		content += "</details>\n\n"
	}

	content += "---\n\n## 🛠️ Strategic Recommendations\n\n"
	for i, rec := range report.Recommendations {
		content += fmt.Sprintf("%d. %s\n", i+1, rec)
	}

	content += "\n---\n*Report generated by BBPTS Enterprise Reporting Engine*"

	return os.WriteFile(outputPath, []byte(content), 0644)
}

// generateHTMLReport exports report as HTML
func (rg *ReportGenerator) generateHTMLReport(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.html")

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        :root {
            --primary: #6366f1;
            --secondary: #4f46e5;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #1e293b;
            --text-sub: #64748b;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #10b981;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', system-ui, sans-serif; background-color: var(--bg); color: var(--text-main); line-height: 1.5; }
        .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
        header { 
            background: linear-gradient(135deg, #1e293b 0%%, #334155 100%%); 
            color: white; 
            padding: 60px 40px; 
            border-radius: 16px; 
            margin-bottom: 40px;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1);
        }
        h1 { font-size: 2.25rem; font-weight: 800; letter-spacing: -0.025em; margin-bottom: 8px; }
        .meta { display: flex; gap: 20px; font-size: 0.875rem; opacity: 0.8; }
        
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 40px; }
        .stat-card { 
            background: var(--card-bg); 
            padding: 24px; 
            border-radius: 12px; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number { font-size: 1.875rem; font-weight: 700; margin-bottom: 4px; }
        .stat-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--text-sub); }
        
        .finding { 
            background: var(--card-bg); 
            border-radius: 12px; 
            padding: 32px; 
            margin-bottom: 24px; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid #e2e8f0;
            transition: transform 0.2s;
        }
        .finding:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); }
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
        .severity-badge { 
            padding: 4px 12px; 
            border-radius: 9999px; 
            font-size: 0.75rem; 
            font-weight: 700; 
            text-transform: uppercase;
        }
        
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #ffedd5; color: #9a3412; }
        .badge-medium { background: #fef3c7; color: #92400e; }
        .badge-low { background: #d1fae5; color: #065f46; }
        
        .finding h3 { font-size: 1.25rem; font-weight: 700; margin-bottom: 8px; }
        .finding-meta { font-size: 0.875rem; color: var(--text-sub); margin-bottom: 16px; }
        .finding-section { margin-top: 20px; padding-top: 20px; border-top: 1px solid #f1f5f9; }
        .section-label { font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: var(--text-sub); margin-bottom: 8px; }
        
        footer { text-align: center; margin-top: 60px; padding: 40px 0; border-top: 1px solid #e2e8f0; color: var(--text-sub); font-size: 0.875rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>%s</h1>
            <div class="meta">
                <p>Generated: %s</p>
                <p>Overall Risk: <strong>%s</strong></p>
            </div>
        </header>

        <section>
            <h2>Statistics</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">%d</div>
                    <div class="stat-label">Targets Assessed</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-number">%d</div>
                    <div class="stat-label">Critical Findings</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">%d</div>
                    <div class="stat-label">High Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">%d</div>
                    <div class="stat-label">Medium Findings</div>
                </div>
            </div>
        </section>

        <section>
            <h2>Detailed Findings</h2>
            %s
        </section>

        <footer>
            <p>&copy; 2024 BBPTS - Bug Bounty Program Tool Set</p>
        </footer>
    </div>
</body>
</html>`,
		report.Title,
		report.Title,
		report.GeneratedAt.Format("2006-01-02 15:04:05"),
		report.Executive.OverallRisk,
		report.TargetCount,
		report.CriticalCount,
		report.HighCount,
		report.MediumCount,
		rg.generateFindingsHTML(report.Findings))

	return os.WriteFile(outputPath, []byte(htmlContent), 0644)
}

// generateFindingsHTML creates HTML for findings
func (rg *ReportGenerator) generateFindingsHTML(findings []DetailedFinding) string {
	html := ""
	for _, finding := range findings {
		severity := strings.ToLower(finding.Severity)
		html += fmt.Sprintf(`
        <div class="finding %s">
            <div class="finding-header">
                <h3>%s</h3>
                <span class="severity-badge %s">%s</span>
            </div>
            <p><strong>Target:</strong> %s</p>
            <p><strong>Score:</strong> %d/100</p>
            <p><strong>Description:</strong> %s</p>
            <p><strong>Evidence:</strong> %s</p>
        </div>
`, severity, finding.Title, severity, finding.Severity, finding.Target, finding.Score,
			finding.Description, finding.Evidence)
	}
	return html
}

// exportForBurp exports findings for Burp Suite import
func (rg *ReportGenerator) exportForBurp(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "burp-import.xml")
	issues := BurpIssues{Issues: make([]BurpIssue, 0, len(report.Findings))}
	for _, finding := range report.Findings {
		issues.Issues = append(issues.Issues, BurpIssue{
			Name:            finding.Title,
			Host:            finding.Target,
			Path:            finding.Target,
			Location:        finding.Target,
			Severity:        normalizeSeverity(finding.Severity),
			Confidence:      "Firm",
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

	data, err := json.MarshalIndent(map[string]any{
		"generated_at": report.GeneratedAt.UTC().Format(time.RFC3339),
		"findings":     out,
	}, "", "  ")
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
			Risk:     strings.Title(strings.ToLower(finding.Severity)),
			Desc:     finding.Description,
			URI:      finding.Target,
			Evidence: finding.Evidence,
		})
	}

	zap := zapReport{
		Version: "2.0",
		Site: zapSite{
			Name:       "bbpts",
			Host:       "bbpts.local",
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

func normalizeSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "High"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Information"
	}
}

// filterSourceReasons removes internal "source: xxx" tracking tokens from
// the reasons list. These are useful internally but should not appear in
// user-facing reports. If all reasons are source tokens, a summary count
// is returned instead.
func filterSourceReasons(reasons []string) []string {
	clean := make([]string, 0, len(reasons))
	sourceCount := 0
	for _, r := range reasons {
		if strings.HasPrefix(r, "source: ") {
			sourceCount++
			continue
		}
		clean = append(clean, r)
	}
	if len(clean) == 0 && sourceCount > 0 {
		clean = append(clean, fmt.Sprintf("Corroborated by %d tool signals", sourceCount))
	}
	return clean
}

// generateAttackSurfaceGraph exports an interactive vis.js graph of the discovered assets
func (rg *ReportGenerator) generateAttackSurfaceGraph(events []recon.Event) error {
	outputPath := filepath.Join(rg.config.OutputPath, "attack_surface_graph.html")

	type Node struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Group string `json:"group"`
	}

	type Edge struct {
		From string `json:"from"`
		To   string `json:"to"`
	}

	nodeMap := make(map[string]Node)
	var edges []Edge

	// Helper to extract base domain
	getBaseDomain := func(urlStr string) string {
		trimmed := strings.TrimPrefix(urlStr, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 {
			host := strings.Split(parts[0], ":")[0]
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				return parts[len(parts)-2] + "." + parts[len(parts)-1]
			}
			return host
		}
		return ""
	}

	for _, ev := range events {
		target := strings.TrimSpace(ev.Target)
		if target == "" {
			continue
		}

		baseDomain := getBaseDomain(target)
		if baseDomain != "" && baseDomain != target {
			nodeMap[baseDomain] = Node{ID: baseDomain, Label: baseDomain, Group: "domain"}
		}

		if strings.HasPrefix(target, "http") {
			// Extract host
			trimmed := strings.TrimPrefix(target, "http://")
			trimmed = strings.TrimPrefix(trimmed, "https://")
			host := strings.Split(trimmed, "/")[0]

			nodeMap[host] = Node{ID: host, Label: host, Group: "subdomain"}
			nodeMap[target] = Node{ID: target, Label: target, Group: "url"}

			if baseDomain != "" && host != baseDomain {
				edges = append(edges, Edge{From: baseDomain, To: host})
			}
			edges = append(edges, Edge{From: host, To: target})
		} else {
			nodeMap[target] = Node{ID: target, Label: target, Group: "asset"}
			if baseDomain != "" {
				edges = append(edges, Edge{From: baseDomain, To: target})
			}
		}
	}

	var nodes []Node
	for _, n := range nodeMap {
		nodes = append(nodes, n)
	}

	nodesJSON, _ := json.Marshal(nodes)
	edgesJSON, _ := json.Marshal(edges)

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>BBPTS Attack Surface Graph</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        body, html { margin: 0; padding: 0; width: 100%%; height: 100%%; background-color: #0f172a; color: white; font-family: sans-serif; }
        #mynetwork { width: 100%%; height: 100%%; border: none; }
        .header { position: absolute; top: 20px; left: 20px; z-index: 100; pointer-events: none; }
        h1 { margin: 0; font-size: 24px; color: #38bdf8; }
        p { margin: 5px 0 0 0; color: #94a3b8; }
    </style>
</head>
<body>
<div class="header">
    <h1>Attack Surface Graph</h1>
    <p>Interactive visualization of discovered assets</p>
</div>
<div id="mynetwork"></div>
<script type="text/javascript">
    var nodes = new vis.DataSet(%s);
    var edges = new vis.DataSet(%s);

    var container = document.getElementById('mynetwork');
    var data = { nodes: nodes, edges: edges };
    var options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: { color: '#e2e8f0', size: 14 }
        },
        edges: {
            color: '#475569',
            smooth: { type: 'continuous' }
        },
        groups: {
            domain: { color: { background: '#ef4444', border: '#b91c1c' }, size: 24 },
            subdomain: { color: { background: '#f59e0b', border: '#b45309' }, size: 20 },
            url: { color: { background: '#10b981', border: '#047857' }, size: 12 },
            asset: { color: { background: '#6366f1', border: '#4338ca' }, size: 16 }
        },
        physics: {
            forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 100, springConstant: 0.08 },
            maxVelocity: 50,
            solver: 'forceAtlas2Based',
            timestep: 0.35,
            stabilization: { iterations: 150 }
        }
    };
    var network = new vis.Network(container, data, options);
</script>
</body>
</html>`, string(nodesJSON), string(edgesJSON))

	return os.WriteFile(outputPath, []byte(htmlContent), 0644)
}
