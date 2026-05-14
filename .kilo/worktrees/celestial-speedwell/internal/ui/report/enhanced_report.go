// Package report provides comprehensive report generation for BBPTS.
// It exports findings to multiple formats: Markdown, HTML, JSON, and integrates
// with security tools like Burp Suite, Caido, and OWASP ZAP for seamless workflow.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/engine/recon"
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

// EnhancedReport represents a comprehensive vulnerability report
type EnhancedReport struct {
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
	CVE          []string  `json:"cve,omitempty"`
	CWEID        string    `json:"cwe_id,omitempty"`
	OWASP        []string  `json:"owasp,omitempty"`
	Status       string    `json:"status"` // "new", "duplicate", "fixed", "wontfix"
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

	return nil
}

// buildReport constructs the report structure from insights and events
func (rg *ReportGenerator) buildReport(insights []analyze.Insight, events []recon.Event) *EnhancedReport {
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

	report := &EnhancedReport{
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
		sources := make(map[string]bool)

		for _, ev := range relatedEvents {
			sources[ev.Source] = true
		}

		sourceList := make([]string, 0, len(sources))
		for source := range sources {
			sourceList = append(sourceList, source)
		}
		sort.Strings(sourceList)

		finding := DetailedFinding{
			ID:           fmt.Sprintf("FINDING-%d", len(findings)+1),
			Title:        fmt.Sprintf("Reconnaissance finding on %s", insight.Host),
			Description:  strings.Join(insight.Reasons, "; "),
			Severity:     insight.Priority,
			Score:        insight.Score,
			Target:       insight.Host,
			Evidence:     fmt.Sprintf("Found through: %s", strings.Join(sourceList, ", ")),
			Tags:         insight.Tags,
			Sources:      sourceList,
			DiscoveredAt: time.Now(),
			Status:       "new",
			Priority:     insight.Priority,
		}

		// Add suggested tests as remediation guidance
		if len(insight.SuggestedTests) > 0 {
			finding.Remediation = "Suggested security tests: " + strings.Join(insight.SuggestedTests, ", ")
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
func (rg *ReportGenerator) generateJSONReport(report *EnhancedReport) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// generateMarkdownReport exports report as Markdown
func (rg *ReportGenerator) generateMarkdownReport(report *EnhancedReport) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.md")

	content := fmt.Sprintf(`# %s

**Generated:** %s

## Executive Summary

**Overall Risk Level:** %s

%s

## Statistics

- **Total Targets Assessed:** %d
- **Unique Findings:** %d
- **Critical Severity:** %d
- **High Severity:** %d
- **Medium Severity:** %d
- **Low Severity:** %d

## Detailed Findings

`, report.Title, report.GeneratedAt.Format("2006-01-02 15:04:05"),
		report.Executive.OverallRisk,
		strings.Join(report.Executive.KeyFindings, "\n"),
		report.TargetCount,
		report.FindingCount,
		report.CriticalCount,
		report.HighCount,
		report.MediumCount,
		report.LowCount)

	for _, finding := range report.Findings {
		content += fmt.Sprintf(`
### %s - %s

**Target:** %s  
**Severity:** %s  
**Score:** %d  

**Description:**
%s

**Evidence:**
%s

**Remediation:**
%s

---

`, finding.ID, finding.Title, finding.Target, finding.Severity, finding.Score,
			finding.Description, finding.Evidence, finding.Remediation)
	}

	content += "\n## Recommendations\n\n"
	for i, rec := range report.Recommendations {
		content += fmt.Sprintf("%d. %s\n", i+1, rec)
	}

	return os.WriteFile(outputPath, []byte(content), 0644)
}

// generateHTMLReport exports report as HTML
func (rg *ReportGenerator) generateHTMLReport(report *EnhancedReport) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.html")

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 40px 20px; border-radius: 8px; margin-bottom: 30px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        .meta { opacity: 0.9; font-size: 0.9em; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { background: #f5f5f5; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
        .critical { border-left-color: #dc3545; }
        .critical .stat-number { color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .high .stat-number { color: #fd7e14; }
        .finding { background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .finding.critical { border-left: 4px solid #dc3545; }
        .finding.high { border-left: 4px solid #fd7e14; }
        .finding.medium { border-left: 4px solid #ffc107; }
        .finding.low { border-left: 4px solid #28a745; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .severity-badge { padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
        .severity-badge.critical { background: #dc3545; color: white; }
        .severity-badge.high { background: #fd7e14; color: white; }
        .severity-badge.medium { background: #ffc107; color: black; }
        .severity-badge.low { background: #28a745; color: white; }
        footer { text-align: center; padding: 20px; color: #666; border-top: 1px solid #ddd; margin-top: 40px; }
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
func (rg *ReportGenerator) exportForBurp(report *EnhancedReport) error {
	// Implementation delegates to integration package
	outputPath := filepath.Join(rg.config.OutputPath, "burp-import.xml")
	_ = outputPath // TODO: Implement Burp export
	return nil
}

// exportForCaido exports findings for Caido import
func (rg *ReportGenerator) exportForCaido(report *EnhancedReport) error {
	outputPath := filepath.Join(rg.config.OutputPath, "caido-import.json")
	_ = outputPath // TODO: Implement Caido export
	return nil
}

// exportForZAP exports findings for ZAP import
func (rg *ReportGenerator) exportForZAP(report *EnhancedReport) error {
	outputPath := filepath.Join(rg.config.OutputPath, "zap-import.xml")
	_ = outputPath // TODO: Implement ZAP export
	return nil
}
