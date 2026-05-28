// Package report provides comprehensive report generation for BBPTS.
// It exports findings to multiple formats: Markdown, HTML, JSON, and integrates
// with security tools like Burp Suite, Caido, and OWASP ZAP for seamless workflow.
package ui

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// ReportConfig holds configuration for report generation
type ReportConfig struct {
	OutputPath    string
	MarkdownPath  string
	IncludeBurp   bool
	IncludeCaido  bool
	IncludeZAP    bool
	IncludeHTML   bool
	IncludeJSON   bool
	Verbose       bool
	MinimumScore  int
	BugBountyType string // "standard", "h1", "intigriti", "bugcrowd", etc.
	TemplatePath  string // Optional custom Go text/template file for HTML report
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

	// Generate custom template report if a template path is provided
	if rg.config.TemplatePath != "" {
		if err := rg.generateCustomTemplateReport(report); err != nil {
			slog.Warn("failed to generate custom template report", "error", err, "template", rg.config.TemplatePath)
		}
	}

	return nil
}

// generateCustomTemplateReport loads a user-supplied Go text/template file
// and executes it with the report data, writing output to custom_report.html.
func (rg *ReportGenerator) generateCustomTemplateReport(report *Report) error {
	tmplData, err := os.ReadFile(rg.config.TemplatePath)
	if err != nil {
		return fmt.Errorf("failed to read custom template %s: %w", rg.config.TemplatePath, err)
	}

	tmpl, err := template.New("custom").Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("failed to parse custom template: %w", err)
	}

	outPath := filepath.Join(rg.config.OutputPath, "custom_report.html")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create custom report file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, report); err != nil {
		return fmt.Errorf("failed to execute custom template: %w", err)
	}

	slog.Info("custom template report generated", "path", outPath)
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

		var evidenceParts []string
		if len(insight.Evidence) > 0 {
			evidenceParts = append(evidenceParts, insight.Evidence...)
		}
		if len(sourceList) > 0 {
			evidenceParts = append(evidenceParts, fmt.Sprintf("Discovered by: %s", strings.Join(sourceList, ", ")))
		}

		finding := DetailedFinding{
			ID:           fmt.Sprintf("FINDING-%d", len(findings)+1),
			Title:        fmt.Sprintf("Reconnaissance finding on %s", insight.Host),
			Description:  strings.Join(cleanReasons, "; "),
			Severity:     insight.Priority,
			Score:        insight.Score,
			Target:       insight.Host,
			Evidence:     strings.Join(evidenceParts, " | "),
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
	outputPath := rg.config.MarkdownPath
	if outputPath == "" {
		outputPath = filepath.Join(rg.config.OutputPath, "report.md")
	}

	content := fmt.Sprintf("# ️ %s\n\n", report.Title)
	content += fmt.Sprintf("> **Generated:** %s  \n", report.GeneratedAt.Format(time.RFC1123))
	content += fmt.Sprintf("> **Risk Level:** %s | **Targets:** %d | **Findings:** %d\n\n",
		report.Executive.OverallRisk, report.TargetCount, report.FindingCount)

	content += "---\n\n## 🚀 Quick Start Guide for Beginners\n\n"
	content += "1. **Import Configs**: Load `burp-import.xml` in Burp Suite (`Project` > `Import scan items`) or `caido-import.json` in Caido (`Workspaces` > `Import`).\n"
	content += "2. **Open Target**: Click target domain links or evidence URLs below to open targets in your browser configured with your proxy.\n"
	content += "3. **Run Checklists**: Follow step-by-step checklists under each finding. Check them off as you test.\n\n"

	content += "---\n\n## 📊 Executive Summary\n\n"
	content += fmt.Sprintf("| Critical | High | Medium | Low |\n| :---: | :---: | :---: | :---: |\n| %d | %d | %d | %d |\n\n",
		report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)

	content += "### Key Highlights\n"
	for _, highlight := range report.Executive.KeyFindings {
		content += fmt.Sprintf("- %s\n", highlight)
	}

	content += "\n---\n\n##  Detailed Findings\n\n"

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

		targetURL := makeURL(finding.Target)
		content += fmt.Sprintf("<details>\n<summary><b>%s <a href=\"%s\">%s</a></b> (Score: %d)</summary>\n\n",
			severityEmoji, targetURL, finding.Target, finding.Score)

		content += "###  Security Analysis\n"
		for _, reason := range strings.Split(finding.Description, "; ") {
			content += fmt.Sprintf("- %s\n", reason)
		}
		content += "\n"

		if finding.Evidence != "" {
			content += "### 🔗 Discovery Context / Evidence URLs\n"
			parts := strings.Split(finding.Evidence, " | ")
			var urls []string
			discoveredBy := ""
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "Discovered by:") {
					discoveredBy = p
				} else if p != "" {
					urls = append(urls, p)
				}
			}
			if discoveredBy != "" {
				content += fmt.Sprintf("*%s*\n", discoveredBy)
			}
			for _, u := range urls {
				content += fmt.Sprintf("- [%s](%s)\n", u, makeURL(u))
			}
			content += "\n"
		}

		if finding.Remediation != "" {
			content += "### 📝 Recommended Testing Checklist\n"
			if strings.HasPrefix(finding.Remediation, "Suggested security tests: ") {
				tests := strings.TrimPrefix(finding.Remediation, "Suggested security tests: ")
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

		content += "### 🎯 Next Steps\n"
		switch strings.ToLower(finding.Severity) {
		case "critical", "high":
			content += "> **🔴 Next Action:** High risk target. Open Burp/Caido proxy. Fuzz the parameters listed in the findings with payloads (SQLi probes, SSRF endpoints, XSS scripts). Pay close attention to database-related input fields.\n\n"
		case "medium":
			content += "> **🟡 Next Action:** Active endpoints found. Verify authentication bypass mechanisms, look for IDOR vulnerabilities on object IDs in paths, or check CORS parameters for wildcards.\n\n"
		default:
			content += "> **🔵 Next Action:** Low priority/recon data. Check for directory listings or sensitive technology disclosures. Verify if security headers like CSP/HSTS are correctly set.\n\n"
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

func makeURL(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		return target
	}
	return "https://" + target
}

// generateHTMLReport exports report as HTML
func (rg *ReportGenerator) generateHTMLReport(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.html")

	findingsHTML := rg.generateFindingsHTML(report.Findings)
	recsHTML := rg.generateRecommendationsHTML(report.Recommendations)

	maxCount := report.CriticalCount
	if report.HighCount > maxCount { maxCount = report.HighCount }
	if report.MediumCount > maxCount { maxCount = report.MediumCount }
	if report.LowCount > maxCount { maxCount = report.LowCount }
	if maxCount == 0 { maxCount = 1 }
	critW := report.CriticalCount * 100 / maxCount
	highW := report.HighCount * 100 / maxCount
	medW  := report.MediumCount * 100 / maxCount
	lowW  := report.LowCount * 100 / maxCount

	riskBadgeClass := "badge-low"
	switch report.Executive.OverallRisk {
	case "Critical": riskBadgeClass = "badge-critical"
	case "High":     riskBadgeClass = "badge-high"
	case "Medium":   riskBadgeClass = "badge-medium"
	}

	critLabel := ""
	if report.CriticalCount > 0 { critLabel = fmt.Sprintf("%d", report.CriticalCount) }
	highLabel := ""
	if report.HighCount > 0 { highLabel = fmt.Sprintf("%d", report.HighCount) }
	medLabel := ""
	if report.MediumCount > 0 { medLabel = fmt.Sprintf("%d", report.MediumCount) }
	lowLabel := ""
	if report.LowCount > 0 { lowLabel = fmt.Sprintf("%d", report.LowCount) }

	html := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>BBPTS Recon Report</title>
<style>
:root{--bg:#090d1a;--surface:#111827;--surface2:#1c2433;--border:#1f2d40;--text:#e2e8f0;--muted:#64748b;--accent:#38bdf8;--primary:#6366f1;--critical:#ef4444;--high:#fb923c;--medium:#fbbf24;--low:#34d399}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65;font-size:15px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1140px;margin:0 auto;padding:32px 20px}
.header{background:linear-gradient(135deg,#1e1b4b,#0f172a);border:1px solid var(--border);border-radius:16px;padding:40px 48px;margin-bottom:28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px}
.header h1{font-size:1.9rem;font-weight:800;letter-spacing:-.03em;margin-bottom:6px}
.header p{color:var(--muted);font-size:.9rem}
.risk-badge{padding:10px 22px;border-radius:9999px;font-size:.8rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em}
.badge-critical{background:rgba(239,68,68,.15);color:var(--critical);border:1px solid rgba(239,68,68,.35)}
.badge-high{background:rgba(251,146,60,.15);color:var(--high);border:1px solid rgba(251,146,60,.35)}
.badge-medium{background:rgba(251,191,36,.15);color:var(--medium);border:1px solid rgba(251,191,36,.35)}
.badge-low{background:rgba(52,211,153,.15);color:var(--low);border:1px solid rgba(52,211,153,.35)}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:28px}
.scard{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;transition:.2s}
.scard:hover{border-color:var(--accent);transform:translateY(-2px)}
.scard .num{font-size:2.3rem;font-weight:800;margin-bottom:4px}
.scard .lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.scard.c .num{color:var(--critical)}.scard.h .num{color:var(--high)}.scard.m .num{color:var(--medium)}.scard.l .num{color:var(--low)}
.chart-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:26px 30px;margin-bottom:28px}
.chart-section h2{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.bar-label{font-size:.78rem;font-weight:700;text-transform:uppercase;width:60px;flex-shrink:0}
.bar-track{flex:1;background:var(--surface2);border-radius:6px;height:20px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px;display:flex;align-items:center;justify-content:flex-end;padding-right:8px;font-size:.72rem;font-weight:700;color:rgba(0,0,0,.75)}
.bar-count{font-size:.82rem;font-weight:700;width:30px;text-align:right;flex-shrink:0}
.guide{background:var(--surface2);border:1px dashed var(--primary);border-radius:14px;padding:26px 30px;margin-bottom:28px}
.guide h2{font-size:1rem;font-weight:800;color:var(--accent);margin-bottom:16px}
.guide-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.gstep{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;position:relative}
.gstep-num{position:absolute;top:-10px;left:-10px;width:24px;height:24px;background:var(--primary);color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.78rem;box-shadow:0 0 8px var(--primary)}
.gstep h3{font-size:.9rem;font-weight:700;margin:4px 0 6px}
.gstep p,.gstep li{font-size:.8rem;color:var(--muted)}
.gstep ul{padding-left:12px}
.gstep code{background:rgba(99,102,241,.18);color:#a5b4fc;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.76rem}
.section-title{font-size:1.2rem;font-weight:800;margin-bottom:18px;padding-bottom:10px;border-bottom:2px solid var(--border)}
.finding{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:20px;overflow:hidden;transition:.2s}
.finding:hover{box-shadow:0 12px 28px rgba(0,0,0,.3)}
.finding-head{padding:18px 22px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;cursor:pointer;user-select:none}
.finding-host a{color:var(--text);font-size:1rem;font-weight:700}
.finding-host a:hover{color:var(--accent)}
.fmeta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev-badge{padding:4px 11px;border-radius:9999px;font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em}
.score-pill{background:var(--surface2);border:1px solid var(--border);border-radius:9999px;padding:3px 11px;font-size:.76rem;color:var(--muted)}
.score-pill strong{color:var(--text)}
.toggle-icon{font-size:1rem;color:var(--muted);transition:.2s;margin-left:6px}
.finding-body{padding:0 22px 22px;display:none;border-top:1px solid var(--border)}
.finding-body.open{display:block}
.fsection{margin-top:18px}
.fsection-label{font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.07em;color:var(--accent);margin-bottom:8px}
.reasons-list{list-style:none;display:flex;flex-direction:column;gap:5px}
.reasons-list li{padding-left:16px;position:relative;font-size:.88rem;color:#cbd5e1}
.reasons-list li::before{content:"›";position:absolute;left:0;color:var(--primary)}
.tag-list{display:flex;flex-wrap:wrap;gap:7px}
.tag{background:rgba(99,102,241,.1);color:#a5b4fc;border:1px solid rgba(99,102,241,.2);border-radius:9999px;padding:2px 9px;font-size:.72rem;font-weight:600}
.evidence-list{list-style:none;display:flex;flex-direction:column;gap:5px}
.evidence-list li{font-size:.8rem}
.evidence-list a{font-family:monospace;color:var(--accent);word-break:break-all}
.checklist{list-style:none;display:flex;flex-direction:column;gap:9px}
.checklist li label{display:flex;align-items:flex-start;gap:9px;cursor:pointer;font-size:.86rem;color:#cbd5e1}
.checklist li label:hover{color:var(--text)}
.checklist li input{width:1.05em;height:1.05em;accent-color:var(--primary);cursor:pointer;flex-shrink:0;margin-top:2px}
.checklist li input:checked+span{text-decoration:line-through;opacity:.45}
.next-action{border-left:4px solid var(--primary);background:rgba(99,102,241,.05);border-radius:0 8px 8px 0;padding:13px 16px;margin-top:16px;font-size:.86rem;color:#e2e8f0}
.next-action.sev-critical,.next-action.sev-high{border-left-color:var(--high)}
.next-action.sev-medium{border-left-color:var(--medium)}
.next-action.sev-low{border-left-color:var(--low)}
.sources-row{font-size:.8rem;color:var(--muted);margin-top:10px}
.recs{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:26px 30px;margin-bottom:28px}
.recs ol{padding-left:20px;color:#cbd5e1}
.recs ol li{margin-bottom:9px;font-size:.9rem}
.empty-state{text-align:center;padding:60px;color:var(--muted);background:var(--surface);border:1px dashed var(--border);border-radius:12px}
footer{text-align:center;padding:36px 0 16px;color:var(--muted);font-size:.8rem;border-top:1px solid var(--border);margin-top:16px}
</style>
</head>
<body>
<div class="wrap">

<header class="header">
  <div>
    <h1>🛡 BBPTS Recon Report</h1>
    <p>Generated ` + report.GeneratedAt.Format("2006-01-02 15:04 UTC") + ` &nbsp;·&nbsp; ` + fmt.Sprintf("%d targets", report.TargetCount) + `</p>
  </div>
  <span class="risk-badge ` + riskBadgeClass + `">Overall Risk: ` + report.Executive.OverallRisk + `</span>
</header>

<div class="summary-grid">
  <div class="scard"><div class="num">` + fmt.Sprintf("%d", report.TargetCount) + `</div><div class="lbl">Targets</div></div>
  <div class="scard c"><div class="num">` + fmt.Sprintf("%d", report.CriticalCount) + `</div><div class="lbl">Critical</div></div>
  <div class="scard h"><div class="num">` + fmt.Sprintf("%d", report.HighCount) + `</div><div class="lbl">High</div></div>
  <div class="scard m"><div class="num">` + fmt.Sprintf("%d", report.MediumCount) + `</div><div class="lbl">Medium</div></div>
  <div class="scard l"><div class="num">` + fmt.Sprintf("%d", report.LowCount) + `</div><div class="lbl">Low</div></div>
  <div class="scard"><div class="num">` + fmt.Sprintf("%d", report.FindingCount) + `</div><div class="lbl">Total</div></div>
</div>

<div class="chart-section">
  <h2>Severity Breakdown</h2>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--critical)">Critical</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", critW) + `%;background:var(--critical)">` + critLabel + `</div></div>
    <div class="bar-count" style="color:var(--critical)">` + fmt.Sprintf("%d", report.CriticalCount) + `</div>
  </div>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--high)">High</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", highW) + `%;background:var(--high)">` + highLabel + `</div></div>
    <div class="bar-count" style="color:var(--high)">` + fmt.Sprintf("%d", report.HighCount) + `</div>
  </div>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--medium)">Medium</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", medW) + `%;background:var(--medium)">` + medLabel + `</div></div>
    <div class="bar-count" style="color:var(--medium)">` + fmt.Sprintf("%d", report.MediumCount) + `</div>
  </div>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--low)">Low</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", lowW) + `%;background:var(--low)">` + lowLabel + `</div></div>
    <div class="bar-count" style="color:var(--low)">` + fmt.Sprintf("%d", report.LowCount) + `</div>
  </div>
</div>

<div class="guide">
  <h2>🚀 What To Do With This Report</h2>
  <div class="guide-grid">
    <div class="gstep"><div class="gstep-num">1</div><h3>Import Into Proxy</h3><ul><li><strong>Burp:</strong> Project &rarr; Import scan items &rarr; <code>burp-import.xml</code></li><li><strong>Caido:</strong> Workspaces &rarr; Import &rarr; <code>caido-import.json</code></li><li><strong>ZAP:</strong> Import <code>zap-import.xml</code></li></ul></div>
    <div class="gstep"><div class="gstep-num">2</div><h3>Understand the Score</h3><p>Each finding has a Risk Score (0&ndash;100). Higher = more attack surface signals. Start with anything above 70.</p></div>
    <div class="gstep"><div class="gstep-num">3</div><h3>Expand a Finding</h3><p>Click any card below to expand it. You&rsquo;ll see exactly <em>why</em> it scored high and what to test.</p></div>
    <div class="gstep"><div class="gstep-num">4</div><h3>Work the Checklist</h3><p>Each finding has checkboxes. Tick off tests as you go. Critical/High first. Look for parameterized URLs &mdash; main attack surface.</p></div>
  </div>
</div>

<div class="section-title">🔍 Detailed Findings</div>
` + findingsHTML + `

<div class="recs">
  <div class="section-title">🛠 Recommendations</div>
  <ol>` + recsHTML + `</ol>
</div>

<footer>BBPTS &mdash; Bug Bounty Pipeline &amp; Tracking System</footer>
</div>
<script>
document.querySelectorAll('.finding-head').forEach(function(h){
  h.addEventListener('click',function(){
    var b=h.nextElementSibling,i=h.querySelector('.toggle-icon');
    if(b){b.classList.toggle('open');if(i)i.textContent=b.classList.contains('open')?'▲':'▼'}
  });
});
var exp=0;
document.querySelectorAll('.finding').forEach(function(card){
  if(exp>=3)return;
  var badge=card.querySelector('.sev-badge');
  if(badge&&/critical|high/i.test(badge.textContent)){
    var b=card.querySelector('.finding-body'),i=card.querySelector('.toggle-icon');
    if(b){b.classList.add('open');exp++;}
    if(i)i.textContent='▲';
  }
});
</script>
</body>
</html>`

	return os.WriteFile(outputPath, []byte(html), 0644)
}

// generateRecommendationsHTML formatting helper
func (rg *ReportGenerator) generateRecommendationsHTML(recs []string) string {
	var sb strings.Builder
	for _, rec := range recs {
		sb.WriteString(fmt.Sprintf("<li>%s</li>", rec))
	}
	return sb.String()
}

// generateFindingsHTML renders individual finding cards.
func (rg *ReportGenerator) generateFindingsHTML(findings []DetailedFinding) string {
	if len(findings) == 0 {
		return `<div class="empty-state">No findings above the minimum score threshold.</div>`
	}
	var sb strings.Builder
	for idx, f := range findings {
		sev := strings.ToLower(f.Severity)
		if sev == "" { sev = "info" }
		color := severityColor(sev)
		targetURL := makeURL(f.Target)
		cbPrefix := fmt.Sprintf("f%d", idx)

		sb.WriteString(fmt.Sprintf(`<div class="finding sev-%s">`, sev))
		sb.WriteString(`<div class="finding-head">`)
		sb.WriteString(fmt.Sprintf(`<div class="finding-host"><a href="%s" target="_blank" rel="noopener">%s</a></div>`, targetURL, f.Target))
		sb.WriteString(`<div class="fmeta">`)
		sb.WriteString(fmt.Sprintf(`<span class="sev-badge" style="background:rgba(%s,.12);color:%s;border:1px solid rgba(%s,.3)">%s</span>`,
			hexToRGBComponents(color), color, hexToRGBComponents(color), strings.ToUpper(sev)))
		sb.WriteString(fmt.Sprintf(`<span class="score-pill">Score <strong>%d</strong>/100</span>`, f.Score))
		sb.WriteString(`<span class="toggle-icon">▼</span>`)
		sb.WriteString(`</div></div>`)

		sb.WriteString(`<div class="finding-body">`)

		reasons := filterEmpty(strings.Split(f.Description, "; "))
		if len(reasons) > 0 {
			sb.WriteString(`<div class="fsection"><div class="fsection-label">🔍 Why This Scored High</div><ul class="reasons-list">`)
			for _, r := range reasons { sb.WriteString(fmt.Sprintf(`<li>%s</li>`, r)) }
			sb.WriteString(`</ul></div>`)
		}

		if len(f.Tags) > 0 {
			sb.WriteString(`<div class="fsection"><div class="fsection-label">🏷 Attack Surface Tags</div><div class="tag-list">`)
			for _, tag := range f.Tags { sb.WriteString(fmt.Sprintf(`<span class="tag">%s</span>`, tag)) }
			sb.WriteString(`</div></div>`)
		}

		if f.Evidence != "" {
			parts := strings.Split(f.Evidence, " | ")
			var urls []string
			discoveredBy := ""
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "Discovered by:") { discoveredBy = p } else if p != "" { urls = append(urls, p) }
			}
			if len(urls) > 0 || discoveredBy != "" {
				sb.WriteString(`<div class="fsection"><div class="fsection-label">🔗 Discovered URLs</div>`)
				if discoveredBy != "" { sb.WriteString(fmt.Sprintf(`<div class="sources-row">%s</div>`, discoveredBy)) }
				if len(urls) > 0 {
					shown := urls; extra := 0
					if len(shown) > 20 { extra = len(shown) - 20; shown = shown[:20] }
					sb.WriteString(`<ul class="evidence-list">`)
					for _, u := range shown { sb.WriteString(fmt.Sprintf(`<li><a href="%s" target="_blank" rel="noopener">%s</a></li>`, makeURL(u), u)) }
					if extra > 0 { sb.WriteString(fmt.Sprintf(`<li style="color:var(--muted)">… and %d more (see JSON report for full list)</li>`, extra)) }
					sb.WriteString(`</ul>`)
				}
				sb.WriteString(`</div>`)
			}
		}

		if f.Remediation != "" {
			sb.WriteString(`<div class="fsection"><div class="fsection-label">📝 Testing Checklist</div><ul class="checklist">`)
			if strings.HasPrefix(f.Remediation, "Suggested security tests: ") {
				tests := strings.TrimPrefix(f.Remediation, "Suggested security tests: ")
				for i, test := range strings.Split(tests, "\x00") {
					test = strings.TrimSpace(test)
					if test == "" { continue }
					cbID := fmt.Sprintf("%s-cb%d", cbPrefix, i)
					sb.WriteString(fmt.Sprintf(`<li><label for="%s"><input type="checkbox" id="%s"><span>%s</span></label></li>`, cbID, cbID, test))
				}
			} else {
				sb.WriteString(fmt.Sprintf(`<li><label><input type="checkbox"><span>%s</span></label></li>`, f.Remediation))
			}
			sb.WriteString(`</ul></div>`)
		}

		sb.WriteString(fmt.Sprintf(`<div class="next-action sev-%s">`, sev))
		switch sev {
		case "critical", "high":
			sb.WriteString(`<strong>🔴 Next Action:</strong> High-value target. Enable your proxy (Burp/Caido), open the target link, and run through the checklist. Focus on parameterized URLs — send to Repeater and try SQLi, SSRF, IDOR payloads. Any /admin or /api paths get tested for auth bypass.`)
		case "medium":
			sb.WriteString(`<strong>🟡 Next Action:</strong> Interesting target. Check if you can access it unauthenticated. Look for IDOR on numeric IDs in the path. Test CORS headers on API endpoints. Try parameter pollution.`)
		default:
			sb.WriteString(`<strong>🔵 Next Action:</strong> Recon data. Verify security headers (CSP, HSTS, X-Frame-Options). Check for exposed directory listings or subdomain takeover opportunities. Look for technology version disclosure.`)
		}
		sb.WriteString(`</div>`)

		if len(f.Sources) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="sources-row">Tools: %s</div>`, strings.Join(f.Sources, ", ")))
		}

		sb.WriteString(`</div></div>`)
	}
	return sb.String()
}

// hexToRGBComponents converts a #RRGGBB hex color to "R,G,B" for use in rgba().
func hexToRGBComponents(hex string) string {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 { return "148,163,184" }
	var r, g, b uint8
	fmt.Sscanf(hex[:2], "%02x", &r)
	fmt.Sscanf(hex[2:4], "%02x", &g)
	fmt.Sscanf(hex[4:6], "%02x", &b)
	return fmt.Sprintf("%d,%d,%d", r, g, b)
}

// filterEmpty removes blank strings from a slice.
func filterEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss { if strings.TrimSpace(s) != "" { out = append(out, s) } }
	return out
}

// severityColor returns a CSS hex color for the given severity label.
func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical": return "#ef4444"
	case "high":     return "#fb923c"
	case "medium":   return "#fbbf24"
	case "low":      return "#34d399"
	default:         return "#94a3b8"
	}
}
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
