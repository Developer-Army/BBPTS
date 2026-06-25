// Package report provides comprehensive report generation for BBPTS.
// It exports findings to multiple formats: Markdown, HTML, JSON, and integrates
// with security tools like Burp Suite, Caido, and OWASP ZAP for seamless workflow.
package ui

import (
	"context"
	"crypto/md5"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

// ReportConfig holds configuration for report generation
type ReportConfig struct {
	OutputPath        string
	MarkdownPath      string
	IncludeBurp       bool
	IncludeCaido      bool
	IncludeZAP        bool
	IncludeHTML       bool
	IncludeJSON       bool
	IncludeMarkdown   bool
	Verbose           bool
	MinimumScore      int
	MinimumConfidence int
	BugBountyType     string // "standard", "h1", "intigriti", "bugcrowd", etc.
	TemplatePath      string // Optional custom Go text/template file for HTML report
}

// Report represents a comprehensive vulnerability report
type Report struct {
	Title           string                        `json:"title"`
	Description     string                        `json:"description"`
	GeneratedAt     time.Time                     `json:"generated_at"`
	ScanDuration    string                        `json:"scan_duration"`
	TargetCount     int                           `json:"target_count"`
	FindingCount    int                           `json:"finding_count"`
	CriticalCount   int                           `json:"critical_count"`
	HighCount       int                           `json:"high_count"`
	MediumCount     int                           `json:"medium_count"`
	LowCount        int                           `json:"low_count"`
	Findings        []DetailedFinding             `json:"findings"`
	Statistics      ReportStatistics              `json:"statistics"`
	Recommendations []string                      `json:"recommendations"`
	Executive       ExecutiveSummary              `json:"executive_summary"`
	TopTargets      []analyze.InvestigationTarget `json:"top_targets,omitempty"`
	AttackPaths     []analyze.AttackPath          `json:"attack_paths,omitempty"`
	ChainedFindings []analyze.VulnerabilityChain  `json:"chained_findings,omitempty"`
	ConfidenceSummary ReportConfidenceSummary     `json:"confidence_summary"`
}

type ReportConfidenceSummary struct {
	TotalEvaluated  int     `json:"total_evaluated"`
	KeptCount       int     `json:"kept_count"`
	SuppressedCount int     `json:"suppressed_count"`
	NoiseReduction  float64 `json:"noise_reduction_percentage"`
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

	ExposureScore       int `json:"exposure_score"`
	AttackabilityScore  int `json:"attackability_score"`
	BusinessImpactScore int `json:"business_impact_score"`
	ConfidenceScore     int `json:"confidence_score"`
	FreshnessScore      int `json:"freshness_score"`
	PathScore           int `json:"path_score"`

	Risk           recon.RiskVector `json:"risk_vector"`
	ScreenshotPath string           `json:"screenshot_path,omitempty"`
	Suppressed     bool             `json:"suppressed"`
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
func (rg *ReportGenerator) GenerateFullReport(insights []analyze.Insight, events []recon.Event, store *storage.Storage) error {
	report := rg.buildReport(insights, events, store)

	// Generate JSON report
	if rg.config.IncludeJSON {
		if err := rg.generateJSONReport(report); err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}
		if err := rg.generateSARIFReport(report); err != nil {
			slog.Warn("failed to generate SARIF report", "error", err)
		}
		jsonPath := filepath.Join(rg.config.OutputPath, "report.json")
		ProcessTriageIntegrations(context.Background(), report, jsonPath)
	}

	// Generate Markdown report
	if rg.config.IncludeMarkdown {
		if err := rg.generateMarkdownReport(report); err != nil {
			return fmt.Errorf("failed to generate Markdown report: %w", err)
		}
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
func (rg *ReportGenerator) buildReport(insights []analyze.Insight, events []recon.Event, store *storage.Storage) *Report {
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

	var topTargets []analyze.InvestigationTarget
	var topPaths []analyze.AttackPath
	var chains []analyze.VulnerabilityChain
	if store != nil {
		nodes, errNodes := store.GetAllAssetNodes(0, 0)
		edges, errEdges := store.GetAllAssetEdges(0, 0)
		if errNodes == nil && errEdges == nil {
			topTargets = analyze.RecommendTargets(nodes, edges)
			paths := analyze.GetAttackPaths(nodes, edges)
			topPaths = analyze.RankAttackPaths(paths)
			if len(topPaths) > 10 {
				topPaths = topPaths[:10]
			}

			// Translate path IDs to node values
			nodeMap := make(map[string]string)
			for _, n := range nodes {
				nodeMap[n.ID] = n.Value
			}
			for i, p := range topPaths {
				var resolved []string
				for _, id := range p.Path {
					if val, ok := nodeMap[id]; ok {
						resolved = append(resolved, val)
					} else {
						resolved = append(resolved, id)
					}
				}
				topPaths[i].Path = resolved
			}

			chains = analyze.FindVulnerabilityChains(nodes, edges)
		}
	}

	totalEv := len(events)
	keptEv := 0
	suppressedEv := 0
	for _, ev := range events {
		if ev.Properties["suppressed"] == "true" {
			suppressedEv++
		} else {
			keptEv++
		}
	}
	reduction := 0.0
	if totalEv > 0 {
		reduction = float64(suppressedEv) / float64(totalEv) * 100.0
	}

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
		TopTargets:      topTargets,
		AttackPaths:     topPaths,
		ChainedFindings: chains,
		ConfidenceSummary: ReportConfidenceSummary{
			TotalEvaluated:  totalEv,
			KeptCount:       keptEv,
			SuppressedCount: suppressedEv,
			NoiseReduction:  reduction,
		},
	}

	if store != nil {
		for _, f := range findings {
			_ = store.SaveReportFinding(f.Title, f.Description, f.Severity, f.Target, f.ScreenshotPath, f.Score, f.ConfidenceScore)
		}
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

	type resultItem struct {
		index      int
		confidence int
	}

	resultsChan := make(chan resultItem, len(insights))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i, insight := range insights {
		wg.Add(1)
		go func(idx int, ins analyze.Insight) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			related := eventMap[ins.Host]
			conf := CalculateConfidenceScore(ctx, ins, related)
			resultsChan <- resultItem{index: idx, confidence: conf}
		}(i, insight)
	}

	wg.Wait()
	close(resultsChan)

	confidenceMap := make(map[int]int)
	for res := range resultsChan {
		confidenceMap[res.index] = res.confidence
	}

	for i, insight := range insights {
		if insight.Score < rg.config.MinimumScore {
			continue
		}

		confVal := confidenceMap[i]
		if confVal < rg.config.MinimumConfidence {
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

		isSuppressed := false
		if len(relatedEvents) > 0 {
			allSuppressed := true
			for _, ev := range relatedEvents {
				if ev.Properties["suppressed"] != "true" {
					allSuppressed = false
					break
				}
			}
			isSuppressed = allSuppressed
		}

		finding := DetailedFinding{
			ID:                  fmt.Sprintf("FINDING-%d", len(findings)+1),
			Title:               fmt.Sprintf("Reconnaissance finding on %s", insight.Host),
			Description:         strings.Join(cleanReasons, "; "),
			Severity:            insight.Priority,
			Score:               insight.Score,
			Target:              insight.Host,
			Evidence:            strings.Join(evidenceParts, " | "),
			Tags:                insight.Tags,
			Sources:             sourceList,
			DiscoveredAt:        time.Now(),
			Priority:            insight.Priority,
			ExposureScore:       insight.ExposureScore,
			AttackabilityScore:  insight.AttackabilityScore,
			BusinessImpactScore: insight.BusinessImpactScore,
			ConfidenceScore:     confVal,
			FreshnessScore:      insight.FreshnessScore,
			PathScore:           insight.PathScore,
			Risk:                insight.Risk,
			Suppressed:          isSuppressed,
		}

		// Lookup screenshot path
		screenshotName := fmt.Sprintf("%x.png", md5.Sum([]byte(makeURL(insight.Host))))
		screenshotPath := filepath.Join("results", "screenshots", screenshotName)
		if _, err := os.Stat(screenshotPath); err == nil {
			finding.ScreenshotPath = "/" + filepath.ToSlash(screenshotPath)
		} else {
			// Fallback: check without scheme
			screenshotNameFallback := fmt.Sprintf("%x.png", md5.Sum([]byte(insight.Host)))
			screenshotPathFallback := filepath.Join("results", "screenshots", screenshotNameFallback)
			if _, err := os.Stat(screenshotPathFallback); err == nil {
				finding.ScreenshotPath = "/" + filepath.ToSlash(screenshotPathFallback)
			}
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
	return GenerateDynamicExecutiveSummary(findings)
}

// generateMarkdownReport exports report as Markdown
func (rg *ReportGenerator) generateMarkdownReport(report *Report) error {
	outputPath := rg.config.MarkdownPath
	if outputPath == "" {
		outputPath = filepath.Join(rg.config.OutputPath, "report.md")
	}

	content := fmt.Sprintf("# %s\n\n", report.Title)
	content += fmt.Sprintf("> **Generated:** %s  \n", report.GeneratedAt.Format(time.RFC1123))
	content += fmt.Sprintf("> **Risk Level:** %s | **Targets:** %d | **Findings:** %d\n\n",
		report.Executive.OverallRisk, report.TargetCount, report.FindingCount)

	content += "---\n\n## Quick Start Guide for Beginners\n\n"
	content += "1. **Import Configs**: Load `burp-import.xml` in Burp Suite (`Project` > `Import scan items`) or `caido-import.json` in Caido (`Workspaces` > `Import`).\n"
	content += "2. **Open Target**: Click target domain links or evidence URLs below to open targets in your browser configured with your proxy.\n"
	content += "3. **Run Checklists**: Follow step-by-step checklists under each finding. Check them off as you test.\n\n"

	content += "---\n\n## Executive Summary\n\n"
	content += fmt.Sprintf("| Critical | High | Medium | Low |\n| :---: | :---: | :---: | :---: |\n| %d | %d | %d | %d |\n\n",
		report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)


	content += "### Key Highlights\n"
	for _, highlight := range report.Executive.KeyFindings {
		content += fmt.Sprintf("- %s\n", highlight)
	}

	if len(report.TopTargets) > 0 {
		content += "\n### Top Investigation Targets (Sniper Scope)\n"
		for i, t := range report.TopTargets {
			content += fmt.Sprintf("%d. **%s** (Score: %.0f)  \n", i+1, t.AssetID, t.FinalScore)
			content += "   Why:\n"
			for _, w := range t.Why {
				content += fmt.Sprintf("   * %s\n", w)
			}
		}
	}

	if len(report.AttackPaths) > 0 {
		content += "\n### Top Attack Paths\n"
		for i, p := range report.AttackPaths {
			content += fmt.Sprintf("%d. `[%.0f]` %s\n", i+1, p.Score, strings.Join(p.Path, " -> "))
		}
	}

	content += "\n---\n\n##  Detailed Findings\n\n"

	for _, finding := range report.Findings {
		severityPrefix := ""
		switch strings.ToLower(finding.Severity) {
		case "critical":
			severityPrefix = "[CRITICAL] "
		case "high":
			severityPrefix = "[HIGH] "
		case "medium":
			severityPrefix = "[MEDIUM] "
		case "low":
			severityPrefix = "[LOW] "
		}

		targetURL := makeURL(finding.Target)
		content += fmt.Sprintf("<details>\n<summary><b>%s<a href=\"%s\">%s</a></b> (Score: %d)</summary>\n\n",
			severityPrefix, targetURL, finding.Target, finding.Score)

		if finding.ExposureScore > 0 || finding.AttackabilityScore > 0 || finding.BusinessImpactScore > 0 || finding.ConfidenceScore > 0 || finding.PathScore > 0 {
			content += "### Risk Vectors Breakdown\n"
			content += fmt.Sprintf("- **Exposure:** %d/100\n", finding.ExposureScore)
			content += fmt.Sprintf("- **Attackability:** %d/100\n", finding.AttackabilityScore)
			content += fmt.Sprintf("- **Business Impact:** %d/100\n", finding.BusinessImpactScore)
			content += fmt.Sprintf("- **Confidence:** %d/100\n", finding.ConfidenceScore)
			content += fmt.Sprintf("- **Path Score:** %d/100\n", finding.PathScore)
			content += "\n"
		}

		content += "### Security Analysis\n"
		for _, reason := range strings.Split(finding.Description, "; ") {
			content += fmt.Sprintf("- %s\n", reason)
		}
		content += "\n"

		if finding.Evidence != "" {
			content += "### Discovery Context / Evidence URLs\n"
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

		if finding.ScreenshotPath != "" {
			content += "### Page Screenshot\n"
			content += fmt.Sprintf("![Screenshot](%s)\n\n", finding.ScreenshotPath)
		}

		if finding.Remediation != "" {
			content += "### Recommended Testing Checklist\n"
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

		content += "### Next Steps\n"
		switch strings.ToLower(finding.Severity) {
		case "critical", "high":
			content += "> **Next Action:** High risk target. Open Burp/Caido proxy. Fuzz the parameters listed in the findings with payloads (SQLi probes, SSRF endpoints, XSS scripts). Pay close attention to database-related input fields.\n\n"
		case "medium":
			content += "> **Next Action:** Active endpoints found. Verify authentication bypass mechanisms, look for IDOR vulnerabilities on object IDs in paths, or check CORS parameters for wildcards.\n\n"
		default:
			content += "> **Next Action:** Low priority/recon data. Check for directory listings or sensitive technology disclosures. Verify if security headers like CSP/HSTS are correctly set.\n\n"
		}

		content += "</details>\n\n"
	}

	content += "---\n\n## Strategic Recommendations\n\n"
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

// filterEmpty removes blank strings from a slice.
func filterEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
