// Package report provides comprehensive report generation for BBPTS.
// It exports findings to multiple formats: Markdown, HTML, JSON, and integrates
// with security tools like Burp Suite, Caido, and OWASP ZAP for seamless workflow.
package ui

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	AITriageEnabled   bool
	AITriageThreshold int
	AITriageProvider  string
	AITriageModel     string
	AITriageURL       string
	AITriageAPIKey    string
	DraftReport       bool
	AutoTransition    bool
}

type Report struct {
	Title             string                        `json:"title"`
	Description       string                        `json:"description"`
	GeneratedAt       time.Time                     `json:"generated_at"`
	ScanDuration      string                        `json:"scan_duration"`
	TargetCount       int                           `json:"target_count"`
	FindingCount      int                           `json:"finding_count"`
	CriticalCount     int                           `json:"critical_count"`
	HighCount         int                           `json:"high_count"`
	MediumCount       int                           `json:"medium_count"`
	LowCount          int                           `json:"low_count"`
	Findings          []DetailedFinding             `json:"findings"`
	Statistics        ReportStatistics              `json:"statistics"`
	Recommendations   []string                      `json:"recommendations"`
	Executive         ExecutiveSummary              `json:"executive_summary"`
	TopTargets        []analyze.InvestigationTarget `json:"top_targets,omitempty"`
	AttackPaths       []analyze.AttackPath          `json:"attack_paths,omitempty"`
	ChainedFindings   []analyze.VulnerabilityChain  `json:"chained_findings,omitempty"`
	ConfidenceSummary ReportConfidenceSummary       `json:"confidence_summary"`
}

type ReportConfidenceSummary struct {
	TotalEvaluated  int     `json:"total_evaluated"`
	KeptCount       int     `json:"kept_count"`
	SuppressedCount int     `json:"suppressed_count"`
	NoiseReduction  float64 `json:"noise_reduction_percentage"`
}

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
	Request      string    `json:"request,omitempty"`
	Response     string    `json:"response,omitempty"`

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

type ExecutiveSummary struct {
	OverallRisk      string          `json:"overall_risk"`
	KeyFindings      []string        `json:"key_findings"`
	ImmediateActions []string        `json:"immediate_actions"`
	LongTermActions  []string        `json:"long_term_actions"`
	ComplianceStatus map[string]bool `json:"compliance_status"`
}

type ReportGenerator struct {
	config ReportConfig
}

func NewReportGenerator(config ReportConfig) *ReportGenerator {
	return &ReportGenerator{config: config}
}

func (rg *ReportGenerator) GenerateFullReport(ctx context.Context, insights []analyze.Insight, events []recon.Event, store *storage.Storage) error {
	report := rg.buildReport(insights, events, store)

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

	if rg.config.IncludeMarkdown {
		if err := rg.generateMarkdownReport(report); err != nil {
			return fmt.Errorf("failed to generate Markdown report: %w", err)
		}
	}

	if rg.config.IncludeHTML {
		if err := rg.generateHTMLReport(report); err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}
	}

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

	if rg.config.IncludeHTML {
		if err := rg.generateAttackSurfaceGraph(events); err != nil {
			return fmt.Errorf("failed to generate attack surface graph: %w", err)
		}
	}

	if rg.config.TemplatePath != "" {
		if err := rg.generateCustomTemplateReport(report); err != nil {
			slog.Warn("failed to generate custom template report", "error", err, "template", rg.config.TemplatePath)
		}
	}

	if rg.config.DraftReport {
		draftPath := filepath.Join(rg.config.OutputPath, "ai_draft_report.md")
		if err := rg.draftReportWithLLM(ctx, report.Findings, draftPath); err != nil {
			slog.Warn("AI report drafting failed", "error", err)
		} else {
			slog.Info("AI-drafted report saved", "path", draftPath)
		}
	}

	return nil
}

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

func (rg *ReportGenerator) buildReport(insights []analyze.Insight, events []recon.Event, store *storage.Storage) *Report {
	findings := rg.convertInsightsToFindings(insights, events)

	if rg.config.AITriageEnabled {
		slog.Info("AI Noise Triage enabled, analyzing findings...", "total_findings", len(findings))
		var filteredFindings []DetailedFinding
		for _, f := range findings {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			triageResult, err := TriageFindingWithLLM(ctx, &f, rg.config.AITriageProvider, rg.config.AITriageModel, rg.config.AITriageURL, rg.config.AITriageAPIKey)
			cancel()

			if err != nil {
				slog.Error("AI triage failed for finding, keeping finding by default", "finding", f.Target, "error", err)
				filteredFindings = append(filteredFindings, f)
				continue
			}

			slog.Info("AI triage result", "finding", f.Target, "confidence", triageResult.Confidence, "explanation", triageResult.Explanation)

			if triageResult.Confidence < rg.config.AITriageThreshold {
				slog.Info("AI noise triage: suppressed finding (below threshold)", "finding", f.Target, "confidence", triageResult.Confidence, "threshold", rg.config.AITriageThreshold)
				continue
			}

			f.ConfidenceScore = triageResult.Confidence
			if triageResult.Explanation != "" {
				f.Description = f.Description + " | AI Triage: " + triageResult.Explanation
			}
			filteredFindings = append(filteredFindings, f)
		}
		findings = filteredFindings
	}

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
		Statistics:      rg.buildStatistics(insights),
		Recommendations: rg.buildRecommendations(),
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
		var scanFindings []storage.ScanFinding
		for _, f := range findings {
			_, _ = store.SaveReportFinding(f.Title, f.Description, f.Severity, f.Target, f.ScreenshotPath, f.Score, f.ConfidenceScore)
			scanFindings = append(scanFindings, storage.ScanFinding{
				Title:    f.Title,
				Target:   f.Target,
				Severity: f.Severity,
			})
		}
		if rg.config.AutoTransition {
			var scannedTargets []string
			for _, in := range insights {
				scannedTargets = append(scannedTargets, in.Host)
			}
			_ = store.AutoTransitionFindingStates(scanFindings, scannedTargets)
		}
	}

	return report
}

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

		var reqVal, respVal string
		for _, ev := range relatedEvents {
			if r, ok := ev.Properties["request"]; ok && r != "" {
				reqVal = r
			}
			if r, ok := ev.Properties["response"]; ok && r != "" {
				respVal = r
			} else if bodyBlob, ok := ev.Properties["response_body_blob"]; ok && bodyBlob != "" {
				if strings.HasPrefix(bodyBlob, "file://") {
					path := strings.TrimPrefix(bodyBlob, "file://")
					if bytes, err := os.ReadFile(path); err == nil {
						respVal = string(bytes)
					}
				}
			} else if body, ok := ev.Properties["response_body"]; ok && body != "" {
				respVal = body
			}
			if reqVal != "" && respVal != "" {
				break
			}
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
			Request:             reqVal,
			Response:            respVal,
			ExposureScore:       insight.ExposureScore,
			AttackabilityScore:  insight.AttackabilityScore,
			BusinessImpactScore: insight.BusinessImpactScore,
			ConfidenceScore:     confVal,
			FreshnessScore:      insight.FreshnessScore,
			PathScore:           insight.PathScore,
			Risk:                insight.Risk,
			Suppressed:          isSuppressed,
		}

		screenshotName := fmt.Sprintf("%x.png", md5.Sum([]byte(makeURL(insight.Host))))
		screenshotPath := filepath.Join(rg.config.OutputPath, "screenshots", screenshotName)
		if _, err := os.Stat(screenshotPath); err == nil {
			finding.ScreenshotPath = "screenshots/" + screenshotName
		} else {

			standardPath := filepath.Join("results", "screenshots", screenshotName)
			if _, err := os.Stat(standardPath); err == nil {
				finding.ScreenshotPath = "/" + filepath.ToSlash(standardPath)
			} else {

				screenshotNameFallback := fmt.Sprintf("%x.png", md5.Sum([]byte(insight.Host)))
				screenshotPathFallback := filepath.Join(rg.config.OutputPath, "screenshots", screenshotNameFallback)
				if _, err := os.Stat(screenshotPathFallback); err == nil {
					finding.ScreenshotPath = "screenshots/" + screenshotNameFallback
				} else {
					standardFallback := filepath.Join("results", "screenshots", screenshotNameFallback)
					if _, err := os.Stat(standardFallback); err == nil {
						finding.ScreenshotPath = "/" + filepath.ToSlash(standardFallback)
					}
				}
			}
		}

		enrichFindingDetails(&finding)

		if len(insight.SuggestedTests) > 0 {
			if finding.Remediation != "" {
				finding.Remediation = finding.Remediation + "\n\nSuggested security tests: " + strings.Join(insight.SuggestedTests, "\x00")
			} else {
				finding.Remediation = "Suggested security tests: " + strings.Join(insight.SuggestedTests, "\x00")
			}
		}

		findings = append(findings, finding)
	}

	return findings
}

func (rg *ReportGenerator) buildStatistics(insights []analyze.Insight) ReportStatistics {
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

func (rg *ReportGenerator) buildRecommendations() []string {
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

func (rg *ReportGenerator) buildExecutiveSummary(findings []DetailedFinding) ExecutiveSummary {
	return GenerateDynamicExecutiveSummary(findings)
}

func (rg *ReportGenerator) generateMarkdownReport(report *Report) error {
	outputPath := rg.config.MarkdownPath
	if outputPath == "" {
		outputPath = filepath.Join(rg.config.OutputPath, "report.md")
	}

	content := fmt.Sprintf("# %s\n\n", report.Title)
	content += fmt.Sprintf("> **Generated:** %s  \n", report.GeneratedAt.Format(time.RFC1123))
	content += fmt.Sprintf("> **Risk Level:** %s | **Targets:** %d | **Findings:** %d\n\n",
		report.Executive.OverallRisk, report.TargetCount, report.FindingCount)

	content += "---\n\n## Quick Start Guide\n\n"
	content += "Follow these easy steps to set up your tools and test the findings:\n\n"
	content += "### 1. Set Up Your Tools\n"
	content += "- **Proxy Tool**: Download [Burp Suite](https://portswigger.net/burp/communitydownload) or [Caido](https://caido.io/). These tools let you see website traffic.\n"
	content += "- **Browser Helper**: Install the [FoxyProxy](https://foxyproxy.org/) browser extension and point it to your proxy listener (usually `127.0.0.1:8080` for Burp or `127.0.0.1:8080`/`127.0.0.1:8000` for Caido).\n"
	content += "- **Import Project Configs**:\n"
	content += "  - **Burp Suite**: Go to `Project` > `Import scan items` and select `burp-import.xml`.\n"
	content += "  - **Caido**: Go to `Workspaces` > `Import` and select `caido-import.json`.\n\n"
	content += "### 2. How to Test Findings\n"
	content += "- **Open Targets**: Open the target URLs listed under the detailed findings in your web browser.\n"
	content += "- **Run Tests**: Under each finding, look at the **Step-by-Step Instructions** and run the commands or steps manually.\n"
	content += "- **Risk Scores**: A higher Risk Score (0-100) means the target is more vulnerable. Test these first!\n\n"
	content += "### Reference Glossary\n"
	content += "| Term | Simple Explanation |\n"
	content += "| :--- | :--- |\n"
	content += "| **SQLi** | Database break-in. Slipping a database command into a text box to trick the computer into showing secret records. |\n"
	content += "| **SSRF** | Server hijacking. Tricking a website server into requesting private files or internal web pages it shouldn't show. |\n"
	content += "| **CORS** | Sharing rules. A loose setting that lets bad external websites steal your logged-in session info. |\n"
	content += "| **GraphQL Introspection** | Map leak. An endpoint setting that gives away the list of every secret query, type, and field in the API database. |\n"
	content += "| **IDOR / BOLA** | ID guessing. Changing numbers in the website link (like changing `/user/1` to `/user/2`) to view other people's screens. |\n"
	content += "| **CSP** | Security shield. A list of rules that stops bad scripts from running on your web browser page. |\n"
	content += "| **WAF** | Guard at the gate. A helper program that blocks bad commands before they reach the main web server. |\n\n"
	content += "### Risk Scoring Legend\n"
	content += "- **Exposure**: How visible the website is to the public internet.\n"
	content += "- **Attackability**: How easy it is for an automated script or beginner to hack the target.\n"
	content += "- **Business Impact**: How bad the damage would be if hackers stole the database or files.\n"
	content += "- **Confidence**: How sure the scanner is that the vulnerability is real.\n"
	content += "- **Path Score**: How many steps/hops it takes to reach the target from the outside.\n\n"

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
			content += fmt.Sprintf("- **Exposure:** %d/100 (Internet Visibility)\n", finding.ExposureScore)
			content += fmt.Sprintf("- **Attackability:** %d/100 (Exploitation Ease)\n", finding.AttackabilityScore)
			content += fmt.Sprintf("- **Business Impact:** %d/100 (Data Risk)\n", finding.BusinessImpactScore)
			content += fmt.Sprintf("- **Confidence:** %d/100 (Signal Accuracy)\n", finding.ConfidenceScore)
			content += fmt.Sprintf("- **Path Score:** %d/100 (Attack Depth)\n", finding.PathScore)
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

		if finding.Impact != "" {
			content += "### Security Impact\n"
			content += finding.Impact + "\n\n"
		}

		if finding.Remediation != "" {
			content += "### Remediation Guidance\n"
			parts := strings.Split(finding.Remediation, "Suggested security tests: ")
			if len(parts) > 1 {
				if strings.TrimSpace(parts[0]) != "" {
					content += strings.TrimSpace(parts[0]) + "\n\n"
				}
				content += "#### Recommended Testing Checklist\n"
				for _, test := range strings.Split(parts[1], "\x00") {
					test = strings.TrimSpace(test)
					if test != "" {
						content += fmt.Sprintf("- [ ] %s\n", test)
					}
				}
			} else if strings.HasPrefix(finding.Remediation, "Suggested security tests: ") {
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

		if len(finding.References) > 0 {
			content += "### Reference Links\n"
			for _, ref := range finding.References {
				content += fmt.Sprintf("- [%s](%s)\n", ref, ref)
			}
			content += "\n"
		}

		content += "### Next Steps\n"
		firstStep := strings.Split(beginnerNextSteps(&finding), "\n")[0]
		firstStep = strings.TrimPrefix(firstStep, "1. **")
		firstStep = strings.Replace(firstStep, "**", "", 1)
		content += "> **Next Action:** " + firstStep + "\n\n"
		content += "<details>\n<summary><b>Beginner Guide & Step-by-Step Verification</b></summary>\n\n"
		for _, step := range strings.Split(beginnerNextSteps(&finding), "\n") {
			content += fmt.Sprintf("- %s\n", step)
		}
		content += "</details>\n"

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

func enrichFindingDetails(f *DetailedFinding) {
	title := f.Title
	hasTag := func(t string) bool {
		for _, tag := range f.Tags {
			if strings.EqualFold(tag, t) {
				return true
			}
		}
		return false
	}
	containsReason := func(r string) bool {
		return strings.Contains(strings.ToLower(f.Description), strings.ToLower(r))
	}

	var impact, remediation string
	var refs []string

	if hasTag("git-leak") || containsReason("git repository") {
		title = fmt.Sprintf("Exposed Git Repository Configuration on %s", f.Target)
		impact = "Exposing the .git directory allows attackers to download your entire source code history, including configuration files, sensitive business logic, and hardcoded API credentials."
		remediation = "1. Delete the .git directory from your web root.\n2. Configure your web server (Nginx/Apache) to deny access to hidden directories:\n\nFor Nginx:\nlocation ~ /\\.git {\n    deny all;\n}"
		refs = []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Weak_Lockout_Mechanism"}
	} else if hasTag("secrets") || containsReason("exposed environment file") || containsReason(".env") {
		title = fmt.Sprintf("Sensitive API Secret / Credential Leak on %s", f.Target)
		impact = "Exposed credentials (.env, config keys) allow attackers to access external APIs, database servers, and cloud resources, potentially leading to unauthorized data access or billing exploits."
		remediation = "1. Revoke the leaked API keys or passwords immediately.\n2. Add the affected file (e.g., .env) to your .gitignore.\n3. Configure your server to block access to env/config files."
		refs = []string{"https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure"}
	} else if hasTag("takeover") || containsReason("takeover") {
		title = fmt.Sprintf("Subdomain Takeover Exposure on %s", f.Target)
		impact = "An attacker can hijack this subdomain by registering it on the orphaned SaaS platform (e.g. AWS S3, GitHub Pages, Heroku), hosting malicious content, running phishing attacks, or stealing cookies."
		remediation = "1. Access your DNS provider console.\n2. Identify the dangling CNAME/A record for this host.\n3. Delete the record if the SaaS platform resource is no longer in use."
		refs = []string{"https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeover", "https://github.com/EdOverflow/can-i-take-over-xyz"}
	} else if hasTag("cors-risk") || containsReason("cors") {
		title = fmt.Sprintf("Permissive CORS Policy Misconfiguration on %s", f.Target)
		impact = "A wildcard or null origin in Cross-Origin Resource Sharing (CORS) headers allows unauthorized external websites to make authenticated API requests and retrieve sensitive user data."
		remediation = "1. Do not set Access-Control-Allow-Origin: * when Access-Control-Allow-Credentials is true.\n2. Maintain a strict whitelist of allowed origins and validate the incoming Origin header against it."
		refs = []string{"https://portswigger.net/web-security/cors"}
	} else if containsReason("graphql") || containsReason("introspection") {
		title = fmt.Sprintf("GraphQL Introspection Enabled on %s", f.Target)
		impact = "Allows arbitrary clients to download the entire GraphQL schema definition (queries, mutations, types, fields), dramatically easing the task of locating hidden API entry points."
		remediation = "Disable introspection queries in your GraphQL configuration for production environments.\n\nFor Apollo Server:\nconst server = new ApolloServer({\n  introspection: false\n});"
		refs = []string{"https://graphql.org/learn/security/"}
	} else if containsReason("directory listing") || hasTag("info-leak") {
		title = fmt.Sprintf("Directory Listing Enabled / Information Leak on %s", f.Target)
		impact = "Enables attackers to browse arbitrary files and directories on the server, potentially exposing source files, logs, database backups, or configurations."
		remediation = "Disable directory listing (indexing) in your web server settings.\n\nFor Nginx (nginx.conf):\nautoindex off;\n\nFor Apache (.htaccess):\nOptions -Indexes"
		refs = []string{"https://owasp.org/www-community/attacks/Information_Disclosure"}
	} else if hasTag("phpmyadmin") {
		title = fmt.Sprintf("Exposed phpMyAdmin Database Console on %s", f.Target)
		impact = "An exposed database admin panel allows attackers to perform brute-force authentication attacks, potentially gaining full control over your relational database."
		remediation = "1. Restrict phpMyAdmin access to trusted IPs only.\n2. Change the default login URL pathway from /phpmyadmin to a secure, obscure route."
		refs = []string{"https://www.phpmyadmin.net/security/"}
	} else if hasTag("monitoring") || containsReason("grafana") || containsReason("prometheus") {
		title = fmt.Sprintf("Exposed Grafana / Prometheus Monitoring Interface on %s", f.Target)
		impact = "Exposes operational telemetry, server metrics, user statistics, or system configurations, aiding attackers in mapping internal architecture."
		remediation = "1. Configure strong authentication (OAuth, LDAP) for all monitoring portals.\n2. Put the interfaces behind a VPN or SSH tunnel."
		refs = []string{"https://grafana.com/docs/grafana/latest/security/"}
	} else if containsReason("bypass") || hasTag("manual-bypass") {
		title = fmt.Sprintf("Access Control / Potential Bypass Opportunity on %s", f.Target)
		impact = "Protected folders or endpoints return access restriction codes (e.g. 403 Forbidden, 401 Unauthorized) but might be bypassable using custom proxy headers or request overrides."
		remediation = "1. Validate access authorization checks strictly on the application server layer.\n2. Do not trust or parse custom client routing headers like X-Original-URL or X-Rewrite-URL."
		refs = []string{"https://portswigger.net/web-security/access-control"}
	} else if hasTag("ssrf-candidate") || containsReason("ssrf") {
		title = fmt.Sprintf("Potential Server-Side Request Forgery (SSRF) on %s", f.Target)
		impact = "SSRF allows attackers to force the backend server to make HTTP requests to arbitrary domains, potentially exposing internal-only systems (e.g., metadata APIs, local database ports)."
		remediation = "1. Enforce strict destination IP/domain whitelists.\n2. Avoid passing raw URLs in user input parameters; use mapped keys instead.\n3. Run the backend service in an isolated network segment without direct access to internal network nodes."
		refs = []string{"https://portswigger.net/web-security/ssrf"}
	} else if hasTag("sqli-candidate") || containsReason("sqli") {
		title = fmt.Sprintf("Potential SQL Injection (SQLi) Vulnerability on %s", f.Target)
		impact = "Enables attackers to manipulate SQL commands executed by the backend database, potentially allowing them to bypass logins, read or write private database content, or execute system commands."
		remediation = "1. Use parameterized queries (prepared statements) for all database operations.\n2. Never concatenate untrusted user input directly into SQL strings."
		refs = []string{"https://owasp.org/www-community/attacks/SQL_Injection"}
	} else {
		switch strings.ToLower(f.Severity) {
		case "critical", "high":
			title = fmt.Sprintf("High Risk Security Vulnerability / Exposure on %s", f.Target)
			impact = "Indicates a high severity finding that could allow attackers to bypass authorization, leak private credentials, or execute arbitrary operations."
			remediation = "1. Upgrade the software component to the latest patched version.\n2. Review the raw request/response logs and perform verification testing.\n3. Put the application behind a Web Application Firewall (WAF)."
		default:
			title = fmt.Sprintf("Security Discovery / Information Exposure on %s", f.Target)
			impact = "Exposes non-sensitive services, open ports, or software version signatures, which help attackers map the target's attack surface during reconnaissance."
			remediation = "1. Restrict public access to non-essential services.\n2. Disable verbose error messages and signature headers that disclose software versions."
		}
		refs = []string{"https://owasp.org/www-project-top-ten/"}
	}

	f.Title = title
	f.Impact = impact
	f.Remediation = remediation
	f.References = refs
}

func getBaseURL(f *DetailedFinding) string {
	parts := strings.Split(f.Evidence, "|")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
			urlParts := strings.SplitN(part, "/", 4)
			if len(urlParts) >= 3 {
				return urlParts[0] + "//" + urlParts[2]
			}
		}
	}
	return makeURL(f.Target)
}

func beginnerNextSteps(f *DetailedFinding) string {
	hasTag := func(t string) bool {
		for _, tag := range f.Tags {
			if strings.EqualFold(tag, t) {
				return true
			}
		}
		return false
	}
	containsReason := func(r string) bool {
		return strings.Contains(strings.ToLower(f.Description), strings.ToLower(r))
	}

	var steps []string
	baseURL := getBaseURL(f)

	if hasTag("git-leak") || containsReason("git repository") {
		steps = []string{
			"Run this terminal command: `curl -I " + baseURL + "/.git/HEAD`",
			"Check output: If you see status `200 OK` and a reference to `refs/heads/`, the history files are leaked!",
			"Download code: Run this command to download the code: `git-dumper " + baseURL + "/.git/ output-dir` and look inside for credentials.",
		}
	} else if hasTag("secrets") || containsReason("exposed environment file") || containsReason(".env") {
		steps = []string{
			"Open this link in your browser: " + baseURL + "/.env (or run `curl -s " + baseURL + "/.env`)",
			"Check output: Look for secret words like `AWS_ACCESS_KEY_ID`, `DB_PASSWORD`, or private keys.",
		}
	} else if hasTag("takeover") || containsReason("takeover") {
		steps = []string{
			"Run this command to check where the domain points: `dig CNAME " + f.Target + " +short`",
			"Check target: If the returned domain points to a deleted SaaS page (like Heroku or AWS S3), anyone can register it!",
			"Takeover target: Go to the SaaS provider page and try to claim/register that exact name.",
		}
	} else if hasTag("cors-risk") || containsReason("cors") {
		steps = []string{
			"Run this test command: `curl -H \"Origin: https://evil.com\" -I " + baseURL + "`",
			"Check output headers: If you see `Access-Control-Allow-Origin: https://evil.com` and `Access-Control-Allow-Credentials: true`, it is vulnerable!",
		}
	} else if containsReason("graphql") || containsReason("introspection") {
		steps = []string{
			"Run this command to download the API map: `curl -s -X POST -H \"Content-Type: application/json\" --data '{\"query\":\"{__schema{types{name}}}\"}' " + baseURL + "/graphql`",
			"Check output: If it prints a list of queries and types, introspection is enabled! Check them for admin endpoints.",
		}
	} else if containsReason("directory listing") || hasTag("info-leak") {
		steps = []string{
			"Open this link in your browser: " + baseURL + " (or run `curl -s " + baseURL + "`)",
			"Check output: If you see a list of files/folders (Index of /), directory listing is enabled. Look for backups like `.zip` or `.sql` files!",
		}
	} else if hasTag("ssrf-candidate") || containsReason("ssrf") {
		steps = []string{
			"Find the URL parameter (like `?url=` or `?file=`) in the discovery links.",
			"Run this callback test command: `curl -i \"" + baseURL + "/path?url=http://your-interactsh-id.oast.fun\"` (replace with your Interactsh listener host)",
			"Check listener: If your listener receives a hit, the target server has connected to your listener host!",
		}
	} else if hasTag("sqli-candidate") || containsReason("sqli") {
		steps = []string{
			"Type a single quote `'` in the input parameter to see if the website crashes or shows database error codes.",
			"Automate check: Run `sqlmap -u \"" + baseURL + "/path?param=val\" --batch`",
		}
	} else {
		switch strings.ToLower(f.Severity) {
		case "critical", "high":
			steps = []string{
				"Open this link in your browser proxy: " + baseURL + ".",
				"Fuzz inputs: Try typing bad characters (like `<script>` tags for XSS or path traversals `../../etc/passwd`) in text boxes.",
				"Quick web check command: `curl -i \"" + baseURL + "\"`",
			}
		default:
			steps = []string{
				"Run this command to check headers: `curl -I \"" + baseURL + "\"`",
				"Check headers: Look for missing security headers (like `Content-Security-Policy`) or versions showing in `Server` / `X-Powered-By` fields.",
			}
		}
	}

	return strings.Join(steps, "\n")
}

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

func filterEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func (rg *ReportGenerator) draftReportWithLLM(ctx context.Context, findings []DetailedFinding, outPath string) error {
	if len(findings) == 0 {
		return fmt.Errorf("no findings to draft report from")
	}

	var findingsBuf strings.Builder
	for i, f := range findings {
		if i >= 20 {
			findingsBuf.WriteString(fmt.Sprintf("\n... and %d more findings omitted for brevity.\n", len(findings)-20))
			break
		}
		findingsBuf.WriteString(fmt.Sprintf("### Finding %d\n", i+1))
		findingsBuf.WriteString(fmt.Sprintf("- Title: %s\n", f.Title))
		findingsBuf.WriteString(fmt.Sprintf("- Target Asset: %s\n", f.Target))
		findingsBuf.WriteString(fmt.Sprintf("- Severity: %s (Score: %d)\n", f.Severity, f.Score))
		findingsBuf.WriteString(fmt.Sprintf("- CVSS Risk Vector: %+v\n", f.Risk))
		findingsBuf.WriteString(fmt.Sprintf("- Tags: %s\n", strings.Join(f.Tags, ", ")))
		findingsBuf.WriteString(fmt.Sprintf("- Sources: %s\n", strings.Join(f.Sources, ", ")))
		findingsBuf.WriteString(fmt.Sprintf("- Description/Evidence: %s\n", f.Description))
		if f.Request != "" {
			findingsBuf.WriteString(fmt.Sprintf("- Raw Request:\n```http\n%s\n```\n", f.Request))
		}
		if f.Response != "" {
			findingsBuf.WriteString(fmt.Sprintf("- Raw Response:\n```http\n%s\n```\n", f.Response))
		}
		findingsBuf.WriteString("\n")
	}

	prompt := fmt.Sprintf(`You are an expert bug bounty hunter and security researcher. Draft a professional, platform-ready bug bounty report suitable for submission to HackerOne or Bugcrowd based on the following automated reconnaissance findings.

For each finding, you MUST generate a draft report containing:
1. Title (Professional and descriptive)
2. Severity & CVSS 3.1 justification (explain how the vector components map to this finding)
3. Impact assessment
4. Steps to reproduce (incorporating the provided raw request and response data, highlighting where the vulnerability is triggered)
5. Remediation recommendations

Here are the scan findings:
%s

Write the entire report in Markdown format. Be specific, professional, and actionable. Do not use generic placeholders.`, findingsBuf.String())

	provider := strings.ToLower(strings.TrimSpace(rg.config.AITriageProvider))
	if provider == "" {
		provider = "gemini"
	}
	model := rg.config.AITriageModel
	if model == "" {
		if provider == "gemini" {
			model = "gemini-2.0-flash"
		} else {
			model = "llama3"
		}
	}

	var content string
	var err error

	switch provider {
	case "gemini":
		content, err = callGeminiText(ctx, prompt, model, rg.config.AITriageAPIKey)
	case "ollama", "local":
		content, err = callOllamaText(ctx, prompt, model, rg.config.AITriageURL, rg.config.AITriageAPIKey)
	default:
		return fmt.Errorf("unsupported AI provider for drafting: %s", provider)
	}

	if err != nil {
		return err
	}

	header := fmt.Sprintf("# AI-Drafted Vulnerability Report\n\n> Generated by BBPTS using %s (%s) on %s\n> **Review and edit before submission** — this is an automated draft.\n\n---\n\n",
		provider, model, time.Now().UTC().Format("2006-01-02 15:04 UTC"))

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return os.WriteFile(outPath, []byte(header+content), 0600)
}

func callGeminiText(ctx context.Context, prompt, model, apiKey string) (string, error) {
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("GEMINI_API_KEY is not set")
	}

	type Part struct {
		Text string `json:"text"`
	}
	type Content struct {
		Parts []Part `json:"parts"`
	}
	type GenConfig struct {
		Temperature float64 `json:"temperature"`
		MaxTokens   int     `json:"maxOutputTokens"`
	}
	type GeminiRequest struct {
		Contents         []Content `json:"contents"`
		GenerationConfig GenConfig `json:"generationConfig"`
	}

	reqBody := GeminiRequest{
		Contents: []Content{{Parts: []Part{{Text: prompt}}}},
		GenerationConfig: GenConfig{
			Temperature: 0.3,
			MaxTokens:   8192,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Gemini API returned status %d: %s", resp.StatusCode, string(body))
	}

	type Candidate struct {
		Content Content `json:"content"`
	}
	type GeminiResponse struct {
		Candidates []Candidate `json:"candidates"`
	}

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return "", err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response from Gemini API")
	}

	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

func callOllamaText(ctx context.Context, prompt, model, apiURL, apiKey string) (string, error) {
	if apiURL == "" {
		apiURL = "http://localhost:11434/v1/chat/completions"
	}

	type Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type ChatRequest struct {
		Model       string    `json:"model"`
		Messages    []Message `json:"messages"`
		Temperature float64   `json:"temperature"`
	}

	reqBody := ChatRequest{
		Model:       model,
		Messages:    []Message{{Role: "user", Content: prompt}},
		Temperature: 0.3,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("local LLM API returned status %d: %s", resp.StatusCode, string(body))
	}

	type Choice struct {
		Message Message `json:"message"`
	}
	type ChatResponse struct {
		Choices []Choice `json:"choices"`
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		type NativeOllamaResponse struct {
			Response string `json:"response"`
		}
		var nativeResp NativeOllamaResponse
		if errNative := json.Unmarshal(body, &nativeResp); errNative == nil && nativeResp.Response != "" {
			return nativeResp.Response, nil
		}
		return "", err
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("empty choice from Chat Completion API")
	}

	return chatResp.Choices[0].Message.Content, nil
}
