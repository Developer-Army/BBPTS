package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ProgramIntelligence holds historical disclosure data and derived insights.
type ProgramIntelligence struct {
	Handle              string                    `json:"handle"`
	Platform            string                    `json:"platform"`
	DisclosedReports    []DisclosedReport          `json:"disclosed_reports"`
	VulnCategoryWeights map[string]float64         `json:"vuln_category_weights"`
	AvgPayoutBySeverity map[string]float64         `json:"avg_payout_by_severity"`
	LastActivity        time.Time                  `json:"last_activity"`
	RecentScopeChanges  []ScopeChange              `json:"recent_scope_changes"`
	RecommendedTools    []string                  `json:"recommended_tools"`
}

type DisclosedReport struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	VulnCategory    string    `json:"vuln_category"`
	Severity        string    `json:"severity"`
	BountyAwarded   float64   `json:"bounty_awarded"`
	DisclosedAt     time.Time `json:"disclosed_at"`
}

type ScopeChange struct {
	Asset     string    `json:"asset"`
	Action    string    `json:"action"` // "added" or "removed"
	ChangedAt time.Time `json:"changed_at"`
}

// ProgramIntelligenceEngine fetches and analyzes program disclosure history.
type ProgramIntelligenceEngine struct {
	client *http.Client
	h1Base string
}

// NewProgramIntelligenceEngine creates a new engine with H1 API credentials.
func NewProgramIntelligenceEngine() *ProgramIntelligenceEngine {
	return &ProgramIntelligenceEngine{
		client: &http.Client{Timeout: 15 * time.Second},
		h1Base: "https://api.hackerone.com/v1/hackers",
	}
}

// FetchDisclosedReports retrieves disclosed reports for a program from H1 API.
func (pie *ProgramIntelligenceEngine) FetchDisclosedReports(handle, username, token string) ([]DisclosedReport, error) {
	if username == "" || token == "" {
		return nil, fmt.Errorf("hackerone credentials required for program intelligence")
	}

	reportsURL := fmt.Sprintf("%s/reports?filter[program][_eq]=%s&filter[disclosed]=true&page[size]=100",
		pie.h1Base, handle)

	req, err := http.NewRequest("GET", reportsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(username, token)

	resp, err := pie.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch disclosed reports: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackerone API returned status %d", resp.StatusCode)
	}

	var reportsResp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Title            string  `json:"title"`
				VulnerabilityInformation string `json:"vulnerability_information"`
				SeverityRating   string  `json:"severity_rating"`
				BountyAwarded    float64 `json:"bounty_awarded_amount"`
				CreatedAt        string  `json:"created_at"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&reportsResp); err != nil {
		return nil, fmt.Errorf("failed to decode reports: %w", err)
	}

	var reports []DisclosedReport
	for _, r := range reportsResp.Data {
		cat := classifyVulnCategory(r.Attributes.Title, r.Attributes.VulnerabilityInformation)
		disclosedAt, _ := time.Parse("2006-01-02T15:04:05Z", r.Attributes.CreatedAt)

		reports = append(reports, DisclosedReport{
			ID:            r.ID,
			Title:         r.Attributes.Title,
			VulnCategory:  cat,
			Severity:      r.Attributes.SeverityRating,
			BountyAwarded: r.Attributes.BountyAwarded,
			DisclosedAt:   disclosedAt,
		})
	}

	return reports, nil
}

// AnalyzeProgram builds intelligence from disclosed reports.
func (pie *ProgramIntelligenceEngine) AnalyzeProgram(handle, platform string, reports []DisclosedReport) *ProgramIntelligence {
	intel := &ProgramIntelligence{
		Handle:              handle,
		Platform:            platform,
		DisclosedReports:    reports,
		VulnCategoryWeights: make(map[string]float64),
		AvgPayoutBySeverity: make(map[string]float64),
	}

	if len(reports) == 0 {
		return intel
	}

	// Count categories
	categoryCounts := make(map[string]int)
	severityPayouts := make(map[string][]float64)
	var lastActivity time.Time

	for _, r := range reports {
		categoryCounts[r.VulnCategory]++
		severityPayouts[r.Severity] = append(severityPayouts[r.Severity], r.BountyAwarded)
		if r.DisclosedAt.After(lastActivity) {
			lastActivity = r.DisclosedAt
		}
	}

	// Calculate weights
	total := float64(len(reports))
	for cat, count := range categoryCounts {
		intel.VulnCategoryWeights[cat] = float64(count) / total
	}

	// Calculate average payouts
	for sev, payouts := range severityPayouts {
		sum := 0.0
		for _, p := range payouts {
			sum += p
		}
		intel.AvgPayoutBySeverity[sev] = sum / float64(len(payouts))
	}

	intel.LastActivity = lastActivity

	// Recommend tools based on vulnerability categories
	intel.RecommendedTools = pie.recommendTools(intel.VulnCategoryWeights)

	return intel
}

func (pie *ProgramIntelligenceEngine) recommendTools(weights map[string]float64) []string {
	type toolScore struct {
		tool  string
		score float64
	}

	toolWeights := map[string]map[string]float64{
		"dalfox":         {"xss": 1.0, "stored_xss": 1.0, "reflected_xss": 0.8},
		"sqlmap":         {"sqli": 1.0, "blind_sqli": 0.9},
		"nuclei":         {"misconfig": 0.8, "exposure": 0.9, "default_creds": 0.7},
		"idor_assist":    {"idor": 1.0, "bola": 1.0},
		"auth_matrix":    {"idor": 0.9, "broken_access": 1.0, "privesc": 0.8},
		"business_logic": {"logic_flaw": 1.0, "race_condition": 0.7},
		"blind_inject":   {"blind_xss": 1.0, "ssti": 0.8, "cmdi": 0.9},
		"ssrf":           {"ssrf": 1.0},
		"cors":           {"cors": 1.0},
		"jwt_analyzer":   {"auth_bypass": 0.8, "jwt": 1.0},
		"open_redirect":  {"redirect": 1.0},
		"crlf":           {"crlf": 1.0},
		"race":           {"race_condition": 1.0},
		"second_order":   {"stored_xss": 0.9, "second_order": 1.0},
		"redos":          {"redos": 1.0, "dos": 0.6},
		"supply_chain":   {"supply_chain": 1.0},
		"tenant_isolate": {"tenant_isolation": 1.0, "idor": 0.7},
	}

	var scores []toolScore
	for tool, catWeights := range toolWeights {
		score := 0.0
		for cat, weight := range catWeights {
			if catWeight, ok := weights[cat]; ok {
				score += catWeight * weight
			}
		}
		if score > 0 {
			scores = append(scores, toolScore{tool: tool, score: score})
		}
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	var tools []string
	for _, s := range scores {
		if s.score > 0.1 {
			tools = append(tools, s.tool)
		}
	}

	return tools
}

func classifyVulnCategory(title, body string) string {
	combined := strings.ToLower(title + " " + body)

	categories := map[string][]string{
		"xss":             {"xss", "cross-site scripting", "reflected", "stored xss", "dom-based"},
		"sqli":            {"sql injection", "sqli", "blind sql", "union-based"},
		"idor":            {"idor", "bola", "insecure direct", "object reference", "access control"},
		"ssrf":            {"ssrf", "server-side request forgery", "server-side request"},
		"rce":             {"rce", "remote code execution", "command injection", "code injection"},
		"lfi":             {"lfi", "local file inclusion", "path traversal", "directory traversal"},
		"redirect":        {"open redirect", "redirect", "url redirect"},
		"cors":            {"cors", "cross-origin", "origin reflection"},
		"misconfig":       {"misconfiguration", "misconfig", "default config"},
		"exposure":        {"exposure", "information disclosure", "leak", "data exposure"},
		"auth_bypass":     {"authentication bypass", "auth bypass", "login bypass", "broken auth"},
		"privilege_esc":   {"privilege escalation", "privesc", "elevation"},
		"dos":             {"denial of service", "dos", "crash", "resource exhaustion"},
		"race_condition":  {"race condition", "race", "concurrent"},
		"logic_flaw":      {"business logic", "logic flaw", "logic bug"},
		"ssti":            {"server-side template injection", "ssti", "template injection"},
		"xxe":             {"xxe", "xml external entity", "xml injection"},
		"deserialization": {"deserialization", "unsafe deserialization", "pickle", "marshal"},
		"default_creds":   {"default credential", "default password", "default login"},
		"cors_misconfig":  {"cors misconfiguration"},
		"jwt":             {"jwt", "json web token", "token forgery"},
		"crlf":            {"crlf", "header injection", "response splitting"},
		"supply_chain":    {"supply chain", "dependency", "npm", "package"},
	}

	for cat, keywords := range categories {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				return cat
			}
		}
	}

	return "other"
}
