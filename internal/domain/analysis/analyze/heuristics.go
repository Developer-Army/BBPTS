package analyze

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// Dynamic heuristic dictionaries. These are intentionally simple so they can
// evolve into config-driven rules later without changing the analyzer contract.
var SensitivePatterns = map[string]int{
	".env":         50,
	"/.git":        50,
	"id_rsa":       50,
	"config.php":   30,
	".bak":         20,
	"/swagger-ui/": 15,
	"/admin":       20,
}

var TechScoreMap = map[string]int{
	"jenkins":          30,
	"kibana":           25,
	"grafana":          20,
	"s3.amazonaws.com": 15,
}

var sqliParamNames = map[string]struct{}{
	"id":        {},
	"ids":       {},
	"item":      {},
	"itemid":    {},
	"product":   {},
	"productid": {},
	"category":  {},
	"cat":       {},
	"filter":    {},
	"sort":      {},
	"order":     {},
	"q":         {},
	"query":     {},
	"search":    {},
	"ref":       {},
	"page":      {},
	"lang":      {},
}

type HeuristicAnalyzer struct{}

func (h *HeuristicAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	applyTargetHeuristics(ev.Target, insight)
	applyPropertyHeuristics(ev, insight)
}

func applyTargetHeuristics(target string, insight *Insight) {
	lowerTarget := strings.ToLower(target)

	for pattern, score := range SensitivePatterns {
		if strings.Contains(lowerTarget, pattern) {
			addTag(insight, "sensitive-asset")
			addReason(insight, "Potential exposure of sensitive file: "+pattern)
			insight.Score += score
		}
	}

	for tech, score := range TechScoreMap {
		if strings.Contains(lowerTarget, tech) {
			addTag(insight, tech)
			addReason(insight, "Infrastructure technology detected: "+tech)
			insight.Score += score
		}
	}

	parsed, err := url.Parse(target)
	if err != nil || parsed.RawQuery == "" {
		return
	}

	query := parsed.Query()
	sqliSignals := 0
	for key, values := range query {
		if isSQLiParam(key, values) {
			sqliSignals++
			addReason(insight, "High-risk parameter detected (likely database input): "+strings.ToLower(key))
		}
	}
	if sqliSignals == 0 {
		return
	}

	addTag(insight, "sqli-candidate")
	addSuggestedTest(insight, "Test selector-style parameters for SQL injection with quote-based, boolean-based, and time-based probes")
	if strings.Contains(lowerTarget, "category=") || strings.Contains(lowerTarget, "filter=") {
		addSuggestedTest(insight, "Check whether filter-style parameters are concatenated into backend queries without parameterization")
	}

	insight.Score += 12 + (sqliSignals-1)*4
}

func applyPropertyHeuristics(ev recon.Event, insight *Insight) {
	title := strings.ToLower(strings.TrimSpace(ev.Properties["title"]))
	server := strings.ToLower(strings.TrimSpace(ev.Properties["server"]))

	if strings.Contains(title, "sql syntax") || strings.Contains(title, "database error") || strings.Contains(title, "mysql") || strings.Contains(title, "postgres") {
		addTag(insight, "db-error")
		addReason(insight, "Evidence of database error messages in the response (Info Leak)")
		addSuggestedTest(insight, "Verify whether crafted input triggers database errors or syntax disclosures")
		insight.Score += 18
	}

	if strings.Contains(server, "php") || strings.Contains(server, "apache") {
		addReason(insight, "Server identifying as dynamic stack: "+ev.Properties["server"])
	}
}

func isSQLiParam(key string, values []string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if _, ok := sqliParamNames[key]; ok {
		return true
	}

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if _, err := strconv.Atoi(value); err == nil {
			return true
		}

		lowerValue := strings.ToLower(value)
		if strings.Contains(lowerValue, "-") || strings.Contains(lowerValue, "_") {
			return true
		}
	}

	return false
}
