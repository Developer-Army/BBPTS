package services

import (
	"strconv"
	"strings"
)

// ScoredEvent embeds the real Event struct with confidence scoring metadata.
type ScoredEvent struct {
	Event
	ConfidenceScore int  `json:"confidence_score"`
	Suppressed      bool `json:"suppressed"`
}

// CorroborateEvents determines other tools that observed the same target and sets the "corroborated_by" property.
func CorroborateEvents(events []Event) []Event {
	targetTools := make(map[string]map[string]bool)
	for _, ev := range events {
		if ev.Target == "" {
			continue
		}
		if targetTools[ev.Target] == nil {
			targetTools[ev.Target] = make(map[string]bool)
		}
		targetTools[ev.Target][ev.Source] = true
	}

	for i, ev := range events {
		if ev.Target == "" {
			continue
		}
		sources := targetTools[ev.Target]
		var otherTools []string
		for src := range sources {
			if src != ev.Source {
				otherTools = append(otherTools, src)
			}
		}
		if len(otherTools) > 0 {
			if events[i].Properties == nil {
				events[i].Properties = make(map[string]string)
			}
			events[i].Properties["corroborated_by"] = strings.Join(otherTools, ",")
		}
	}
	return events
}

// ScoreEvent calculates the confidence score of an event based on standard signal groups.
func ScoreEvent(ev Event) int {
	score := 50 // Base baseline score

	// Group 1: Source tool credibility
	switch strings.ToLower(ev.Source) {
	case "nuclei":
		score += 15
	case "gau":
		score += -10
	case "shodan":
		score += -5
	}

	// Group 2: Event type specificity
	switch strings.ToLower(ev.Type) {
	case "vulnerability":
		score += 20
	case "info":
		score += -15
	}

	// Group 3: HTTP response
	if ev.Properties != nil {
		if scVal, ok := ev.Properties["status_code"]; ok {
			if sc, err := strconv.Atoi(scVal); err == nil {
				if sc == 200 {
					score += 10
				} else if sc == 404 {
					score += -20
				}
			}
		}
		if clVal, ok := ev.Properties["content_length"]; ok {
			if cl, err := strconv.ParseInt(clVal, 10, 64); err == nil && cl == 0 {
				score += -10
			}
		}
	}

	// Group 4: Target URL quality
	targetLower := strings.ToLower(ev.Target)
	// Check loopback
	if strings.Contains(targetLower, "127.0.0.1") || strings.Contains(targetLower, "localhost") || strings.Contains(targetLower, "[::1]") {
		score += -25
	} else {
		// Check static asset
		isStatic := false
		staticExts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"}
		for _, ext := range staticExts {
			if strings.HasSuffix(targetLower, ext) || strings.Contains(targetLower, ext+"?") {
				isStatic = true
				break
			}
		}
		if isStatic {
			score += -15
		} else {
			// Check high-value path
			highValuePaths := []string{"/admin", "/api/", "/login", "/dashboard", ".env", ".git", "config"}
			isHighValue := false
			for _, hv := range highValuePaths {
				if strings.Contains(targetLower, hv) {
					isHighValue = true
					break
				}
			}
			if isHighValue {
				score += 10
			}
		}
	}

	// Group 5: Multi-tool corroboration
	if ev.Properties != nil {
		if cbVal, ok := ev.Properties["corroborated_by"]; ok && cbVal != "" {
			otherTools := strings.Split(cbVal, ",")
			totalTools := len(otherTools) + 1
			if totalTools >= 3 {
				score += 20
			} else if totalTools == 2 {
				score += 12
			}
		} else {
			score += -5
		}
	} else {
		score += -5
	}

	// Group 6: Nuclei template metadata
	if ev.Properties != nil {
		if ncVal, ok := ev.Properties["nuclei_confidence"]; ok && strings.ToLower(ncVal) == "confirmed" {
			score += 15
		}
		if nsVal, ok := ev.Properties["nuclei_severity"]; ok && strings.ToLower(nsVal) == "info" {
			score += -10
		}
	}

	// Clamp score between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// Filter filters scored events based on the threshold.
func Filter(events []ScoredEvent) []ScoredEvent {
	var kept []ScoredEvent
	for _, ev := range events {
		if !ev.Suppressed {
			kept = append(kept, ev)
		}
	}
	return kept
}
