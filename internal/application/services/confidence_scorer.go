package services

import (
	"strconv"
	"strings"
)

type ScoredEvent struct {
	Event
	ConfidenceScore int  `json:"confidence_score"`
	Suppressed      bool `json:"suppressed"`
}

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

func ScoreEvent(ev Event) int {
	score := 50

	switch strings.ToLower(ev.Source) {
	case "nuclei":

		if ev.Properties != nil {
			if nsVal, ok := ev.Properties["nuclei_severity"]; ok {
				switch strings.ToLower(nsVal) {
				case "critical", "high":
					score += 15
				case "medium":
					score += 10
				case "low":
					score += 5
				}
			}
		}
	case "gau":
		score += -10
	case "shodan":
		score += -5
	}

	switch strings.ToLower(ev.Type) {
	case "vulnerability":
		score += 20
	case "info":
		score += -15
	}

	if ev.Properties != nil {
		if scVal, ok := ev.Properties["status_code"]; ok {
			if sc, err := strconv.Atoi(scVal); err == nil {
				switch sc {
				case 200:
					score += 10
				case 404:
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

	targetLower := strings.ToLower(ev.Target)

	if strings.Contains(targetLower, "127.0.0.1") || strings.Contains(targetLower, "localhost") || strings.Contains(targetLower, "[::1]") {
		score += -25
	} else {

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

	if ev.Properties != nil {
		if cbVal, ok := ev.Properties["corroborated_by"]; ok && cbVal != "" {
			otherTools := strings.Split(cbVal, ",")
			passiveSources := map[string]bool{"gau": true, "shodan": true}
			corroborationWeight := 0.0
			for _, tool := range otherTools {
				tool = strings.ToLower(strings.TrimSpace(tool))
				if tool == "" {
					continue
				}
				if passiveSources[tool] {
					corroborationWeight += 0.5
				} else {
					corroborationWeight += 1.0
				}
			}

			switch {
			case corroborationWeight >= 3:
				score += 20
			case corroborationWeight >= 2:
				score += 12
			case corroborationWeight >= 1:
				score += 5
			}
		} else {
			score += -5
		}
	} else {
		score += -5
	}

	if ev.Properties != nil {
		if ncVal, ok := ev.Properties["nuclei_confidence"]; ok && strings.EqualFold(ncVal, "confirmed") {
			score += 15
		}
		if nsVal, ok := ev.Properties["nuclei_severity"]; ok && strings.EqualFold(nsVal, "info") {
			score += -10
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

func Filter(events []ScoredEvent) []ScoredEvent {
	var kept []ScoredEvent
	for _, ev := range events {
		if !ev.Suppressed {
			kept = append(kept, ev)
		}
	}
	return kept
}
