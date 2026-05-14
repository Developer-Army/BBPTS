package config

import "strings"

// ToolPreset maps a short name to default tools and timing for repeatable workflows.
type ToolPreset struct {
	Tools     string `json:"tools"`
	Timeout   string `json:"timeout"` // Go duration string, e.g. "90s"
	RateLimit int    `json:"rate_limit"`
}

// ProgramProfile groups defaults and exclusions for a specific bounty program or scope.
type ProgramProfile struct {
	Tools         string   `json:"tools"`
	RateLimit     int      `json:"rate_limit"`
	Timeout       string   `json:"timeout"`
	ExcludeHosts  []string `json:"exclude_hosts"`
	ExcludeSuffix []string `json:"exclude_suffix"`
}

// FilterTargets removes hosts that match program exclusion lists (substring suffix or exact host).
func FilterTargets(hosts []string, profile ProgramProfile) []string {
	if len(profile.ExcludeHosts) == 0 && len(profile.ExcludeSuffix) == 0 {
		return hosts
	}

	exacts := make(map[string]struct{}, len(profile.ExcludeHosts))
	for _, h := range profile.ExcludeHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			exacts[h] = struct{}{}
		}
	}

	suffixes := make([]string, 0, len(profile.ExcludeSuffix))
	for _, s := range profile.ExcludeSuffix {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			suffixes = append(suffixes, s)
		}
	}

	out := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		lh := strings.ToLower(strings.TrimSpace(raw))
		if _, skip := exacts[lh]; skip {
			continue
		}
		skip := false
		for _, suf := range suffixes {
			if strings.HasSuffix(lh, suf) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, raw)
		}
	}
	return out
}
