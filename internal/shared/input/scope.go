package input

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

type ScopeEngine struct {
	Allows   []string
	Excludes []string
}

func NewScopeEngine(allows, excludes []string) *ScopeEngine {
	return &ScopeEngine{Allows: allows, Excludes: excludes}
}

func LoadScopeFile(path string) (*ScopeEngine, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseScope(file)
}

type H1ScopeItem struct {
	AssetIdentifier       string `json:"asset_identifier"`
	AssetType             string `json:"asset_type"`
	EligibleForBounty     bool   `json:"eligible_for_bounty"`
	EligibleForSubmission bool   `json:"eligible_for_submission"`
}

type H1ProgramResponse struct {
	StructuredScopes []H1ScopeItem `json:"structured_scopes"`
	Target           struct {
		StructuredScopes []H1ScopeItem `json:"structured_scopes"`
	} `json:"target"`
}

type BugcrowdTarget struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	InScope  bool   `json:"in_scope"`
}

type BugcrowdTargetGroup struct {
	Name    string           `json:"name"`
	InScope bool             `json:"in_scope"`
	Targets []BugcrowdTarget `json:"targets"`
}

type BugcrowdProgram struct {
	TargetGroups []BugcrowdTargetGroup `json:"target_groups"`
	Targets      []BugcrowdTarget      `json:"targets"`
}

func ParseJSONScope(data []byte) (*ScopeEngine, bool) {
	// 1. Try HackerOne
	var h1 H1ProgramResponse
	if err := json.Unmarshal(data, &h1); err == nil {
		scopes := h1.StructuredScopes
		if len(scopes) == 0 {
			scopes = h1.Target.StructuredScopes
		}
		if len(scopes) > 0 {
			var allows []string
			var excludes []string
			for _, item := range scopes {
				val := strings.TrimSpace(strings.ToLower(item.AssetIdentifier))
				if val == "" {
					continue
				}

				inScope := item.EligibleForSubmission
				if inScope {
					allows = append(allows, val)
				} else {
					excludes = append(excludes, val)
				}
			}
			return &ScopeEngine{Allows: allows, Excludes: excludes}, true
		}
	}

	// Try alternate list format of HackerOne
	var h1List []H1ScopeItem
	if err := json.Unmarshal(data, &h1List); err == nil && len(h1List) > 0 && h1List[0].AssetIdentifier != "" {
		var allows []string
		var excludes []string
		for _, item := range h1List {
			val := strings.TrimSpace(strings.ToLower(item.AssetIdentifier))
			if val == "" {
				continue
			}
			if item.EligibleForSubmission {
				allows = append(allows, val)
			} else {
				excludes = append(excludes, val)
			}
		}
		return &ScopeEngine{Allows: allows, Excludes: excludes}, true
	}

	// 2. Try Bugcrowd
	var bc BugcrowdProgram
	if err := json.Unmarshal(data, &bc); err == nil {
		var allows []string
		var excludes []string
		hasTargets := false

		for _, tg := range bc.TargetGroups {
			for _, t := range tg.Targets {
				val := strings.TrimSpace(strings.ToLower(t.Name))
				if val == "" {
					continue
				}
				hasTargets = true
				if tg.InScope && t.InScope {
					allows = append(allows, val)
				} else {
					excludes = append(excludes, val)
				}
			}
		}

		for _, t := range bc.Targets {
			val := strings.TrimSpace(strings.ToLower(t.Name))
			if val == "" {
				continue
			}
			hasTargets = true
			if t.InScope {
				allows = append(allows, val)
			} else {
				excludes = append(excludes, val)
			}
		}

		if hasTargets {
			return &ScopeEngine{Allows: allows, Excludes: excludes}, true
		}
	}

	return nil, false
}

func ParseScope(r io.Reader) (*ScopeEngine, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if se, ok := ParseJSONScope(data); ok {
		return se, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var allows []string
	var excludes []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		isExclude := false
		if strings.HasPrefix(line, "!") {
			isExclude = true
			line = strings.TrimPrefix(line, "!")
		} else if strings.HasPrefix(line, "exclude:") {
			isExclude = true
			line = strings.TrimPrefix(line, "exclude:")
		}

		line = strings.TrimSpace(strings.ToLower(line))
		if line == "" {
			continue
		}

		if isExclude {
			excludes = append(excludes, line)
		} else {
			allows = append(allows, line)
		}
	}

	return &ScopeEngine{Allows: allows, Excludes: excludes}, scanner.Err()
}

func (se *ScopeEngine) IsInScope(target string) bool {
	host := strings.ToLower(target)
	if strings.Contains(host, "://") {
		if u, err := url.Parse(target); err == nil {
			host = u.Hostname()
		}
	} else {
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
	}

	for _, p := range se.Excludes {
		if isCIDRorIP(p) {
			if MatchCIDRPattern(host, p) {
				return false
			}
		} else {
			if MatchPattern(host, p) {
				return false
			}
		}
	}

	if len(se.Allows) == 0 {
		return true
	}

	for _, p := range se.Allows {
		if isCIDRorIP(p) {
			if MatchCIDRPattern(host, p) {
				return true
			}
		} else {
			if MatchPattern(host, p) {
				return true
			}
		}
	}

	return false
}

func MatchPattern(host, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(host, parts[0]) && strings.HasSuffix(host, parts[1])
		}
	}
	return host == pattern
}

func MatchCIDRPattern(host, pattern string) bool {
	_, ipnet, err := net.ParseCIDR(pattern)
	if err != nil {

		patIP := net.ParseIP(pattern)
		if patIP == nil {
			return false
		}

		hostIP := net.ParseIP(host)
		if hostIP != nil {
			return hostIP.Equal(patIP)
		}

		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				if ip.Equal(patIP) {
					return true
				}
			}
		}
		return false
	}

	hostIP := net.ParseIP(host)
	if hostIP != nil {
		return ipnet.Contains(hostIP)
	}

	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if ipnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func isCIDRorIP(p string) bool {
	if strings.Contains(p, "/") {
		_, _, err := net.ParseCIDR(p)
		return err == nil
	}
	return net.ParseIP(p) != nil
}
