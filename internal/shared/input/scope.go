package input

import (
	"bufio"
	"io"
	"net/url"
	"os"
	"strings"
)

// ScopeEngine loads allowed and excluded scope rules and checks targets against them.
type ScopeEngine struct {
	Allows   []string
	Excludes []string
}

// NewScopeEngine creates a scope engine from lists of allow/exclude patterns.
func NewScopeEngine(allows, excludes []string) *ScopeEngine {
	return &ScopeEngine{Allows: allows, Excludes: excludes}
}

// LoadScopeFile parses a scope file into a ScopeEngine.
func LoadScopeFile(path string) (*ScopeEngine, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseScope(file)
}

// ParseScope parses allow/exclude patterns from a reader.
func ParseScope(r io.Reader) (*ScopeEngine, error) {
	scanner := bufio.NewScanner(r)
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

// IsInScope checks if a target (domain or URL) is in scope.
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

	// Check excludes first
	for _, p := range se.Excludes {
		if MatchPattern(host, p) {
			return false
		}
	}

	// If Allows is empty, default to in-scope
	if len(se.Allows) == 0 {
		return true
	}

	for _, p := range se.Allows {
		if MatchPattern(host, p) {
			return true
		}
	}

	return false
}

// MatchPattern checks if a host matches a wildcard pattern.
// Pattern can be like "example.com", "*.example.com", or "abc.*.example.com".
func MatchPattern(host, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
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
