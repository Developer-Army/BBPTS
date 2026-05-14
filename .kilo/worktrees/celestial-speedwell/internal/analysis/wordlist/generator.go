package wordlist

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/engine/recon"
)

// Generator extracts intelligence from recon events to build custom wordlists.
type Generator struct {
	keywords   map[string]struct{}
	paths      map[string]struct{}
	parameters map[string]struct{}
}

// NewGenerator creates a new wordlist generator.
func NewGenerator() *Generator {
	return &Generator{
		keywords:   make(map[string]struct{}),
		paths:      make(map[string]struct{}),
		parameters: make(map[string]struct{}),
	}
}

// ProcessEvents extracts keywords and patterns from a slice of events.
func (g *Generator) ProcessEvents(events []recon.Event) {
	// Regexp to find potential keywords (alphanumeric, 3-20 chars)
	wordRegex := regexp.MustCompile(`[a-zA-Z0-9-]{3,20}`)

	for _, ev := range events {
		// 1. Extract from Target (URL or Host)
		parts := strings.FieldsFunc(ev.Target, func(c rune) bool {
			return c == '/' || c == '.' || c == '?' || c == '&' || c == '=' || c == ':' || c == '-' || c == '_'
		})
		for _, p := range parts {
			if wordRegex.MatchString(p) {
				g.keywords[strings.ToLower(p)] = struct{}{}
			}
		}

		// 2. Extract from Properties (if any)
		for k, v := range ev.Properties {
			if k == "path" || k == "url" {
				g.paths[v] = struct{}{}
			}
			// Extract potential parameter names
			if strings.Contains(v, "=") {
				paramParts := strings.Split(v, "=")
				if len(paramParts) > 0 {
					g.parameters[paramParts[0]] = struct{}{}
				}
			}
		}
	}
}

// SaveCustomWordlist writes the extracted intelligence to a file.
func (g *Generator) SaveCustomWordlist(scope string, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}

	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s_custom_wordlist.txt", scope))
	file, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Collect all unique strings
	var all []string
	for k := range g.keywords {
		all = append(all, k)
	}
	for k := range g.paths {
		// Clean path to get the last segment
		segments := strings.Split(k, "/")
		last := segments[len(segments)-1]
		if last != "" {
			all = append(all, last)
		}
	}
	for k := range g.parameters {
		all = append(all, k)
	}

	// Deduplicate
	unique := make(map[string]struct{})
	var final []string
	for _, s := range all {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || len(s) < 3 {
			continue
		}
		if _, ok := unique[s]; !ok {
			unique[s] = struct{}{}
			final = append(final, s)
		}
	}

	sort.Strings(final)

	for _, s := range final {
		if _, err := writer.WriteString(s + "\n"); err != nil {
			return outputPath, err
		}
	}

	return outputPath, writer.Flush()
}
