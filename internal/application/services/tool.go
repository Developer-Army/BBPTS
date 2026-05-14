package services

import (
	"context"
	"path/filepath"
	"strings"
)

type Tool interface {
	Name() string
	Run(ctx context.Context, targets []string, threads int) ([]Event, error)
}

type Event struct {
	Target     string            `json:"target"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties"`
}

func NewEvent(target, source, eventType string, properties map[string]string) Event {
	if properties == nil {
		properties = make(map[string]string)
	}
	return Event{Target: target, Source: source, Type: eventType, Properties: properties}
}

func NewEventWithSeverity(target, source, eventType string, properties map[string]string, severity string) Event {
	if properties == nil {
		properties = make(map[string]string)
	}
	if severity != "" {
		properties["severity"] = severity
	}
	return NewEvent(target, source, eventType, properties)
}

func ParseOutputLines(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	unique := make([]string, 0, len(lines))
	seen := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		unique = append(unique, line)
	}
	return unique
}

func RunCommandLines(ctx context.Context, name string, args ...string) ([]string, error) {
	return RunCommandStream(ctx, name, args...)
}

func RunCommandWithInputLines(ctx context.Context, stdin []byte, name string, args ...string) ([]string, error) {
	return RunCommandStreamWithInput(ctx, stdin, name, args...)
}

// NewEventsFromLines converts a list of targets (one per line) into a slice of
// Event records with the specified source and shared metadata.
func NewEventsFromLines(lines []string, source string, metadata map[string]string) []Event {
	return NewEventsFromLinesFunc(lines, source, func(line string) map[string]string {
		if len(metadata) == 0 {
			return nil
		}
		copy := make(map[string]string, len(metadata))
		for k, v := range metadata {
			copy[k] = v
		}
		return copy
	})
}

// NewEventsFromLinesFunc converts a list of targets into a slice of Event records,
// using a generator function to produce properties for each line.
func NewEventsFromLinesFunc(lines []string, source string, metadataFunc func(string) map[string]string) []Event {
	if metadataFunc == nil {
		metadataFunc = func(string) map[string]string { return nil }
	}

	// Pre-allocate with initial capacity to reduce allocations
	events := make([]Event, 0, len(lines))

	// Ensure we don't process duplicate events internally
	seen := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip ASCII art / banners (heuristic: high density of box-drawing or art characters)
		if strings.Count(line, "/")+strings.Count(line, "_")+strings.Count(line, "\\")+strings.Count(line, "|") > 5 {
			continue
		}

		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}

		properties := metadataFunc(line)
		events = append(events, NewEvent(line, source, "discovery", properties))
	}
	return events
}

type contextKey string

const (
	apiKeyContextKey      contextKey = "api_keys"
	wordlistDirContextKey contextKey = "wordlist_dir"
	tmpResultsDirKey      contextKey = "tmp_results_dir"
	proxiesContextKey     contextKey = "proxies"
)

func WithAPIKeys(ctx context.Context, keys map[string]string) context.Context {
	return context.WithValue(ctx, apiKeyContextKey, keys)
}

func GetAPIKey(ctx context.Context, provider string) string {
	if keys, ok := ctx.Value(apiKeyContextKey).(map[string]string); ok {
		return keys[provider]
	}
	return ""
}

func WithWordlistsDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, wordlistDirContextKey, dir)
}

func WithTmpResultsDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, tmpResultsDirKey, dir)
}

func tmpResultsDirFromContext(ctx context.Context) string {
	if dir, ok := ctx.Value(tmpResultsDirKey).(string); ok {
		return dir
	}
	return ""
}

func wordlistsDirFromContext(ctx context.Context) string {
	if dir, ok := ctx.Value(wordlistDirContextKey).(string); ok {
		return dir
	}
	return ""
}

func GetWordlistPath(ctx context.Context, name string) string {
	dir := wordlistsDirFromContext(ctx)
	if dir == "" {
		return ""
	}
	// Mapping for common wordlist types
	mapping := map[string]string{
		"dns":       "dns-5k.txt",
		"directory": "raft-small-files.txt",
		"subdomain": "subdomains-top1million-5000.txt",
		"api":       "api-endpoints.txt",
	}
	if filename, ok := mapping[name]; ok {
		return filepath.Join(dir, filename)
	}
	// Fallback to common.txt for unknown types
	return filepath.Join(dir, "common.txt")
}

func WithProxies(ctx context.Context, proxies []string) context.Context {
	return context.WithValue(ctx, proxiesContextKey, proxies)
}

func GetProxies(ctx context.Context) []string {
	if proxies, ok := ctx.Value(proxiesContextKey).([]string); ok {
		return proxies
	}
	return nil
}
