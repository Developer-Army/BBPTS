package recon

import (
	"context"
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
