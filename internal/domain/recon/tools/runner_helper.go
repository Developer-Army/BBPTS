package tools

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func waitForCommand(ctx context.Context, cmd commandHandle, stderr *bytes.Buffer) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		TerminateCommand(cmd)
		// Ensure cmd.Wait() returns before we read/return stderr-backed errors.
		// This prevents races where os/exec is still copying stderr.
		<-errCh
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			errText := strings.TrimSpace(stderr.String())
			if errText == "" {
				return err
			}
			return fmt.Errorf("%w: %s", err, errText)
		}
		return nil
	}
}

// ExecTool runs an external tool safely. It uses platform-specific process cleanup
// so that a timed out tool does not leave child processes behind.
func ExecTool(ctx context.Context, name string, args []string, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	cmd := PrepareCommand(ctx, name, args...)
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s: %w", name, err)
	}

	if err := waitForCommand(ctx, cmd, &stderr); err != nil {
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}

	rawOutput := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var cleanOutput []string
	for _, line := range rawOutput {
		if strings.TrimSpace(line) != "" {
			cleanOutput = append(cleanOutput, strings.TrimSpace(line))
		}
	}

	return cleanOutput, nil
}

func RunCommandLines(ctx context.Context, name string, args ...string) ([]string, error) {
	return RunCommandStream(ctx, name, args...)
}

func RunCommandWithInputLines(ctx context.Context, stdin []byte, name string, args ...string) ([]string, error) {
	return RunCommandStreamWithInput(ctx, stdin, name, args...)
}

// NewEventsFromLines converts a list of targets (one per line) into a slice of
// Event records with the specified source and shared metadata.
func NewEventsFromLines(lines []string, source string, metadata map[string]string) []recon.Event {
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
func NewEventsFromLinesFunc(lines []string, source string, metadataFunc func(string) map[string]string) []recon.Event {
	if metadataFunc == nil {
		metadataFunc = func(string) map[string]string { return nil }
	}

	// Pre-allocate with initial capacity to reduce allocations
	events := make([]recon.Event, 0, len(lines))

	// Ensure we don't process duplicate events internally
	seen := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip ASCII art / banners (heuristic: high density of box-drawing or art characters)
		if !strings.Contains(line, "://") {
			if strings.Count(line, "/")+strings.Count(line, "_")+strings.Count(line, "\\")+strings.Count(line, "|") > 5 {
				continue
			}
		}

		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}

		properties := metadataFunc(line)
		events = append(events, recon.NewEvent(line, source, "discovery", properties))
	}
	return events
}
