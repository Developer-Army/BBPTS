package services

import (
	"bufio"
	"context"
	"log/slog"
	"strings"
	"time"
)

// InteractshTool wraps interactsh-client for OOB vulnerability testing.
type InteractshTool struct{}

func (t *InteractshTool) Name() string {
	return "interactsh"
}

func (t *InteractshTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	// Interactsh is usually used to generate a payload URL or monitor for interactions.
	// For this adapter, we will use it to generate a unique session and return it.
	// Since interactsh-client polls forever, we start it, read the first line of stdout (the URL),
	// and then immediately terminate it.

	cmd := prepareCommand(ctx, "interactsh-client", "-n", "1")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		slog.Warn("interactsh-client binary not found or failed to start; skipping tool", "error", err)
		return nil, nil
	}

	var url string
	scanner := bufio.NewScanner(stdout)
	lineChan := make(chan string, 1)
	go func() {
		if scanner.Scan() {
			lineChan <- scanner.Text()
		} else {
			lineChan <- ""
		}
	}()

	select {
	case line := <-lineChan:
		url = strings.TrimSpace(line)
	case <-time.After(3 * time.Second):
		slog.Warn("interactsh-client timed out registering session; skipping tool")
		terminateCommand(cmd)
		_ = cmd.Wait()
		return nil, nil
	case <-ctx.Done():
		terminateCommand(cmd)
		_ = cmd.Wait()
		return nil, ctx.Err()
	}

	terminateCommand(cmd)
	_ = cmd.Wait() // Reclaim process resources

	if url == "" {
		slog.Warn("interactsh-client returned empty URL; skipping tool")
		return nil, nil
	}

	return []Event{
		NewEvent(url, t.Name(), "oob_session", map[string]string{
			"description": "Unique Interactsh OOB session generated",
		}),
	}, nil
}
