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
	// Interactsh-client polls for out-of-band interactions.
	// We start the command and read the first line of stdout to get the URL,
	// then keep it running in a background goroutine to log any incoming interactions
	// until the context is cancelled.

	cmd := prepareCommand(ctx, "interactsh-client")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		slog.Warn("interactsh-client binary not found or failed to start; skipping tool", "error", err)
		return nil, nil
	}

	scanner := bufio.NewScanner(stdout)
	lineChan := make(chan string, 1)
	go func() {
		if scanner.Scan() {
			lineChan <- scanner.Text()
		} else {
			lineChan <- ""
		}
	}()

	var url string
	select {
	case line := <-lineChan:
		url = strings.TrimSpace(line)
	case <-time.After(5 * time.Second):
		slog.Warn("interactsh-client timed out registering session; skipping tool")
		terminateCommand(cmd)
		_ = cmd.Wait()
		return nil, nil
	case <-ctx.Done():
		terminateCommand(cmd)
		_ = cmd.Wait()
		return nil, ctx.Err()
	}

	if url == "" {
		slog.Warn("interactsh-client returned empty URL; skipping tool")
		terminateCommand(cmd)
		_ = cmd.Wait()
		return nil, nil
	}

	// Keep the process running in the background until context is canceled.
	go func() {
		// Wait for context done, then kill the process
		go func() {
			<-ctx.Done()
			terminateCommand(cmd)
		}()

		// Read continuous interaction logs from stdout
		for scanner.Scan() {
			text := scanner.Text()
			if strings.Contains(text, "[") || strings.Contains(text, "interaction") || strings.Contains(text, "DNS") || strings.Contains(text, "HTTP") {
				slog.Info("Interactsh interaction detected", "log", text)
			}
		}

		_ = cmd.Wait() // Reclaim resources
	}()

	return []Event{
		NewEvent(url, t.Name(), "oob_session", map[string]string{
			"description": "Unique Interactsh OOB session generated",
		}),
	}, nil
}
