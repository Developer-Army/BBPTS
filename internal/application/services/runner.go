package services

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// RunCommandStream runs an external command and reads stdout stream line-by-line, returning unique lines.
func RunCommandStream(ctx context.Context, name string, args ...string) ([]string, error) {
	return RunCommandStreamWithInput(ctx, nil, name, args...)
}

// RunCommandStreamWithInput runs an external command with stdin provided, and reads stdout stream line-by-line, returning unique lines.
func RunCommandStreamWithInput(ctx context.Context, stdin []byte, name string, args ...string) ([]string, error) {
	cmd := prepareCommand(ctx, name, args...)

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	unique := make([]string, 0)
	seen := map[string]struct{}{}

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		unique = append(unique, line)
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return unique, scanErr
	}

	err = waitForCommand(ctx, cmd, &stderr)
	if err != nil {
		errStr := strings.TrimSpace(stderr.String())
		if errStr != "" {
			slog.Debug("command failed", "tool", name, "error", err, "stderr", errStr)
			return unique, fmt.Errorf("%s failed: %w", name, err)
		}
		slog.Debug("command failed", "tool", name, "error", err)
		return unique, fmt.Errorf("%s failed: %w", name, err)
	}

	return unique, nil
}
