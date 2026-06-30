package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"log/slog"
	"strings"
)

type TrufflehogTool struct{}

type truffleResult struct {
	Verified bool   `json:"verified"`
	Secret   string `json:"raw"`
	Type     string `json:"type"`
	Source   string `json:"sourceType"`
}

func (t *TrufflehogTool) Name() string {
	return "trufflehog"
}

func (t *TrufflehogTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := make([]recon.Event, 0)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		var args []string
		isURL := strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
		if isURL {
			targetLower := strings.ToLower(target)
			isGit := strings.HasSuffix(targetLower, ".git") ||
				strings.Contains(targetLower, "github.com") ||
				strings.Contains(targetLower, "gitlab.com") ||
				strings.Contains(targetLower, "bitbucket.org")

			if !isGit {
				slog.Debug("trufflehog: skipping plain web target (already scanned by regex/secrets modules)", "target", target)
				continue
			}
			args = []string{"git", target, "--json"}
		} else {
			args = []string{"filesystem", target, "--json"}
		}

		lines, err := RunCommandLines(ctx, "trufflehog", args...)
		if err != nil {
			slog.Debug("trufflehog execution warning", "target", target, "error", err)
			continue
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var result truffleResult
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				continue
			}

			if result.Secret == "" {
				continue
			}

			props := map[string]string{
				"secret_type": result.Type,
				"source":      result.Source,
				"verified":    fmt.Sprintf("%v", result.Verified),
			}

			severity := "medium"
			if result.Verified {
				severity = "high"
			}

			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "secret-found", props, severity))
		}
	}

	return events, nil
}
