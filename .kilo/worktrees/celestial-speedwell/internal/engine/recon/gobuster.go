package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type GobusterTool struct{}

func (t *GobusterTool) Name() string {
	return "gobuster"
}

func (t *GobusterTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	wordlistsDir := wordlistsDirFromContext(ctx)
	if wordlistsDir == "" {
		home, _ := os.UserHomeDir()
		wordlistsDir = filepath.Join(home, ".bbpts", "wordlists")
	}

	wordlist := GetWordlistPath(ctx, "directory")
	if wordlist == "" {
		// Fallback to raft-small-files.txt
		wordlist = filepath.Join(wordlistsDir, "raft-small-files.txt")
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			wordlist = filepath.Join(wordlistsDir, "common.txt")
		}
	}

	events := []Event{}
	for _, target := range targets {
		if !strings.HasPrefix(target, "http") {
			continue
		}

		args := []string{"dir", "-u", target, "-w", wordlist, "-q", "-z", "--no-error", "-t", fmt.Sprintf("%d", threads)}

		lines, err := RunCommandStream(ctx, "gobuster", args...)
		if err != nil {
			continue
		}

		for _, line := range lines {
			// Gobuster output format can be "Found: /path (Status: 200)"
			path := strings.TrimSpace(line)
			if strings.HasPrefix(path, "/") {
				fullURL := fmt.Sprintf("%s/%s", target, path)
				events = append(events, NewEvent(fullURL, t.Name(), "directory", map[string]string{"path": path}))
			}
		}
	}

	return events, nil
}
