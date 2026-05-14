package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FFUFTool struct{}

func (t *FFUFTool) Name() string {
	return "ffuf"
}

func (t *FFUFTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	wordlistsDir := wordlistsDirFromContext(ctx)
	if wordlistsDir == "" {
		home, _ := os.UserHomeDir()
		wordlistsDir = filepath.Join(home, ".bbpts", "wordlists")
	}

	// Use directory wordlist for content discovery
	wordlist := GetWordlistPath(ctx, "directory")
	if wordlist == "" {
		// Fallback to raft-small-files.txt
		wordlist = filepath.Join(wordlistsDir, "raft-small-files.txt")
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			// Fallback to common.txt if raft-small is missing
			wordlist = filepath.Join(wordlistsDir, "common.txt")
		}
	}

	events := []Event{}
	for _, target := range targets {
		if !strings.HasPrefix(target, "http") {
			continue // ffuf needs a URL
		}

		// Ensure URL ends with FUZZ if not already present
		url := target
		if !strings.Contains(url, "FUZZ") {
			if !strings.HasSuffix(url, "/") {
				url += "/"
			}
			url += "FUZZ"
		}

		args := []string{"-u", url, "-w", wordlist, "-s", "-mc", "200,204,301,302,307,401,403", "-t", fmt.Sprintf("%d", threads)}

		// Optimization: Use RunCommandStream to process results line by line
		lines, err := RunCommandStream(ctx, "ffuf", args...)
		if err != nil {
			continue // Skip failed targets
		}

		for _, line := range lines {
			// ffuf with -s outputs just the results.
			// We need to reconstruct the full URL.
			foundPath := strings.TrimSpace(line)
			if foundPath == "" {
				continue
			}
			fullURL := strings.TrimSuffix(target, "/") + "/" + foundPath
			events = append(events, NewEvent(fullURL, t.Name(), "directory", map[string]string{"path": foundPath}))
		}
	}

	return events, nil
}
