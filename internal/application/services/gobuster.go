package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
		if LowResourceFromCtx(ctx) {
			wordlist = filepath.Join(wordlistsDir, "seclists_common.txt")
			if _, err := os.Stat(wordlist); os.IsNotExist(err) {
				wordlist = filepath.Join(wordlistsDir, "raft-small-files.txt")
			}
		} else {
			// Fallback to raft-small-files.txt
			wordlist = filepath.Join(wordlistsDir, "raft-small-files.txt")
			if _, err := os.Stat(wordlist); os.IsNotExist(err) {
				wordlist = filepath.Join(wordlistsDir, "seclists_common.txt")
			}
		}
	}

	var validTargets []string
	for _, target := range targets {
		if strings.HasPrefix(target, "http") {
			validTargets = append(validTargets, target)
		}
	}
	if len(validTargets) == 0 {
		return nil, nil
	}

	maxWorkers := threads
	if maxWorkers > 5 {
		maxWorkers = 5
	}
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	targetThreads := threads / maxWorkers
	if targetThreads < 1 {
		targetThreads = 1
	}

	events := []Event{}
	var mu sync.Mutex
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, target := range validTargets {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			args := []string{"dir", "-u", url, "-w", wordlist, "-q", "-z", "--no-error", "-t", fmt.Sprintf("%d", targetThreads)}

			headers := HeadersFromCtx(ctx)
			for k, v := range headers {
				args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
			}

			timeoutDuration := 60 * time.Second
			if LowResourceFromCtx(ctx) {
				timeoutDuration = 15 * time.Second
			}
			targetCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
			defer cancel()

			lines, err := RunCommandStream(targetCtx, "gobuster", args...)
			if err != nil {
				return
			}

			var targetEvents []Event
			for _, line := range lines {
				// Gobuster output format can be "Found: /path (Status: 200)"
				path := strings.TrimSpace(line)
				if strings.HasPrefix(path, "/") {
					fullURL := fmt.Sprintf("%s/%s", url, path)
					targetEvents = append(targetEvents, NewEvent(fullURL, t.Name(), "directory", map[string]string{"path": path}))
				}
			}

			if len(targetEvents) > 0 {
				mu.Lock()
				events = append(events, targetEvents...)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return events, nil
}
