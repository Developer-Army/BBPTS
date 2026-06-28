package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type FFUFTool struct{}

func (t *FFUFTool) Name() string {
	return "ffuf"
}

func (t *FFUFTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	wordlistsDir := recon.WordlistsDirFromContext(ctx)
	if wordlistsDir == "" {
		home, _ := os.UserHomeDir()
		wordlistsDir = filepath.Join(home, ".bbpts", "wordlists")
	}

	// Use directory wordlist for content discovery
	wordlist := recon.GetWordlistPath(ctx, "directory")
	if wordlist == "" {
		if scanCtx.LowResource {
			wordlist = filepath.Join(wordlistsDir, "seclists_common.txt")
			if _, err := os.Stat(wordlist); os.IsNotExist(err) {
				wordlist = filepath.Join(wordlistsDir, "raft-small-files.txt")
			}
		} else {
			// Fallback to raft-small-files.txt
			wordlist = filepath.Join(wordlistsDir, "raft-small-files.txt")
			if _, err := os.Stat(wordlist); os.IsNotExist(err) {
				// Fallback to common.txt if raft-small is missing
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

	events := []recon.Event{}
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

			// Ensure URL ends with FUZZ if not already present
			fuzzURL := url
			if !strings.Contains(fuzzURL, "FUZZ") {
				if !strings.HasSuffix(fuzzURL, "/") {
					fuzzURL += "/"
				}
				fuzzURL += "FUZZ"
			}

			args := []string{"-u", fuzzURL, "-w", wordlist, "-s", "-mc", "200,204,301,302,307,401,403", "-t", fmt.Sprintf("%d", targetThreads)}

			rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
			if rateLimit > 0 {
				targetRate := rateLimit / maxWorkers
				if targetRate < 1 {
					targetRate = 1
				}
				args = append(args, "-rate", fmt.Sprintf("%d", targetRate))
			}

			headers := scanCtx.Headers
			for k, v := range headers {
				args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
			}

			// Optimization: Use RunCommandStream to process results line by line
			timeoutDuration := 60 * time.Second
			if scanCtx.LowResource {
				timeoutDuration = 15 * time.Second
			}
			targetCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
			defer cancel()

			lines, err := RunCommandStream(targetCtx, "ffuf", args...)
			if err != nil {
				return
			}

			var targetEvents []recon.Event
			for _, line := range lines {
				foundPath := strings.TrimSpace(line)
				if foundPath == "" {
					continue
				}
				fullURL := strings.TrimSuffix(url, "/") + "/" + foundPath
				targetEvents = append(targetEvents, recon.NewEvent(fullURL, t.Name(), "directory", map[string]string{"path": foundPath}))
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
