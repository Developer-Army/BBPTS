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

	wordlist := GetWordlistPath(ctx, "subdomain")
	if wordlist == "" {
		wordlist = filepath.Join(wordlistsDir, "subdomains-top1million-5000.txt")
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			wordlist = filepath.Join(wordlistsDir, "dns-5k.txt")
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

			args := []string{"vhost", "-u", url, "-w", wordlist, "-q", "-z", "--no-error", "-t", fmt.Sprintf("%d", targetThreads)}

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
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// e.g. "Found: admin.example.com (Status: 200)"
				if strings.Contains(line, "Found:") {
					parts := strings.Split(line, "Found:")
					if len(parts) > 1 {
						vhost := strings.TrimSpace(strings.Split(parts[1], "(")[0])
						if vhost != "" {
							targetEvents = append(targetEvents, NewEvent(vhost, t.Name(), "vhost", map[string]string{"vhost": vhost}))
						}
					}
				} else if !strings.HasPrefix(line, "[") && !strings.Contains(line, "Error:") {
					// Fallback for simple line output
					vhost := strings.TrimSpace(strings.Split(line, "(")[0])
					if vhost != "" && !strings.Contains(vhost, " ") {
						targetEvents = append(targetEvents, NewEvent(vhost, t.Name(), "vhost", map[string]string{"vhost": vhost}))
					}
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
