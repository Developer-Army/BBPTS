package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type ArjunTool struct{}

func (t *ArjunTool) Name() string {
	return "arjun"
}

func (t *ArjunTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
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

	events := make([]Event, 0)
	var mu sync.Mutex
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, target := range validTargets {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// Run arjun to find hidden parameters
			args := []string{"-u", urlStr, "--passive"}
			headers := HeadersFromCtx(ctx)
			for k, v := range headers {
				args = append(args, "--headers", fmt.Sprintf("%s: %s", k, v))
			}
			lines, err := RunCommandLines(ctx, "arjun", args...)
			if err != nil {
				return
			}

			var targetEvents []Event
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Arjun outputs urls with discovered parameters appended
				if strings.Contains(line, "?") || strings.Contains(line, "&") {
					targetEvents = append(targetEvents, NewEvent(line, t.Name(), "discovery", map[string]string{
						"discovered_by": "arjun",
					}))
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
