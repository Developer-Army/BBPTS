package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"strings"
	"sync"
)

type DalfoxTool struct{}

type dalfoxOutput struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Payload   string `json:"payload"`
	Parameter string `json:"parameter"`
	Severity  string `json:"severity"`
	Evidence  string `json:"evidence"`
}

func (t *DalfoxTool) Name() string {
	return "dalfox"
}

func (t *DalfoxTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

	events := make([]recon.Event, 0)
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

			args := []string{"url", url, "--json"}
			if oobURL := scanCtx.InteractshOOBURL; oobURL != "" {
				args = append(args, "-b", oobURL)
			}
			headers := scanCtx.Headers
			for k, v := range headers {
				args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
			}
			for _, header := range wafBypassHeaders(scanCtx.WAFContext) {
				args = append(args, "-H", header)
			}
			if scanCtx.WAFContext != "" {
				args = append(args, "--waf-evasion")
			}
			lines, err := RunCommandLines(ctx, "dalfox", args...)
			if err != nil {
				return
			}

			var targetEvents []recon.Event
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				var out dalfoxOutput
				if err := json.Unmarshal([]byte(line), &out); err != nil {
					continue
				}

				if out.URL == "" {
					continue
				}

				props := map[string]string{}
				if out.Severity != "" {
					props["severity"] = out.Severity
				}
				if out.Payload != "" {
					props["payload"] = out.Payload
				}
				if out.Parameter != "" {
					props["parameter"] = out.Parameter
				}
				if out.Evidence != "" {
					props["evidence"] = out.Evidence
				}

				targetEvents = append(targetEvents, recon.NewEvent(out.URL, t.Name(), "vulnerability", props))
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
