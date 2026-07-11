package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net"
	"strings"
	"sync"
	"time"
)

type PermutationTool struct{}

func (t *PermutationTool) Name() string {
	return "permutation"
}

func (t *PermutationTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	prefixes := []string{"dev", "staging", "api", "prod", "test", "demo", "admin", "beta", "internal", "support", "sys", "web"}
	suffixes := []string{"dev", "staging", "api", "prod", "test", "demo", "admin", "beta", "internal", "support", "sys", "web", "1", "2", "3"}

	var candidates []string
	seen := make(map[string]bool)

	for _, target := range targets {
		target = strings.TrimSpace(strings.ToLower(target))
		if target == "" {
			continue
		}

		if strings.Contains(target, "://") {
			parts := strings.Split(target, "://")
			target = parts[len(parts)-1]
		}
		if idx := strings.Index(target, "/"); idx != -1 {
			target = target[:idx]
		}
		if idx := strings.Index(target, ":"); idx != -1 {
			target = target[:idx]
		}

		parts := strings.Split(target, ".")
		if len(parts) < 3 {
			continue
		}

		sub := parts[0]
		domain := strings.Join(parts[1:], ".")

		variants := []string{
			sub,
		}

		for _, p := range prefixes {
			variants = append(variants,
				fmt.Sprintf("%s-%s", p, sub),
				fmt.Sprintf("%s%s", p, sub),
			)
		}
		for _, s := range suffixes {
			variants = append(variants,
				fmt.Sprintf("%s-%s", sub, s),
				fmt.Sprintf("%s%s", sub, s),
			)
		}

		for _, v := range variants {
			domainVar := fmt.Sprintf("%s.%s", v, domain)
			if !seen[domainVar] {
				seen[domainVar] = true
				candidates = append(candidates, domainVar)
			}
		}
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	results := make(chan string, len(candidates))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, "1.1.1.1:53")
		},
	}

	for _, cand := range candidates {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			ips, err := resolver.LookupIPAddr(ctxTimeout, domain)
			if err == nil && len(ips) > 0 {
				results <- domain
			}
		}(cand)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var events []recon.Event
	for res := range results {
		events = append(events, recon.NewEvent(res, t.Name(), "subdomain", map[string]string{
			"resolved": "true",
		}))
	}

	return events, nil
}
