package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type AmassTool struct{}

func (t *AmassTool) Name() string {
	return "amass"
}

func (t *AmassTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"enum", "-silent", "-dL", "-"}

	wordlistsDir := wordlistsDirFromContext(ctx)
	if wordlistsDir != "" {
		subdomainWordlist := GetWordlistPath(ctx, "subdomain")
		if subdomainWordlist == "" {
			// Fallback to default subdomain wordlist
			subdomainWordlist = filepath.Join(wordlistsDir, "subdomains-top1million-5000.txt")
		}
		if _, err := os.Stat(subdomainWordlist); err == nil {
			args = append(args, "-brute", "-w", subdomainWordlist)
		}
	}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "amass", args...)
	if err != nil {
		return nil, fmt.Errorf("amass execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"source_target": value}
	}), nil
}
