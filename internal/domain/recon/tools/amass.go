package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

type AmassTool struct{}

func (t *AmassTool) Name() string {
	return "amass"
}

func (t *AmassTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var args []string
	scanMode := recon.GetScanMode(ctx)
	if scanMode == "light" {
		args = []string{"enum", "-passive", "-silent", "-d", strings.Join(targets, ",")}
	} else {
		args = []string{"enum", "-silent", "-d", strings.Join(targets, ",")}

		wordlistsDir := recon.WordlistsDirFromContext(ctx)
		if wordlistsDir != "" {
			subdomainWordlist := recon.GetWordlistPath(ctx, "subdomain")
			if subdomainWordlist == "" {
				subdomainWordlist = filepath.Join(wordlistsDir, "subdomains-top1million-5000.txt")
			}
			if _, err := os.Stat(subdomainWordlist); err == nil {
				args = append(args, "-brute", "-w", subdomainWordlist)
			}
		}
	}

	keys := recon.APIKeysFromCtx(ctx)
	if dsConfigPath, err := config.WriteAmassDatasourcesConfig(keys); err == nil && dsConfigPath != "" {
		args = append(args, "-config", dsConfigPath)
		defer os.Remove(dsConfigPath)
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
