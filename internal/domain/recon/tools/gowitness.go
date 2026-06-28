package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type GowitnessTool struct{}

func (t *GowitnessTool) Name() string {
	return "gowitness"
}

func (t *GowitnessTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Filter HTTP targets
	var httpTargets []string
	for _, target := range targets {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			httpTargets = append(httpTargets, target)
		}
	}
	if len(httpTargets) == 0 {
		return nil, nil
	}

	// Create temp file for targets list
	tmpFile, err := os.CreateTemp("", "gowitness_targets_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create gowitness temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	for _, target := range httpTargets {
		if _, err := tmpFile.WriteString(target + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write to gowitness temp file: %w", err)
		}
	}

	// Ensure destination directory exists
	destDir := "results/screenshots"
	if tmpDir := recon.GetTmpResultsDir(ctx); tmpDir != "" {
		destDir = filepath.Join(filepath.Dir(tmpDir), "screenshots")
	}
	_ = os.MkdirAll(destDir, 0755)

	args := []string{"scan", "file", "-f", tmpFile.Name(), "--screenshot-path", destDir, "--threads", fmt.Sprintf("%d", threads)}

	headers := scanCtx.Headers
	for k, v := range headers {
		args = append(args, "--header", fmt.Sprintf("%s: %s", k, v))
	}

	// Execute gowitness
	_, err = RunCommandLines(ctx, "gowitness", args...)
	if err != nil {
		return nil, fmt.Errorf("gowitness execution failed: %w", err)
	}

	// Match and rename gowitness screenshots to match MD5 naming convention of BBPTS reporting
	files, errRead := os.ReadDir(destDir)
	if errRead == nil {
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".png") {
				continue
			}
			name := strings.ToLower(f.Name())
			for _, target := range httpTargets {
				host := target
				if strings.Contains(host, "://") {
					if u, err := url.Parse(target); err == nil {
						host = u.Host
					}
				}
				cleanHost := strings.ReplaceAll(host, ".", "-")
				cleanHost = strings.ReplaceAll(cleanHost, ":", "-")

				if strings.Contains(name, cleanHost) {
					srcPath := filepath.Join(destDir, f.Name())
					md5URL := fmt.Sprintf("%x.png", md5.Sum([]byte(target)))
					md5Host := fmt.Sprintf("%x.png", md5.Sum([]byte(host)))

					targetWithSlash := target
					if !strings.HasSuffix(targetWithSlash, "/") {
						targetWithSlash += "/"
					}
					md5URLSlash := fmt.Sprintf("%x.png", md5.Sum([]byte(targetWithSlash)))

					_ = copyFile(srcPath, filepath.Join(destDir, md5URL))
					_ = copyFile(srcPath, filepath.Join(destDir, md5Host))
					_ = copyFile(srcPath, filepath.Join(destDir, md5URLSlash))
				}
			}
		}
	}

	events := make([]recon.Event, 0, len(httpTargets))
	for _, target := range httpTargets {
		events = append(events, recon.NewEvent(target, t.Name(), "screenshot", map[string]string{
			"screenshot_dir": destDir,
		}))
	}

	return events, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
