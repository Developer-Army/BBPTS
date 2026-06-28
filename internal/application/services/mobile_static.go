package services

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type MobileStaticTool struct{}

func (t *MobileStaticTool) Name() string { return "mobile_static" }

var mobileSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(?:secret|client[_-]?secret)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']`),
	regexp.MustCompile(`(?i)(?:token|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["']?(AKIA[0-9A-Z]{16})["']?`),
	regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']([^"']{40})["']`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(?:firebase[_-]?url|firebasedatabaseurl)\s*[:=]\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)(?:oauth[_-]?client[_-]?id)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(?:basic[_-]?auth)\s*[:=]\s*["']([^"']{8,})["']`),
}

var mobileEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://[a-zA-Z0-9._/-]+(?:api|v[0-9]+)[a-zA-Z0-9._/-]*`),
	regexp.MustCompile(`(?:GET|POST|PUT|DELETE|PATCH)\s+([/][a-zA-Z0-9._/-]+)`),
	regexp.MustCompile(`"((?:/[a-zA-Z0-9._/-]+){2,})"`),
}

var mobileConfigPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:bundle[_-]?id|package[_-]?name)\s*[:=]\s*["']([a-zA-Z0-9.]+)["']`),
	regexp.MustCompile(`(?i)(?:version[_-]?name|version[_-]?code)\s*[:=]\s*["']?([0-9.]+)["']?`),
	regexp.MustCompile(`(?i)(?:deeplink|app[_-]?link)\s*[:=]\s*["']([a-zA-Z0-9._:/-]+)["']`),
}

type mobileFinding struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	File     string `json:"file"`
	Severity string `json:"severity"`
}

func (t *MobileStaticTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	maxThreads := threads
	if LowResourceFromCtx(ctx) {
		if maxThreads > 2 {
			maxThreads = 2
		}
	} else if maxThreads > 4 {
		maxThreads = 4
	}

	events := []Event{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxThreads)

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		wg.Add(1)
		go func(tgt string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			evts := t.analyzeTarget(ctx, tgt)
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *MobileStaticTool) analyzeTarget(ctx context.Context, target string) []Event {
	lower := strings.ToLower(target)

	switch {
	case strings.HasSuffix(lower, ".ipa") || strings.HasSuffix(lower, ".apk"):
		evts, err := t.analyzeLocalBinary(ctx, target)
		if err != nil {
			slog.Debug("mobile_static: local analysis failed", "target", target, "error", err)
			return t.reconFallback(target)
		}
		return evts

	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		evts, err := t.analyzeRemote(ctx, target)
		if err != nil {
			slog.Debug("mobile_static: remote fetch failed", "target", target, "error", err)
			return t.reconFallback(target)
		}
		return evts

	case strings.Contains(target, "apple.com") || strings.Contains(target, "itunes"):
		return t.reconFromAppleID(target)

	case strings.Contains(target, "play.google.com") || strings.Contains(target, "market://"):
		return t.reconFromGPStore(target)

	default:
		return t.reconFallback(target)
	}
}

func (t *MobileStaticTool) analyzeLocalBinary(ctx context.Context, path string) ([]Event, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".ipa" && ext != ".apk" {
		return nil, fmt.Errorf("unsupported: %s", ext)
	}

	tmpDir, err := os.MkdirTemp("", "bbpts-mobile-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if fi.Size() > 500*1024*1024 {
		return nil, fmt.Errorf("file too large: %d bytes", fi.Size())
	}

	r, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return t.analyzeRawStream(path)
	}

	if err := extractZipStream(r, tmpDir); err != nil {
		return nil, err
	}

	return t.scanExtractedDir(tmpDir, targetFromPath(path))
}

func (t *MobileStaticTool) analyzeRemote(ctx context.Context, appURL string) ([]Event, error) {
	client := NewSafeHTTPClient(20 * time.Second)
	req, err := http.NewRequestWithContext(ctx, "GET", appURL, nil)
	if err != nil {
		return nil, err
	}
	headers := HeadersFromCtx(ctx)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmpDir, err := os.MkdirTemp("", "bbpts-mobile-remote-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "app.bin")
	out, err := os.Create(tmpFile)
	if err != nil {
		return nil, err
	}

	limited := io.LimitReader(resp.Body, 200*1024*1024)
	n, err := io.Copy(out, limited)
	out.Close()
	if err != nil {
		return nil, err
	}

	if n < 4 {
		return nil, fmt.Errorf("empty response")
	}

	buf := make([]byte, 4)
	f, _ := os.Open(tmpFile)
	f.Read(buf)
	f.Close()

	if bytes.Equal(buf, []byte("PK")) {
		r, err := zip.OpenReader(tmpFile)
		if err == nil {
			defer r.Close()
			if err := extractZipStream(&r.Reader, tmpDir); err == nil {
				return t.scanExtractedDir(tmpDir, appURL)
			}
		}
	}

	return t.analyzeRawStream(tmpFile)
}

func (t *MobileStaticTool) analyzeRawStream(path string) ([]Event, error) {
	events := []Event{}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 512*1024)

	seen := map[string]bool{}
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, p := range mobileSecretPatterns {
			matches := p.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				val := m[1]
				if len(val) > 80 {
					val = val[:80] + "..."
				}
				if seen[val] {
					continue
				}
				seen[val] = true

				events = append(events, NewEvent(path, t.Name(), "secret_exposed", map[string]string{
					"secret_type":  extractSecretType(m[0]),
					"secret_value": val,
					"line":         fmt.Sprintf("%d", lineNum),
					"severity":     classifySecretSeverity(m[0]),
					"scan_type":    "mobile_static",
				}))
			}
		}

		for _, p := range mobileEndpointPatterns {
			matches := p.FindAllString(line, -1)
			for _, u := range matches {
				if len(u) > 300 || seen[u] {
					continue
				}
				seen[u] = true
				events = append(events, NewEvent(u, t.Name(), "api_endpoint", map[string]string{
					"url":       u,
					"line":      fmt.Sprintf("%d", lineNum),
					"scan_type": "mobile_static",
				}))
			}
		}
	}

	return events, nil
}

func (t *MobileStaticTool) scanExtractedDir(dir, target string) ([]Event, error) {
	events := []Event{}
	seen := map[string]bool{}
	fileCount := 0

	analyzeable := map[string]bool{
		".json": true, ".xml": true, ".plist": true, ".yaml": true,
		".yml": true, ".properties": true, ".gradle": true, ".swift": true,
		".m": true, ".h": true, ".java": true, ".kt": true, ".smali": true,
		".js": true, ".ts": true, ".env": true, ".cfg": true,
		".conf": true, ".entitlements": true, ".strings": true,
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 20*1024*1024 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !analyzeable[ext] {
			return nil
		}

		fileCount++
		if LowResourceFromCtx(context.Background()) && fileCount > 50 {
			return filepath.SkipDir
		}

		relPath, _ := filepath.Rel(dir, path)
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 128*1024), 256*1024)

		for scanner.Scan() {
			line := scanner.Text()

			for _, p := range mobileSecretPatterns {
				matches := p.FindAllStringSubmatch(line, -1)
				for _, m := range matches {
					val := m[1]
					if len(val) > 80 {
						val = val[:80] + "..."
					}
					if seen[val] {
						continue
					}
					seen[val] = true
					events = append(events, NewEvent(target, t.Name(), "secret_exposed", map[string]string{
						"secret_type":  extractSecretType(m[0]),
						"secret_value": val,
						"file":         relPath,
						"severity":     classifySecretSeverity(m[0]),
						"scan_type":    "mobile_static",
					}))
				}
			}

			for _, p := range mobileEndpointPatterns {
				matches := p.FindAllString(line, -1)
				for _, u := range matches {
					if len(u) > 300 || seen[u] {
						continue
					}
					seen[u] = true
					events = append(events, NewEvent(u, t.Name(), "api_endpoint", map[string]string{
						"url":       u,
						"file":      relPath,
						"scan_type": "mobile_static",
					}))
				}
			}

			for _, p := range mobileConfigPatterns {
				matches := p.FindAllStringSubmatch(line, -1)
				for _, m := range matches {
					if len(m) >= 2 && !seen[m[1]] {
						seen[m[1]] = true
						events = append(events, NewEvent(target, t.Name(), "config_file", map[string]string{
							"config_key": m[1],
							"file":       relPath,
							"scan_type":  "mobile_static",
						}))
					}
				}
			}
		}
		return nil
	})

	summary := map[string]string{
		"scan_type":     "mobile_static_summary",
		"target":        target,
		"files_scanned": fmt.Sprintf("%d", fileCount),
		"findings":      fmt.Sprintf("%d", len(events)),
	}
	events = append(events, NewEvent(target, t.Name(), "discovery", summary))

	return events, err
}

func (t *MobileStaticTool) reconFallback(target string) []Event {
	return []Event{NewEvent(target, t.Name(), "discovery", map[string]string{
		"scan_type":  "mobile_recon",
		"platform":   detectMobilePlatform(target),
		"identifier": target,
		"note":       "binary not available, recon mode",
	})}
}

func (t *MobileStaticTool) reconFromAppleID(target string) []Event {
	return []Event{NewEvent(target, t.Name(), "discovery", map[string]string{
		"scan_type": "apple_recon", "platform": "ios", "identifier": target,
	})}
}

func (t *MobileStaticTool) reconFromGPStore(target string) []Event {
	return []Event{NewEvent(target, t.Name(), "discovery", map[string]string{
		"scan_type": "gp_recon", "platform": "android", "identifier": target,
	})}
}

func extractZipStream(r *zip.Reader, dest string) error {
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(filepath.Clean(fpath), filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, 0700)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), 0700); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}
		io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
	}
	return nil
}

func targetFromPath(path string) string {
	return filepath.Base(path)
}

func detectMobilePlatform(target string) string {
	lower := strings.ToLower(target)
	if strings.HasSuffix(lower, ".ipa") || strings.Contains(lower, "apple.com") {
		return "ios"
	}
	if strings.HasSuffix(lower, ".apk") || strings.Contains(lower, "play.google.com") {
		return "android"
	}
	return "unknown"
}

func extractSecretType(match string) string {
	lower := strings.ToLower(match)
	switch {
	case strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey"):
		return "api_key"
	case strings.Contains(lower, "secret"):
		return "client_secret"
	case strings.Contains(lower, "password"):
		return "password"
	case strings.Contains(lower, "token"):
		return "auth_token"
	case strings.Contains(lower, "aws"):
		return "aws_key"
	case strings.Contains(lower, "private key"):
		return "private_key"
	case strings.Contains(lower, "firebase"):
		return "firebase_url"
	case strings.Contains(lower, "oauth"):
		return "oauth_client_id"
	default:
		return "unknown"
	}
}

func classifySecretSeverity(match string) string {
	lower := strings.ToLower(match)
	switch {
	case strings.Contains(lower, "private key") || strings.Contains(lower, "aws"):
		return "critical"
	case strings.Contains(lower, "api_key") || strings.Contains(lower, "secret") || strings.Contains(lower, "password"):
		return "high"
	case strings.Contains(lower, "token"):
		return "medium"
	default:
		return "low"
	}
}
