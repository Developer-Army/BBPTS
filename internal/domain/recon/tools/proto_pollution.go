package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/browser"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/playwright-community/playwright-go"
	"golang.org/x/time/rate"
)

type ProtoPollutionTool struct {
	pool   *browser.PooledBrowser
	client *network.StealthClient
	mu     sync.Mutex
}

func (t *ProtoPollutionTool) Name() string {
	return "proto_pollution"
}

func (t *ProtoPollutionTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 30
	}

	t.mu.Lock()
	if t.pool == nil {
		cfg := browser.DefaultPoolConfig()
		cfg.MaxBrowsers = 3
		cfg.MaxContexts = 20
		pool, err := browser.NewPooledBrowser(cfg)
		if err != nil {
			slog.Warn("Failed to initialize browser pool for proto_pollution", "error", err)
		} else {
			t.pool = pool
		}
	}
	t.mu.Unlock()

	proxies := recon.GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}

	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	var errClient error
	t.client, errClient = network.NewStealthClient(profile, proxy)
	if errClient != nil || t.client == nil {
		return nil, fmt.Errorf("failed to create stealth client: %w", errClient)
	}

	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" || !strings.HasPrefix(target, "http") {
			return nil, nil
		}

		var events []recon.Event

		if t.pool != nil {
			csEvents, err := t.checkClientSide(ctx, target)
			if err != nil {
				slog.Debug("Client-side prototype pollution check failed", "target", target, "error", err)
			} else {
				events = append(events, csEvents...)
			}
		}

		ssEvents, err := t.checkServerSide(ctx, target)
		if err != nil {
			slog.Debug("Server-side prototype pollution check failed", "target", target, "error", err)
		} else {
			events = append(events, ssEvents...)
		}

		return events, nil
	})
}

func (t *ProtoPollutionTool) checkClientSide(ctx context.Context, target string) ([]recon.Event, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("__proto__[bbpts_polluted]", "yes_proto")
	q.Set("constructor[prototype][bbpts_polluted]", "yes_proto")
	u.RawQuery = q.Encode()

	domain := u.Host
	headers := recon.HeadersFromCtx(ctx)

	ctxBrowser, err := t.pool.GetContext(domain, headers)
	if err != nil {
		return nil, err
	}
	defer t.pool.ReleaseContext(domain, ctxBrowser)

	page, err := ctxBrowser.NewPage()
	if err != nil {
		return nil, err
	}
	defer page.Close()

	_, err = page.Goto(u.String(), playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(10000),
	})
	if err != nil {
		return nil, err
	}

	val, err := page.Evaluate("() => { return Object.prototype.bbpts_polluted || window.bbpts_polluted; }")
	if err != nil {
		return nil, err
	}

	var events []recon.Event
	if strVal, ok := val.(string); ok && strVal == "yes_proto" {
		events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
			"vuln_name":   "Client-Side Prototype Pollution",
			"severity":    "high",
			"description": fmt.Sprintf("Client-side prototype pollution detected on %s via injected parameters.", target),
		}, "high"))
	}

	return events, nil
}

func (t *ProtoPollutionTool) checkServerSide(ctx context.Context, target string) ([]recon.Event, error) {
	payload := map[string]interface{}{
		"__proto__": map[string]string{
			"bbpts_polluted": "yes_proto",
		},
		"constructor": map[string]interface{}{
			"prototype": map[string]string{
				"bbpts_polluted": "yes_proto",
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	headers := recon.HeadersFromCtx(ctx)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	var resp *http.Response
	if t.client != nil {
		resp, err = t.client.Do(req)
	} else {
		client := NewSafeHTTPClient(5 * time.Second)
		resp, err = client.Do(req)
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return nil, err
	}

	var events []recon.Event
	bodyStr := string(respBody)
	if strings.Contains(bodyStr, `"bbpts_polluted"`) && (strings.Contains(bodyStr, `"yes_proto"`) || strings.Contains(bodyStr, `yes_proto`)) {

		cleanPayload := map[string]interface{}{}
		cleanBody, errClean := json.Marshal(cleanPayload)
		if errClean == nil {
			cleanReq, errReq := http.NewRequestWithContext(ctx, "POST", target, bytes.NewBuffer(cleanBody))
			if errReq == nil {
				cleanReq.Header.Set("Content-Type", "application/json")
				cleanReq.Header.Set("Accept", "application/json")
				for k, v := range headers {
					cleanReq.Header.Set(k, v)
				}
				var cleanResp *http.Response
				var errDo error
				if t.client != nil {
					cleanResp, errDo = t.client.Do(cleanReq)
				} else {
					client := NewSafeHTTPClient(5 * time.Second)
					cleanResp, errDo = client.Do(cleanReq)
				}
				if errDo == nil {
					defer cleanResp.Body.Close()
					cleanRespBody, errRead := io.ReadAll(io.LimitReader(cleanResp.Body, 100*1024))
					if errRead == nil {
						cleanBodyStr := string(cleanRespBody)
						if strings.Contains(cleanBodyStr, `"bbpts_polluted"`) && (strings.Contains(cleanBodyStr, `"yes_proto"`) || strings.Contains(cleanBodyStr, `yes_proto`)) {
							events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
								"vuln_name":   "Server-Side Prototype Pollution (JSON Body Injection)",
								"severity":    "high",
								"description": fmt.Sprintf("Server prototype was successfully polluted on %s (confirmed via clean follow-up request).", target),
							}, "high"))
						}
					}
				}
			}
		}
	}

	return events, nil
}

var _ recon.Tool = (*ProtoPollutionTool)(nil)
