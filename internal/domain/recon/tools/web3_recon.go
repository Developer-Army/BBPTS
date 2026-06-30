package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type Web3ReconTool struct{}

func (t *Web3ReconTool) Name() string {
	return "web3_recon"
}

func (t *Web3ReconTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 30
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

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		client := NewSafeHTTPClient(5 * time.Second)
		var events []recon.Event

		rpcPayload := `{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`
		rpcURL := fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host)

		req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, strings.NewReader(rpcPayload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			for k, v := range scanCtx.Headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err == nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				if resp.StatusCode == 200 && strings.Contains(bodyStr, "jsonrpc") && (strings.Contains(bodyStr, "result") || strings.Contains(bodyStr, "clientVersion")) {
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "Exposed Web3 JSON-RPC Endpoint",
						"severity":    "high",
						"url":         rpcURL,
						"evidence":    bodyStr,
						"description": fmt.Sprintf("Exposed Ethereum/Web3 JSON-RPC endpoint detected at %s. Unauthenticated access allows querying node and account status.", rpcURL),
					}, "high"))
				}
			}
		}

		walletPaths := []string{
			"/wallet.json",
			"/.ethereum/keystore",
			"/keystore",
		}

		for _, wPath := range walletPaths {
			walletURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, wPath)
			wReq, err := http.NewRequestWithContext(ctx, "GET", walletURL, nil)
			if err != nil {
				continue
			}
			for k, v := range scanCtx.Headers {
				wReq.Header.Set(k, v)
			}
			wResp, err := client.Do(wReq)
			if err == nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(wResp.Body, 16*1024))
				wResp.Body.Close()
				bodyStr := string(bodyBytes)

				if wResp.StatusCode == 200 && strings.Contains(bodyStr, "crypto") && strings.Contains(bodyStr, "ciphertext") && strings.Contains(bodyStr, "id") {
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "Exposed Ethereum Keystore Wallet File",
						"severity":    "critical",
						"url":         walletURL,
						"evidence":    bodyStr,
						"description": fmt.Sprintf("Exposed Ethereum private key / keystore file discovered at %s. Attackers can decrypt it to drain assets.", walletURL),
					}, "critical"))
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*Web3ReconTool)(nil)
