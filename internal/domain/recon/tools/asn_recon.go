package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type ASNReconTool struct{}

func (t *ASNReconTool) Name() string {
	return "asn_recon"
}

var ripeBaseURL = "https://stat.ripe.net"

type ripeASNResponse struct {
	Data struct {
		ASNs []string `json:"asns"`
	} `json:"data"`
}

type ripePrefixesResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func (t *ASNReconTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 5
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		host := target
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			u, err := url.Parse(target)
			if err == nil {
				host = u.Hostname()
			}
		}

		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, nil
		}

		ip := ips[0]
		isTestMock := strings.Contains(ripeBaseURL, "127.0.0.1") || strings.Contains(ripeBaseURL, "localhost")
		if !isTestMock && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
			slog.Debug("asn_recon: skipping local/private IP to prevent public scope leak", "ip", ip.String())
			return nil, nil
		}

		ipStr := ip.String()

		client := NewSafeHTTPClient(10 * time.Second)

		asnURL := fmt.Sprintf("%s/data/asn-by-ip/data.json?resource=%s", ripeBaseURL, ipStr)
		req, err := http.NewRequestWithContext(ctx, "GET", asnURL, nil)
		if err != nil {
			return nil, nil
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		var ripeASN ripeASNResponse
		if err := json.Unmarshal(bodyBytes, &ripeASN); err != nil || len(ripeASN.Data.ASNs) == 0 {
			return nil, nil
		}

		asn := ripeASN.Data.ASNs[0]

		prefixesURL := fmt.Sprintf("%s/data/announced-prefixes/data.json?resource=AS%s", ripeBaseURL, asn)
		pReq, err := http.NewRequestWithContext(ctx, "GET", prefixesURL, nil)
		if err != nil {
			return nil, nil
		}

		pResp, err := client.Do(pReq)
		if err != nil {
			return nil, nil
		}
		pBodyBytes, _ := io.ReadAll(io.LimitReader(pResp.Body, 5*1024*1024))
		pResp.Body.Close()

		var ripePrefixes ripePrefixesResponse
		if err := json.Unmarshal(pBodyBytes, &ripePrefixes); err != nil {
			return nil, nil
		}

		var events []recon.Event

		for _, p := range ripePrefixes.Data.Prefixes {
			events = append(events, recon.NewEvent(p.Prefix, t.Name(), "discovery", map[string]string{
				"asn":    asn,
				"ip":     ipStr,
				"domain": host,
				"type":   "ip_range",
			}))
		}

		return events, nil
	})
}

var _ recon.Tool = (*ASNReconTool)(nil)
