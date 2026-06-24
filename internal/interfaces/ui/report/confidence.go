package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// CalculateConfidenceScore scores a target URL or host (0-100) based on response status consistency,
// multiple-request confirmation, header correlation, and parameter sensitivity.
func CalculateConfidenceScore(ctx context.Context, insight analyze.Insight, events []recon.Event) int {
	// 1. Parameter Sensitivity (0-100)
	paramScore := calculateParamSensitivity(insight, events)

	// 2. Header Correlation (0-100)
	headerScore := calculateHeaderCorrelation(ctx, insight, events)

	// 3. Response Status Consistency (0-100)
	consistencyScore := calculateStatusConsistency(ctx, insight, events)

	// 4. Multiple-Request Confirmation (0-100)
	confirmScore := calculateRequestConfirmation(ctx, insight, events)

	// Blend: equal weights (25% each)
	blended := float64(paramScore)*0.25 + float64(headerScore)*0.25 + float64(consistencyScore)*0.25 + float64(confirmScore)*0.25
	return int(blended)
}

func calculateParamSensitivity(insight analyze.Insight, events []recon.Event) int {
	hasParams := false
	hasHighRisk := false

	highRiskParams := map[string]bool{
		"id": true, "ids": true, "user": true, "userid": true, "account": true,
		"order": true, "invoice": true, "cmd": true, "exec": true, "eval": true,
		"query": true, "search": true, "q": true, "filter": true, "sort": true,
		"token": true, "key": true, "auth": true, "admin": true, "redirect": true,
		"url": true, "next": true, "dest": true, "destination": true, "return": true,
		"to": true, "file": true, "path": true, "filepath": true, "template": true,
		"dir": true, "document": true,
	}

	checkURL := func(raw string) {
		if !strings.Contains(raw, "?") {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			if !strings.HasPrefix(raw, "http") {
				u, err = url.Parse("https://" + raw)
			}
		}
		if err == nil && u != nil {
			q := u.Query()
			if len(q) > 0 {
				hasParams = true
				for k := range q {
					kLower := strings.ToLower(k)
					if highRiskParams[kLower] {
						hasHighRisk = true
					}
				}
			}
		}
	}

	for _, ev := range events {
		checkURL(ev.Target)
	}
	checkURL(insight.Host)

	if hasHighRisk {
		return 100
	}
	if hasParams {
		return 50
	}
	return 0
}

func calculateHeaderCorrelation(ctx context.Context, insight analyze.Insight, events []recon.Event) int {
	hasCorrelation := false
	isCORS := false
	isBypass := false
	isSensitive := false

	for _, tag := range insight.Tags {
		tLower := strings.ToLower(tag)
		if strings.Contains(tLower, "cors") {
			isCORS = true
		}
		if strings.Contains(tLower, "bypass") {
			isBypass = true
		}
		if strings.Contains(tLower, "sensitive") {
			isSensitive = true
		}
	}

	targetURL := getTargetURL(insight, events)
	if targetURL != "" {
		client := services.NewSafeHTTPClient(2 * time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if isCORS {
					acao := resp.Header.Get("Access-Control-Allow-Origin")
					if acao != "" {
						hasCorrelation = true
					}
				}
				if isBypass {
					server := resp.Header.Get("Server")
					via := resp.Header.Get("Via")
					if server != "" || via != "" {
						hasCorrelation = true
					}
				}
				if isSensitive {
					ct := resp.Header.Get("Content-Type")
					if strings.Contains(ct, "text") || strings.Contains(ct, "octet-stream") || resp.StatusCode == 200 {
						hasCorrelation = true
					}
				}
				for _, tag := range insight.Tags {
					server := strings.ToLower(resp.Header.Get("Server"))
					powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
					tagLower := strings.ToLower(tag)
					if (server != "" && strings.Contains(server, tagLower)) || (powered != "" && strings.Contains(powered, tagLower)) {
						hasCorrelation = true
					}
				}
				if hasCorrelation {
					return 100
				}
			}
		}
	}

	for _, ev := range events {
		if ev.Properties != nil {
			if isCORS && ev.Properties["cors_type"] != "" {
				return 70
			}
			if isBypass && ev.Properties["bypass_type"] != "" {
				return 70
			}
			if ev.Properties["server"] != "" || ev.Properties["technologies"] != "" {
				return 70
			}
		}
	}

	return 30
}

func calculateStatusConsistency(ctx context.Context, insight analyze.Insight, events []recon.Event) int {
	targetURL := getTargetURL(insight, events)
	if targetURL == "" {
		return 50
	}

	client := services.NewSafeHTTPClient(2 * time.Second)
	statusCodes := make([]int, 0, 3)

	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			break
		default:
		}
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			statusCodes = append(statusCodes, -1)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			statusCodes = append(statusCodes, -1)
			continue
		}
		statusCodes = append(statusCodes, resp.StatusCode)
		resp.Body.Close()
		time.Sleep(50 * time.Millisecond)
	}

	unique := make(map[int]bool)
	failures := 0
	for _, code := range statusCodes {
		if code == -1 {
			failures++
		} else {
			unique[code] = true
		}
	}

	if failures == 3 {
		eventCodes := make(map[string]bool)
		for _, ev := range events {
			if code, ok := ev.Properties["status_code"]; ok && code != "" {
				eventCodes[code] = true
			}
		}
		if len(eventCodes) == 1 {
			return 80
		}
		return 50
	}

	switch len(unique) {
	case 1:
		if failures == 0 {
			return 100
		}
		return 70
	case 2:
		return 60
	default:
		return 20
	}
}

func calculateRequestConfirmation(ctx context.Context, insight analyze.Insight, events []recon.Event) int {
	targetURL := getTargetURL(insight, events)
	if targetURL == "" {
		return 40
	}

	isCORS := false
	isBypass := false
	isOpenRedirect := false

	for _, tag := range insight.Tags {
		tLower := strings.ToLower(tag)
		if strings.Contains(tLower, "cors") {
			isCORS = true
		}
		if strings.Contains(tLower, "bypass") {
			isBypass = true
		}
		if strings.Contains(tLower, "redirect") {
			isOpenRedirect = true
		}
	}

	client := services.NewSafeHTTPClient(2 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	if isCORS {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			req.Header.Set("Origin", "https://evil-confirm.com")
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				acao := resp.Header.Get("Access-Control-Allow-Origin")
				if acao == "https://evil-confirm.com" || acao == "*" {
					return 100
				}
			}
		}
	}

	if isBypass {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return 100
				}
			}
		}
	}

	if isOpenRedirect {
		parsed, err := url.Parse(targetURL)
		if err == nil {
			q := parsed.Query()
			for param := range q {
				q.Set(param, "https://example.com")
				parsed.RawQuery = q.Encode()
				confirmURL := parsed.String()
				req, err := http.NewRequestWithContext(ctx, "GET", confirmURL, nil)
				if err == nil {
					resp, err := client.Do(req)
					if err == nil {
						resp.Body.Close()
						loc := resp.Header.Get("Location")
						if resp.StatusCode >= 300 && resp.StatusCode < 400 && (strings.HasPrefix(loc, "https://example.com") || strings.HasPrefix(loc, "//example.com")) {
							return 100
						}
					}
				}
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return 80
		}
	}

	sources := make(map[string]bool)
	for _, ev := range events {
		sources[ev.Source] = true
	}
	if len(sources) >= 2 {
		return 85
	}
	return 40
}

func getTargetURL(insight analyze.Insight, events []recon.Event) string {
	for _, ev := range events {
		if strings.HasPrefix(ev.Target, "http://") || strings.HasPrefix(ev.Target, "https://") {
			return ev.Target
		}
	}
	if strings.HasPrefix(insight.Host, "http://") || strings.HasPrefix(insight.Host, "https://") {
		return insight.Host
	}
	return "https://" + insight.Host
}
