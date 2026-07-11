package tools

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

type SSRFTool struct{}
type CRLFTool struct{}
type EmailHeaderInjectionTool struct{}
type APIVersionProbeTool struct{}
type JSONPTool struct{}
type WebDAVTool struct{}
type DNSZoneTransferTool struct{}
type HTTP2DowngradeTool struct{}
type TLSMisconfigTool struct{}

func (t *SSRFTool) Name() string                 { return "ssrf" }
func (t *CRLFTool) Name() string                 { return "crlf" }
func (t *EmailHeaderInjectionTool) Name() string { return "email_header_injection" }
func (t *APIVersionProbeTool) Name() string      { return "api_version_probe" }
func (t *JSONPTool) Name() string                { return "jsonp" }
func (t *WebDAVTool) Name() string               { return "webdav" }
func (t *DNSZoneTransferTool) Name() string      { return "dns_zone_transfer" }
func (t *HTTP2DowngradeTool) Name() string       { return "http2_downgrade" }
func (t *TLSMisconfigTool) Name() string         { return "tls_misconfig" }

var ssrfParamNames = map[string]bool{
	"url": true, "path": true, "redirect": true, "next": true, "dest": true, "uri": true,
	"target": true, "continue": true, "return": true, "return_url": true, "callback": true,
}

func (t *SSRFTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	oobURL := scanCtx.InteractshOOBURL
	if oobURL == "" || len(targets) == 0 {
		return nil, nil
	}
	return processHTTPTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, raw string) []recon.Event {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			return nil
		}
		q := parsed.Query()
		var events []recon.Event
		for param := range q {
			if !ssrfParamNames[strings.ToLower(param)] {
				continue
			}
			testURL := *parsed
			testQ := parsed.Query()
			testQ.Set(param, oobURL)
			testURL.RawQuery = testQ.Encode()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			_, _ = NewSafeHTTPClient(6 * time.Second).Do(req)
			events = append(events, recon.NewEventWithSeverity(testURL.String(), t.Name(), "ssrf_probe", map[string]string{
				"severity":    "info",
				"parameter":   param,
				"payload":     oobURL,
				"description": "SSRF OOB probe sent to URL-bearing parameter; confirm interaction in interactsh logs.",
			}, "info"))
		}
		return events
	})
}

func (t *CRLFTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	return processHTTPTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, raw string) []recon.Event {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			return nil
		}
		q := parsed.Query()
		for param := range q {
			testURL := *parsed
			testQ := parsed.Query()
			testQ.Set(param, "bbpts\r\nX-BBPTS-CRLF: injected")
			testURL.RawQuery = testQ.Encode()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			resp, err := NewSafeHTTPClient(6 * time.Second).Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if strings.EqualFold(resp.Header.Get("X-BBPTS-CRLF"), "injected") {
				return []recon.Event{recon.NewEventWithSeverity(testURL.String(), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "CRLF Response Header Injection",
					"severity":    "high",
					"parameter":   param,
					"description": "URL parameter CRLF payload was reflected into response headers.",
				}, "high")}
			}
		}
		return nil
	})
}

var emailHeaderParams = map[string]bool{"email": true, "to": true, "from": true, "cc": true, "bcc": true}

func (t *EmailHeaderInjectionTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	return processHTTPTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, raw string) []recon.Event {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			return nil
		}
		form := parsed.Query()
		var testedParam string
		for param := range form {
			if emailHeaderParams[strings.ToLower(param)] {
				form.Set(param, "bbpts@example.com\r\nBcc: injected-bbpts@example.com")
				testedParam = param
				break
			}
		}
		if testedParam == "" {
			return nil
		}
		base := *parsed
		base.RawQuery = ""
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := NewSafeHTTPClient(8 * time.Second).Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		if resp.StatusCode < 400 && (bytes.Contains(body, []byte("Bcc: injected-bbpts@example.com")) || bytes.Contains(body, []byte("injected-bbpts@example.com"))) {
			return []recon.Event{recon.NewEventWithSeverity(base.String(), t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Email Header Injection",
				"severity":    "high",
				"parameter":   testedParam,
				"description": "Email-related parameter accepted a CRLF header injection payload.",
			}, "high")}
		}
		return nil
	})
}

func (t *APIVersionProbeTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	return processHTTPTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, raw string) []recon.Event {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil
		}
		path := parsed.Path
		var current string
		for _, marker := range []string{"/api/v2/", "/api/v3/", "/api/v1/"} {
			if strings.Contains(path, marker) {
				current = marker
				break
			}
		}
		if current == "" {
			return nil
		}
		var events []recon.Event
		for _, version := range []string{"/api/v1/", "/api/v0/", "/api/beta/", "/api/v2/"} {
			if version == current {
				continue
			}
			testURL := *parsed
			testURL.Path = strings.Replace(path, current, version, 1)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			resp, err := NewSafeHTTPClient(6 * time.Second).Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				events = append(events, recon.NewEventWithSeverity(testURL.String(), t.Name(), "discovery", map[string]string{
					"severity":    "medium",
					"description": "Alternate API version responded with HTTP 200; test for weaker auth or rate limits.",
				}, "medium"))
			}
		}
		return events
	})
}

func (t *JSONPTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	return processHTTPTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, raw string) []recon.Event {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			return nil
		}
		q := parsed.Query()
		var param string
		for p := range q {
			pl := strings.ToLower(p)
			if pl == "callback" || pl == "jsonp" {
				param = p
				break
			}
		}
		if param == "" {
			return nil
		}
		q.Set(param, "bbptsJsonp")
		parsed.RawQuery = q.Encode()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		resp, err := NewSafeHTTPClient(6 * time.Second).Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		if strings.HasPrefix(strings.TrimSpace(string(body)), "bbptsJsonp(") {
			return []recon.Event{recon.NewEventWithSeverity(parsed.String(), t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "JSONP Callback Reflection",
				"severity":    "medium",
				"parameter":   param,
				"description": "Arbitrary JSONP callback name was reflected, enabling browser-based data exfiltration if sensitive data is returned.",
			}, "medium")}
		}
		return nil
	})
}

func (t *WebDAVTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	return processHTTPTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, raw string) []recon.Event {
		base, err := originURL(raw)
		if err != nil {
			return nil
		}
		client := NewSafeHTTPClient(8 * time.Second)
		var events []recon.Event
		for _, method := range []string{"PROPFIND", "MKCOL"} {
			req, _ := http.NewRequestWithContext(ctx, method, base, nil)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					events = append(events, recon.NewEventWithSeverity(base, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "WebDAV Method Enabled",
						"severity":    "high",
						"method":      method,
						"description": fmt.Sprintf("WebDAV method %s succeeded on live host.", method),
					}, "high"))
				}
			}
		}
		putURL := strings.TrimRight(base, "/") + "/.bbpts-webdav-probe.txt"
		req, _ := http.NewRequestWithContext(ctx, http.MethodPut, putURL, strings.NewReader("bbpts-webdav-probe"))
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				events = append(events, recon.NewEventWithSeverity(putURL, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "WebDAV File Upload Enabled",
					"severity":    "critical",
					"method":      "PUT",
					"description": "Unauthenticated PUT upload succeeded on the WebDAV endpoint.",
				}, "critical"))
			}
		}
		return events
	})
}

func (t *DNSZoneTransferTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	return processTextTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, target string) []recon.Event {
		domain := domainFromURLOrHost(target)
		if domain == "" {
			return nil
		}
		nsRecords, err := net.LookupNS(domain)
		if err != nil {
			return nil
		}
		var events []recon.Event
		for _, ns := range nsRecords {
			lines, err := RunCommandLines(ctx, "dig", "@"+strings.TrimSuffix(ns.Host, "."), domain, "AXFR", "+time=5", "+tries=1")
			if err != nil || len(lines) < 5 {
				continue
			}
			joined := strings.ToLower(strings.Join(lines, "\n"))
			if strings.Contains(joined, "\tsoa\t") || strings.Contains(joined, " soa ") {
				events = append(events, recon.NewEventWithSeverity(domain, t.Name(), "vulnerability", map[string]string{
					"vuln_name":    "DNS Zone Transfer Enabled",
					"severity":     "high",
					"nameserver":   ns.Host,
					"record_count": fmt.Sprintf("%d", len(lines)),
					"description":  "Nameserver allowed AXFR zone transfer.",
				}, "high"))
			}
		}
		return events
	})
}

func (t *HTTP2DowngradeTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if !scanCtx.ForceHTTP1 {
		return nil, nil
	}
	return processHTTPTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, raw string) []recon.Event {
		http1Resp, http1Body := fetchWithTransport(ctx, raw, false)
		http2Resp, http2Body := fetchWithTransport(ctx, raw, true)
		if http1Resp == 0 || http2Resp == 0 {
			return nil
		}
		if http1Resp != http2Resp || bodyFingerprint(http1Body) != bodyFingerprint(http2Body) {
			return []recon.Event{recon.NewEventWithSeverity(raw, t.Name(), "discovery", map[string]string{
				"severity":     "medium",
				"http1_status": fmt.Sprintf("%d", http1Resp),
				"http2_status": fmt.Sprintf("%d", http2Resp),
				"description":  "Endpoint behaved differently over HTTP/1.1 and HTTP/2; test for protocol-specific auth, cache, or routing bypasses.",
			}, "medium")}
		}
		return nil
	})
}

func (t *TLSMisconfigTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	return processTextTargets(ctx, t.Name(), targets, threads, func(ctx context.Context, target string) []recon.Event {
		host := domainFromURLOrHost(target)
		if host == "" {
			return nil
		}
		lines, err := RunCommandLines(ctx, "testssl.sh", "--warnings", "off", "--fast", "--jsonfile", "/dev/stdout", host)
		if err != nil || len(lines) == 0 {
			return nativeTLSChecks(t.Name(), host)
		}
		joined := strings.ToLower(strings.Join(lines, "\n"))
		checks := []string{"beast", "poodle", "drown", "robot", "expired", "self-signed", "dh bits"}
		var events []recon.Event
		for _, check := range checks {
			if strings.Contains(joined, check) && (strings.Contains(joined, "vulnerable") || strings.Contains(joined, "offered") || strings.Contains(joined, "expired") || strings.Contains(joined, "self-signed")) {
				events = append(events, recon.NewEventWithSeverity(host, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "TLS Misconfiguration",
					"severity":    "medium",
					"check":       check,
					"description": "testssl.sh reported a TLS misconfiguration requiring validation.",
				}, "medium"))
			}
		}
		return events
	})
}

func processHTTPTargets(ctx context.Context, name string, targets []string, threads int, fn func(context.Context, string) []recon.Event) ([]recon.Event, error) {
	return processTextTargets(ctx, name, filterHTTPURLs(targets), threads, fn)
}

func processTextTargets(ctx context.Context, name string, targets []string, threads int, fn func(context.Context, string) []recon.Event) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	rateLimit := ToolRateLimitFromCtx(ctx, name)
	if rateLimit <= 0 {
		rateLimit = 30
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))
	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		return fn(ctx, strings.TrimSpace(target)), nil
	})
}

func filterHTTPURLs(targets []string) []string {
	var out []string
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
			out = append(out, target)
		}
	}
	return out
}

func originURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid URL")
	}
	return parsed.Scheme + "://" + parsed.Host + "/", nil
}

func domainFromURLOrHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		raw = parsed.Host
	}
	raw = strings.Trim(raw, "[]")
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.TrimSuffix(strings.Split(raw, "/")[0], ".")
	if net.ParseIP(raw) != nil || !strings.Contains(raw, ".") {
		return ""
	}
	return strings.ToLower(raw)
}

func fetchWithTransport(ctx context.Context, raw string, useHTTP2 bool) (int, []byte) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: recon.InsecureFromCtx(ctx)}}
	if useHTTP2 {
		_ = http2.ConfigureTransport(tr)
	} else {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, body
}

func bodyFingerprint(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) > 2048 {
		body = body[:2048]
	}
	return fmt.Sprintf("%d:%x", len(body), body)
}

func nativeTLSChecks(source, host string) []recon.Event {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", net.JoinHostPort(host, "443"), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	var events []recon.Event
	for _, cert := range state.PeerCertificates {
		if time.Now().After(cert.NotAfter) {
			events = append(events, recon.NewEventWithSeverity(host, source, "vulnerability", map[string]string{
				"vuln_name":   "Expired TLS Certificate",
				"severity":    "medium",
				"description": "TLS certificate is expired.",
			}, "medium"))
		}
		if cert.CheckSignatureFrom(cert) == nil && cert.IsCA {
			events = append(events, recon.NewEventWithSeverity(host, source, "vulnerability", map[string]string{
				"vuln_name":   "Self-Signed TLS Certificate",
				"severity":    "low",
				"description": "TLS certificate appears self-signed.",
			}, "low"))
		}
	}
	return events
}

var _ recon.Tool = (*SSRFTool)(nil)
var _ recon.Tool = (*CRLFTool)(nil)
var _ recon.Tool = (*EmailHeaderInjectionTool)(nil)
var _ recon.Tool = (*APIVersionProbeTool)(nil)
var _ recon.Tool = (*JSONPTool)(nil)
var _ recon.Tool = (*WebDAVTool)(nil)
var _ recon.Tool = (*DNSZoneTransferTool)(nil)
var _ recon.Tool = (*HTTP2DowngradeTool)(nil)
var _ recon.Tool = (*TLSMisconfigTool)(nil)
