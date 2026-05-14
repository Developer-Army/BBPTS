package services

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// FailureClass represents the categorized reason for an operation failure.
type FailureClass string

const (
	ClassSuccess        FailureClass = "SUCCESS"
	ClassWAFBlock       FailureClass = "WAF_BLOCK"
	ClassRateLimited    FailureClass = "RATE_LIMITED"
	ClassDeadHost       FailureClass = "DEAD_HOST"
	ClassCaptcha        FailureClass = "CAPTCHA_CHALLENGE"
	ClassNetworkTimeout FailureClass = "NETWORK_TIMEOUT"
	ClassUnknown        FailureClass = "UNKNOWN"
)

// ErrorClassifier inspects HTTP responses to categorize the failure mode intelligently.
type ErrorClassifier struct{}

func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{}
}

// Classify inspects the response and error to determine the exact failure class.
// It reads a chunk of the response body if available to check for WAF/Captcha signatures.
func (ec *ErrorClassifier) Classify(resp *http.Response, err error) FailureClass {
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline") {
			return ClassNetworkTimeout
		}
		if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no such host") {
			return ClassDeadHost
		}
		return ClassUnknown
	}

	if resp == nil {
		return ClassUnknown
	}

	// HTTP Status Heuristics
	if resp.StatusCode == 429 {
		return ClassRateLimited
	}

	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		// Could be a WAF or a genuine access denied. We check headers and body.
		if isWAFHeader(resp.Header) {
			return ClassWAFBlock
		}
	}

	// Check body signatures for WAFs or Captchas (Cloudflare, PerimeterX, Datadome)
	if resp.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		// Restore the body so it can be read downstream if needed
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		bodyStr := strings.ToLower(string(bodyBytes))

		if strings.Contains(bodyStr, "cf-browser-verification") || strings.Contains(bodyStr, "captcha") || strings.Contains(bodyStr, "hcaptcha") {
			return ClassCaptcha
		}

		if strings.Contains(bodyStr, "access denied") && (resp.StatusCode == 403) {
			return ClassWAFBlock
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return ClassSuccess
	}

	return ClassUnknown
}

func isWAFHeader(header http.Header) bool {
	wafHeaders := []string{
		"cf-ray", "x-amz-cf-id", "x-sucuri-id", "x-fw-rule",
		"server", "x-datadome", "x-px",
	}

	for _, wh := range wafHeaders {
		if header.Get(wh) != "" {
			if wh == "server" {
				val := strings.ToLower(header.Get("server"))
				if strings.Contains(val, "cloudflare") || strings.Contains(val, "akamai") || strings.Contains(val, "imperva") {
					return true
				}
				continue
			}
			return true
		}
	}
	return false
}
