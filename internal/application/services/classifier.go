package services

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

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

type ErrorClassifier struct{}

func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{}
}

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

	if resp.StatusCode == 429 {
		return ClassRateLimited
	}

	if resp.StatusCode == 403 || resp.StatusCode == 406 {

		if isWAFHeader(resp.Header) {
			return ClassWAFBlock
		}
	}

	if resp.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

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
