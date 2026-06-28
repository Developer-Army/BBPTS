package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

// AITriageResult represents the LLM response.
type AITriageResult struct {
	Confidence  int    `json:"confidence"`
	Explanation string `json:"explanation"`
}

// TriageFindingWithLLM sends the finding's request/response pair to the LLM and gets triage results.
func TriageFindingWithLLM(ctx context.Context, f *DetailedFinding, provider, model, apiURL, apiKey string) (*AITriageResult, error) {
	reqData := f.Request
	respData := f.Response

	// Fallback: If request/response pair is empty and it is an HTTP target, perform a quick GET request.
	if (reqData == "" || respData == "") && strings.HasPrefix(f.Target, "http") {
		slog.Info("Request/Response missing for AI triage, performing fallback request", "target", f.Target)
		req, err := http.NewRequestWithContext(ctx, "GET", f.Target, nil)
		if err == nil {
			client := tools.NewSafeHTTPClient(3 * time.Second)
			client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				reqDump, _ := httputil.DumpRequestOut(req, false)
				reqData = string(reqDump)

				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
				var respBuilder strings.Builder
				respBuilder.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
				for k, v := range resp.Header {
					respBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
				}
				respBuilder.WriteString("\r\n")
				respBuilder.WriteString(string(bodyBytes))
				respData = respBuilder.String()
			}
		}
	}

	if reqData == "" && respData == "" {
		// Use finding details as fallback
		reqData = "Target: " + f.Target
		respData = "Finding: " + f.Title + "\nDescription: " + f.Description
	}

	prompt := fmt.Sprintf(`Analyze the following HTTP request and response pair to determine if it represents a real vulnerability or a false positive.

Finding Title: %s
Description: %s

Request:
%s

Response:
%s

Is this a real vulnerability or a false positive? Rate confidence 0–100 and explain.
You must output your analysis strictly in valid JSON format:
{
  "confidence": <integer 0-100>,
  "explanation": "<your explanation here>"
}`, f.Title, f.Description, reqData, respData)

	rawText, err := tools.CallLLM(ctx, prompt, provider, model, apiURL, apiKey)
	if err != nil {
		return nil, err
	}

	return parseTriageJSON(rawText)
}

func parseTriageJSON(text string) (*AITriageResult, error) {
	cleaned := tools.CleanLLMJSON(text)
	var result AITriageResult
	if err := json.Unmarshal([]byte(cleaned), &result); err != nil {
		// Attempt parsing by looking for JSON block
		start := strings.Index(cleaned, "{")
		end := strings.LastIndex(cleaned, "}")
		if start != -1 && end != -1 && end > start {
			if err := json.Unmarshal([]byte(cleaned[start:end+1]), &result); err == nil {
				return &result, nil
			}
		}
		return nil, fmt.Errorf("failed to parse AI triage JSON: %w, text: %s", err, text)
	}
	return &result, nil
}
