package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
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
			client := services.NewSafeHTTPClient(3 * time.Second)
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

	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "gemini"
	}

	switch provider {
	case "gemini":
		return callGemini(ctx, prompt, model, apiKey)
	case "ollama", "local":
		return callOllamaOrLocal(ctx, prompt, model, apiURL, apiKey)
	default:
		return nil, fmt.Errorf("unsupported AI triage provider: %s", provider)
	}
}

func callGemini(ctx context.Context, prompt, model, apiKey string) (*AITriageResult, error) {
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY is not set")
	}
	if model == "" {
		model = "gemini-2.5-flash"
	}

	type Part struct {
		Text string `json:"text"`
	}
	type Content struct {
		Parts []Part `json:"parts"`
	}
	type GenConfig struct {
		Temperature      float64 `json:"temperature"`
		MaxTokens        int     `json:"maxOutputTokens"`
		ResponseMimeType string  `json:"responseMimeType"`
	}
	type GeminiRequest struct {
		Contents         []Content `json:"contents"`
		GenerationConfig GenConfig `json:"generationConfig"`
	}

	reqBody := GeminiRequest{
		Contents: []Content{{Parts: []Part{{Text: prompt}}}},
		GenerationConfig: GenConfig{
			Temperature:      0.1,
			MaxTokens:        2048,
			ResponseMimeType: "application/json",
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Gemini API returned status %d: %s", resp.StatusCode, string(body))
	}

	type Candidate struct {
		Content Content `json:"content"`
	}
	type GeminiResponse struct {
		Candidates []Candidate `json:"candidates"`
	}

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return nil, err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty response from Gemini API")
	}

	text := geminiResp.Candidates[0].Content.Parts[0].Text
	return parseTriageJSON(text)
}

func callOllamaOrLocal(ctx context.Context, prompt, model, apiURL, apiKey string) (*AITriageResult, error) {
	if apiURL == "" {
		apiURL = "http://localhost:11434/v1/chat/completions"
	}
	if model == "" {
		model = "llama3"
	}

	type Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type ChatRequest struct {
		Model       string    `json:"model"`
		Messages    []Message `json:"messages"`
		Temperature float64   `json:"temperature"`
	}

	reqBody := ChatRequest{
		Model:       model,
		Messages:    []Message{{Role: "user", Content: prompt}},
		Temperature: 0.1,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("local LLM API returned status %d: %s", resp.StatusCode, string(body))
	}

	type Choice struct {
		Message Message `json:"message"`
	}
	type ChatResponse struct {
		Choices []Choice `json:"choices"`
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		// Try Ollama native `/api/generate` structure as fallback
		type NativeOllamaResponse struct {
			Response string `json:"response"`
		}
		var nativeResp NativeOllamaResponse
		if errNative := json.Unmarshal(body, &nativeResp); errNative == nil && nativeResp.Response != "" {
			return parseTriageJSON(nativeResp.Response)
		}
		return nil, err
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("empty choice from Chat Completion API")
	}

	return parseTriageJSON(chatResp.Choices[0].Message.Content)
}

func parseTriageJSON(text string) (*AITriageResult, error) {
	cleaned := cleanJSON(text)
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

func cleanJSON(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimSuffix(content, "```")
	} else if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")
	}
	return strings.TrimSpace(content)
}
