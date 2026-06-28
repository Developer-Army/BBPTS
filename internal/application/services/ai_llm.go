package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// CallLLM sends a prompt to the configured LLM provider and returns the raw text response.
// Supports "gemini", "openai", "anthropic", and "ollama"/"local" providers.
func CallLLM(ctx context.Context, prompt, provider, model, apiURL, apiKey string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "gemini"
	}

	switch provider {
	case "gemini":
		return callGeminiRaw(ctx, prompt, model, apiKey)
	case "openai":
		return callOpenAIChatRaw(ctx, prompt, model, apiURL, apiKey)
	case "anthropic", "claude":
		return callAnthropicRaw(ctx, prompt, model, apiURL, apiKey)
	case "ollama", "local":
		return callOllamaRaw(ctx, prompt, model, apiURL, apiKey)
	default:
		return "", fmt.Errorf("unsupported LLM provider: %s", provider)
	}
}

func callOpenAIChatRaw(ctx context.Context, prompt, model, apiURL, apiKey string) (string, error) {
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("OPENAI_API_KEY is not set")
	}
	if apiURL == "" {
		apiURL = "https://api.openai.com/v1/chat/completions"
	}
	if model == "" {
		model = "gpt-4o"
	}

	type Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type OpenAIRequest struct {
		Model       string    `json:"model"`
		Messages    []Message `json:"messages"`
		Temperature float64   `json:"temperature"`
	}

	reqBody := OpenAIRequest{
		Model:       model,
		Messages:    []Message{{Role: "user", Content: prompt}},
		Temperature: 0.1,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OpenAI API returned status %d: %s", resp.StatusCode, string(body))
	}

	type Choice struct {
		Message Message `json:"message"`
	}
	type OpenAIResponse struct {
		Choices []Choice `json:"choices"`
	}

	var openAIResp OpenAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return "", err
	}

	if len(openAIResp.Choices) == 0 {
		return "", fmt.Errorf("empty choice from OpenAI Chat Completions API")
	}

	return openAIResp.Choices[0].Message.Content, nil
}


func callAnthropicRaw(ctx context.Context, prompt, model, apiURL, apiKey string) (string, error) {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}
	if apiURL == "" {
		apiURL = "https://api.anthropic.com/v1/messages"
	}
	if model == "" {
		model = "claude-sonnet-4-6"
	}

	type Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type AnthropicRequest struct {
		Model       string    `json:"model"`
		MaxTokens   int       `json:"max_tokens"`
		Temperature float64   `json:"temperature"`
		Messages    []Message `json:"messages"`
	}
	reqBody := AnthropicRequest{
		Model:       model,
		MaxTokens:   4096,
		Temperature: 0.1,
		Messages:    []Message{{Role: "user", Content: prompt}},
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Anthropic API returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	for _, part := range parsed.Content {
		if strings.TrimSpace(part.Text) != "" {
			return part.Text, nil
		}
	}
	return "", fmt.Errorf("empty response from Anthropic API")
}

// callGeminiRaw calls the Gemini API and returns the raw text response.
func callGeminiRaw(ctx context.Context, prompt, model, apiKey string) (string, error) {
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("GEMINI_API_KEY is not set")
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
			MaxTokens:        4096,
			ResponseMimeType: "application/json",
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Gemini API returned status %d: %s", resp.StatusCode, string(body))
	}

	type Candidate struct {
		Content Content `json:"content"`
	}
	type GeminiResponse struct {
		Candidates []Candidate `json:"candidates"`
	}

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return "", err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response from Gemini API")
	}

	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

// callOllamaRaw calls an OpenAI-compatible API (Ollama/local) and returns the raw text response.
func callOllamaRaw(ctx context.Context, prompt, model, apiURL, apiKey string) (string, error) {
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
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("local LLM API returned status %d: %s", resp.StatusCode, string(body))
	}

	type Choice struct {
		Message Message `json:"message"`
	}
	type ChatResponse struct {
		Choices []Choice `json:"choices"`
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		// Try Ollama native `/api/generate` format as fallback
		type NativeOllamaResponse struct {
			Response string `json:"response"`
		}
		var nativeResp NativeOllamaResponse
		if errNative := json.Unmarshal(body, &nativeResp); errNative == nil && nativeResp.Response != "" {
			return nativeResp.Response, nil
		}
		return "", err
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("empty choice from Chat Completion API")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// CleanLLMJSON strips markdown fences and whitespace from LLM JSON output.
func CleanLLMJSON(content string) string {
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

// GetLLMConfig extracts LLM provider settings from the context's API keys.
func GetLLMConfig(ctx context.Context) (provider, model, apiURL, apiKey string) {
	provider = "gemini"
	model = "gemini-2.5-flash"
	apiKey = GetAPIKey(ctx, "gemini")
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		if key := GetAPIKey(ctx, "anthropic"); key != "" || os.Getenv("ANTHROPIC_API_KEY") != "" {
			provider = "anthropic"
			model = "claude-sonnet-4-6"
			apiKey = key
			if apiKey == "" {
				apiKey = os.Getenv("ANTHROPIC_API_KEY")
			}
			return
		}
	}
	if apiKey == "" {
		if key := GetAPIKey(ctx, "openai"); key != "" || os.Getenv("OPENAI_API_KEY") != "" {
			provider = "openai"
			model = "gpt-4o"
			apiKey = key
			if apiKey == "" {
				apiKey = os.Getenv("OPENAI_API_KEY")
			}
		}
	}
	return
}
