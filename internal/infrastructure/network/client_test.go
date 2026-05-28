package network

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func init() {
	os.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")
}

func TestStealthClientInjectsCustomHeaders(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	profile := BrowserProfile{
		Name:      "TestProfile",
		UserAgent: "TestUA",
	}

	client, err := NewStealthClient(profile, "")
	if err != nil {
		t.Fatalf("failed to create stealth client: %v", err)
	}
	defer client.Close()

	headers := map[string]string{
		"X-HackerOne-Researcher": "charlie",
		"X-Custom-Test-Header":   "success",
	}
	client.SetCustomHeaders(headers)

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedHeaders.Get("X-HackerOne-Researcher") != "charlie" {
		t.Errorf("expected X-HackerOne-Researcher to be 'charlie', got '%s'", receivedHeaders.Get("X-HackerOne-Researcher"))
	}
	if receivedHeaders.Get("X-Custom-Test-Header") != "success" {
		t.Errorf("expected X-Custom-Test-Header to be 'success', got '%s'", receivedHeaders.Get("X-Custom-Test-Header"))
	}
	if receivedHeaders.Get("User-Agent") != "TestUA" {
		t.Errorf("expected User-Agent to be 'TestUA', got '%s'", receivedHeaders.Get("User-Agent"))
	}
}

func TestStealthClientPostSendsBody(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	profile := BrowserProfile{
		Name:      "TestProfile",
		UserAgent: "TestUA",
	}

	client, err := NewStealthClient(profile, "")
	if err != nil {
		t.Fatalf("failed to create stealth client: %v", err)
	}
	defer client.Close()

	testBody := []byte("hello-world-stealth-post")
	resp, err := client.Post(server.URL, "text/plain", testBody)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	resp.Body.Close()

	if string(receivedBody) != string(testBody) {
		t.Errorf("expected body '%s', got '%s'", string(testBody), string(receivedBody))
	}
}
