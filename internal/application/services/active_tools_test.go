package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSTool(t *testing.T) {
	// Setup test server reflecting origin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tool := &CORSTool{}
	if tool.Name() != "cors" {
		t.Errorf("Expected name cors, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("CORS Run failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 CORS vulnerability event, got %d", len(events))
	}
}

func TestBypass403Tool(t *testing.T) {
	// Setup test server returning 403 on standard, 200 on bypassed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	tool := &Bypass403Tool{}
	if tool.Name() != "bypass403" {
		t.Errorf("Expected name bypass403, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("Bypass403 Run failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 bypass vulnerability event, got %d", len(events))
	}
}

func TestJWTAnalyzerTool(t *testing.T) {
	tool := &JWTAnalyzerTool{}
	if tool.Name() != "jwt_analyzer" {
		t.Errorf("Expected name jwt_analyzer, got %s", tool.Name())
	}

	// Test with a dummy HS256 JWT signed with weak secret "secret"
	// Header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	// Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022} -> eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
	// Signature of header+payload with key "secret" -> XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o
	dummyJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

	events, err := tool.Run(context.Background(), []string{dummyJWT}, 1)
	if err != nil {
		t.Fatalf("JWT Run failed: %v", err)
	}

	if len(events) == 0 {
		t.Error("Expected to find weak key JWT vulnerability event, got 0")
	}
}

func TestOpenRedirectTool(t *testing.T) {
	// Setup test server reflecting parameter redirect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("next")
		if dest != "" {
			w.Header().Set("Location", dest)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tool := &OpenRedirectTool{}
	if tool.Name() != "open_redirect" {
		t.Errorf("Expected name open_redirect, got %s", tool.Name())
	}

	target := server.URL + "?next=evil.com"
	events, err := tool.Run(context.Background(), []string{target}, 1)
	if err != nil {
		t.Fatalf("OpenRedirect Run failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 open redirect event, got %d", len(events))
	}
}
