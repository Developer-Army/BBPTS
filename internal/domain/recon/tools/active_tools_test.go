package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func init() {
	os.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")
}

func TestCORSTool(t *testing.T) {

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

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("CORS Run failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 CORS vulnerability event, got %d", len(events))
	}
}

func TestBypass403Tool(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Success"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	tool := &Bypass403Tool{}
	if tool.Name() != "bypass403" {
		t.Errorf("Expected name bypass403, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("Bypass403 Run failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 bypass vulnerability event, got %d", len(events))
	}
}

func TestBypass403Tool_Wildcard200(t *testing.T) {
	tool := &Bypass403Tool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Wildcard Content"))
	}))
	defer server.Close()

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("Bypass403 Run failed: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("Expected 0 bypass vulnerability events for wildcard 200 server, got %d", len(events))
	}
}

func TestJWTAnalyzerTool(t *testing.T) {
	tool := &JWTAnalyzerTool{}
	if tool.Name() != "jwt_analyzer" {
		t.Errorf("Expected name jwt_analyzer, got %s", tool.Name())
	}

	dummyJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{dummyJWT}, 1)
	if err != nil {
		t.Fatalf("JWT Run failed: %v", err)
	}

	if len(events) == 0 {
		t.Error("Expected to find weak key JWT vulnerability event, got 0")
	}
}

func TestOpenRedirectTool(t *testing.T) {

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
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{target}, 1)
	if err != nil {
		t.Fatalf("OpenRedirect Run failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 open redirect event, got %d", len(events))
	}
}

func TestSSRFTool(t *testing.T) {
	tool := &SSRFTool{}
	if tool.Name() != "ssrf" {
		t.Errorf("Expected name ssrf, got %s", tool.Name())
	}
	ctx := recon.WithInteractshOOBURL(context.Background(), "http://interactsh-oob.com")
	events, err := tool.Run(ctx, &recon.ScanContext{InteractshOOBURL: "http://interactsh-oob.com"}, []string{"http://example.com/api?url=test"}, 1)
	if err != nil {
		t.Fatalf("SSRF Run failed: %v", err)
	}
	if len(events) == 0 {
		t.Error("Expected at least 1 SSRF probe event")
	}
}

func TestCRLFTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "X-BBPTS-CRLF") {
			w.Header().Set("X-BBPTS-CRLF", "injected")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tool := &CRLFTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL + "?param=test"}, 1)
	if err != nil {
		t.Fatalf("CRLF Run failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("Expected 1 CRLF event, got %d", len(events))
	}
}

func TestEmailHeaderInjectionTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		email := r.FormValue("email")
		if strings.Contains(email, "Bcc: injected") {
			_, _ = w.Write([]byte("injected-bbpts@example.com"))
		}
	}))
	defer server.Close()

	tool := &EmailHeaderInjectionTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL + "?email=test"}, 1)
	if err != nil {
		t.Fatalf("Email Header Run failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("Expected 1 Email Header Injection event, got %d", len(events))
	}
}

func TestAPIVersionProbeTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tool := &APIVersionProbeTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL + "/api/v1/users"}, 1)
	if err != nil {
		t.Fatalf("API Version Probe Run failed: %v", err)
	}
	if len(events) == 0 {
		t.Error("Expected discovery events for other API versions")
	}
}

func TestJSONPTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cb := r.URL.Query().Get("callback")
		if cb != "" {
			_, _ = w.Write([]byte(cb + "({}))"))
		}
	}))
	defer server.Close()

	tool := &JSONPTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL + "?callback=test"}, 1)
	if err != nil {
		t.Fatalf("JSONP Run failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("Expected 1 JSONP event, got %d", len(events))
	}
}

func TestWebDAVTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tool := &WebDAVTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("WebDAV Run failed: %v", err)
	}
	if len(events) == 0 {
		t.Error("Expected WebDAV events")
	}
}

func TestDNSZoneTransferTool(t *testing.T) {
	tool := &DNSZoneTransferTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{"localhost"}, 1)
	if err != nil {
		t.Fatalf("DNS Zone Transfer Run failed: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}
}

func TestHTTP2DowngradeTool(t *testing.T) {
	tool := &HTTP2DowngradeTool{}
	ctx := recon.WithForceHTTP1(context.Background(), true)

	events, err := tool.Run(ctx, &recon.ScanContext{ForceHTTP1: true}, []string{"http://127.0.0.1:9999/"}, 1)
	if err != nil {
		t.Fatalf("HTTP2 Downgrade Run failed: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}
}

func TestTLSMisconfigTool(t *testing.T) {
	tool := &TLSMisconfigTool{}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{"http://127.0.0.1:9999/"}, 1)
	if err != nil {
		t.Fatalf("TLS Misconfig Run failed: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}
}
