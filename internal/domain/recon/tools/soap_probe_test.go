package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSOAPProbeTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && (r.URL.Query().Has("wsdl") || strings.Contains(r.URL.RawQuery, "wsdl")) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<wsdl:definitions xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\"></wsdl:definitions>"))
			return
		}
		if r.Method == "POST" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("xml parser error: failed to load external entity http://interactsh-oob.com/xxe.dtd"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &SOAPProbeTool{}
	if tool.Name() != "soap_probe" {
		t.Errorf("expected tool name soap_probe, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL + "/service.asmx"}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundWSDL, foundXXE bool
	for _, ev := range events {
		if ev.Type == "discovery" && ev.Properties["type"] == "soap_wsdl" {
			foundWSDL = true
		}
		if ev.Type == "vulnerability" && ev.Properties["vuln_name"] == "XML External Entity (XXE) Injection Attempt" {
			foundXXE = true
		}
	}

	if !foundWSDL {
		t.Error("expected to discover exposed WSDL")
	}
	if !foundXXE {
		t.Error("expected to discover XXE vulnerability")
	}
}
