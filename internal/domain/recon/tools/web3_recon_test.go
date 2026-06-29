package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWeb3ReconTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"Geth/v1.10.8-stable/linux-amd64/go1.16.6","id":1}`))
			return
		}
		if r.URL.Path == "/wallet.json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"crypto":{"ciphertext":"12345"},"id":"abc","version":3}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &Web3ReconTool{}
	if tool.Name() != "web3_recon" {
		t.Errorf("expected tool name web3_recon, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundRPC, foundKeystore bool
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		if name == "Exposed Web3 JSON-RPC Endpoint" {
			foundRPC = true
		}
		if name == "Exposed Ethereum Keystore Wallet File" {
			foundKeystore = true
		}
	}

	if !foundRPC {
		t.Error("expected to discover exposed RPC endpoint")
	}
	if !foundKeystore {
		t.Error("expected to discover exposed keystore wallet file")
	}
}
