package services

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

func TestDryRunContext(t *testing.T) {
	ctx := context.Background()
	if recon.DryRunFromCtx(ctx) {
		t.Error("expected default context to not be dry-run")
	}

	dryCtx := recon.WithDryRun(ctx, true)
	if !recon.DryRunFromCtx(dryCtx) {
		t.Error("expected dry-run context to be active")
	}
}

func TestRunCommandDryRun(t *testing.T) {
	ctx := recon.WithDryRun(context.Background(), true)

	lines, err := tools.RunCommandStreamWithInput(ctx, nil, "subfinder", "-silent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(lines) == 0 {
		t.Fatal("expected mock subfinder lines, got empty")
	}

	foundSub1 := false
	for _, l := range lines {
		if strings.Contains(l, "sub1.") {
			foundSub1 = true
			break
		}
	}
	if !foundSub1 {
		t.Errorf("expected sub1 in mock lines, got: %v", lines)
	}
}

func TestAssetStoreStreaming(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bbpts_assetstore_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "assets.jsonl")

	cfg := Config{
		AssetStore: storePath,
	}

	orchestrator := NewOrchestrator(cfg)

	ev := Event{
		Target:     "https://api.acme-corp.io",
		Source:     "subfinder",
		Type:       "subdomain",
		Properties: map[string]string{"foo": "bar"},
	}

	orchestrator.reportEvent(ev)

	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("failed to read asset store file: %v", err)
	}

	var parsed struct {
		Target     string            `json:"target"`
		Source     string            `json:"source"`
		Type       string            `json:"type"`
		Properties map[string]string `json:"properties"`
		Timestamp  string            `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse jsonl line: %v", err)
	}

	if parsed.Target != ev.Target {
		t.Errorf("expected Target %q, got %q", ev.Target, parsed.Target)
	}
	if parsed.Source != ev.Source {
		t.Errorf("expected Source %q, got %q", ev.Source, parsed.Source)
	}
	if parsed.Type != ev.Type {
		t.Errorf("expected Type %q, got %q", ev.Type, parsed.Type)
	}
	if parsed.Properties["foo"] != "bar" {
		t.Errorf("expected properties.foo to be 'bar'")
	}
	if parsed.Timestamp == "" {
		t.Errorf("expected non-empty timestamp")
	}
}
