package storage

import (
	"os"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func TestChaos_AdversarialBlobInjection(t *testing.T) {

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	tempDir, err := os.MkdirTemp("", "bbpts-storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
		os.RemoveAll(tempDir)
	}()

	s, err := NewStorage("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to init storage: %v", err)
	}
	defer s.Close()

	massivePayload := strings.Repeat("A", 2*1024*1024)

	ev := recon.Event{
		Target: "https://adversarial.target.com/app.js",
		Source: "js_analyzer",
		Type:   "javascript",
		Properties: map[string]string{
			"status":        "200",
			"response_body": massivePayload,
		},
	}

	err = s.SaveEvent(ev)
	if err != nil {
		t.Fatalf("Storage engine failed to handle massive event: %v", err)
	}

	events, err := s.GetEventsByTarget("https://adversarial.target.com/app.js")
	if err != nil {
		t.Fatalf("Failed to retrieve event: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("Event was not saved")
	}

	retrieved := events[0]

	if _, exists := retrieved.Properties["response_body"]; exists {
		t.Fatal("Adversarial payload was stored in HOT storage! Database bloat failure.")
	}

	blobURI, exists := retrieved.Properties["response_body_blob"]
	if !exists {
		t.Fatal("Blob pointer missing from hot storage.")
	}

	if !strings.HasPrefix(blobURI, "file://results/blobs/") {
		t.Fatalf("Invalid blob URI format: %s", blobURI)
	}

	blobPath := strings.TrimPrefix(blobURI, "file://")
	stat, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("Blob file missing from disk: %v", err)
	}
	if stat.Size() != int64(len(massivePayload)) {
		t.Fatalf("Blob file size mismatch. Expected %d, got %d", len(massivePayload), stat.Size())
	}

	os.RemoveAll("results/blobs")

	t.Logf("Adversarial Injection Success: 2MB payload safely intercepted, hashed, and moved to Cold Storage at %s", blobPath)
}
