package storage

import (
	"os"
	"strings"
	"testing"
)

// Scenario 3: Adversarial Edge-Case Injection (Scale/Blob Test)
// Ensures the database does not bloat when fed massive 2MB response payloads.
func TestChaos_AdversarialBlobInjection(t *testing.T) {
	// Setup in-memory sqlite for test
	s, err := NewStorage("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to init storage: %v", err)
	}
	defer s.Close()

	// Generate a 2MB adversarial payload (e.g. huge minified JS chunk or gzip bomb)
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

	// Save the event
	err = s.SaveEvent(ev)
	if err != nil {
		t.Fatalf("Storage engine failed to handle massive event: %v", err)
	}

	// Retrieve the event
	events, err := s.GetEventsByTarget("https://adversarial.target.com/app.js")
	if err != nil {
		t.Fatalf("Failed to retrieve event: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("Event was not saved")
	}

	retrieved := events[0]

	// Verify Hot/Cold Separation
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

	// Verify the blob actually exists on disk
	blobPath := strings.TrimPrefix(blobURI, "file://")
	stat, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("Blob file missing from disk: %v", err)
	}
	if stat.Size() != int64(len(massivePayload)) {
		t.Fatalf("Blob file size mismatch. Expected %d, got %d", len(massivePayload), stat.Size())
	}

	// Cleanup the test blob
	os.RemoveAll("results/blobs")

	t.Logf("Adversarial Injection Success: 2MB payload safely intercepted, hashed, and moved to Cold Storage at %s", blobPath)
}
