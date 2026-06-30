package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func TestEscalatorBreach(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts.db")
	store, err := storage.NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	policyID, err := store.AddSLAPolicy("Critical Breach Policy", "critical", 2)
	if err != nil {
		t.Fatalf("AddSLAPolicy failed: %v", err)
	}

	teamID, _ := store.AddTeam("Devops")
	ownerID, _ := store.AddOwner("Bob", "bob@corp.com")

	_ = store.SetAssetOwner("db.corp.com", &ownerID, &teamID, "Initial allocation")

	receivedAlert := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		receivedAlert <- payload["text"]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err = store.AddEscalationRule(policyID, 0, "slack", map[string]interface{}{"url": server.URL})
	if err != nil {
		t.Fatalf("AddEscalationRule failed: %v", err)
	}

	findingID, err := store.AddFindingForTest("Exposed DB Key", "Leaked credentials", "critical", "db.corp.com")
	if err != nil {
		t.Fatalf("AddFindingForTest failed: %v", err)
	}

	assignmentID, err := store.AssignFinding(findingID, &teamID, &ownerID, "critical")
	if err != nil {
		t.Fatalf("AssignFinding failed: %v", err)
	}

	err = store.ForceAssignmentOverdueForTest(assignmentID, 1*time.Hour)
	if err != nil {
		t.Fatalf("ForceAssignmentOverdueForTest failed: %v", err)
	}

	escalator := NewEscalator(store, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	escalator.Start(ctx)

	select {
	case alertText := <-receivedAlert:
		if !strings.Contains(alertText, "SLA Breach Escalation") {
			t.Errorf("Unexpected alert text: %s", alertText)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for escalation alert webhook")
	}

	escalator.Stop()

	// Verify status updated to escalated_lvl_0 (with polling to prevent race condition)
	var status string
	for i := 0; i < 10; i++ {
		status, err = store.GetAssignmentStatusForTest(assignmentID)
		if err == nil && status == "escalated_lvl_0" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if status != "escalated_lvl_0" {
		t.Errorf("Expected assignment status to be 'escalated_lvl_0', got '%s'", status)
	}
}

func TestEscalatorHierarchicalRouting(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts_routing.db")
	store, err := storage.NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	davidID, _ := store.AddOwner("David (Exec)", "david@corp.com")
	charlieID, _ := store.AddOwner("Charlie (Director)", "charlie@corp.com")
	aliceID, _ := store.AddOwner("Alice (Manager)", "alice@corp.com")
	bobID, _ := store.AddOwner("Bob (Owner)", "bob@corp.com")

	_ = store.SetOwnerManager(bobID, aliceID)
	_ = store.SetOwnerManager(aliceID, charlieID)
	_ = store.SetOwnerManager(charlieID, davidID)

	_, _ = store.AddSLAPolicy("Critical Policy", "critical", 2)
	teamID, _ := store.AddTeam("Security")

	escalator := NewEscalator(store, 10*time.Millisecond)

	oa := storage.OverdueAssignment{
		OwnerID:  &bobID,
		TeamID:   &teamID,
		Severity: "critical",
	}
	name, email := escalator.resolveEscalationRecipient(oa, 1)
	if name != "Alice (Manager)" || email != "alice@corp.com" {
		t.Errorf("Expected Level 1 to route to Alice, got %s (%s)", name, email)
	}

	name, email = escalator.resolveEscalationRecipient(oa, 5)
	if name != "Charlie (Director)" || email != "charlie@corp.com" {
		t.Errorf("Expected Level 2 to route to Charlie, got %s (%s)", name, email)
	}

	name, email = escalator.resolveEscalationRecipient(oa, 10)
	if name != "David (Exec)" || email != "david@corp.com" {
		t.Errorf("Expected Level 3 to route to David, got %s (%s)", name, email)
	}
}
