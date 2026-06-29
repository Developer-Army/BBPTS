package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMassAssignmentTool(t *testing.T) {
	var mu sync.Mutex
	db := map[string]interface{}{
		"id":       "user123",
		"name":     "Bob",
		"role":     "user",
		"isAdmin":  false,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(db)
		case "PUT", "PATCH", "POST":
			bodyBytes, _ := io.ReadAll(r.Body)
			var reqData map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &reqData); err == nil {
				// Update db
				for k, v := range reqData {
					db[k] = v
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"updated"}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	tool := &MassAssignmentTool{}
	if tool.Name() != "mass_assignment" {
		t.Errorf("expected tool name mass_assignment, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundMassAssignment bool
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		if name == "Mass Assignment API Vulnerability" {
			foundMassAssignment = true
			if !strings.Contains(ev.Properties["parameters"], "isAdmin=true") {
				t.Errorf("expected parameters evidence to contain isAdmin=true, got %s", ev.Properties["parameters"])
			}
		}
	}

	if !foundMassAssignment {
		t.Error("expected to detect Mass Assignment API Vulnerability")
	}
}
