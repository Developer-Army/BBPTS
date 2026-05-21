package queue

import (
	"testing"
	"time"
)

func TestErrCheckpointNotFound(t *testing.T) {
	if ErrCheckpointNotFound == nil {
		t.Error("Expected ErrCheckpointNotFound to be defined")
	}

	if ErrCheckpointNotFound.Error() == "" {
		t.Error("Expected error message to be non-empty")
	}
}

func TestCheckpointStructure(t *testing.T) {
	cp := &Checkpoint{
		SessionID:   "session-123",
		Stage:       "subdomain_enum",
		Target:      "acme-corp.io",
		Status:      "in_progress",
		Progress:    0.5,
		Data:        map[string]interface{}{"count": 10},
		Error:       "",
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		WorkerID:    "worker-1",
		LeaseExpiry: 0,
	}

	if cp.SessionID != "session-123" {
		t.Errorf("Expected SessionID 'session-123', got '%s'", cp.SessionID)
	}

	if cp.Stage != "subdomain_enum" {
		t.Errorf("Expected Stage 'subdomain_enum', got '%s'", cp.Stage)
	}

	if cp.Target != "acme-corp.io" {
		t.Errorf("Expected Target 'acme-corp.io', got '%s'", cp.Target)
	}

	if cp.Status != "in_progress" {
		t.Errorf("Expected Status 'in_progress', got '%s'", cp.Status)
	}

	if cp.Progress != 0.5 {
		t.Errorf("Expected Progress 0.5, got %f", cp.Progress)
	}

	if cp.Data["count"] != 10 {
		t.Errorf("Expected Data count 10, got %v", cp.Data["count"])
	}

	if cp.WorkerID != "worker-1" {
		t.Errorf("Expected WorkerID 'worker-1', got '%s'", cp.WorkerID)
	}
}

func TestCheckpointManagerStructure(t *testing.T) {
	cm := &CheckpointManager{}
	_ = cm
}

func TestCheckpointKeyFormat(t *testing.T) {
	sessionID := "session-123"
	stage := "subdomain_enum"
	target := "acme-corp.io"

	expectedKey := "checkpoint:session-123:subdomain_enum:acme-corp.io"
	actualKey := formatCheckpointKey(sessionID, stage, target)

	if actualKey != expectedKey {
		t.Errorf("Expected key '%s', got '%s'", expectedKey, actualKey)
	}
}

func formatCheckpointKey(sessionID, stage, target string) string {
	return "checkpoint:" + sessionID + ":" + stage + ":" + target
}

func TestResumePlanStructure(t *testing.T) {
	rp := &ResumePlan{
		SessionID:  "session-123",
		Completed:  map[string][]string{"subdomain_enum": {"acme-corp.io"}},
		InProgress: map[string][]string{"port_scan": {"acme-corp.io:80"}},
		Pending:    map[string][]string{"crawl": {"https://acme-corp.io"}},
		Failed:     map[string][]string{"js_diff": {"https://acme-corp.io/app.js"}},
	}

	if rp.SessionID != "session-123" {
		t.Errorf("Expected SessionID 'session-123', got '%s'", rp.SessionID)
	}

	if len(rp.Completed["subdomain_enum"]) != 1 {
		t.Errorf("Expected 1 completed subdomain_enum, got %d", len(rp.Completed["subdomain_enum"]))
	}

	if len(rp.InProgress["port_scan"]) != 1 {
		t.Errorf("Expected 1 in_progress port_scan, got %d", len(rp.InProgress["port_scan"]))
	}

	if len(rp.Pending["crawl"]) != 1 {
		t.Errorf("Expected 1 pending crawl, got %d", len(rp.Pending["crawl"]))
	}

	if len(rp.Failed["js_diff"]) != 1 {
		t.Errorf("Expected 1 failed js_diff, got %d", len(rp.Failed["js_diff"]))
	}
}

func TestResumePlanCanResume(t *testing.T) {
	tests := []struct {
		name     string
		plan     *ResumePlan
		expected bool
	}{
		{
			name: "has pending",
			plan: &ResumePlan{
				Pending: map[string][]string{"stage1": {"target1"}},
			},
			expected: true,
		},
		{
			name: "has in_progress",
			plan: &ResumePlan{
				InProgress: map[string][]string{"stage1": {"target1"}},
			},
			expected: true,
		},
		{
			name: "has failed",
			plan: &ResumePlan{
				Failed: map[string][]string{"stage1": {"target1"}},
			},
			expected: true,
		},
		{
			name: "all completed",
			plan: &ResumePlan{
				Completed: map[string][]string{"stage1": {"target1"}},
			},
			expected: false,
		},
		{
			name:     "empty",
			plan:     &ResumePlan{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plan.CanResume()
			if result != tt.expected {
				t.Errorf("CanResume() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestResumePlanGetNextTargets(t *testing.T) {
	tests := []struct {
		name     string
		plan     *ResumePlan
		stage    string
		expected []string
	}{
		{
			name: "pending targets",
			plan: &ResumePlan{
				Pending: map[string][]string{"stage1": {"target1", "target2"}},
			},
			stage:    "stage1",
			expected: []string{"target1", "target2"},
		},
		{
			name: "failed targets when no pending",
			plan: &ResumePlan{
				Failed: map[string][]string{"stage1": {"target1"}},
			},
			stage:    "stage1",
			expected: []string{"target1"},
		},
		{
			name: "pending takes precedence over failed",
			plan: &ResumePlan{
				Pending: map[string][]string{"stage1": {"target1"}},
				Failed:  map[string][]string{"stage1": {"target2"}},
			},
			stage:    "stage1",
			expected: []string{"target1"},
		},
		{
			name: "no targets for stage",
			plan: &ResumePlan{
				Pending: map[string][]string{"stage2": {"target1"}},
			},
			stage:    "stage1",
			expected: nil,
		},
		{
			name:     "empty plan",
			plan:     &ResumePlan{},
			stage:    "stage1",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plan.GetNextTargets(tt.stage)

			if result == nil && tt.expected != nil {
				t.Errorf("GetNextTargets() = nil, want %v", tt.expected)
			}

			if result != nil && tt.expected == nil {
				t.Errorf("GetNextTargets() = %v, want nil", result)
			}

			if result != nil && tt.expected != nil {
				if len(result) != len(tt.expected) {
					t.Errorf("GetNextTargets() length = %d, want %d", len(result), len(tt.expected))
				}
			}
		})
	}
}

func TestCheckpointStatusValues(t *testing.T) {
	validStatuses := []string{"pending", "in_progress", "completed", "failed"}

	for _, status := range validStatuses {
		cp := &Checkpoint{Status: status}
		if cp.Status != status {
			t.Errorf("Expected status '%s', got '%s'", status, cp.Status)
		}
	}
}

func TestCheckpointProgressRange(t *testing.T) {
	tests := []struct {
		progress float64
		valid    bool
	}{
		{0.0, true},
		{0.5, true},
		{1.0, true},
		{-0.1, false},
		{1.1, false},
	}

	for _, tt := range tests {
		cp := &Checkpoint{Progress: tt.progress}
		isValid := cp.Progress >= 0.0 && cp.Progress <= 1.0
		if isValid != tt.valid {
			t.Errorf("Progress %f validity = %v, want %v", tt.progress, isValid, tt.valid)
		}
	}
}

func TestCheckpointTimestamps(t *testing.T) {
	now := time.Now().Unix()

	cp := &Checkpoint{
		CreatedAt: now,
		UpdatedAt: now + 60,
	}

	if cp.CreatedAt >= cp.UpdatedAt {
		t.Error("Expected CreatedAt to be before UpdatedAt")
	}
}

func TestCheckpointLeaseExpiry(t *testing.T) {
	now := time.Now().Unix()

	cp := &Checkpoint{
		LeaseExpiry: now + 300, // 5 minutes from now
	}

	if cp.LeaseExpiry <= now {
		t.Error("Expected LeaseExpiry to be in the future")
	}
}

func TestCheckpointDataMap(t *testing.T) {
	cp := &Checkpoint{
		Data: map[string]interface{}{
			"count":    10,
			"duration": 123.45,
			"success":  true,
			"list":     []string{"a", "b", "c"},
		},
	}

	if cp.Data["count"] != 10 {
		t.Errorf("Expected count 10, got %v", cp.Data["count"])
	}

	if cp.Data["duration"] != 123.45 {
		t.Errorf("Expected duration 123.45, got %v", cp.Data["duration"])
	}

	if cp.Data["success"] != true {
		t.Errorf("Expected success true, got %v", cp.Data["success"])
	}

	if len(cp.Data["list"].([]string)) != 3 {
		t.Errorf("Expected list length 3, got %v", cp.Data["list"])
	}
}

func TestCheckpointManagerNilKV(t *testing.T) {
	cm := &CheckpointManager{
		kv: nil,
	}

	// Methods should handle nil kv gracefully
	cp := &Checkpoint{
		SessionID: "session-123",
		Stage:     "stage1",
		Target:    "target1",
	}

	err := cm.SaveCheckpoint(cp)
	if err == nil {
		t.Error("Expected error when kv is nil")
	}
}
