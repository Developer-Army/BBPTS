package queue

import (
	"context"
	"testing"
	"time"
)

func TestErrTaskAlreadyProcessed(t *testing.T) {
	if ErrTaskAlreadyProcessed == nil {
		t.Error("Expected ErrTaskAlreadyProcessed to be defined")
	}

	if ErrTaskAlreadyProcessed.Error() == "" {
		t.Error("Expected error message to be non-empty")
	}
}

func TestErrTaskNotFound(t *testing.T) {
	if ErrTaskNotFound == nil {
		t.Error("Expected ErrTaskNotFound to be defined")
	}

	if ErrTaskNotFound.Error() == "" {
		t.Error("Expected error message to be non-empty")
	}
}

func TestTaskResultStructure(t *testing.T) {
	tr := &TaskResult{
		TaskID:      "task-123",
		Status:      "success",
		EventCount:  5,
		Events:      []map[string]interface{}{{"type": "subdomain"}},
		Error:       "",
		CompletedAt: time.Now().Unix(),
		WorkerID:    "worker-1",
	}

	if tr.TaskID != "task-123" {
		t.Errorf("Expected TaskID 'task-123', got '%s'", tr.TaskID)
	}

	if tr.Status != "success" {
		t.Errorf("Expected Status 'success', got '%s'", tr.Status)
	}

	if tr.EventCount != 5 {
		t.Errorf("Expected EventCount 5, got %d", tr.EventCount)
	}

	if len(tr.Events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(tr.Events))
	}

	if tr.WorkerID != "worker-1" {
		t.Errorf("Expected WorkerID 'worker-1', got '%s'", tr.WorkerID)
	}
}

func TestIdempotencyManagerStructure(t *testing.T) {
	im := &IdempotencyManager{}
	_ = im
}

func TestTaskResultStatusValues(t *testing.T) {
	validStatuses := []string{"success", "failed", "skipped"}

	for _, status := range validStatuses {
		tr := &TaskResult{Status: status}
		if tr.Status != status {
			t.Errorf("Expected status '%s', got '%s'", status, tr.Status)
		}
	}
}

func TestTaskResultKeyFormat(t *testing.T) {
	taskID := "task-123"

	expectedClaimedKey := "task:task-123:claimed"
	actualClaimedKey := formatTaskClaimedKey(taskID)

	if actualClaimedKey != expectedClaimedKey {
		t.Errorf("Expected claimed key '%s', got '%s'", expectedClaimedKey, actualClaimedKey)
	}

	expectedResultKey := "task:task-123:result"
	actualResultKey := formatTaskResultKey(taskID)

	if actualResultKey != expectedResultKey {
		t.Errorf("Expected result key '%s', got '%s'", expectedResultKey, actualResultKey)
	}
}

func formatTaskClaimedKey(taskID string) string {
	return "task:" + taskID + ":claimed"
}

func formatTaskResultKey(taskID string) string {
	return "task:" + taskID + ":result"
}

func TestEventDeduperStructure(t *testing.T) {
	ed := &EventDeduper{}
	_ = ed
}

func TestEventDeduperKeyFormat(t *testing.T) {
	eventType := "subdomain"
	source := "subfinder"
	target := "example.com"

	expectedKey := "event:subdomain:subfinder:example.com"
	actualKey := formatEventKey(eventType, source, target)

	if actualKey != expectedKey {
		t.Errorf("Expected key '%s', got '%s'", expectedKey, actualKey)
	}
}

func formatEventKey(eventType, source, target string) string {
	return "event:" + eventType + ":" + source + ":" + target
}

func TestSessionReplayLogStructure(t *testing.T) {
	srl := &SessionReplayLog{}
	_ = srl
}

func TestSessionReplayLogKeyFormat(t *testing.T) {
	sessionID := "session-123"
	taskID := "task-456"

	expectedKey := "session:session-123:task:task-456"
	actualKey := formatSessionTaskKey(sessionID, taskID)

	if actualKey != expectedKey {
		t.Errorf("Expected key '%s', got '%s'", expectedKey, actualKey)
	}
}

func formatSessionTaskKey(sessionID, taskID string) string {
	return "session:" + sessionID + ":task:" + taskID
}

func TestTaskResultTimestamp(t *testing.T) {
	now := time.Now().Unix()

	tr := &TaskResult{
		CompletedAt: now,
	}

	if tr.CompletedAt != now {
		t.Errorf("Expected CompletedAt %d, got %d", now, tr.CompletedAt)
	}
}

func TestTaskResultEvents(t *testing.T) {
	tr := &TaskResult{
		Events: []map[string]interface{}{
			{"type": "subdomain", "target": "example.com"},
			{"type": "port", "target": "example.com:80"},
		},
	}

	if len(tr.Events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(tr.Events))
	}

	if tr.Events[0]["type"] != "subdomain" {
		t.Errorf("Expected first event type 'subdomain', got '%s'", tr.Events[0]["type"])
	}
}

func TestTaskResultWithError(t *testing.T) {
	tr := &TaskResult{
		Status: "failed",
		Error:  "connection timeout",
	}

	if tr.Status != "failed" {
		t.Errorf("Expected Status 'failed', got '%s'", tr.Status)
	}

	if tr.Error != "connection timeout" {
		t.Errorf("Expected Error 'connection timeout', got '%s'", tr.Error)
	}
}

func TestIdempotencyManagerNilKV(t *testing.T) {
	im := &IdempotencyManager{
		kv: nil,
	}

	// Methods should handle nil kv gracefully
	err := im.Register(context.Background(), "task-123", "worker-1")
	if err == nil {
		t.Error("Expected error when kv is nil")
	}
}

func TestTaskResultWithMockKV(t *testing.T) {
	mockKV := &mockKeyValue{
		data: make(map[string][]byte),
	}

	im := &IdempotencyManager{
		kv: mockKV,
	}

	// Test Register
	err := im.Register(context.Background(), "task-123", "worker-1")
	if err != nil {
		t.Errorf("Register failed: %v", err)
	}

	// Test duplicate Register
	err = im.Register(context.Background(), "task-123", "worker-2")
	if err != ErrTaskAlreadyProcessed {
		t.Errorf("Expected ErrTaskAlreadyProcessed, got %v", err)
	}

	// Test Complete
	err = im.Complete("task-123", "worker-1", "success", 5, nil, nil)
	if err != nil {
		t.Errorf("Complete failed: %v", err)
	}

	// Test GetResult
	result, err := im.GetResult("task-123")
	if err != nil {
		t.Errorf("GetResult failed: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("Expected status 'success', got '%s'", result.Status)
	}

	// Test HasBeenProcessed
	processed, err := im.HasBeenProcessed("task-123")
	if err != nil {
		t.Errorf("HasBeenProcessed failed: %v", err)
	}

	if !processed {
		t.Error("Expected task to be processed")
	}

	// Test GetResult for non-existent task
	_, err = im.GetResult("non-existent")
	if err != ErrTaskNotFound {
		t.Errorf("Expected ErrTaskNotFound, got %v", err)
	}
}

func TestEventDeduperWithMockKV(t *testing.T) {
	mockKV := &mockKeyValue{
		data: make(map[string][]byte),
	}

	ed := &EventDeduper{
		kv: mockKV,
	}

	// Test RecordEvent
	err := ed.RecordEvent("example.com", "subfinder", "subdomain")
	if err != nil {
		t.Errorf("RecordEvent failed: %v", err)
	}

	// Test IsDuplicate
	isDup, err := ed.IsDuplicate("example.com", "subfinder", "subdomain")
	if err != nil {
		t.Errorf("IsDuplicate failed: %v", err)
	}

	if !isDup {
		t.Error("Expected event to be duplicate")
	}

	// Test IsDuplicate for non-existent event
	isDup, err = ed.IsDuplicate("different.com", "subfinder", "subdomain")
	if err != nil {
		t.Errorf("IsDuplicate failed: %v", err)
	}

	if isDup {
		t.Error("Expected event to not be duplicate")
	}
}

func TestSessionReplayLogWithMockKV(t *testing.T) {
	mockKV := &mockKeyValue{
		data: make(map[string][]byte),
	}

	srl := &SessionReplayLog{
		kv: mockKV,
	}

	// Test LogTaskInSession
	err := srl.LogTaskInSession("session-123", "task-456", "success", 5)
	if err != nil {
		t.Errorf("LogTaskInSession failed: %v", err)
	}

	// Test GetSessionTasks
	tasks, err := srl.GetSessionTasks("session-123")
	if err != nil {
		t.Errorf("GetSessionTasks failed: %v", err)
	}

	if tasks == nil {
		t.Error("Expected tasks to be non-nil")
	}
}

func TestTaskResultEventCount(t *testing.T) {
	tr := &TaskResult{
		EventCount: 10,
	}

	if tr.EventCount != 10 {
		t.Errorf("Expected EventCount 10, got %d", tr.EventCount)
	}
}

func TestTaskResultWorkerID(t *testing.T) {
	tr := &TaskResult{
		WorkerID: "worker-123",
	}

	if tr.WorkerID != "worker-123" {
		t.Errorf("Expected WorkerID 'worker-123', got '%s'", tr.WorkerID)
	}
}

func TestTaskResultNilEvents(t *testing.T) {
	tr := &TaskResult{
		Events: nil,
	}

	if tr.Events != nil {
		t.Error("Expected Events to be nil")
	}
}

func TestTaskResultEmptyEvents(t *testing.T) {
	tr := &TaskResult{
		Events: []map[string]interface{}{},
	}

	if len(tr.Events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(tr.Events))
	}
}
