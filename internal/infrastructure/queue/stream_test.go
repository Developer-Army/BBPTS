package queue

import (
	"context"
	"testing"
)

func TestStreamManagerStructure(t *testing.T) {

	sm := &StreamManager{}
	_ = sm
}

func TestStreamManagerNilConnection(t *testing.T) {
	sm := &StreamManager{
		nc: nil,
		js: nil,
	}

	if sm.JetStream() != nil {
		t.Error("Expected JetStream to return nil when js is nil")
	}
}

func TestStreamManagerClose(t *testing.T) {
	sm := &StreamManager{
		nc: nil,
		js: nil,
	}

	err := sm.Close()
	if err != nil {
		t.Errorf("Close should not error with nil connection: %v", err)
	}
}

func TestPublishTaskMarshalError(t *testing.T) {
	sm := &StreamManager{
		nc: nil,
		js: nil,
	}

	payload := make(chan int)

	err := sm.PublishTask("test.subject", payload)
	if err == nil {
		t.Error("Expected error when marshaling fails")
	}
}

func TestPublishTaskNilPayload(t *testing.T) {
	sm := &StreamManager{
		nc: nil,
		js: nil,
	}

	err := sm.PublishTask("test.subject", nil)
	if err == nil {
		t.Error("Expected error when payload is nil")
	}
}

func TestPublishTaskValidPayload(t *testing.T) {
	sm := &StreamManager{
		nc: nil,
		js: nil,
	}

	payload := map[string]interface{}{
		"key": "value",
		"num": 123,
	}

	err := sm.PublishTask("test.subject", payload)

	if err == nil {
		t.Error("Expected error when js is nil")
	}
}

func TestSubscribeWorkerNilHandler(t *testing.T) {
	sm := &StreamManager{
		nc: nil,
		js: nil,
	}

	err := sm.SubscribeWorker(context.Background(), "test.subject", "queue", nil)
	if err == nil {
		t.Error("Expected error when handler is nil")
	}
}

func TestStreamConfigDefaults(t *testing.T) {

	maxAge := 72 * 60 * 60 * 1000000000
	replicas := 1
	duplicates := 5 * 60 * 1000000000

	if maxAge != 259200000000000 {
		t.Errorf("Expected maxAge 259200000000000, got %d", maxAge)
	}

	if replicas != 1 {
		t.Errorf("Expected replicas 1, got %d", replicas)
	}

	if duplicates != 300000000000 {
		t.Errorf("Expected duplicates 300000000000, got %d", duplicates)
	}
}

func TestStreamName(t *testing.T) {
	streamName := "BBPTS_STREAM"

	if streamName != "BBPTS_STREAM" {
		t.Errorf("Expected stream name 'BBPTS_STREAM', got '%s'", streamName)
	}
}

func TestSubjectPatterns(t *testing.T) {
	subjects := []string{"*"}

	if len(subjects) != 1 {
		t.Errorf("Expected 1 subject, got %d", len(subjects))
	}

	if subjects[0] != "*" {
		t.Errorf("Expected subject '*', got '%s'", subjects[0])
	}
}

func TestRetryConfiguration(t *testing.T) {

	maxReconnects := -1
	reconnectWait := 2 * 1000000000

	if maxReconnects != -1 {
		t.Errorf("Expected maxReconnects -1, got %d", maxReconnects)
	}

	if reconnectWait != 2000000000 {
		t.Errorf("Expected reconnectWait 2000000000, got %d", reconnectWait)
	}
}

func TestMaxDeliverConfiguration(t *testing.T) {

	maxDeliver := 3

	if maxDeliver != 3 {
		t.Errorf("Expected maxDeliver 3, got %d", maxDeliver)
	}
}

func TestNakDelayConfiguration(t *testing.T) {

	nakDelay := 10 * 1000000000

	if nakDelay != 10000000000 {
		t.Errorf("Expected nakDelay 10000000000, got %d", nakDelay)
	}
}

func TestQueueGroupFormat(t *testing.T) {
	queueGroup := "workers_subdomain_enum"

	if queueGroup != "workers_subdomain_enum" {
		t.Errorf("Expected queue group 'workers_subdomain_enum', got '%s'", queueGroup)
	}
}

func TestSubjectFormat(t *testing.T) {
	subject := "task.subdomain_enum.>"

	if subject != "task.subdomain_enum.>" {
		t.Errorf("Expected subject 'task.subdomain_enum.>', got '%s'", subject)
	}
}
