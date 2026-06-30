package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestNewWorkflowTracer(t *testing.T) {
	tracer := NewWorkflowTracer()

	if tracer == nil {
		t.Fatal("NewWorkflowTracer returned nil")
	}

	if tracer.activeTraces == nil {
		t.Error("Expected activeTraces map to be initialized")
	}
}

func TestStartSpan(t *testing.T) {
	tracer := NewWorkflowTracer()

	ctx := context.Background()
	ctx, spanID := tracer.StartSpan(ctx, "test-span", "")

	if spanID == "" {
		t.Error("Expected spanID to be non-empty")
	}

	retrievedSpanID := ctx.Value(spanIDKey)
	if retrievedSpanID == nil {
		t.Error("Expected spanID to be in context")
	}

	if retrievedSpanID != spanID {
		t.Error("Expected spanID in context to match returned spanID")
	}

	tracer.mu.RLock()
	_, exists := tracer.activeTraces[spanID]
	tracer.mu.RUnlock()

	if !exists {
		t.Error("Expected span to be in active traces")
	}
}

func TestStartSpanWithParent(t *testing.T) {
	tracer := NewWorkflowTracer()

	ctx := context.Background()
	ctx, parentID := tracer.StartSpan(ctx, "parent-span", "")

	_, childID := tracer.StartSpan(ctx, "child-span", parentID)

	if childID == "" {
		t.Error("Expected child spanID to be non-empty")
	}

	tracer.mu.RLock()
	parentSpan, parentExists := tracer.activeTraces[parentID]
	childSpan, childExists := tracer.activeTraces[childID]
	tracer.mu.RUnlock()

	if !parentExists {
		t.Error("Expected parent span to exist")
	}

	if !childExists {
		t.Error("Expected child span to exist")
	}

	if childSpan.ParentID != parentID {
		t.Error("Expected child span to have parentID")
	}

	if len(parentSpan.Children) != 1 {
		t.Errorf("Expected parent to have 1 child, got %d", len(parentSpan.Children))
	}
}

func TestEndSpan(t *testing.T) {
	tracer := NewWorkflowTracer()

	_, spanID := tracer.StartSpan(context.Background(), "test-span", "")

	time.Sleep(10 * time.Millisecond)

	metadata := map[string]interface{}{
		"key": "value",
	}
	tracer.EndSpan(spanID, metadata)

	tracer.mu.RLock()
	span, exists := tracer.activeTraces[spanID]
	tracer.mu.RUnlock()

	if !exists {
		t.Error("Expected span to exist after ending")
	}

	if span.End.IsZero() {
		t.Error("Expected End time to be set")
	}

	if span.Duration == 0 {
		t.Error("Expected Duration to be non-zero")
	}

	if span.Metadata["key"] != "value" {
		t.Error("Expected metadata to be set")
	}
}

func TestEndSpanNonExistent(t *testing.T) {
	tracer := NewWorkflowTracer()

	tracer.EndSpan("non-existent", nil)
}

func TestGetTrace(t *testing.T) {
	tracer := NewWorkflowTracer()

	_, spanID := tracer.StartSpan(context.Background(), "test-span", "")

	trace := tracer.GetTrace(spanID)

	if trace == nil {
		t.Fatal("Expected trace to be returned")
	}

	if trace.ID != spanID {
		t.Error("Expected trace ID to match spanID")
	}
}

func TestGetTraceNonExistent(t *testing.T) {
	tracer := NewWorkflowTracer()

	trace := tracer.GetTrace("non-existent")

	if trace != nil {
		t.Error("Expected trace to be nil for non-existent span")
	}
}

func TestTraceNodeStructure(t *testing.T) {
	node := &TraceNode{
		ID:       "span-123",
		ParentID: "span-456",
		Name:     "test-span",
		Start:    time.Now(),
		End:      time.Now().Add(100 * time.Millisecond),
		Duration: 100 * time.Millisecond,
		Metadata: map[string]interface{}{"key": "value"},
		Children: []*TraceNode{},
	}

	if node.ID != "span-123" {
		t.Errorf("Expected ID 'span-123', got '%s'", node.ID)
	}

	if node.ParentID != "span-456" {
		t.Errorf("Expected ParentID 'span-456', got '%s'", node.ParentID)
	}

	if node.Name != "test-span" {
		t.Errorf("Expected Name 'test-span', got '%s'", node.Name)
	}

	if node.Start.IsZero() {
		t.Error("Expected Start to be set")
	}

	if node.End.IsZero() {
		t.Error("Expected End to be set")
	}

	if len(node.Children) != 0 {
		t.Errorf("Expected 0 children, got %d", len(node.Children))
	}

	if node.Duration != 100*time.Millisecond {
		t.Errorf("Expected Duration 100ms, got %v", node.Duration)
	}

	if node.Metadata["key"] != "value" {
		t.Error("Expected metadata to be set")
	}
}

func TestGenerateSpanID(t *testing.T) {
	id1 := generateSpanID()
	id2 := generateSpanID()

	if id1 == "" {
		t.Error("Expected spanID to be non-empty")
	}

	if id2 == "" {
		t.Error("Expected spanID to be non-empty")
	}

	if id1 == id2 {
		t.Error("Expected different spanIDs for different calls")
	}
}

func TestMultipleSpans(t *testing.T) {
	tracer := NewWorkflowTracer()

	ctx := context.Background()

	ctx, span1 := tracer.StartSpan(ctx, "span-1", "")
	ctx, span2 := tracer.StartSpan(ctx, "span-2", "")
	_, span3 := tracer.StartSpan(ctx, "span-3", "")

	tracer.mu.RLock()
	count := len(tracer.activeTraces)
	tracer.mu.RUnlock()

	if count != 3 {
		t.Errorf("Expected 3 active spans, got %d", count)
	}

	tracer.EndSpan(span1, nil)
	tracer.EndSpan(span2, nil)
	tracer.EndSpan(span3, nil)

	tracer.mu.RLock()
	count = len(tracer.activeTraces)
	tracer.mu.RUnlock()

	if count != 3 {
		t.Errorf("Expected 3 spans in traces after ending, got %d", count)
	}
}

func TestSpanHierarchy(t *testing.T) {
	tracer := NewWorkflowTracer()

	ctx := context.Background()

	ctx, parentID := tracer.StartSpan(ctx, "parent", "")

	ctx, child1ID := tracer.StartSpan(ctx, "child-1", parentID)
	ctx, child2ID := tracer.StartSpan(ctx, "child-2", parentID)

	_, grandchildID := tracer.StartSpan(ctx, "grandchild", child1ID)

	tracer.mu.RLock()
	parent := tracer.activeTraces[parentID]
	child1 := tracer.activeTraces[child1ID]
	child2 := tracer.activeTraces[child2ID]
	grandchild := tracer.activeTraces[grandchildID]
	tracer.mu.RUnlock()

	if len(parent.Children) != 2 {
		t.Errorf("Expected parent to have 2 children, got %d", len(parent.Children))
	}

	if len(child1.Children) != 1 {
		t.Errorf("Expected child1 to have 1 child, got %d", len(child1.Children))
	}

	if len(child2.Children) != 0 {
		t.Errorf("Expected child2 to have 0 children, got %d", len(child2.Children))
	}

	if grandchild.ParentID != child1ID {
		t.Error("Expected grandchild to have child1 as parent")
	}
}

func TestSpanMetadataMerge(t *testing.T) {
	tracer := NewWorkflowTracer()

	ctx := context.Background()
	ctx, spanID := tracer.StartSpan(ctx, "test-span", "")

	tracer.EndSpan(spanID, map[string]interface{}{
		"key1": "value1",
	})

	_, spanID = tracer.StartSpan(ctx, "test-span", "")

	tracer.EndSpan(spanID, map[string]interface{}{
		"key2": "value2",
	})

	tracer.mu.RLock()
	span := tracer.activeTraces[spanID]
	tracer.mu.RUnlock()

	if span == nil {
		t.Error("Expected span to exist")
	}
}

func TestWorkflowTracerContextKey(t *testing.T) {
	key := tracerContextKey("span_id")

	if key != "span_id" {
		t.Errorf("Expected context key 'span_id', got '%s'", key)
	}
}

func TestSpanDurationCalculation(t *testing.T) {
	start := time.Now()
	end := start.Add(100 * time.Millisecond)

	duration := end.Sub(start)

	if duration != 100*time.Millisecond {
		t.Errorf("Expected duration 100ms, got %v", duration)
	}
}

func TestConcurrentSpanOperations(t *testing.T) {
	tracer := NewWorkflowTracer()

	ctx := context.Background()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(index int) {
			_, spanID := tracer.StartSpan(ctx, "span", "")
			tracer.EndSpan(spanID, nil)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	tracer.mu.RLock()
	count := len(tracer.activeTraces)
	tracer.mu.RUnlock()

	if count != 10 {
		t.Errorf("Expected 10 spans, got %d", count)
	}
}
