package telemetry

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type tracerContextKey string

const spanIDKey tracerContextKey = "span_id"

// TraceNode represents a node in the trace tree.
type TraceNode struct {
	ID       string
	ParentID string
	Name     string
	Start    time.Time
	End      time.Time
	Duration time.Duration
	Metadata map[string]interface{}
	Children []*TraceNode
}

// Tracer provides distributed workflow tracking.
// In production, this would bridge to OpenTelemetry / Jaeger.
type Tracer struct {
	activeTraces map[string]*TraceNode
	mu           sync.RWMutex
}

// NewTracer creates a new tracer instance.
func NewTracer() *Tracer {
	return &Tracer{
		activeTraces: make(map[string]*TraceNode),
	}
}

// DefaultTracer is a global tracer instance.
var DefaultTracer = NewTracer()

// GetSpanID retrieves the current span ID from context.
func GetSpanID(ctx context.Context) string {
	if val := ctx.Value(spanIDKey); val != nil {
		if id, ok := val.(string); ok {
			return id
		}
	}
	return ""
}

// StartSpan begins a new trace span.
func (t *Tracer) StartSpan(ctx context.Context, name string, parentID string) (context.Context, string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	spanID := generateSpanID()
	node := &TraceNode{
		ID:       spanID,
		ParentID: parentID,
		Name:     name,
		Start:    time.Now(),
		Metadata: make(map[string]interface{}),
	}

	t.activeTraces[spanID] = node

	// If parent exists, add as child
	if parentID != "" {
		if parent, exists := t.activeTraces[parentID]; exists {
			parent.Children = append(parent.Children, node)
		}
	}

	return context.WithValue(ctx, spanIDKey, spanID), spanID
}

// EndSpan completes a trace span.
func (t *Tracer) EndSpan(spanID string, metadata map[string]interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	node, exists := t.activeTraces[spanID]
	if !exists {
		return
	}

	node.End = time.Now()
	node.Duration = node.End.Sub(node.Start)

	// Merge metadata
	for k, v := range metadata {
		node.Metadata[k] = v
	}
}

// GetTrace retrieves a complete trace tree.
func (t *Tracer) GetTrace(rootID string) *TraceNode {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.activeTraces[rootID]
}

// generateSpanID creates a unique span identifier.
func generateSpanID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
