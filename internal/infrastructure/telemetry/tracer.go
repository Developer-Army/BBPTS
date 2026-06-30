package telemetry

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var spanCounter uint64

type tracerContextKey string

const spanIDKey tracerContextKey = "span_id"

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

type WorkflowTracer struct {
	activeTraces map[string]*TraceNode
	mu           sync.RWMutex
}

func NewWorkflowTracer() *WorkflowTracer {
	return &WorkflowTracer{
		activeTraces: make(map[string]*TraceNode),
	}
}

var InternalTracer = NewWorkflowTracer()

func GetSpanID(ctx context.Context) string {
	if val := ctx.Value(spanIDKey); val != nil {
		if id, ok := val.(string); ok {
			return id
		}
	}
	return ""
}

func (t *WorkflowTracer) StartSpan(ctx context.Context, name string, parentID string) (context.Context, string) {
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

	if parentID != "" {
		if parent, exists := t.activeTraces[parentID]; exists {
			parent.Children = append(parent.Children, node)
		}
	}

	return context.WithValue(ctx, spanIDKey, spanID), spanID
}

func (t *WorkflowTracer) EndSpan(spanID string, metadata map[string]interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	node, exists := t.activeTraces[spanID]
	if !exists {
		return
	}

	node.End = time.Now()
	node.Duration = node.End.Sub(node.Start)

	for k, v := range metadata {
		node.Metadata[k] = v
	}
}

func (t *WorkflowTracer) GetTrace(rootID string) *TraceNode {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.activeTraces[rootID]
}

func generateSpanID() string {
	count := atomic.AddUint64(&spanCounter, 1)
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), count)
}
