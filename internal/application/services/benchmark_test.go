package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

func BenchmarkBatchProcessorSmall(b *testing.B) {
	bp := NewBatchProcessor(BatchConfig{BatchSize: 10, MaxConcurrentBatches: 2})
	targets := makeTargets(20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bp.Process(context.Background(), targets, func(ctx context.Context, batch []string) ([]Event, error) {
			events := make([]Event, len(batch))
			for j, t := range batch {
				events[j] = NewEvent(t, "bench", "discovery", nil)
			}
			return events, nil
		})
	}
}

func BenchmarkBatchProcessorLarge(b *testing.B) {
	bp := NewBatchProcessor(BatchConfig{BatchSize: 50, MaxConcurrentBatches: 5})
	targets := makeTargets(500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bp.Process(context.Background(), targets, func(ctx context.Context, batch []string) ([]Event, error) {
			events := make([]Event, len(batch))
			for j, t := range batch {
				events[j] = NewEvent(t, "bench", "discovery", nil)
			}
			return events, nil
		})
	}
}

func BenchmarkCacheKeyGeneration(b *testing.B) {
	targets := makeTargets(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CacheKey("subfinder", targets, 10)
	}
}

func BenchmarkNewEventsFromLines(b *testing.B) {
	lines := makeTargets(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEventsFromLines(lines, "benchmark-tool", nil)
	}
}

func BenchmarkParseOutputLines(b *testing.B) {

	lines := make([]string, 2000)
	for i := range lines {
		lines[i] = fmt.Sprintf("target-%d.acme-corp.io", i%500)
	}
	rawOutput := []byte("")
	for _, l := range lines {
		rawOutput = append(rawOutput, []byte(l+"\n")...)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseOutputLines(rawOutput)
	}
}

func BenchmarkMockPipeline(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tools.NewMockPipeline("acme-corp.io")
	}
}

func makeTargets(n int) []string {
	targets := make([]string, n)
	for i := range targets {
		targets[i] = fmt.Sprintf("host-%d.acme-corp.io", i)
	}
	return targets
}
