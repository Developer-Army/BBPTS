package services

import (
	"context"
	"fmt"
	"testing"
)

// BenchmarkBatchProcessorSmall benchmarks batch processing with a small target list.
func BenchmarkBatchProcessorSmall(b *testing.B) {
	bp := NewBatchProcessor(BatchConfig{BatchSize: 10, MaxConcurrentBatches: 2})
	targets := makeTargets(20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bp.Process(context.Background(), targets, func(ctx context.Context, batch []string) ([]Event, error) {
			events := make([]Event, len(batch))
			for j, t := range batch {
				events[j] = NewEvent(t, "bench", "discovery", nil)
			}
			return events, nil
		})
	}
}

// BenchmarkBatchProcessorLarge benchmarks batch processing with a large target list.
func BenchmarkBatchProcessorLarge(b *testing.B) {
	bp := NewBatchProcessor(BatchConfig{BatchSize: 50, MaxConcurrentBatches: 5})
	targets := makeTargets(500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bp.Process(context.Background(), targets, func(ctx context.Context, batch []string) ([]Event, error) {
			events := make([]Event, len(batch))
			for j, t := range batch {
				events[j] = NewEvent(t, "bench", "discovery", nil)
			}
			return events, nil
		})
	}
}

// BenchmarkCacheKeyGeneration benchmarks cache key generation.
func BenchmarkCacheKeyGeneration(b *testing.B) {
	targets := makeTargets(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CacheKey("subfinder", targets, 10)
	}
}

// BenchmarkNewEventsFromLines benchmarks event creation from raw output lines.
func BenchmarkNewEventsFromLines(b *testing.B) {
	lines := makeTargets(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEventsFromLines(lines, "benchmark-tool", nil)
	}
}

// BenchmarkParseOutputLines benchmarks raw output parsing and deduplication.
func BenchmarkParseOutputLines(b *testing.B) {
	// Generate output with duplicates
	lines := make([]string, 2000)
	for i := range lines {
		lines[i] = fmt.Sprintf("target-%d.example.com", i%500)
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

// BenchmarkMockPipeline benchmarks full pipeline mock generation.
func BenchmarkMockPipeline(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewMockPipeline("example.com")
	}
}

func makeTargets(n int) []string {
	targets := make([]string, n)
	for i := range targets {
		targets[i] = fmt.Sprintf("host-%d.example.com", i)
	}
	return targets
}
