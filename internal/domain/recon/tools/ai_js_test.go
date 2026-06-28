package tools

import (
	"strings"
	"testing"
)

func TestBeautifyJS(t *testing.T) {
	input := `var a=1;function foo(){var b=2;if(b){console.log(b)}}`
	result := beautifyJS(input)

	if result == input {
		t.Error("beautifyJS should format minified JS")
	}
	if len(result) <= len(input) {
		t.Error("beautified JS should be longer due to added whitespace")
	}
	if !strings.Contains(result, "\n") {
		t.Error("beautified JS should contain newlines")
	}
}

func TestChunkContent(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		chunkSize int
		wantMin   int
	}{
		{"empty", "", 100, 0},
		{"small", "hello world", 100, 1},
		{"exact", "hello", 5, 1},
		{"needs_chunking", "abcdefghijklmnopqrstuvwxyz", 10, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chunks := chunkContent(tc.content, tc.chunkSize)
			if len(chunks) < tc.wantMin {
				t.Errorf("chunkContent(%q, %d) = %d chunks; want >= %d", tc.content, tc.chunkSize, len(chunks), tc.wantMin)
			}
		})
	}
}
