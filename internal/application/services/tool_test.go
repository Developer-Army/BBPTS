package services

import (
	"context"
	"testing"
)

func TestContextHeaders(t *testing.T) {
	ctx := context.Background()
	headers := map[string]string{
		"X-HackerOne-Researcher": "bob",
		"X-Testing":              "true",
	}

	ctx = WithHeaders(ctx, headers)

	retrieved := HeadersFromCtx(ctx)
	if retrieved == nil {
		t.Fatal("expected retrieved headers to not be nil")
	}

	if retrieved["X-HackerOne-Researcher"] != "bob" {
		t.Errorf("expected X-HackerOne-Researcher to be 'bob', got '%s'", retrieved["X-HackerOne-Researcher"])
	}

	if retrieved["X-Testing"] != "true" {
		t.Errorf("expected X-Testing to be 'true', got '%s'", retrieved["X-Testing"])
	}
}

func TestContextHeadersNil(t *testing.T) {
	ctx := context.Background()
	retrieved := HeadersFromCtx(ctx)
	if retrieved != nil {
		t.Errorf("expected retrieved headers to be nil for empty context, got %v", retrieved)
	}
}
