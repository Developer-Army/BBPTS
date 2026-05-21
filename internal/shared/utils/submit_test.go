package utils

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type mockDoer struct {
	resp *http.Response
	err  error
}

func (m mockDoer) Do(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func TestAutoSubmitSkipsUnconfiguredPlatform(t *testing.T) {
	t.Setenv("BBPTS_H1_USER", "")
	t.Setenv("BBPTS_H1_API_TOKEN", "")

	restore := SetHTTPClient(mockDoer{err: errors.New("should not be called")})
	defer restore()

	if err := AutoSubmit("hackerone", "example", "title", "description", "high"); err != nil {
		t.Fatalf("AutoSubmit() returned error for unconfigured platform: %v", err)
	}
}

func TestHackerOneSubmitReturnsHTTPErrorBody(t *testing.T) {
	t.Setenv("BBPTS_H1_USER", "user")
	t.Setenv("BBPTS_H1_API_TOKEN", "token")

	restore := SetHTTPClient(mockDoer{resp: &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Body:       io.NopCloser(strings.NewReader("bad payload")),
	}})
	defer restore()

	err := NewHackerOneClient("example").SubmitReport("title", "description", "high")
	if err == nil || !strings.Contains(err.Error(), "bad payload") {
		t.Fatalf("SubmitReport() error = %v, want body text", err)
	}
}

func TestBugcrowdSubmitHandlesNetworkError(t *testing.T) {
	t.Setenv("BBPTS_BUGCROWD_API_TOKEN", "token")

	restore := SetHTTPClient(mockDoer{err: errors.New("network down")})
	defer restore()

	err := NewBugcrowdClient("example").SubmitReport("title", "description", "high")
	if err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("SubmitReport() error = %v, want network error", err)
	}
}
