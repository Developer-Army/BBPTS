package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
)

func TestCalculateParamSensitivity(t *testing.T) {
	ins := analyze.Insight{Host: "https://example.com/test?url=https://evil.com"}
	score := calculateParamSensitivity(ins, nil)
	if score != 100 {
		t.Errorf("Expected score 100 for high-risk parameter 'url', got %d", score)
	}

	ins2 := analyze.Insight{Host: "https://example.com/test?foo=bar"}
	score2 := calculateParamSensitivity(ins2, nil)
	if score2 != 50 {
		t.Errorf("Expected score 50 for general parameter 'foo', got %d", score2)
	}

	ins3 := analyze.Insight{Host: "https://example.com/test"}
	score3 := calculateParamSensitivity(ins3, nil)
	if score3 != 0 {
		t.Errorf("Expected score 0 for no parameters, got %d", score3)
	}
}

func TestCalculateHeaderCorrelation_Dynamic(t *testing.T) {
	t.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "https://evil-confirm.com")
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ins := analyze.Insight{
		Host: server.URL,
		Tags: []string{"cors"},
	}

	score := calculateHeaderCorrelation(context.Background(), ins, nil)
	if score != 100 {
		t.Errorf("Expected score 100 for correlated CORS header, got %d", score)
	}
}

func TestCalculateStatusConsistency_Dynamic(t *testing.T) {
	t.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ins := analyze.Insight{Host: server.URL}
	score := calculateStatusConsistency(context.Background(), ins, nil)
	if score != 100 {
		t.Errorf("Expected score 100 for consistent 200 OK status codes, got %d", score)
	}
}

func TestCalculateRequestConfirmation_CORS(t *testing.T) {
	t.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		origin := req.Header.Get("Origin")
		if origin != "" {
			rw.Header().Set("Access-Control-Allow-Origin", origin)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ins := analyze.Insight{
		Host: server.URL,
		Tags: []string{"cors"},
	}

	score := calculateRequestConfirmation(context.Background(), ins, nil)
	if score != 100 {
		t.Errorf("Expected CORS confirmation score 100, got %d", score)
	}
}

func TestCalculateConfidenceScore_Combined(t *testing.T) {
	t.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ins := analyze.Insight{
		Host: server.URL + "?url=https://evil.com",
		Tags: []string{"cors"},
	}

	score := CalculateConfidenceScore(context.Background(), ins, nil)
	if score != 100 {
		t.Errorf("Expected total score 100, got %d", score)
	}
}
