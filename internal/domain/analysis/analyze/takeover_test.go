package analyze

import (
	"context"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func TestTakeoverAnalyzer(t *testing.T) {
	analyzer := NewTakeoverAnalyzer()

	analyzer.lookupCNAME = func(ctx context.Context, host string) (string, error) {
		if host == "sub.target.com" {
			return "dangling.github.io", nil
		}
		return "", nil
	}

	insight := &Insight{
		Host: "sub.target.com",
	}

	ev := recon.Event{
		Target: "sub.target.com",
		Source: "dnsx",
	}

	analyzer.Analyze(ev, insight)

	foundTag := false
	for _, tag := range insight.Tags {
		if tag == "subdomain-takeover" {
			foundTag = true
			break
		}
	}

	if !foundTag {
		t.Errorf("expected subdomain-takeover tag, got %v", insight.Tags)
	}

	foundReason := false
	for _, reason := range insight.Reasons {
		if strings.Contains(reason, "CNAME points to vulnerable SaaS provider") {
			foundReason = true
			break
		}
	}

	if !foundReason {
		t.Errorf("expected takeover reason in insight reasons, got %v", insight.Reasons)
	}
}
