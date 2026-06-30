package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitExposureTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.git/HEAD") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/.git/config") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/Developer-Army/BBPTS.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &GitExposureTool{}
	if tool.Name() != "git_exposure" {
		t.Errorf("expected tool name git_exposure, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundGit, foundConfig bool
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		if name == "Exposed Git Repository" {
			foundGit = true
		}
		if name == "Git Configuration Exposure" {
			foundConfig = true
			if !strings.Contains(ev.Properties["description"], "https://github.com/Developer-Army/BBPTS.git") {
				t.Errorf("expected remote URL in description, got %s", ev.Properties["description"])
			}
		}
	}

	if !foundGit {
		t.Error("expected to detect Exposed Git Repository vulnerability")
	}
	if !foundConfig {
		t.Error("expected to detect Git Configuration Exposure vulnerability")
	}
}
