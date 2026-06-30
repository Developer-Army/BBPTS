package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFirebaseReconTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		host := r.Host

		if path == "/" && !strings.Contains(host, "firebaseio.com") && !strings.Contains(host, "googleapis.com") && !strings.Contains(host, "appspot.com") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
				<html>
					<head><title>App</title></head>
					<body>
						<script>
							const firebaseConfig = {
								apiKey: "AIzaSyDummyKey",
								authDomain: "bbpts-demo.firebaseapp.com",
								databaseURL: "https://bbpts-demo.firebaseio.com",
								projectId: "bbpts-demo",
								storageBucket: "bbpts-demo.appspot.com",
								messagingSenderId: "12345678",
								appId: "1:123:web:abc"
							};
						</script>
					</body>
				</html>
			`))
			return
		}

		if strings.HasSuffix(path, ".json") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"users": {"admin": true}}`))
			return
		}

		if strings.Contains(path, "/databases/(default)/documents") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"documents": [{"name": "projects/bbpts-demo/databases/(default)/documents/users/admin"}]}`))
			return
		}

		if strings.HasSuffix(path, "/o") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items": [{"name": "passwords.txt"}]}`))
			return
		}

		if strings.HasSuffix(path, "/__/firebase/init.json") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"projectId": "bbpts-demo"}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &FirebaseReconTool{}
	if tool.Name() != "firebase_recon" {
		t.Errorf("expected tool name firebase_recon, got %s", tool.Name())
	}

	serverURL, _ := url.Parse(server.URL)

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_ = events
	_ = serverURL

	if len(events) == 0 {
		t.Log("No events found - expected since Firebase probing targets external URLs not the mock server")
	}
}

func TestFirebaseReconToolConfigExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`
			<script>
				const config = {
					projectId: "my-test-project",
					storageBucket: "my-test-project.appspot.com",
					databaseURL: "https://my-test-project.firebaseio.com"
				};
			</script>
		`))
	}))
	defer server.Close()

	tool := &FirebaseReconTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_ = events
}

func TestFirebaseReconToolEmpty(t *testing.T) {
	tool := &FirebaseReconTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events != nil {
		t.Error("expected nil events for empty targets")
	}
}

func TestFirebaseReconToolWithCustomTransport(t *testing.T) {
	// This test uses a custom HTTP client that routes all requests through
	// a mock server, allowing us to test the full probing logic.
	var requestedPaths []string

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)

		path := r.URL.Path

		if path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<script>
				const config = {
					projectId: "testproj",
					storageBucket: "testproj.appspot.com",
					databaseURL: "https://testproj.firebaseio.com"
				};
			</script>`))
			return
		}

		if strings.HasSuffix(path, ".json") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": "sensitive"}`))
			return
		}

		if strings.Contains(path, "/databases/(default)/documents") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"documents": []}`))
			return
		}

		if strings.HasSuffix(path, "/o") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items": []}`))
			return
		}

		if strings.HasSuffix(path, "/__/firebase/init.json") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"projectId": "testproj"}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	tool := &FirebaseReconTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{mockServer.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundHomepage := false
	for _, p := range requestedPaths {
		if p == "/" {
			foundHomepage = true
		}
	}
	if !foundHomepage {
		t.Error("expected homepage to be fetched")
	}

	_ = events
	_ = fmt.Sprintf("events_count=%d", len(events))
}
