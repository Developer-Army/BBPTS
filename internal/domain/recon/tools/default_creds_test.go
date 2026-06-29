package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestDefaultCredsTool_Jenkins(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jobs":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())

	tool := &DefaultCredsTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Jenkins check is mapped to port 8080. Wait! Our mock server doesn't run on port 8080.
	// So we can directly test helper functions, or verify that running on an unknown port returns nothing.
	if len(events) > 0 && port != 8080 {
		t.Errorf("expected no events for port %d, got %d", port, len(events))
	}

	// Now let's test directly calling checkJenkins using our server
	var manualEvents []recon.Event
	tool.checkJenkins(context.Background(), http.DefaultClient, u.Scheme, u.Hostname(), port, &manualEvents)

	if len(manualEvents) == 0 {
		t.Error("expected to trigger Jenkins vulnerability discovery event")
	} else if manualEvents[0].Properties["vuln_name"] != "Unauthenticated Jenkins Dashboard Access" {
		t.Errorf("expected Unauthenticated Jenkins Dashboard Access, got %s", manualEvents[0].Properties["vuln_name"])
	}
}

func TestDefaultCredsTool_Redis(t *testing.T) {
	// Start a TCP server to mock Redis responses
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start tcp listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 64)
		_, err = conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("+PONG\r\n"))
	}()

	addr := listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	tool := &DefaultCredsTool{}
	var events []recon.Event
	tool.checkRedis(context.Background(), host, port, &events)

	if len(events) == 0 {
		t.Error("expected to trigger Redis vulnerability event")
	} else if events[0].Properties["vuln_name"] != "Unauthenticated Redis Database Access" {
		t.Errorf("expected Unauthenticated Redis Database Access, got %s", events[0].Properties["vuln_name"])
	}
}
