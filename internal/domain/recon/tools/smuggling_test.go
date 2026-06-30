package tools

import (
	"bufio"
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSmugglingTool(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping timing-sensitive request smuggling test in CI")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start raw listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				var headers []string
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					if line == "" {
						break
					}
					headers = append(headers, line)
				}

				isProbe := false
				for _, h := range headers {
					if strings.Contains(h, "Transfer-Encoding: chunked") {
						isProbe = true
						break
					}
				}

				if isProbe {

					time.Sleep(3100 * time.Millisecond)
				}

				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(conn)
		}
	}()

	tool := &SmugglingTool{}
	if tool.Name() != "smuggling" {
		t.Errorf("expected tool name smuggling, got %s", tool.Name())
	}

	targetURL := "http://" + listener.Addr().String()
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{targetURL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundCLTE, foundTECL bool
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		switch name {
		case "HTTP Request Smuggling (CL.TE)":
			foundCLTE = true
		case "HTTP Request Smuggling (TE.CL)":
			foundTECL = true
		}
	}

	if !foundCLTE {
		t.Error("expected to detect HTTP Request Smuggling (CL.TE)")
	}
	if !foundTECL {
		t.Error("expected to detect HTTP Request Smuggling (TE.CL)")
	}
}
