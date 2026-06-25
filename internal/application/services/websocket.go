package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type WebSocketTool struct{}

func (t *WebSocketTool) Name() string {
	return "websocket"
}

func (t *WebSocketTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}

	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		wsURL := target
		if strings.HasPrefix(target, "http://") {
			wsURL = "ws://" + strings.TrimPrefix(target, "http://")
		} else if strings.HasPrefix(target, "https://") {
			wsURL = "wss://" + strings.TrimPrefix(target, "https://")
		}

		if !strings.HasPrefix(wsURL, "ws://") && !strings.HasPrefix(wsURL, "wss://") {
			return nil, nil
		}

		parsed, err := url.Parse(wsURL)
		if err != nil {
			return nil, nil
		}

		var events []Event

		// Test 1: Missing Origin Validation (CSWSH)
		vuln, detail, checkErr := t.checkCSWSH(ctx, parsed, "http://evil.com")
		if checkErr == nil && vuln {
			events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Cross-Site WebSocket Hijacking (CSWSH)",
				"severity":    "high",
				"origin":      "http://evil.com",
				"description": fmt.Sprintf("WebSocket endpoint at %s accepted connection upgraded with an external Origin header (http://evil.com). Detail: %s", target, detail),
			}, "high"))
		}

		return events, nil
	})
}

func (t *WebSocketTool) checkCSWSH(ctx context.Context, u *url.URL, origin string) (bool, string, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	if u.Scheme == "wss" {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}

	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path = path + "?" + u.RawQuery
	}

	reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Origin: %s\r\n\r\n", path, u.Host, origin)

	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		return false, "", err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 101 {
		return true, fmt.Sprintf("Status 101 Switching Protocols. Upgrade: %s, Connection: %s", resp.Header.Get("Upgrade"), resp.Header.Get("Connection")), nil
	}

	return false, fmt.Sprintf("Status %d %s", resp.StatusCode, resp.Status), nil
}

var _ Tool = (*WebSocketTool)(nil)
