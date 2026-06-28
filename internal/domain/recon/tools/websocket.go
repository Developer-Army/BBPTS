package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
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

func (t *WebSocketTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}

	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
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

		var events []recon.Event

		// Test 1: Missing Origin Validation (CSWSH)
		vuln, detail, checkErr := t.checkCSWSH(ctx, parsed, "http://evil.com")
		if checkErr == nil && vuln {
			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Cross-Site WebSocket Hijacking (CSWSH)",
				"severity":    "high",
				"origin":      "http://evil.com",
				"description": fmt.Sprintf("WebSocket endpoint at %s accepted connection upgraded with an external Origin header (http://evil.com). Detail: %s", target, detail),
			}, "high"))
		}

		// Test 2: Unauthenticated message injection to privileged channel.
		injected, detail, checkErr := t.checkUnauthenticatedAdminSubscribe(ctx, parsed)
		if checkErr == nil && injected {
			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Unauthenticated WebSocket Message Injection",
				"severity":    "high",
				"payload":     `{"action":"subscribe","channel":"admin"}`,
				"description": fmt.Sprintf("WebSocket endpoint at %s returned data after an unauthenticated admin channel subscription. Detail: %s", target, detail),
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

func (t *WebSocketTool) checkUnauthenticatedAdminSubscribe(ctx context.Context, u *url.URL) (bool, string, error) {
	conn, reader, err := t.openWebSocket(ctx, u, "")
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	payload := `{"action":"subscribe","channel":"admin"}`
	if err := writeWebSocketTextFrame(conn, payload); err != nil {
		return false, "", err
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respPayload, err := readWebSocketFrame(reader)
	if err != nil {
		return false, "", nil
	}
	body := strings.ToLower(string(respPayload))
	if strings.Contains(body, "unauthoriz") || strings.Contains(body, "forbidden") || strings.Contains(body, "denied") || strings.Contains(body, "auth") {
		return false, truncateStr(string(respPayload), 200), nil
	}
	for _, marker := range []string{"admin", "data", "event", "message", "success", "subscribed"} {
		if strings.Contains(body, marker) {
			return true, truncateStr(string(respPayload), 200), nil
		}
	}
	return false, truncateStr(string(respPayload), 200), nil
}

func (t *WebSocketTool) openWebSocket(ctx context.Context, u *url.URL, origin string) (net.Conn, *bufio.Reader, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	var err error
	if u.Scheme == "wss" {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, nil, err
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path = path + "?" + u.RawQuery
	}
	headers := ""
	if origin != "" {
		headers = "Origin: " + origin + "\r\n"
	}
	reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n%s\r\n", path, u.Host, headers)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, nil, fmt.Errorf("websocket upgrade rejected: %s", resp.Status)
	}
	return conn, reader, nil
}

func writeWebSocketTextFrame(w io.Writer, payload string) error {
	data := []byte(payload)
	frame := []byte{0x81}
	maskKey := []byte{0x13, 0x37, 0x42, 0x99}
	if len(data) < 126 {
		frame = append(frame, byte(0x80|len(data)))
	} else {
		frame = append(frame, 0x80|126, byte(len(data)>>8), byte(len(data)))
	}
	frame = append(frame, maskKey...)
	for i, b := range data {
		frame = append(frame, b^maskKey[i%4])
	}
	_, err := w.Write(frame)
	return err
}

func readWebSocketFrame(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(header[1] & 0x7f)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		if ext[0] != 0 || ext[1] != 0 || ext[2] != 0 || ext[3] != 0 {
			return nil, fmt.Errorf("websocket frame too large")
		}
		length = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}
	if header[1]&0x80 != 0 {
		mask := make([]byte, 4)
		if _, err := io.ReadFull(r, mask); err != nil {
			return nil, err
		}
	}
	if length > 64*1024 {
		return nil, fmt.Errorf("websocket frame too large")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

var _ recon.Tool = (*WebSocketTool)(nil)
