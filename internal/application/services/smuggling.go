package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type SmugglingTool struct{}

func (t *SmugglingTool) Name() string {
	return "smuggling"
}

func (t *SmugglingTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 30
	}

	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]Event, error) {
		target = strings.TrimSpace(target)
		if target == "" || !strings.HasPrefix(target, "http") {
			return nil, nil
		}

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		var events []Event

		// Test 1: CL.TE Timing Check
		isCLTE, err := t.checkCLTE(ctx, parsed)
		if err == nil && isCLTE {
			events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "HTTP Request Smuggling (CL.TE)",
				"severity":    "high",
				"description": fmt.Sprintf("HTTP Request Smuggling CL.TE detected via timing delay on %s.", target),
			}, "high"))
		}

		// Test 2: TE.CL Timing Check
		isTECL, err := t.checkTECL(ctx, parsed)
		if err == nil && isTECL {
			events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "HTTP Request Smuggling (TE.CL)",
				"severity":    "high",
				"description": fmt.Sprintf("HTTP Request Smuggling TE.CL detected via timing delay on %s.", target),
			}, "high"))
		}

		return events, nil
	})
}

func (t *SmugglingTool) sendRaw(ctx context.Context, u *url.URL, payload string, timeout time.Duration) (time.Duration, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}

	if err != nil {
		return 0, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return 0, err
	}

	// Wait for response status line
	reader := bufio.NewReader(conn)
	_, readErr := reader.ReadString('\n')
	duration := time.Since(start)

	if readErr != nil {
		// If read timed out, return the duration of timeout
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			return duration, nil
		}
		return 0, readErr
	}

	return duration, nil
}

func (t *SmugglingTool) checkCLTE(ctx context.Context, u *url.URL) (bool, error) {
	// First establish a baseline response time
	baselinePayload := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", u.Host)
	baseline, err := t.sendRaw(ctx, u, baselinePayload, 8*time.Second)
	if err != nil {
		return false, err
	}

	// CL.TE Smuggling timing check
	// Content-Length specifies 6 bytes, but we send chunked end "0\r\n\r\n" which is 5 bytes.
	// The back-end server using Content-Length waits for the 6th byte, causing a timeout/delay.
	cltePayload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: 6\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n"+
		"0\r\n\r\n", u.Host)

	delay, err := t.sendRaw(ctx, u, cltePayload, 10*time.Second)
	if err != nil {
		return false, nil // assume non-vulnerable or connection error on malformed
	}

	// If baseline was fast but smuggling probe delayed by more than 2 seconds
	if baseline < 2*time.Second && delay >= 3*time.Second {
		return true, nil
	}

	return false, nil
}

func (t *SmugglingTool) checkTECL(ctx context.Context, u *url.URL) (bool, error) {
	baselinePayload := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", u.Host)
	baseline, err := t.sendRaw(ctx, u, baselinePayload, 8*time.Second)
	if err != nil {
		return false, err
	}

	// TE.CL Smuggling timing check
	// Content-Length is 4 bytes (forwards "1a\r\n").
	// Back-end server parses "1a" chunk and waits for 26 bytes of data. Timeout occurs.
	teclPayload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: 4\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n"+
		"1a\r\n"+
		"X", u.Host)

	delay, err := t.sendRaw(ctx, u, teclPayload, 10*time.Second)
	if err != nil {
		return false, nil
	}

	if baseline < 2*time.Second && delay >= 3*time.Second {
		return true, nil
	}

	return false, nil
}

var _ Tool = (*SmugglingTool)(nil)
