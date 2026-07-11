package tools

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
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

func (t *SmugglingTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 30
	}

	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" || !strings.HasPrefix(target, "http") {
			return nil, nil
		}

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		var events []recon.Event

		isCLTE, cltePayload, clteResp, err := t.checkCLTE(ctx, parsed)
		if err == nil && isCLTE {
			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "HTTP Request Smuggling (CL.TE)",
				"severity":    "high",
				"description": fmt.Sprintf("HTTP Request Smuggling CL.TE detected via timing delay on %s.", target),
				"request":     cltePayload,
				"response":    clteResp,
			}, "high"))
		}

		isTECL, teclPayload, teclResp, err := t.checkTECL(ctx, parsed)
		if err == nil && isTECL {
			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "HTTP Request Smuggling (TE.CL)",
				"severity":    "high",
				"description": fmt.Sprintf("HTTP Request Smuggling TE.CL detected via timing delay on %s.", target),
				"request":     teclPayload,
				"response":    teclResp,
			}, "high"))
		}

		return events, nil
	})
}

func (t *SmugglingTool) sendRaw(ctx context.Context, u *url.URL, payload string, timeout time.Duration) (time.Duration, string, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
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
		return 0, "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return 0, "", err
	}

	reader := bufio.NewReader(conn)
	respBuf := make([]byte, 0, 4096)
	for len(respBuf) < 4096 {
		b, readErr := reader.ReadByte()
		if readErr != nil {
			break
		}
		respBuf = append(respBuf, b)
		if b == '\n' && len(respBuf) >= 2 {
			break
		}
	}
	duration := time.Since(start)
	respStr := string(respBuf)

	if duration < timeout {

		return duration, respStr, nil
	}
	return duration, respStr, nil
}

func (t *SmugglingTool) checkCLTE(ctx context.Context, u *url.URL) (bool, string, string, error) {

	baselinePayload := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", u.Host)
	baseline, _, err := t.sendRaw(ctx, u, baselinePayload, 8*time.Second)
	if err != nil {
		return false, "", "", err
	}

	cltePayload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: 6\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n"+
		"0\r\n\r\n", u.Host)

	delay, respStr, err := t.sendRaw(ctx, u, cltePayload, 10*time.Second)
	if err != nil {
		return false, cltePayload, "", nil
	}

	if baseline < 2*time.Second && delay >= 3*time.Second {
		return true, cltePayload, respStr, nil
	}

	return false, cltePayload, respStr, nil
}

func (t *SmugglingTool) checkTECL(ctx context.Context, u *url.URL) (bool, string, string, error) {
	baselinePayload := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", u.Host)
	baseline, _, err := t.sendRaw(ctx, u, baselinePayload, 8*time.Second)
	if err != nil {
		return false, "", "", err
	}

	teclPayload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: 4\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n"+
		"1a\r\n"+
		"X", u.Host)

	delay, respStr, err := t.sendRaw(ctx, u, teclPayload, 10*time.Second)
	if err != nil {
		return false, teclPayload, "", nil
	}

	if baseline < 2*time.Second && delay >= 3*time.Second {
		return true, teclPayload, respStr, nil
	}

	return false, teclPayload, respStr, nil
}

var _ recon.Tool = (*SmugglingTool)(nil)
