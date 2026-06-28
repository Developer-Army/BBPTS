package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
	"github.com/Developer-Army/BBPTS/internal/domain/security"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
)

type Tool = recon.Tool
type Event = recon.Event

func NewEvent(target, source, eventType string, properties map[string]string) Event {
	return recon.NewEvent(target, source, eventType, properties)
}

func NewEventWithSeverity(target, source, eventType string, properties map[string]string, severity string) Event {
	return recon.NewEventWithSeverity(target, source, eventType, properties, severity)
}

func ParseOutputLines(output []byte) []string {
	return recon.ParseOutputLines(output)
}


func RunCommandLines(ctx context.Context, name string, args ...string) ([]string, error) {
	return tools.RunCommandStream(ctx, name, args...)
}

func RunCommandWithInputLines(ctx context.Context, stdin []byte, name string, args ...string) ([]string, error) {
	return tools.RunCommandStreamWithInput(ctx, stdin, name, args...)
}

// NewEventsFromLines converts a list of targets (one per line) into a slice of
// Event records with the specified source and shared metadata.
func NewEventsFromLines(lines []string, source string, metadata map[string]string) []Event {
	return NewEventsFromLinesFunc(lines, source, func(line string) map[string]string {
		if len(metadata) == 0 {
			return nil
		}
		copy := make(map[string]string, len(metadata))
		for k, v := range metadata {
			copy[k] = v
		}
		return copy
	})
}

// NewEventsFromLinesFunc converts a list of targets into a slice of Event records,
// using a generator function to produce properties for each line.
func NewEventsFromLinesFunc(lines []string, source string, metadataFunc func(string) map[string]string) []Event {
	if metadataFunc == nil {
		metadataFunc = func(string) map[string]string { return nil }
	}

	// Pre-allocate with initial capacity to reduce allocations
	events := make([]Event, 0, len(lines))

	// Ensure we don't process duplicate events internally
	seen := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip ASCII art / banners (heuristic: high density of box-drawing or art characters)
		if !strings.Contains(line, "://") {
			if strings.Count(line, "/")+strings.Count(line, "_")+strings.Count(line, "\\")+strings.Count(line, "|") > 5 {
				continue
			}
		}

		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}

		properties := metadataFunc(line)
		events = append(events, NewEvent(line, source, "discovery", properties))
	}
	return events
}



// NewSafeHTTPClient returns an http.Client with built-in SSRF protection.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				pinnedAddr, _, err := security.ResolveAndValidateAddr(ctx, addr)
				if err != nil {
					return nil, err
				}
				h, _, err := net.SplitHostPort(pinnedAddr)
				if err == nil {
					if addrVal, err := netip.ParseAddr(h); err == nil && security.IsPrivateAddr(addrVal) {
						return nil, fmt.Errorf("SSRF prevention: private IP blocked: %s", h)
					}
				}
				dialer := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, pinnedAddr)
			},
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			san := security.NewSanitizer()
			if err := san.ValidateURL(req.URL.String()); err != nil {
				return fmt.Errorf("SSRF validation blocked redirect: %w", err)
			}
			return nil
		},
	}
}

// NewSafeRateLimitedClient returns a client wrapper that has both SSRF protection and Adaptive Backoff.
func NewSafeRateLimitedClient(timeout time.Duration, baseDelayMs, maxDelayMs int) *network.RateLimiter {
	client := NewSafeHTTPClient(timeout)
	return network.NewRateLimiter(client, baseDelayMs, maxDelayMs)
}

