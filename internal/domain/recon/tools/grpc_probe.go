package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

type GRPCProbeTool struct{}

func (t *GRPCProbeTool) Name() string {
	return "grpc_probe"
}

func (t *GRPCProbeTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 20
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		var host string
		var port int
		var isHTTP bool

		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			isHTTP = true
			parsed, err := url.Parse(target)
			if err == nil {
				host = parsed.Hostname()
				pStr := parsed.Port()
				if pStr != "" {
					port, _ = strconv.Atoi(pStr)
				} else {
					if parsed.Scheme == "https" {
						port = 443
					} else {
						port = 80
					}
				}
			} else {
				return nil, nil
			}
		} else {
			h, pStr, err := net.SplitHostPort(target)
			if err == nil {
				host = h
				port, _ = strconv.Atoi(pStr)
			} else {
				host = target
				port = 50051 // default gRPC port
			}
		}

		var events []recon.Event

		// If it's a raw host:port scan (like port 50051 or 50052), probe it directly.
		// If it's a standard HTTP target, we only scan if we have reason to believe it supports gRPC.
		// But let's check both HTTP and HTTPS modes on the target port
		protocols := []string{"http", "https"}
		if isHTTP {
			if strings.HasPrefix(target, "https://") {
				protocols = []string{"https"}
			} else {
				protocols = []string{"http"}
			}
		}

		for _, proto := range protocols {
			tCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			isGRPC, hasReflection, err := t.probeGRPC(tCtx, proto, host, port)
			cancel()

			if isGRPC {
				// Emit a discovery event
				events = append(events, recon.NewEvent(fmt.Sprintf("%s:%d", host, port), t.Name(), "discovery", map[string]string{
					"type":       "grpc_service",
					"protocol":   proto,
					"reflection": fmt.Sprintf("%t", hasReflection),
				}))

				if hasReflection {
					events = append(events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "gRPC Server Reflection Enabled",
						"severity":    "medium",
						"protocol":    proto,
						"description": fmt.Sprintf("gRPC service at %s:%d has Server Reflection enabled. Attackers can map out the entire API schema.", host, port),
					}, "medium"))
				}
				break // Found a valid service, skip other protocol attempts
			}
			_ = err
		}

		return events, nil
	})
}

func (t *GRPCProbeTool) probeGRPC(ctx context.Context, scheme, host string, port int) (bool, bool, error) {
	// Build HTTP/2 client
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}
	// Force HTTP/2
	_ = http2.ConfigureTransport(transport)

	client := &http.Client{
		Transport: transport,
		Timeout:   4 * time.Second,
	}

	// We probe Server Reflection method ServerReflectionInfo
	reflectionPath := "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
	targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, reflectionPath)

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(""))
	if err != nil {
		return false, false, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()

	// In gRPC, headers or trailers contain "grpc-status"
	grpcStatusHeader := resp.Header.Get("grpc-status")
	grpcStatusTrailer := resp.Trailer.Get("grpc-status")
	contentType := resp.Header.Get("Content-Type")

	isGRPC := strings.Contains(contentType, "application/grpc") || grpcStatusHeader != "" || grpcStatusTrailer != ""
	hasReflection := false

	if isGRPC {
		// If grpc-status is NOT 12 (UNIMPLEMENTED), reflection might be enabled.
		// Standard code 12 means the ServerReflection method was not found on this server.
		// Code 3 (INVALID_ARGUMENT) or other codes mean reflection is registered but our empty body was invalid.
		statusCode := grpcStatusHeader
		if statusCode == "" {
			statusCode = grpcStatusTrailer
		}
		if statusCode != "" && statusCode != "12" {
			hasReflection = true
		}
	}

	return isGRPC, hasReflection, nil
}

var _ recon.Tool = (*GRPCProbeTool)(nil)
