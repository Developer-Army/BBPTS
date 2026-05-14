// Package model defines core domain structures and logic for representing assets.
package model

import (
	"net"
	"strings"
)

// Asset represents a single normalized target asset.
type Asset struct {
	Target string `json:"target"`
	Type   string `json:"type"`
}

// ClassifyTarget evaluates a target string and returns its type classification
// (e.g., "ip", "host:port", "domain", or "unknown").
func ClassifyTarget(target string) string {
	if target == "" {
		return "unknown"
	}
	if net.ParseIP(target) != nil {
		return "ip"
	}
	if strings.Contains(target, ":") {
		return "host:port"
	}
	return "domain"
}
