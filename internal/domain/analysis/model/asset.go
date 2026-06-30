// Package model defines core domain structures and logic for representing assets.
package model

import (
	"net"
	"strings"
)

type Asset struct {
	Target string `json:"target"`
	Type   string `json:"type"`
}

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
