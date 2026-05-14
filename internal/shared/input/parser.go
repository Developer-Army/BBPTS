// Package input provides utilities for reading and parsing target input files.
// It supports simple domain lists, CSV files with rich metadata, and structured formats.
package input

import (
	"bufio"
	"encoding/csv"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Target represents an enriched target with optional metadata
type Target struct {
	URL      string   // The target domain/URL
	Scope    string   // Scope level: "in", "out", or "private"
	Priority string   // Priority: "critical", "high", "medium", "low"
	Tags     []string // Custom tags for organizing targets
	Notes    string   // Additional notes
}

// IsInScope reports whether the target should be included in active scanning.
// Only explicit out-of-scope markers are excluded.
func (t Target) IsInScope() bool {
	switch strings.ToLower(strings.TrimSpace(t.Scope)) {
	case "out", "oos", "out-of-scope", "outscope", "exclude", "excluded":
		return false
	default:
		return true
	}
}

// validateURL checks if a URL is safe for scanning (prevents SSRF).
// Allows only http/https schemes, no localhost/private IPs.
func validateURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	// Check for localhost/loopback
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}
	// Check private IPs
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

// Parser handles reading and parsing input files containing bug bounty targets.
type Parser struct{}

// NewParser creates a new instance of a Parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseFile reads an input file (e.g., CSV or newline-separated domains) and
// returns a slice of target strings. It automatically detects the file type
// based on the extension.
//
// Supported formats:
// - Simple list: one domain per line
// - CSV with headers: url,scope,priority,tags,notes
// - CSV without headers: treated as simple domains
func (p *Parser) ParseFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".csv":
		return p.parseCSV(file)
	default:
		return p.parseLines(file)
	}
}

// ParseFileWithMetadata reads an input file and returns targets with metadata.
// This provides richer information than ParseFile.
func (p *Parser) ParseFileWithMetadata(path string) ([]Target, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".csv":
		return p.parseCSVWithMetadata(file)
	default:
		return p.parseLinesToTargets(file)
	}
}

func (p *Parser) parseCSV(r io.Reader) ([]string, error) {
	targets, err := p.parseCSVWithMetadata(r)
	if err != nil {
		return nil, err
	}

	flat := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.URL == "" {
			continue
		}
		flat = append(flat, target.URL)
	}
	return flat, nil
}

func (p *Parser) parseLines(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	targets := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !validateURL(line) {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// parseCSVWithMetadata parses CSV with optional headers
// Supports generic headers and bug bounty platform specific headers (HackerOne, Bugcrowd, etc)
func (p *Parser) parseCSVWithMetadata(r io.Reader) ([]Target, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return []Target{}, nil
	}

	targets := []Target{}
	headerMap := make(map[string]int)
	startRow := 0

	// Common bug bounty platform headers
	targetHeaders := []string{"url", "target", "identifier", "asset_identifier", "endpoint", "domain", "asset identifier"}
	scopeHeaders := []string{"scope", "eligible_for_submission", "eligible_for_bounty", "in_scope", "eligible"}

	firstRow := records[0]
	isHeader := false

	for i, field := range firstRow {
		cleanField := strings.ToLower(strings.TrimSpace(field))

		// Check for target/URL column
		for _, th := range targetHeaders {
			if cleanField == th {
				headerMap["url"] = i
				isHeader = true
				break
			}
		}

		// Check for scope/eligibility columns
		for _, sh := range scopeHeaders {
			if cleanField == sh {
				headerMap[cleanField] = i
				isHeader = true
				break
			}
		}

		// Other metadata
		if cleanField == "priority" || cleanField == "severity" || cleanField == "max_severity" {
			headerMap["priority"] = i
			isHeader = true
		}
		if cleanField == "tags" || cleanField == "asset_type" || cleanField == "type" {
			headerMap["tags"] = i
			isHeader = true
		}
		if cleanField == "notes" || cleanField == "instruction" {
			headerMap["notes"] = i
			isHeader = true
		}
	}

	if isHeader {
		startRow = 1
	}

	for i := startRow; i < len(records); i++ {
		record := records[i]
		if len(record) == 0 {
			continue
		}

		if isHeader {
			var url string
			if idx, ok := headerMap["url"]; ok && idx < len(record) {
				url = strings.TrimSpace(record[idx])
			}

			if url == "" || strings.HasPrefix(url, "#") {
				continue
			}

			if !validateURL(url) {
				continue
			}

			target := Target{URL: url, Scope: "in", Priority: "medium"}

			if !rowIsEligible(record, headerMap) {
				target.Scope = "out"
			}
			if idx, ok := headerMap["priority"]; ok && idx < len(record) {
				target.Priority = strings.ToLower(strings.TrimSpace(record[idx]))
			}
			if idx, ok := headerMap["tags"]; ok && idx < len(record) {
				tagStr := strings.TrimSpace(record[idx])
				if tagStr != "" {
					target.Tags = strings.Split(tagStr, ";")
					// Clean up tags
					for j := range target.Tags {
						target.Tags[j] = strings.TrimSpace(target.Tags[j])
					}
				}
			}
			if idx, ok := headerMap["notes"]; ok && idx < len(record) {
				target.Notes = strings.TrimSpace(record[idx])
			}

			targets = append(targets, target)
		} else {
			// If no headers, treat each field as a separate target
			for _, field := range record {
				url := strings.TrimSpace(field)
				if url == "" || strings.HasPrefix(url, "#") {
					continue
				}
				if !validateURL(url) {
					continue
				}
				targets = append(targets, Target{
					URL:      url,
					Scope:    "in",
					Priority: "medium",
				})
			}
		}
	}

	return targets, nil
}

func rowIsEligible(record []string, headerMap map[string]int) bool {
	// Explicit scope markers
	if idx, ok := headerMap["scope"]; ok && idx < len(record) {
		if isNegativeScopeValue(record[idx]) {
			return false
		}
	}

	// Any explicit "false/no/0/out" in these platform fields means out-of-scope.
	for _, key := range []string{"eligible_for_submission", "eligible_for_bounty", "in_scope", "eligible"} {
		idx, ok := headerMap[key]
		if !ok || idx >= len(record) {
			continue
		}
		if isNegativeScopeValue(record[idx]) {
			return false
		}
	}

	return true
}

func isNegativeScopeValue(v string) bool {
	val := strings.ToLower(strings.TrimSpace(v))
	switch val {
	case "false", "no", "0", "out", "oos", "out-of-scope", "outscope", "exclude", "excluded", "not eligible":
		return true
	default:
		return false
	}
}

// parseLinesToTargets converts simple newline-separated list to Target objects
func (p *Parser) parseLinesToTargets(r io.Reader) ([]Target, error) {
	scanner := bufio.NewScanner(r)
	targets := []Target{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !validateURL(line) {
			continue // Skip invalid URLs
		}
		targets = append(targets, Target{
			URL:      line,
			Scope:    "in",
			Priority: "medium",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}
