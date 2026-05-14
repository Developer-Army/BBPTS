// Package input provides utilities for reading and parsing target input files.
// It supports simple domain lists, CSV files with rich metadata, and structured formats.
package input

import (
	"bufio"
	"encoding/csv"
	"io"
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
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// parseCSVWithMetadata parses CSV with optional headers (url, scope, priority, tags, notes)
// Example format:
// url,scope,priority,tags,notes
// example.com,in,high,api;sensitive,Critical API endpoint
// api.example.com,in,medium,api,,
// staging.example.com,out,low,staging;internal,,
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

	// Check if first row is a header
	firstRow := records[0]
	headers := []string{"url", "scope", "priority", "tags", "notes"}
	isHeader := false

	for _, field := range firstRow {
		field = strings.ToLower(strings.TrimSpace(field))
		for _, header := range headers {
			if field == header {
				isHeader = true
				break
			}
		}
	}

	if isHeader {
		startRow = 1
		for i, field := range firstRow {
			headerMap[strings.ToLower(strings.TrimSpace(field))] = i
		}
	}

	for i := startRow; i < len(records); i++ {
		record := records[i]
		if len(record) == 0 {
			continue
		}

		if !isHeader {
			for _, field := range record {
				url := strings.TrimSpace(field)
				if url == "" || strings.HasPrefix(url, "#") {
					continue
				}
				targets = append(targets, Target{
					URL:      url,
					Scope:    "in",
					Priority: "medium",
				})
			}
			continue
		}

		url := strings.TrimSpace(record[0])
		if url == "" || strings.HasPrefix(url, "#") {
			continue
		}

		target := Target{URL: url, Scope: "in", Priority: "medium"}

		// Parse optional metadata if headers exist
		if isHeader {
			if idx, ok := headerMap["scope"]; ok && idx < len(record) {
				target.Scope = strings.ToLower(strings.TrimSpace(record[idx]))
			}
			if idx, ok := headerMap["priority"]; ok && idx < len(record) {
				target.Priority = strings.ToLower(strings.TrimSpace(record[idx]))
			}
			if idx, ok := headerMap["tags"]; ok && idx < len(record) {
				tagStr := strings.TrimSpace(record[idx])
				if tagStr != "" {
					target.Tags = strings.Split(tagStr, ";")
					for j, tag := range target.Tags {
						target.Tags[j] = strings.TrimSpace(tag)
					}
				}
			}
			if idx, ok := headerMap["notes"]; ok && idx < len(record) {
				target.Notes = strings.TrimSpace(record[idx])
			}
		}

		targets = append(targets, target)
	}

	return targets, nil
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
