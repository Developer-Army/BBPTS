package tools

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestEmailEnumToolName(t *testing.T) {
	tool := &EmailEnumTool{}
	if tool.Name() != "email_enum" {
		t.Errorf("expected tool name 'email_enum', got %q", tool.Name())
	}
}

func TestInferUsernamePatterns(t *testing.T) {
	tests := []struct {
		name     string
		pairs    []namePair
		domain   string
		wantLen  int
		wantTop  string
		wantConf float64
	}{
		{
			name: "first.last pattern",
			pairs: []namePair{
				{first: "john", last: "doe", email: "john.doe@example.com"},
				{first: "jane", last: "smith", email: "jane.smith@example.com"},
				{first: "bob", last: "jones", email: "bob.jones@example.com"},
			},
			domain:   "example.com",
			wantLen:  1,
			wantTop:  "first.last",
			wantConf: 1.0,
		},
		{
			name: "flast pattern",
			pairs: []namePair{
				{first: "john", last: "doe", email: "jdoe@corp.io"},
				{first: "jane", last: "smith", email: "jsmith@corp.io"},
				{first: "bob", last: "jones", email: "bjones@corp.io"},
			},
			domain:   "corp.io",
			wantLen:  1,
			wantTop:  "flast",
			wantConf: 1.0,
		},
		{
			name: "firstl pattern",
			pairs: []namePair{
				{first: "john", last: "doe", email: "johnd@test.com"},
				{first: "jane", last: "smith", email: "janes@test.com"},
			},
			domain:   "test.com",
			wantLen:  1,
			wantTop:  "firstl",
			wantConf: 1.0,
		},
		{
			name: "first_last pattern",
			pairs: []namePair{
				{first: "alice", last: "wonder", email: "alice_wonder@dev.io"},
				{first: "bob", last: "builder", email: "bob_builder@dev.io"},
				{first: "eve", last: "hacker", email: "eve_hacker@dev.io"},
			},
			domain:   "dev.io",
			wantLen:  1,
			wantTop:  "first_last",
			wantConf: 1.0,
		},
		{
			name: "mixed patterns - returns multiple",
			pairs: []namePair{
				{first: "john", last: "doe", email: "john.doe@mix.com"},
				{first: "jane", last: "smith", email: "jsmith@mix.com"},
				{first: "bob", last: "jones", email: "bob.jones@mix.com"},
				{first: "alice", last: "wonder", email: "alice.wonder@mix.com"},
				{first: "eve", last: "hacker", email: "ehacker@mix.com"},
			},
			domain:   "mix.com",
			wantLen:  2, // first.last (60%) and flast (40%)
			wantTop:  "first.last",
			wantConf: 0.6,
		},
		{
			name:    "single pair - insufficient data",
			pairs:   []namePair{{first: "john", last: "doe", email: "john.doe@solo.com"}},
			domain:  "solo.com",
			wantLen: 0,
		},
		{
			name:    "empty pairs",
			pairs:   nil,
			domain:  "empty.com",
			wantLen: 0,
		},
		{
			name: "wrong domain suffix - no matches",
			pairs: []namePair{
				{first: "john", last: "doe", email: "john.doe@other.com"},
				{first: "jane", last: "smith", email: "jane.smith@other.com"},
			},
			domain:  "target.com",
			wantLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patterns := inferUsernamePatterns(tc.pairs, tc.domain)

			if len(patterns) != tc.wantLen {
				t.Errorf("expected %d patterns, got %d: %+v", tc.wantLen, len(patterns), patterns)
				return
			}

			if tc.wantLen > 0 {
				top := patterns[0]
				if top.Format != tc.wantTop {
					t.Errorf("expected top pattern %q, got %q", tc.wantTop, top.Format)
				}
				if fmt.Sprintf("%.1f", top.Confidence) != fmt.Sprintf("%.1f", tc.wantConf) {
					t.Errorf("expected confidence %.1f, got %.1f", tc.wantConf, top.Confidence)
				}
			}
		})
	}
}

func TestInferUsernamePatterns_LastFirst(t *testing.T) {
	pairs := []namePair{
		{first: "john", last: "doe", email: "doe.john@rev.com"},
		{first: "jane", last: "smith", email: "smith.jane@rev.com"},
		{first: "bob", last: "jones", email: "jones.bob@rev.com"},
	}
	patterns := inferUsernamePatterns(pairs, "rev.com")
	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern")
	}
	if patterns[0].Format != "last.first" {
		t.Errorf("expected last.first, got %q", patterns[0].Format)
	}
}

func TestInferUsernamePatterns_FirstOnly(t *testing.T) {
	pairs := []namePair{
		{first: "john", last: "doe", email: "john@simple.com"},
		{first: "jane", last: "smith", email: "jane@simple.com"},
		{first: "bob", last: "jones", email: "bob@simple.com"},
	}
	patterns := inferUsernamePatterns(pairs, "simple.com")
	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern")
	}
	if patterns[0].Format != "first" {
		t.Errorf("expected first, got %q", patterns[0].Format)
	}
}

func TestPatternGenerators(t *testing.T) {
	tests := []struct {
		format string
		first  string
		last   string
		want   string
	}{
		{"first.last", "john", "doe", "john.doe"},
		{"flast", "john", "doe", "jdoe"},
		{"firstl", "john", "doe", "johnd"},
		{"first_last", "john", "doe", "john_doe"},
		{"first", "john", "doe", "john"},
		{"last.first", "john", "doe", "doe.john"},
		{"lastf", "john", "doe", "doej"},
		{"lfirst", "john", "doe", "djohn"},
		{"first-last", "john", "doe", "john-doe"},
	}

	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			gen, ok := patternGenerators[tc.format]
			if !ok {
				t.Fatalf("pattern generator %q not found", tc.format)
			}
			got := gen(tc.first, tc.last)
			if got != tc.want {
				t.Errorf("%s(%q, %q) = %q, want %q", tc.format, tc.first, tc.last, got, tc.want)
			}
		})
	}
}

func TestHunterResponseParsing(t *testing.T) {
	// Verify struct tags parse correctly with sample JSON
	jsonData := `{
		"data": {
			"domain": "example.com",
			"organization": "Example Inc",
			"pattern": "{first}.{last}",
			"emails": [
				{
					"value": "john.doe@example.com",
					"type": "personal",
					"confidence": 95,
					"first_name": "John",
					"last_name": "Doe",
					"position": "CTO",
					"department": "engineering",
					"linkedin": "https://linkedin.com/in/johndoe",
					"sources": [
						{"domain": "example.com", "uri": "https://example.com/team"}
					]
				}
			]
		},
		"meta": {"results": 1, "limit": 100, "offset": 0}
	}`

	var resp hunterDomainSearchResponse
	if err := parseJSON([]byte(jsonData), &resp); err != nil {
		t.Fatalf("failed to parse hunter response: %v", err)
	}

	if resp.Data.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", resp.Data.Domain)
	}
	if resp.Data.Organization != "Example Inc" {
		t.Errorf("organization = %q, want Example Inc", resp.Data.Organization)
	}
	if resp.Data.Pattern != "{first}.{last}" {
		t.Errorf("pattern = %q, want {first}.{last}", resp.Data.Pattern)
	}
	if len(resp.Data.Emails) != 1 {
		t.Fatalf("expected 1 email, got %d", len(resp.Data.Emails))
	}

	email := resp.Data.Emails[0]
	if email.Value != "john.doe@example.com" {
		t.Errorf("email = %q", email.Value)
	}
	if email.Confidence != 95 {
		t.Errorf("confidence = %d, want 95", email.Confidence)
	}
	if email.FirstName != "John" {
		t.Errorf("first_name = %q", email.FirstName)
	}
	if email.Position != "CTO" {
		t.Errorf("position = %q", email.Position)
	}
	if email.Department != "engineering" {
		t.Errorf("department = %q", email.Department)
	}
	if len(email.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(email.Sources))
	}
}

func TestEmailEnumDeduplication(t *testing.T) {
	seen := make(map[dedupeKey]struct{})

	k1 := dedupeKey{target: "example.com", eventType: "email_found", value: "john@example.com"}
	k2 := dedupeKey{target: "example.com", eventType: "email_found", value: "john@example.com"}
	k3 := dedupeKey{target: "example.com", eventType: "email_pattern", value: "first.last"}

	seen[k1] = struct{}{}

	if _, dup := seen[k2]; !dup {
		t.Error("expected k2 to be detected as duplicate of k1")
	}
	if _, dup := seen[k3]; dup {
		t.Error("k3 should not be a duplicate")
	}
}

// parseJSON is a test helper to parse JSON bytes.
func parseJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
