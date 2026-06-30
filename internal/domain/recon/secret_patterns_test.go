package recon

import (
	"testing"
)

func TestSecretPatterns(t *testing.T) {
	if len(SecretPatterns) == 0 {
		t.Error("SecretPatterns should not be empty")
	}

	for _, pattern := range SecretPatterns {
		if pattern.Name == "" {
			t.Error("Pattern name should not be empty")
		}
		if pattern.Severity == "" {
			t.Error("Pattern severity should not be empty")
		}
		if pattern.Pattern == nil {
			t.Error("Pattern regex should not be nil")
		}
	}
}

func TestSecretPatterns_AWS(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"AWS Access Key", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS Access Key lowercase", "akiaiosfodnn7example", true},
		{"Invalid AWS key", "AKIA123", false},
		{"Random string", "randomstring", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find AWS Access Key pattern
			var pattern *SecretPattern
			for _, p := range SecretPatterns {
				if p.Name == "AWS Access Key ID" {
					pattern = &p
					break
				}
			}
			if pattern == nil {
				t.Fatal("AWS Access Key ID pattern not found")
			}

			matched := pattern.Pattern.MatchString(tt.input)
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_GitHub(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"GitHub PAT", "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz123456", true},
		{"GitHub OAuth", "gho_" + "1234567890abcdefghijklmnopqrstuvwxyz123456", true},
		{"GitHub App", "ghu_" + "1234567890abcdefghijklmnopqrstuvwxyz123456", true},
		{"Invalid GitHub", "ghp_123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find any GitHub pattern
			var matched bool
			for _, p := range SecretPatterns {
				if p.Pattern.MatchString(tt.input) {
					matched = true
					break
				}
			}
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_Slack(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Slack Bot Token", "xoxb-" + "123456789012-" + "1234567890123-" + "abcdefghijklmnopqrstuvwxyz1234", true},
		{"Slack Webhook", "https://" + "hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX", true},
		{"Invalid Slack", "xoxb-123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched bool
			for _, p := range SecretPatterns {
				if p.Pattern.MatchString(tt.input) {
					matched = true
					break
				}
			}
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_Stripe(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Stripe Secret Key", "sk_live_" + "1234567890abcdefghijklmnopqrstuvwxyz123456", true},
		{"Stripe Publishable Key", "pk_live_" + "1234567890abcdefghijklmnopqrstuvwxyz123456", true},
		{"Invalid Stripe", "sk_live_123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched bool
			for _, p := range SecretPatterns {
				if p.Pattern.MatchString(tt.input) {
					matched = true
					break
				}
			}
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_JWT(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
		{"Invalid JWT", "not.a.jwt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pattern *SecretPattern
			for _, p := range SecretPatterns {
				if p.Name == "JSON Web Token" {
					pattern = &p
					break
				}
			}
			if pattern == nil {
				t.Fatal("JWT pattern not found")
			}

			matched := pattern.Pattern.MatchString(tt.input)
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_PrivateKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"Generic Private Key", "-----BEGIN PRIVATE KEY-----", true},
		{"EC Private Key", "-----BEGIN EC PRIVATE KEY-----", true},
		{"Not a private key", "some random text", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched bool
			for _, p := range SecretPatterns {
				if p.Pattern.MatchString(tt.input) {
					matched = true
					break
				}
			}
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_Database(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"MongoDB", "mongodb://user:pass@localhost:27017/db", true},
		{"PostgreSQL", "postgres://user:pass@localhost:5432/db", true},
		{"MySQL", "mysql://user:pass@localhost:3306/db", true},
		{"Redis", "redis://localhost:6379", true},
		{"Not a DB string", "http://acme-corp.io", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pattern *SecretPattern
			for _, p := range SecretPatterns {
				if p.Name == "Database Connection String" {
					pattern = &p
					break
				}
			}
			if pattern == nil {
				t.Fatal("Database pattern not found")
			}

			matched := pattern.Pattern.MatchString(tt.input)
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_InternalIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"10.x.x.x", "10.0.0.1", true},
		{"172.16.x.x", "172.16.0.1", true},
		{"192.168.x.x", "192.168.1.1", true},
		{"Public IP", "8.8.8.8", false},
		{"Not an IP", "not an ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pattern *SecretPattern
			for _, p := range SecretPatterns {
				if p.Name == "Internal IP Address" {
					pattern = &p
					break
				}
			}
			if pattern == nil {
				t.Fatal("Internal IP pattern not found")
			}

			matched := pattern.Pattern.MatchString(tt.input)
			if matched != tt.expected {
				t.Errorf("expected match %v, got %v for input %s", tt.expected, matched, tt.input)
			}
		})
	}
}

func TestSecretPatterns_SeverityLevels(t *testing.T) {
	severities := make(map[string]bool)
	for _, pattern := range SecretPatterns {
		severities[pattern.Severity] = true
	}

	expectedSeverities := []string{"critical", "high", "medium", "low"}
	for _, severity := range expectedSeverities {
		if !severities[severity] {
			t.Errorf("expected severity level %s not found", severity)
		}
	}
}

func TestScanForSecrets(t *testing.T) {
	content := `line1: nothing here
line2: AKIAIOSFODNN7EXAMPLE is leaked
line3: some text
line4: mongodb://user:pass@host:27017/db
line5: AKIAIOSFODNN7EXAMPLE duplicate should be skipped`

	matches := ScanForSecrets(content)

	if len(matches) < 2 {
		t.Fatalf("expected at least 2 matches, got %d", len(matches))
	}

	foundAWS := false
	foundDB := false
	for _, m := range matches {
		if m.PatternName == "AWS Access Key ID" && m.Line == 2 {
			foundAWS = true
		}
		if m.PatternName == "Database Connection String" && m.Line == 4 {
			foundDB = true
		}
	}
	if !foundAWS {
		t.Error("expected AWS Access Key ID match on line 2")
	}
	if !foundDB {
		t.Error("expected Database Connection String match on line 4")
	}

	awsCount := 0
	for _, m := range matches {
		if m.PatternName == "AWS Access Key ID" && m.Value == "AKIAIOSFODNN7EXAMPLE" {
			awsCount++
		}
	}
	if awsCount != 1 {
		t.Errorf("expected 1 deduplicated AWS key match, got %d", awsCount)
	}
}

func TestScanForSecrets_Empty(t *testing.T) {
	matches := ScanForSecrets("")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty content, got %d", len(matches))
	}
}
