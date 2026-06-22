package security

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	oldLookupIP := lookupIP
	lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "acme-corp.io" {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		return oldLookupIP(ctx, host)
	}

	code := m.Run()
	lookupIP = oldLookupIP
	os.Exit(code)
}

func TestNewSanitizer(t *testing.T) {
	s := NewSanitizer()

	if s == nil {
		t.Fatal("NewSanitizer returned nil")
	}

	if s.fleetNamePattern == nil {
		t.Error("Expected fleetNamePattern to be initialized")
	}

	if s.toolNamePattern == nil {
		t.Error("Expected toolNamePattern to be initialized")
	}

	if s.filePathPattern == nil {
		t.Error("Expected filePathPattern to be initialized")
	}

	if s.urlPattern == nil {
		t.Error("Expected urlPattern to be initialized")
	}
}

func TestValidateFleetName(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid fleet name",
			input:   "my-fleet-1",
			wantErr: false,
		},
		{
			name:    "valid with underscore",
			input:   "my_fleet_2",
			wantErr: false,
		},
		{
			name:    "valid alphanumeric",
			input:   "Fleet123",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "a-very-long-fleet-name-that-exceeds-the-maximum-allowed-length-of-sixty-four-characters",
			wantErr: true,
		},
		{
			name:    "with shell metacharacter",
			input:   "fleet;name",
			wantErr: true,
		},
		{
			name:    "with space",
			input:   "fleet name",
			wantErr: true,
		},
		{
			name:    "with pipe",
			input:   "fleet|name",
			wantErr: true,
		},
		{
			name:    "with special chars",
			input:   "fleet@name",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidateFleetName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFleetName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateToolName(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid tool name",
			input:   "subfinder",
			wantErr: false,
		},
		{
			name:    "valid with hyphen",
			input:   "naabu-v2",
			wantErr: false,
		},
		{
			name:    "valid lowercase",
			input:   "nuclei",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "uppercase not allowed",
			input:   "Subfinder",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "a-very-long-tool-name-that-exceeds-the-maximum-allowed-length-of-thirty-two-chars",
			wantErr: true,
		},
		{
			name:    "with underscore",
			input:   "tool_name",
			wantErr: true,
		},
		{
			name:    "with shell metacharacter",
			input:   "tool;name",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidateToolName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToolName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid file path",
			input:   "/path/to/file.txt",
			wantErr: false,
		},
		{
			name:    "valid relative path",
			input:   "path/to/file.txt",
			wantErr: false,
		},
		{
			name:    "valid with underscore",
			input:   "/path/to/my_file.txt",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "directory traversal",
			input:   "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "simple traversal",
			input:   "../file.txt",
			wantErr: true,
		},
		{
			name:    "with shell metacharacter",
			input:   "/path/;rm -rf",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   string(make([]byte, 300)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidateFilePath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid https URL",
			input:   "https://acme-corp.io",
			wantErr: false,
		},
		{
			name:    "valid http URL",
			input:   "http://acme-corp.io",
			wantErr: false,
		},
		{
			name:    "valid URL with path",
			input:   "https://acme-corp.io/path/to/resource",
			wantErr: false,
		},
		{
			name:    "valid URL with query",
			input:   "https://acme-corp.io?param=value",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "no scheme",
			input:   "acme-corp.io",
			wantErr: true,
		},
		{
			name:    "localhost",
			input:   "http://localhost",
			wantErr: true,
		},
		{
			name:    "127.0.0.1",
			input:   "http://127.0.0.1",
			wantErr: true,
		},
		{
			name:    "192.168.1.1",
			input:   "http://192.168.1.1",
			wantErr: true,
		},
		{
			name:    "10.0.0.1",
			input:   "http://10.0.0.1",
			wantErr: true,
		},
		{
			name:    "169.254.1.1",
			input:   "http://169.254.1.1",
			wantErr: true,
		},
		{
			name:    "with shell metacharacter",
			input:   "https://acme-corp.io;rm -rf",
			wantErr: true,
		},
		{
			name:    "file:// protocol",
			input:   "file:///etc/passwd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidateURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeShellArg(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean arg",
			input:    "clean-arg",
			expected: "clean-arg",
		},
		{
			name:     "with semicolon",
			input:    "arg;value",
			expected: "argvalue",
		},
		{
			name:     "with pipe",
			input:    "arg|value",
			expected: "argvalue",
		},
		{
			name:     "with ampersand",
			input:    "arg&value",
			expected: "argvalue",
		},
		{
			name:     "with backtick",
			input:    "arg`value",
			expected: "argvalue",
		},
		{
			name:     "with dollar sign",
			input:    "arg$value",
			expected: "argvalue",
		},
		{
			name:     "with parentheses",
			input:    "arg(value)",
			expected: "argvalue",
		},
		{
			name:     "with space",
			input:    "arg value",
			expected: "argvalue",
		},
		{
			name:     "with multiple metachars",
			input:    "arg;|&`$()",
			expected: "arg",
		},
		{
			name:     "with newline",
			input:    "arg\nvalue",
			expected: "argvalue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeShellArg(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeShellArg() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidateInteger(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name    string
		value   int
		min     int
		max     int
		wantErr bool
	}{
		{
			name:    "valid in range",
			value:   50,
			min:     0,
			max:     100,
			wantErr: false,
		},
		{
			name:    "at minimum",
			value:   0,
			min:     0,
			max:     100,
			wantErr: false,
		},
		{
			name:    "at maximum",
			value:   100,
			min:     0,
			max:     100,
			wantErr: false,
		},
		{
			name:    "below minimum",
			value:   -1,
			min:     0,
			max:     100,
			wantErr: true,
		},
		{
			name:    "above maximum",
			value:   101,
			min:     0,
			max:     100,
			wantErr: true,
		},
		{
			name:    "negative range valid",
			value:   -50,
			min:     -100,
			max:     0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidateInteger(tt.value, tt.min, tt.max)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInteger() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCommandArgs(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid args",
			args:    []string{"arg1", "arg2", "arg3"},
			wantErr: false,
		},
		{
			name:    "empty args allowed",
			args:    []string{"", "arg2"},
			wantErr: false,
		},
		{
			name:    "with semicolon",
			args:    []string{"arg1;rm", "arg2"},
			wantErr: true,
		},
		{
			name:    "with pipe",
			args:    []string{"arg1", "arg2|cat"},
			wantErr: true,
		},
		{
			name:    "with ampersand",
			args:    []string{"arg1", "arg2&&echo"},
			wantErr: true,
		},
		{
			name:    "with command chaining",
			args:    []string{"arg1", "arg2;echo test"},
			wantErr: true,
		},
		{
			name:    "with command substitution",
			args:    []string{"arg1", "$(whoami)"},
			wantErr: true,
		},
		{
			name:    "with backtick",
			args:    []string{"arg1", "`whoami`"},
			wantErr: true,
		},
		{
			name:    "with dollar paren",
			args:    []string{"arg1", "$(/bin/sh)"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidateCommandArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommandArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSafeString(t *testing.T) {
	s := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "short string",
			input:    "short",
			maxLen:   100,
			expected: "short",
		},
		{
			name:     "exact length",
			input:    "exactly",
			maxLen:   7,
			expected: "exactly",
		},
		{
			name:     "too long",
			input:    "this is a very long string",
			maxLen:   10,
			expected: "this is a...",
		},
		{
			name:     "with control chars",
			input:    "test\x00string",
			maxLen:   100,
			expected: "teststring",
		},
		{
			name:     "with tab",
			input:    "test\tstring",
			maxLen:   100,
			expected: "test\tstring",
		},
		{
			name:     "with newline",
			input:    "test\nstring",
			maxLen:   100,
			expected: "test\nstring",
		},
		{
			name:     "with other control char",
			input:    "test\x01string",
			maxLen:   100,
			expected: "teststring",
		},
		{
			name:     "empty string",
			input:    "",
			maxLen:   100,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SafeString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("SafeString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestContainsShellMetacharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "clean string",
			input:    "clean-string",
			expected: false,
		},
		{
			name:     "with semicolon",
			input:    "string;value",
			expected: true,
		},
		{
			name:     "with pipe",
			input:    "string|value",
			expected: true,
		},
		{
			name:     "with ampersand",
			input:    "string&value",
			expected: true,
		},
		{
			name:     "with backtick",
			input:    "string`value",
			expected: true,
		},
		{
			name:     "with dollar",
			input:    "string$value",
			expected: true,
		},
		{
			name:     "with parentheses",
			input:    "string(value)",
			expected: true,
		},
		{
			name:     "with angle brackets",
			input:    "string<value>",
			expected: true,
		},
		{
			name:     "with braces",
			input:    "string{value}",
			expected: true,
		},
		{
			name:     "with brackets",
			input:    "string[value]",
			expected: true,
		},
		{
			name:     "with backslash",
			input:    "string\\value",
			expected: true,
		},
		{
			name:     "with quote",
			input:    "string\"value",
			expected: true,
		},
		{
			name:     "with single quote",
			input:    "string'value",
			expected: true,
		},
		{
			name:     "with space",
			input:    "string value",
			expected: true,
		},
		{
			name:     "with asterisk",
			input:    "string*value",
			expected: true,
		},
		{
			name:     "with question mark",
			input:    "string?value",
			expected: true,
		},
		{
			name:     "with exclamation",
			input:    "string!value",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsShellMetacharacters(tt.input)
			if result != tt.expected {
				t.Errorf("containsShellMetacharacters() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsShellMetacharacter(t *testing.T) {
	tests := []struct {
		char     rune
		expected bool
	}{
		{';', true},
		{'|', true},
		{'&', true},
		{'`', true},
		{'$', true},
		{'(', true},
		{')', true},
		{'<', true},
		{'>', true},
		{'{', true},
		{'}', true},
		{'[', true},
		{']', true},
		{'\\', true},
		{'"', true},
		{'\'', true},
		{' ', true},
		{'\t', true},
		{'\n', true},
		{'\r', true},
		{'*', true},
		{'?', true},
		{'!', true},
		{'a', false},
		{'A', false},
		{'0', false},
		{'-', false},
		{'_', false},
		{'.', false},
		{'/', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			result := isShellMetacharacter(tt.char)
			if result != tt.expected {
				t.Errorf("isShellMetacharacter(%c) = %v, want %v", tt.char, result, tt.expected)
			}
		})
	}
}

func TestIsInternalURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "public https",
			input:    "https://acme-corp.io",
			expected: false,
		},
		{
			name:     "public http",
			input:    "http://acme-corp.io",
			expected: false,
		},
		{
			name:     "localhost http",
			input:    "http://localhost",
			expected: true,
		},
		{
			name:     "localhost https",
			input:    "https://localhost",
			expected: true,
		},
		{
			name:     "127.0.0.1 http",
			input:    "http://127.0.0.1",
			expected: true,
		},
		{
			name:     "127.0.0.1 https",
			input:    "https://127.0.0.1",
			expected: true,
		},
		{
			name:     "0.0.0.0 http",
			input:    "http://0.0.0.0",
			expected: true,
		},
		{
			name:     "0.0.0.0 https",
			input:    "https://0.0.0.0",
			expected: true,
		},
		{
			name:     "ipv6 loopback http",
			input:    "http://[::1]",
			expected: true,
		},
		{
			name:     "ipv6 loopback https",
			input:    "https://[::1]",
			expected: true,
		},
		{
			name:     "169.254.0.0/16",
			input:    "http://169.254.1.1",
			expected: true,
		},
		{
			name:     "192.168.0.0/16",
			input:    "http://192.168.1.1",
			expected: true,
		},
		{
			name:     "10.0.0.0/8",
			input:    "http://10.0.0.1",
			expected: true,
		},
		{
			name:     "file protocol",
			input:    "file:///etc/passwd",
			expected: true,
		},
		{
			name:     "public ip",
			input:    "http://8.8.8.8",
			expected: false,
		},
		{
			name:     "public domain",
			input:    "https://google.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isInternalURL(tt.input)
			if result != tt.expected {
				t.Errorf("isInternalURL() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRedactSecrets(t *testing.T) {
	RegisterSecretToRedact("SuperSecretTokenString123")
	RegisterSecretToRedact("Short") // Should be ignored (too short)

	input := "AWS key is AKIA1234567890123456 and token is SuperSecretTokenString123 but Short is preserved"
	expected := "AWS key is ●●●●●●●● and token is ●●●●●●●● but Short is preserved"

	redacted := RedactSecrets(input)
	if redacted != expected {
		t.Errorf("RedactSecrets() = %q, want %q", redacted, expected)
	}
}

func TestIsPrivateIPAndAddr(t *testing.T) {
	tests := []struct {
		ip        string
		isPrivate bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %s", tt.ip)
			}
			if got := IsPrivateIP(ip); got != tt.isPrivate {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.isPrivate)
			}

			addr, err := netip.ParseAddr(tt.ip)
			if err != nil {
				t.Fatalf("failed to parse netip.Addr %s", tt.ip)
			}
			if got := IsPrivateAddr(addr); got != tt.isPrivate {
				t.Errorf("IsPrivateAddr(%s) = %v, want %v", tt.ip, got, tt.isPrivate)
			}
		})
	}
}

func TestParseMixedNotationIP_Advanced(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectIP  string
		expectOK  bool
	}{
		{"empty string", "", "", false},
		{"brackets IPv6", "[::1]", "", false},
		{"too many segments", "1.2.3.4.5", "", false},
		{"invalid octal parse", "0178.0.0.1", "", false},
		{"hex notation", "0x7f.0.0.1", "127.0.0.1", true},
		{"octal notation", "0177.0.0.1", "127.0.0.1", true},
		{"dword notation", "2130706433", "127.0.0.1", true},
		{"invalid dword overflow", "4294967296", "", false},
		{"two segments", "127.1", "127.0.0.1", true},
		{"three segments", "127.0.1", "127.0.0.1", true},
		{"out of range part 2 segments", "127.16777216", "", false},
		{"out of range part 3 segments", "127.0.65536", "", false},
		{"four segments out of range", "127.0.0.256", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := ParseMixedNotationIP(tt.input)
			if ok != tt.expectOK {
				t.Errorf("ParseMixedNotationIP(%q) ok = %v, want %v", tt.input, ok, tt.expectOK)
			}
			if ok && ip.String() != tt.expectIP {
				t.Errorf("ParseMixedNotationIP(%q) got = %v, want %v", tt.input, ip.String(), tt.expectIP)
			}
		})
	}
}

func TestResolveAndValidateAddr_Advanced(t *testing.T) {
	ctx := context.Background()

	// 1. Test invalid address format
	_, _, err := ResolveAndValidateAddr(ctx, "invalid-addr")
	if err == nil {
		t.Error("expected error for invalid host:port format")
	}

	// 2. Test direct IP - public
	pinned, original, err := ResolveAndValidateAddr(ctx, "8.8.8.8:53")
	if err != nil {
		t.Errorf("unexpected error for public IP: %v", err)
	}
	if original != "8.8.8.8" || pinned != "8.8.8.8:53" {
		t.Errorf("unexpected results: original=%s, pinned=%s", original, pinned)
	}

	// 3. Test direct IP - private
	_, _, err = ResolveAndValidateAddr(ctx, "127.0.0.1:80")
	if err == nil {
		t.Error("expected error for private direct IP")
	}

	// 4. Test resolved domain - public (acme-corp.io resolves to 8.8.8.8 via TestMain lookupIP stub)
	pinned, original, err = ResolveAndValidateAddr(ctx, "acme-corp.io:443")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if original != "acme-corp.io" || pinned != "8.8.8.8:443" {
		t.Errorf("unexpected results: original=%s, pinned=%s", original, pinned)
	}

	// 5. Test DNS resolution failure
	_, _, err = ResolveAndValidateAddr(ctx, "nonexistent-domain.local:80")
	if err == nil {
		t.Error("expected error for non-resolvable domain")
	}
}

func TestValidateResolvedIPEx_EdgeCases(t *testing.T) {
	s := NewSanitizer()

	// Test empty host
	if err := s.ValidateResolvedIPEx("", true); err == nil {
		t.Error("expected error for empty host")
	}

	// Test host with brackets
	if err := s.ValidateResolvedIPEx("[8.8.8.8]", true); err != nil {
		t.Errorf("unexpected error for host with brackets: %v", err)
	}

	// Test host resolving to empty list of IPs (via stub returning nil)
	oldLookupIP := lookupIP
	lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{}, nil
	}
	defer func() { lookupIP = oldLookupIP }()

	if err := s.ValidateResolvedIPEx("acme-corp.io", true); err == nil {
		t.Error("expected error when no IP addresses resolve")
	}
}

func TestValidateURLStrict(t *testing.T) {
	s := NewSanitizer()

	// Test valid public URL
	if err := s.ValidateURLStrict("https://acme-corp.io/path"); err != nil {
		t.Errorf("unexpected error for valid URL: %v", err)
	}

	// Test empty URL
	if err := s.ValidateURLStrict(""); err == nil {
		t.Error("expected error for empty URL")
	}

	// Test invalid URL format
	if err := s.ValidateURLStrict("invalid-url"); err == nil {
		t.Error("expected error for invalid URL format")
	}

	// Test shell metacharacters in URL
	if err := s.ValidateURLStrict("https://acme-corp.io;echo"); err == nil {
		t.Error("expected error for shell injection in URL")
	}

	// Test private URL
	if err := s.ValidateURLStrict("http://127.0.0.1/admin"); err == nil {
		t.Error("expected error for private URL")
	}
}

func TestSanitizerVerifyPrivateIPs(t *testing.T) {
	// Test nil IP returns true by default
	if !IsPrivateIP(nil) {
		t.Error("expected IsPrivateIP(nil) to return true")
	}

	// If BBPTS_ALLOW_PRIVATE_IPS is set to true, private IPs shouldn't be blocked.
	os.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")
	defer os.Unsetenv("BBPTS_ALLOW_PRIVATE_IPS")

	if IsPrivateIP(net.ParseIP("127.0.0.1")) {
		t.Error("expected IsPrivateIP to return false when BBPTS_ALLOW_PRIVATE_IPS is true")
	}
	addr, _ := netip.ParseAddr("127.0.0.1")
	if IsPrivateAddr(addr) {
		t.Error("expected IsPrivateAddr to return false when BBPTS_ALLOW_PRIVATE_IPS is true")
	}
}

func TestValidateResolvedIPAndStrict(t *testing.T) {
	s := NewSanitizer()

	// Test public IP
	if err := s.ValidateResolvedIP("8.8.8.8"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := s.ValidateResolvedIPStrict("8.8.8.8"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Test private IP
	if err := s.ValidateResolvedIP("127.0.0.1"); err == nil {
		t.Error("expected error for private IP")
	}
	if err := s.ValidateResolvedIPStrict("127.0.0.1"); err == nil {
		t.Error("expected error for private IP")
	}
}


