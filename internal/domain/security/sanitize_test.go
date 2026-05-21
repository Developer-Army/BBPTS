package security

import (
	"testing"
)

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
			input:   "https://example.com",
			wantErr: false,
		},
		{
			name:    "valid http URL",
			input:   "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid URL with path",
			input:   "https://example.com/path/to/resource",
			wantErr: false,
		},
		{
			name:    "valid URL with query",
			input:   "https://example.com?param=value",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "no scheme",
			input:   "example.com",
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
			input:   "https://example.com;rm -rf",
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
			input:    "https://example.com",
			expected: false,
		},
		{
			name:     "public http",
			input:    "http://example.com",
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
