package security

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"unicode"
)

// Sanitizer provides input validation and sanitization for security.
type Sanitizer struct {
	// Allowed patterns for different input types
	fleetNamePattern    *regexp.Regexp
	toolNamePattern     *regexp.Regexp
	filePathPattern     *regexp.Regexp
	urlPattern          *regexp.Regexp
}

// NewSanitizer creates a new sanitizer with security patterns.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		// Fleet names: alphanumeric, hyphens, underscores only, max 64 chars
		fleetNamePattern: regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`),
		// Tool names: lowercase alphanumeric, hyphens only (standard tool naming)
		toolNamePattern: regexp.MustCompile(`^[a-z0-9-]{1,32}$`),
		// File paths: prevent directory traversal
		filePathPattern: regexp.MustCompile(`^[a-zA-Z0-9_./-]{1,256}$`),
		// Basic URL pattern for validation
		urlPattern: regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/$.?#].[^\s]*$`),
	}
}

// ValidateFleetName validates a fleet name for security.
func (s *Sanitizer) ValidateFleetName(name string) error {
	if name == "" {
		return fmt.Errorf("fleet name cannot be empty")
	}
	
	// Check for shell metacharacters
	if containsShellMetacharacters(name) {
		return fmt.Errorf("fleet name contains invalid characters: %s", name)
	}
	
	// Check against allowed pattern
	if !s.fleetNamePattern.MatchString(name) {
		return fmt.Errorf("fleet name must be alphanumeric with hyphens/underscores only, max 64 chars: %s", name)
	}
	
	return nil
}

// ValidateToolName validates a tool name for security.
func (s *Sanitizer) ValidateToolName(name string) error {
	if name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}
	
	// Check for shell metacharacters
	if containsShellMetacharacters(name) {
		return fmt.Errorf("tool name contains invalid characters: %s", name)
	}
	
	// Check against allowed pattern
	if !s.toolNamePattern.MatchString(name) {
		return fmt.Errorf("tool name must be lowercase alphanumeric with hyphens only, max 32 chars: %s", name)
	}
	
	return nil
}

// ValidateFilePath validates a file path to prevent directory traversal.
func (s *Sanitizer) ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}
	
	// Check for directory traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("file path contains directory traversal: %s", path)
	}
	
	// Check for shell metacharacters
	if containsShellMetacharacters(path) {
		return fmt.Errorf("file path contains invalid characters: %s", path)
	}
	
	// Check against allowed pattern
	if !s.filePathPattern.MatchString(path) {
		return fmt.Errorf("file path contains invalid characters: %s", path)
	}
	
	return nil
}

// ValidateURL validates a URL for security.
func (s *Sanitizer) ValidateURL(url string) error {
	if url == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	
	// Check for shell metacharacters
	if containsShellMetacharacters(url) {
		return fmt.Errorf("URL contains invalid characters: %s", url)
	}
	
	// Basic URL validation
	if !s.urlPattern.MatchString(url) {
		return fmt.Errorf("invalid URL format: %s", url)
	}
	
	// Check for SSRF attempts (localhost, internal IPs)
	if isInternalURL(url) {
		slog.Warn("Internal URL detected, may indicate SSRF attempt", "url", url)
		return fmt.Errorf("URL points to internal address: %s", url)
	}
	
	return nil
}

// SanitizeShellArg sanitizes a shell argument to prevent injection.
func (s *Sanitizer) SanitizeShellArg(arg string) string {
	// Remove shell metacharacters
	result := strings.Map(func(r rune) rune {
		if isShellMetacharacter(r) {
			return -1 // Remove the character
		}
		return r
	}, arg)
	
	return strings.TrimSpace(result)
}

// ValidateInteger validates an integer value within a range.
func (s *Sanitizer) ValidateInteger(value int, min, max int) error {
	if value < min {
		return fmt.Errorf("value %d is below minimum %d", value, min)
	}
	if value > max {
		return fmt.Errorf("value %d is above maximum %d", value, max)
	}
	return nil
}

// containsShellMetacharacters checks if a string contains shell metacharacters.
func containsShellMetacharacters(s string) bool {
	for _, r := range s {
		if isShellMetacharacter(r) {
			return true
		}
	}
	return false
}

// isShellMetacharacter checks if a rune is a shell metacharacter.
func isShellMetacharacter(r rune) bool {
	shellMetacharacters := ";|&`$()<>{}[]\\\"' \t\n\r*?!"
	return strings.ContainsRune(shellMetacharacters, r)
}

// isInternalURL checks if a URL points to an internal address (SSRF protection).
func isInternalURL(url string) bool {
	lowerURL := strings.ToLower(url)
	
	// Check for localhost variants
	internalPatterns := []string{
		"http://localhost",
		"https://localhost",
		"http://127.",
		"https://127.",
		"http://0.",
		"https://0.",
		"http://[::1]",
		"https://[::1]",
		"http://169.254.",
		"https://169.254.",
		"http://192.168.",
		"https://192.168.",
		"http://10.",
		"https://10.",
		"http://file://",
		"https://file://",
	}
	
	for _, pattern := range internalPatterns {
		if strings.HasPrefix(lowerURL, pattern) {
			return true
		}
	}
	
	return false
}

// ValidateCommandArgs validates command arguments for security.
func (s *Sanitizer) ValidateCommandArgs(args []string) error {
	for i, arg := range args {
		if arg == "" {
			continue // Empty args are typically OK
		}
		
		// Check for shell metacharacters
		if containsShellMetacharacters(arg) {
			return fmt.Errorf("argument %d contains shell metacharacters: %s", i, arg)
		}
		
		// Check for command chaining attempts
		if strings.Contains(arg, "&&") || strings.Contains(arg, "||") || strings.Contains(arg, ";") {
			return fmt.Errorf("argument %d contains command chaining: %s", i, arg)
		}
		
		// Check for variable substitution attempts
		if strings.Contains(arg, "$(") || strings.Contains(arg, "`") {
			return fmt.Errorf("argument %d contains command substitution: %s", i, arg)
		}
	}
	
	return nil
}

// SafeString converts a string to a safe representation for logging.
func (s *Sanitizer) SafeString(str string, maxLength int) string {
	if len(str) > maxLength {
		str = str[:maxLength] + "..."
	}
	
	// Remove control characters
	result := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, str)
	
	return result
}
