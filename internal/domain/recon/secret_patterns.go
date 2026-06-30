// Package recon provides reconnaissance domain logic
package recon

import (
	"regexp"
	"strings"
)

type SecretPattern struct {
	Name     string
	Severity string // "critical", "high", "medium", "low"
	Pattern  *regexp.Regexp
}

type SecretMatch struct {
	PatternName string
	Severity    string
	Value       string
	Line        int // 1-indexed line number where the match was found
}

var SecretPatterns = []SecretPattern{

	{Name: "AWS Access Key ID", Severity: "critical", Pattern: regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
	{Name: "AWS Secret Access Key", Severity: "critical", Pattern: regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`)},

	{Name: "Google API Key", Severity: "high", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{Name: "Google OAuth Client Secret", Severity: "high", Pattern: regexp.MustCompile(`(?i)client_secret.*?['"]([\\w\\-]+)['"]`)},

	{Name: "GitHub Personal Access Token", Severity: "critical", Pattern: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`)},
	{Name: "GitHub OAuth Access Token", Severity: "critical", Pattern: regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`)},
	{Name: "GitHub App Token", Severity: "critical", Pattern: regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`)},

	{Name: "Slack Bot Token", Severity: "high", Pattern: regexp.MustCompile(`xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`)},
	{Name: "Slack Webhook URL", Severity: "high", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`)},

	{Name: "Stripe Secret Key", Severity: "critical", Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,99}`)},
	{Name: "Stripe Publishable Key", Severity: "low", Pattern: regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,99}`)},

	{Name: "JSON Web Token", Severity: "medium", Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)},

	{Name: "RSA Private Key", Severity: "critical", Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`)},
	{Name: "Generic Private Key", Severity: "critical", Pattern: regexp.MustCompile(`-----BEGIN (?:EC |DSA )?PRIVATE KEY-----`)},

	{Name: "Twilio API Key", Severity: "high", Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},

	{Name: "Mailgun API Key", Severity: "high", Pattern: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},

	{Name: "SendGrid API Key", Severity: "high", Pattern: regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`)},

	{Name: "Heroku API Key", Severity: "high", Pattern: regexp.MustCompile(`(?i)heroku.*?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)},

	{Name: "Firebase Database URL", Severity: "medium", Pattern: regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`)},

	{Name: "Password in URL", Severity: "high", Pattern: regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"]`)},
	{Name: "Authorization Bearer", Severity: "medium", Pattern: regexp.MustCompile(`(?i)(?:authorization|bearer)\s*[=:]\s*['"]?Bearer\s+[A-Za-z0-9\-._~+/]+=*['"]?`)},

	{Name: "Database Connection String", Severity: "critical", Pattern: regexp.MustCompile(`(?i)(?:mongodb|postgres|mysql|redis)://[^\s'"]+`)},

	{Name: "Internal IP Address", Severity: "medium", Pattern: regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)},
}

func ScanForSecrets(content string) []SecretMatch {
	lines := strings.Split(content, "\n")
	var matches []SecretMatch
	seen := make(map[string]struct{})

	for lineIdx, line := range lines {
		for _, sp := range SecretPatterns {
			found := sp.Pattern.FindAllString(line, -1)
			for _, val := range found {
				key := sp.Name + "|" + val
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				matches = append(matches, SecretMatch{
					PatternName: sp.Name,
					Severity:    sp.Severity,
					Value:       val,
					Line:        lineIdx + 1,
				})
			}
		}
	}
	return matches
}
