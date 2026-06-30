// Package recon provides reconnaissance domain logic
package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Event struct {
	Target     string            `json:"target"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties"`
}

const (
	OpContains    = "contains"
	OpEquals      = "equals"
	OpStartsWith  = "starts_with"
	OpEndsWith    = "ends_with"
	OpNotContains = "not_contains"
)

type Condition struct {
	// Field is the event field to evaluate: "target", "source", or any property key.
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type Action struct {
	// Type is the action kind: "trigger_tool", "alert", "tag", "block", or "elevate".
	Type string `json:"type"`

	// Tool is the tool name to inject into the pipeline (used when Type == "trigger_tool").
	Tool string `json:"tool,omitempty"`

	// Tag is the tag to add to the insight (used when Type == "tag").
	Tag string `json:"tag,omitempty"`

	// Message is an optional human-readable description of the action.
	Message string `json:"message,omitempty"`
}

type Rule struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Priority    string      `json:"priority"` // "critical", "high", "medium", "low"
	Conditions  []Condition `json:"conditions"`
	Action      Action      `json:"action"`
}

type RuleSet struct {
	Rules []Rule `json:"rules"`
}

type Match struct {
	Rule  Rule
	Event Event
}

func DefaultRules() *RuleSet {
	return &RuleSet{
		Rules: []Rule{
			{
				ID:          "exposed-env",
				Description: "Exposed .env file — likely contains credentials",
				Priority:    "critical",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: ".env"},
				},
				Action: Action{Type: "tag", Tag: "exposed-secrets", Message: " .env file found — check for DB creds, API keys"},
			},
			{
				ID:          "exposed-git",
				Description: "Exposed .git directory — source code disclosure",
				Priority:    "critical",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "/.git"},
				},
				Action: Action{Type: "tag", Tag: "source-disclosure", Message: " .git directory exposed — attempt git-dumper"},
			},
			{
				ID:          "exposed-backup",
				Description: "Backup file found — common source of info disclosure",
				Priority:    "high",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: ".bak"},
				},
				Action: Action{Type: "tag", Tag: "backup-file", Message: "️ Backup file found — may contain source code or config"},
			},
			{
				ID:          "api-v-endpoint",
				Description: "Versioned API endpoint — common IDOR/auth bypass surface",
				Priority:    "high",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "/api/v"},
				},
				Action: Action{Type: "trigger_tool", Tool: "ffuf", Message: "API version endpoint found — fuzzing for hidden routes"},
			},
			{
				ID:          "graphql-endpoint",
				Description: "GraphQL endpoint detected — introspection and IDOR risk",
				Priority:    "high",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "/graphql"},
				},
				Action: Action{Type: "tag", Tag: "graphql", Message: "🔎 GraphQL endpoint found — test introspection and batching attacks"},
			},
			{
				ID:          "admin-panel",
				Description: "Admin panel detected",
				Priority:    "high",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "/admin"},
				},
				Action: Action{Type: "tag", Tag: "admin-panel", Message: "️ Admin panel detected — test for default creds and RBAC bypass"},
			},
			{
				ID:          "jenkins-exposed",
				Description: "Jenkins CI instance exposed",
				Priority:    "critical",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "jenkins"},
				},
				Action: Action{Type: "tag", Tag: "ci-exposure", Message: " Jenkins exposed — test /script and /configure endpoints"},
			},
			{
				ID:          "swagger-exposed",
				Description: "Swagger/OpenAPI docs exposed — full API map",
				Priority:    "medium",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "swagger"},
				},
				Action: Action{Type: "tag", Tag: "api-docs", Message: "📖 Swagger UI exposed — extract all API endpoints automatically"},
			},
			{
				ID:          "phpmyadmin-exposed",
				Description: "phpMyAdmin exposed — direct database access risk",
				Priority:    "critical",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "phpmyadmin"},
				},
				Action: Action{Type: "tag", Tag: "db-exposure", Message: " phpMyAdmin exposed — attempt default credentials"},
			},
			{
				ID:          "s3-bucket-reference",
				Description: "AWS S3 bucket reference found — check for public access",
				Priority:    "high",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: ".s3.amazonaws.com"},
				},
				Action: Action{Type: "tag", Tag: "cloud-storage", Message: "☁️ S3 bucket URL found — test for public read/write access"},
			},
			{
				ID:          "crtsh-wildcard",
				Description: "Wildcard certificate found — large scope expansion opportunity",
				Priority:    "medium",
				Conditions: []Condition{
					{Field: "source", Operator: OpEquals, Value: "crtsh"},
					{Field: "target", Operator: OpStartsWith, Value: "*."},
				},
				Action: Action{Type: "trigger_tool", Tool: "subfinder", Message: "Wildcard cert found — expand subdomain enumeration"},
			},
			{
				ID:          "dev-staging-env",
				Description: "Development or staging environment found",
				Priority:    "high",
				Conditions: []Condition{
					{Field: "target", Operator: OpContains, Value: "dev."},
				},
				Action: Action{Type: "tag", Tag: "dev-environment", Message: "️ Dev/staging environment found — often lacks prod-level security"},
			},
		},
	}
}

func (rs *RuleSet) Evaluate(events []Event) ([]Match, []string) {
	var matches []Match
	triggeredTools := map[string]struct{}{}

	for _, ev := range events {
		for _, rule := range rs.Rules {
			if rs.matchesAll(ev, rule.Conditions) {
				matches = append(matches, Match{Rule: rule, Event: ev})
				slog.Info("rule matched",
					"rule_id", rule.ID,
					"priority", rule.Priority,
					"target", ev.Target,
					"message", rule.Action.Message,
				)
				if rule.Action.Type == "trigger_tool" && rule.Action.Tool != "" {
					triggeredTools[rule.Action.Tool] = struct{}{}
				}
			}
		}
	}

	tools := make([]string, 0, len(triggeredTools))
	for t := range triggeredTools {
		tools = append(tools, t)
	}
	return matches, tools
}

func (rs *RuleSet) matchesAll(ev Event, conditions []Condition) bool {
	for _, cond := range conditions {
		if !rs.matchesOne(ev, cond) {
			return false
		}
	}
	return len(conditions) > 0
}

func (rs *RuleSet) matchesOne(ev Event, cond Condition) bool {
	val := strings.ToLower(rs.resolveField(ev, cond.Field))
	check := strings.ToLower(cond.Value)

	switch cond.Operator {
	case OpContains:
		return strings.Contains(val, check)
	case OpEquals:
		return val == check
	case OpStartsWith:
		return strings.HasPrefix(val, check)
	case OpEndsWith:
		return strings.HasSuffix(val, check)
	case OpNotContains:
		return !strings.Contains(val, check)
	default:
		return false
	}
}

func (rs *RuleSet) resolveField(ev Event, field string) string {
	switch field {
	case "target":
		return ev.Target
	case "source":
		return ev.Source
	default:
		return ev.Properties[field]
	}
}

func LoadFromFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("no custom rules file found, using built-in rules", "path", path)
			return DefaultRules(), nil
		}
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("failed to parse rules file: %w", err)
	}

	slog.Info("loaded custom rules", "count", len(rs.Rules), "path", path)
	return &rs, nil
}

func WriteDefault(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "rules.json")
	data, err := json.MarshalIndent(DefaultRules(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
