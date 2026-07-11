package services

import (
	"fmt"
	"strings"
	"time"
)

type PlaybookGenerator struct{}

type Playbook struct {
	Target      string            `json:"target"`
	GeneratedAt time.Time         `json:"generated_at"`
	TechStack   []string          `json:"tech_stack"`
	Sessions    []PlaybookSession `json:"sessions"`
	Summary     string            `json:"summary"`
}

type PlaybookSession struct {
	Title    string         `json:"title"`
	Duration string         `json:"duration"`
	Steps    []PlaybookStep `json:"steps"`
}

type PlaybookStep struct {
	Action   string `json:"action"`
	Tool     string `json:"tool,omitempty"`
	Expected string `json:"expected"`
	Priority string `json:"priority"` // high, medium, low
}

func NewPlaybookGenerator() *PlaybookGenerator {
	return &PlaybookGenerator{}
}

func (pg *PlaybookGenerator) Generate(target string, techStack []string, endpoints []string, findings []string) *Playbook {
	p := &Playbook{
		Target:      target,
		GeneratedAt: time.Now(),
		TechStack:   techStack,
	}

	p.Sessions = append(p.Sessions,
		pg.authSession(target, techStack, findings),
		pg.idorSession(target, endpoints),
		pg.injectionSession(target, techStack),
		pg.businessLogicSession(target, endpoints),
		pg.misconfigSession(target, techStack),
	)

	p.Summary = pg.generateSummary(p)
	return p
}

func (pg *PlaybookGenerator) authSession(target string, techStack []string, _ []string) PlaybookSession {
	session := PlaybookSession{
		Title:    "Authentication Testing",
		Duration: "30 min",
	}

	session.Steps = append(session.Steps,
		PlaybookStep{
			Action:   fmt.Sprintf("Test JWT configuration on %s/api/auth/me", target),
			Tool:     "jwt_analyzer",
			Expected: "401 if properly validated, 200 with weak config",
			Priority: "high",
		},
		PlaybookStep{
			Action:   "Test for alg:none JWT bypass",
			Expected: "Token accepted with none algorithm = critical finding",
			Priority: "high",
		},
	)

	if containsTech(techStack, "oauth") || containsTech(techStack, "cognito") {
		session.Steps = append(session.Steps,
			PlaybookStep{
				Action:   "Test OAuth state parameter bypass",
				Expected: "CSRF on account linking if state not validated",
				Priority: "high",
			},
			PlaybookStep{
				Action:   "Test password reset flow for account enumeration",
				Expected: "Different responses for valid vs invalid emails",
				Priority: "medium",
			},
			PlaybookStep{
				Action:   "Test session fixation - does session ID change after login?",
				Expected: "New session ID after authentication",
				Priority: "medium",
			},
		)
	} else {
		session.Steps = append(session.Steps,
			PlaybookStep{
				Action:   "Test password reset flow for account enumeration",
				Expected: "Different responses for valid vs invalid emails",
				Priority: "medium",
			},
			PlaybookStep{
				Action:   "Test session fixation - does session ID change after login?",
				Expected: "New session ID after authentication",
				Priority: "medium",
			},
		)
	}

	return session
}

func (pg *PlaybookGenerator) idorSession(_ string, endpoints []string) PlaybookSession {
	session := PlaybookSession{
		Title:    "IDOR / Access Control Testing",
		Duration: "45 min",
	}

	session.Steps = append(session.Steps, PlaybookStep{
		Action:   "Create two test accounts (User A, User B)",
		Expected: "Two valid sessions with different user IDs",
		Priority: "high",
	})

	for _, ep := range endpoints {
		if containsID(ep) {
			session.Steps = append(session.Steps, PlaybookStep{
				Action:   fmt.Sprintf("Access %s with User B's session (User A's resource)", ep),
				Tool:     "auth_matrix",
				Expected: "403/404 if properly protected, 200 = IDOR",
				Priority: "high",
			})
		}
	}

	session.Steps = append(session.Steps,
		PlaybookStep{
			Action:   "Test IDOR via UUID/sequential ID manipulation",
			Expected: "Increment IDs: /api/users/1001 -> /api/users/1002",
			Priority: "high",
		},
		PlaybookStep{
			Action:   "Test horizontal privilege escalation on admin endpoints",
			Expected: "Non-admin accessing /admin/* paths",
			Priority: "high",
		},
	)

	return session
}

func (pg *PlaybookGenerator) injectionSession(_ string, techStack []string) PlaybookSession {
	session := PlaybookSession{
		Title:    "Injection Testing",
		Duration: "30 min",
	}

	session.Steps = append(session.Steps,
		PlaybookStep{
			Action:   "Test all input fields for reflected XSS",
			Tool:     "dalfox",
			Expected: "Payload reflected in response without sanitization",
			Priority: "high",
		},
		PlaybookStep{
			Action:   "Test SSTI on any template rendering endpoints",
			Tool:     "blind_inject",
			Expected: "{{7*7}} renders as 49 = SSTI confirmed",
			Priority: "medium",
		},
		PlaybookStep{
			Action:   "Test SSRF via URL parameters and webhooks",
			Tool:     "ssrf",
			Expected: "Internal service access via crafted URL",
			Priority: "high",
		},
	)

	return session
}

func (pg *PlaybookGenerator) businessLogicSession(_ string, _ []string) PlaybookSession {
	session := PlaybookSession{
		Title:    "Business Logic Testing",
		Duration: "20 min",
	}

	session.Steps = append(session.Steps,
		PlaybookStep{
			Action:   "Test negative quantity/amount on payment endpoints",
			Tool:     "business_logic",
			Expected: "Negative values should be rejected",
			Priority: "high",
		},
		PlaybookStep{
			Action:   "Test coupon reuse in parallel requests",
			Tool:     "race",
			Expected: "Single-use coupon applied twice = race condition",
			Priority: "high",
		},
		PlaybookStep{
			Action:   "Test step skipping in multi-step flows",
			Expected: "Access /checkout without completing /cart",
			Priority: "medium",
		},
		PlaybookStep{
			Action:   "Test price manipulation in checkout",
			Expected: "Modified price accepted = critical logic flaw",
			Priority: "high",
		},
	)

	return session
}

func (pg *PlaybookGenerator) misconfigSession(_ string, techStack []string) PlaybookSession {
	session := PlaybookSession{
		Title:    "Configuration & Exposure Testing",
		Duration: "15 min",
	}

	session.Steps = append(session.Steps,
		PlaybookStep{
			Action:   "Check for exposed admin panels",
			Tool:     "nuclei",
			Expected: "/admin, /dashboard accessible without auth",
			Priority: "high",
		},
		PlaybookStep{
			Action:   "Check for exposed debug/stack traces",
			Expected: "Debug mode enabled in production",
			Priority: "medium",
		},
	)

	if containsTech(techStack, "spring") {
		session.Steps = append(session.Steps, PlaybookStep{
			Action:   "Check Spring Boot Actuator endpoints",
			Expected: "/actuator/env, /actuator/heapdump accessible",
			Priority: "high",
		})
	}

	session.Steps = append(session.Steps,
		PlaybookStep{
			Action:   "Test CORS configuration",
			Tool:     "cors",
			Expected: "Origin reflection with credentials = medium",
			Priority: "medium",
		},
		PlaybookStep{
			Action:   "Check for exposed .env and config files",
			Tool:     "nuclei",
			Expected: "Credentials in .env or config files",
			Priority: "high",
		},
	)

	return session
}

func (pg *PlaybookGenerator) generateSummary(p *Playbook) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Hunting Playbook — %s\n\n", p.Target))
	sb.WriteString(fmt.Sprintf("Generated: %s\n", p.GeneratedAt.Format("2006-01-02 15:04")))
	sb.WriteString(fmt.Sprintf("Tech stack: %s\n\n", strings.Join(p.TechStack, ", ")))
	sb.WriteString("### Sessions\n")
	for i, s := range p.Sessions {
		sb.WriteString(fmt.Sprintf("%d. **%s** (%s) — %d steps\n", i+1, s.Title, s.Duration, len(s.Steps)))
	}
	return sb.String()
}

func containsTech(techs []string, target string) bool {
	for _, t := range techs {
		if strings.Contains(strings.ToLower(t), target) {
			return true
		}
	}
	return false
}

func containsID(endpoint string) bool {
	idPatterns := []string{"/users/", "/user/", "/accounts/", "/documents/", "/files/", "/orders/", "/items/", "/products/"}
	for _, p := range idPatterns {
		if strings.Contains(endpoint, p) {
			return true
		}
	}
	return false
}
