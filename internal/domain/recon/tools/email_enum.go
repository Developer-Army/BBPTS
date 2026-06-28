package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// EmailEnumTool performs passive email enumeration via the Hunter.io API.
// Infers internal username patterns and cross-references developer GitHub accounts.
// Runs at Stage 0 — zero traffic to target, API-only queries.
type EmailEnumTool struct{}

func (t *EmailEnumTool) Name() string {
	return "email_enum"
}

// --- Hunter.io API types ---

type hunterDomainSearchResponse struct {
	Data   hunterData   `json:"data"`
	Meta   hunterMeta   `json:"meta"`
	Errors []hunterErr  `json:"errors"`
}

type hunterData struct {
	Domain       string         `json:"domain"`
	Disposable   bool           `json:"disposable"`
	Webmail      bool           `json:"webmail"`
	AcceptAll    bool           `json:"accept_all"`
	Pattern      string         `json:"pattern"`
	Organization string         `json:"organization"`
	Emails       []hunterEmail  `json:"emails"`
}

type hunterEmail struct {
	Value      string   `json:"value"`
	Type       string   `json:"type"`
	Confidence int      `json:"confidence"`
	FirstName  string   `json:"first_name"`
	LastName   string   `json:"last_name"`
	Position   string   `json:"position"`
	Seniority  string   `json:"seniority"`
	Department string   `json:"department"`
	LinkedIn   string   `json:"linkedin"`
	Twitter    string   `json:"twitter"`
	PhoneNbr   string   `json:"phone_number"`
	Sources    []hunterSource `json:"sources"`
}

type hunterSource struct {
	Domain      string `json:"domain"`
	URI         string `json:"uri"`
	ExtractedOn string `json:"extracted_on"`
	LastSeenOn  string `json:"last_seen_on"`
	StillOnPage bool   `json:"still_on_page"`
}

type hunterMeta struct {
	Results int    `json:"results"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	Params  struct {
		Domain  string `json:"domain"`
		Company string `json:"company"`
		Type    string `json:"type"`
	} `json:"params"`
}

type hunterErr struct {
	ID      string `json:"id"`
	Code    int    `json:"code"`
	Details string `json:"details"`
}

// --- GitHub user search types ---

type githubUserSearchResponse struct {
	Items []githubUserItem `json:"items"`
}

type githubUserItem struct {
	Login     string `json:"login"`
	HTMLURL   string `json:"html_url"`
	AvatarURL string `json:"avatar_url"`
	Type      string `json:"type"`
	PublicRepos int  `json:"public_repos"`
}

// --- Username pattern types ---

type usernamePattern struct {
	Format     string  // e.g., "first.last", "flast"
	Confidence float64 // 0.0 - 1.0
	Matches    int
	Total      int
}

// namePair holds a first/last/email triple for pattern inference.
type namePair struct {
	first, last, email string
}

// --- Rate limiting for Hunter.io ---

var (
	hunterMu        sync.Mutex
	hunterLastCall  time.Time
	hunterDelay     = 1200 * time.Millisecond // ~50 req/min for paid, safe for free tier
)

func limitHunterAPI() {
	hunterMu.Lock()
	defer hunterMu.Unlock()
	elapsed := time.Since(hunterLastCall)
	if elapsed < hunterDelay {
		time.Sleep(hunterDelay - elapsed)
	}
	hunterLastCall = time.Now()
}

// patternGenerators defines functions to generate expected email local-parts
// from a (first, last) name pair for each pattern format.
var patternGenerators = map[string]func(first, last string) string{
	"first.last":  func(f, l string) string { return f + "." + l },
	"flast":       func(f, l string) string { return string(f[0]) + l },
	"firstl":      func(f, l string) string { return f + string(l[0]) },
	"first_last":  func(f, l string) string { return f + "_" + l },
	"first":       func(f, _ string) string { return f },
	"last.first":  func(f, l string) string { return l + "." + f },
	"lastf":       func(f, l string) string { return l + string(f[0]) },
	"lfirst":      func(f, l string) string { return string(l[0]) + f },
	"first-last":  func(f, l string) string { return f + "-" + l },
}

func (t *EmailEnumTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	hunterKey := scanCtx.APIKeys["hunter"]
	if hunterKey == "" {
		slog.Debug("Hunter.io API key not configured, skipping email_enum")
		return nil, nil
	}

	githubKey := scanCtx.APIKeys["github"]

	var (
		allEvents []recon.Event
		mu        sync.Mutex
		wg        sync.WaitGroup
		seen      = make(map[dedupeKey]struct{})
	)

	sem := make(chan struct{}, threads)

	for _, target := range targets {
		domain := strings.TrimSpace(target)
		if domain == "" {
			continue
		}
		domain = stripProtocol(domain)

		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			events := t.processDomain(ctx, scanCtx, dom, hunterKey, githubKey, &seen, &mu)
			mu.Lock()
			allEvents = append(allEvents, events...)
			mu.Unlock()
		}(domain)
	}

	wg.Wait()
	return allEvents, nil
}

func (t *EmailEnumTool) processDomain(
	ctx context.Context,
	scanCtx *recon.ScanContext,
	domain, hunterKey, githubKey string,
	seen *map[dedupeKey]struct{},
	mu *sync.Mutex,
) []recon.Event {
	var events []recon.Event
	client := NewSafeHTTPClient(20 * time.Second)

	// 1. Query Hunter.io domain search
	hunterResp, err := t.queryHunter(ctx, client, scanCtx, hunterKey, domain)
	if err != nil {
		slog.Debug("email_enum hunter.io query failed", "domain", domain, "error", err)
		return events
	}

	if len(hunterResp.Errors) > 0 {
		slog.Warn("email_enum hunter.io returned errors",
			"domain", domain,
			"error", hunterResp.Errors[0].Details,
		)
		return events
	}

	slog.Info("email_enum: Hunter.io results",
		"domain", domain,
		"emails_found", len(hunterResp.Data.Emails),
		"organization", hunterResp.Data.Organization,
		"reported_pattern", hunterResp.Data.Pattern,
	)

	// 2. Emit email_found events
	var namePairs []namePair

	for _, email := range hunterResp.Data.Emails {
		if email.Value == "" {
			continue
		}

		key := dedupeKey{target: domain, eventType: "email_found", value: email.Value}
		mu.Lock()
		if _, dup := (*seen)[key]; dup {
			mu.Unlock()
			continue
		}
		(*seen)[key] = struct{}{}
		mu.Unlock()

		props := map[string]string{
			"source":     "email_enum",
			"email":      email.Value,
			"confidence": fmt.Sprintf("%d", email.Confidence),
		}
		if email.FirstName != "" {
			props["first_name"] = email.FirstName
		}
		if email.LastName != "" {
			props["last_name"] = email.LastName
		}
		if email.Position != "" {
			props["position"] = email.Position
		}
		if email.Department != "" {
			props["department"] = email.Department
		}
		if email.Seniority != "" {
			props["seniority"] = email.Seniority
		}
		if email.Type != "" {
			props["email_type"] = email.Type
		}
		if email.LinkedIn != "" {
			props["linkedin"] = email.LinkedIn
		}
		if email.Twitter != "" {
			props["twitter"] = email.Twitter
		}
		if hunterResp.Data.Organization != "" {
			props["organization"] = hunterResp.Data.Organization
		}

		events = append(events, recon.NewEvent(domain, t.Name(), "email_found", props))

		// Collect name pairs for pattern inference
		if email.FirstName != "" && email.LastName != "" {
			namePairs = append(namePairs, namePair{
				first: strings.ToLower(email.FirstName),
				last:  strings.ToLower(email.LastName),
				email: strings.ToLower(email.Value),
			})
		}
	}

	// 3. Infer username patterns
	patterns := inferUsernamePatterns(namePairs, domain)
	for _, pat := range patterns {
		key := dedupeKey{target: domain, eventType: "email_pattern", value: pat.Format}
		mu.Lock()
		if _, dup := (*seen)[key]; dup {
			mu.Unlock()
			continue
		}
		(*seen)[key] = struct{}{}
		mu.Unlock()

		props := map[string]string{
			"source":       "email_enum",
			"pattern":      pat.Format,
			"confidence":   fmt.Sprintf("%.0f%%", pat.Confidence*100),
			"sample_count": fmt.Sprintf("%d/%d", pat.Matches, pat.Total),
		}
		// Include Hunter.io's reported pattern if available
		if hunterResp.Data.Pattern != "" {
			props["hunter_pattern"] = hunterResp.Data.Pattern
		}

		events = append(events, recon.NewEvent(domain, t.Name(), "email_pattern", props))
	}

	// 4. GitHub cross-reference for developer emails
	if githubKey != "" {
		githubEvents := t.crossRefGitHub(ctx, client, scanCtx, githubKey, domain, hunterResp.Data.Emails, seen, mu)
		events = append(events, githubEvents...)
	}

	return events
}

// queryHunter calls the Hunter.io domain-search API.
func (t *EmailEnumTool) queryHunter(ctx context.Context, client *http.Client, scanCtx *recon.ScanContext, apiKey, domain string) (*hunterDomainSearchResponse, error) {
	apiURL := fmt.Sprintf(
		"https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s&limit=100",
		domain, apiKey,
	)

	cfg := RetryConfig{
		MaxRetries:     3,
		BaseDelay:      2 * time.Second,
		MaxDelay:       30 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.25,
	}

	var resp *http.Response
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		limitHunterAPI()

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "BBPTS-Recon/1.0")

		headers := scanCtx.Headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		qg := scanCtx.QuotaGuard
		if qg != nil {
			qg.Increment("hunter")
		}

		r, err := client.Do(req)
		if err != nil {
			return true, err
		}

		if r.StatusCode == 429 {
			r.Body.Close()
			return true, fmt.Errorf("hunter.io rate limited: %d", r.StatusCode)
		}
		if r.StatusCode == 401 || r.StatusCode == 403 {
			r.Body.Close()
			return false, fmt.Errorf("hunter.io auth error: %d (check API key)", r.StatusCode)
		}
		if r.StatusCode != 200 {
			r.Body.Close()
			return r.StatusCode >= 500, fmt.Errorf("hunter.io request failed: %d", r.StatusCode)
		}

		resp = r
		return false, nil
	})

	if err != nil || resp == nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result hunterDomainSearchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&result); err != nil {
		return nil, fmt.Errorf("hunter.io decode error: %w", err)
	}
	return &result, nil
}

// inferUsernamePatterns analyzes (first, last, email) triples to detect patterns.
func inferUsernamePatterns(pairs []namePair, domain string) []usernamePattern {
	if len(pairs) < 2 {
		return nil
	}

	suffix := "@" + strings.ToLower(domain)
	results := make(map[string]int)
	total := 0

	for _, pair := range pairs {
		if !strings.HasSuffix(pair.email, suffix) {
			continue
		}
		localPart := strings.TrimSuffix(pair.email, suffix)
		if localPart == "" || pair.first == "" || pair.last == "" {
			continue
		}

		total++
		for format, gen := range patternGenerators {
			expected := gen(pair.first, pair.last)
			if localPart == expected {
				results[format]++
			}
		}
	}

	if total == 0 {
		return nil
	}

	// Sort by match count descending
	type kv struct {
		format  string
		matches int
	}
	var sorted []kv
	for f, m := range results {
		if m > 0 {
			sorted = append(sorted, kv{format: f, matches: m})
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].matches > sorted[j].matches
	})

	// Return patterns with >20% match rate
	var patterns []usernamePattern
	for _, s := range sorted {
		confidence := float64(s.matches) / float64(total)
		if confidence < 0.2 {
			continue
		}
		patterns = append(patterns, usernamePattern{
			Format:     s.format,
			Confidence: confidence,
			Matches:    s.matches,
			Total:      total,
		})
	}
	return patterns
}

// crossRefGitHub searches GitHub for developer accounts matching discovered emails.
func (t *EmailEnumTool) crossRefGitHub(
	ctx context.Context,
	client *http.Client,
	scanCtx *recon.ScanContext,
	githubKey, domain string,
	emails []hunterEmail,
	seen *map[dedupeKey]struct{},
	mu *sync.Mutex,
) []recon.Event {
	var events []recon.Event

	// Filter to likely developer emails (engineering/IT departments or generic)
	var devEmails []hunterEmail
	for _, email := range emails {
		dept := strings.ToLower(email.Department)
		pos := strings.ToLower(email.Position)
		isDev := dept == "" || // Unknown dept — include
			strings.Contains(dept, "engineering") ||
			strings.Contains(dept, "it") ||
			strings.Contains(dept, "technology") ||
			strings.Contains(dept, "development") ||
			strings.Contains(dept, "security") ||
			strings.Contains(pos, "engineer") ||
			strings.Contains(pos, "developer") ||
			strings.Contains(pos, "devops") ||
			strings.Contains(pos, "sre") ||
			strings.Contains(pos, "architect") ||
			strings.Contains(pos, "cto") ||
			strings.Contains(pos, "security")
		if isDev && email.Value != "" {
			devEmails = append(devEmails, email)
		}
	}

	// Cap at 10 lookups to stay within GitHub rate limits
	if len(devEmails) > 10 {
		devEmails = devEmails[:10]
	}

	for _, email := range devEmails {
		select {
		case <-ctx.Done():
			return events
		default:
		}

		users, err := searchGitHubUser(ctx, client, scanCtx, githubKey, email.Value)
		if err != nil {
			slog.Debug("email_enum github user search failed", "email", email.Value, "error", err)
			continue
		}

		for _, user := range users {
			key := dedupeKey{target: domain, eventType: "github_account", value: user.Login}
			mu.Lock()
			if _, dup := (*seen)[key]; dup {
				mu.Unlock()
				continue
			}
			(*seen)[key] = struct{}{}
			mu.Unlock()

			props := map[string]string{
				"source":      "email_enum",
				"email":       email.Value,
				"github_user": user.Login,
				"github_url":  user.HTMLURL,
				"public_repos": fmt.Sprintf("%d", user.PublicRepos),
			}
			if email.FirstName != "" || email.LastName != "" {
				props["name"] = strings.TrimSpace(email.FirstName + " " + email.LastName)
			}
			if email.Position != "" {
				props["position"] = email.Position
			}

			events = append(events, recon.NewEvent(domain, t.Name(), "github_account", props))
		}
	}

	return events
}

// searchGitHubUser queries the GitHub Users search API for an email address.
func searchGitHubUser(ctx context.Context, client *http.Client, scanCtx *recon.ScanContext, apiKey, email string) ([]githubUserItem, error) {
	apiURL := fmt.Sprintf("https://api.github.com/search/users?q=%s+in:email&per_page=5", email)

	cfg := RetryConfig{
		MaxRetries:     2,
		BaseDelay:      3 * time.Second,
		MaxDelay:       15 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.2,
	}

	var resp *http.Response
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		limitGithubSearch()

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "token "+apiKey)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		headers := scanCtx.Headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		qg := scanCtx.QuotaGuard
		if qg != nil {
			qg.Increment("github")
		}

		r, err := client.Do(req)
		if err != nil {
			return true, err
		}

		if r.StatusCode == 403 || r.StatusCode == 429 {
			r.Body.Close()
			return true, fmt.Errorf("github rate limited: %d", r.StatusCode)
		}
		if r.StatusCode != 200 {
			r.Body.Close()
			return false, fmt.Errorf("github user search failed: %d", r.StatusCode)
		}

		resp = r
		return false, nil
	})

	if err != nil || resp == nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result githubUserSearchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5*1024*1024)).Decode(&result); err != nil {
		return nil, fmt.Errorf("github user search decode error: %w", err)
	}
	return result.Items, nil
}
