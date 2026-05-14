package services

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
)

// GraphQLScanner represents a module that attempts to discover and introspect GraphQL endpoints.
type GraphQLScanner struct {
	client *network.StealthClient
}

func NewGraphQLScanner() Tool {
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	client, _ := network.NewStealthClient(profile, "")
	return &GraphQLScanner{client: client}
}

func (g *GraphQLScanner) Name() string {
	return "graphql"
}

// commonGraphQLEndpoints lists typical paths where GraphQL APIs are hosted.
var commonGraphQLEndpoints = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/v2/graphql",
	"/graphql/v1",
	"/graphql/api",
	"/graphql/console",
}

// introspectionQuery is the standard query to fetch the entire GraphQL schema.
const introspectionQuery = `
	query IntrospectionQuery {
		__schema {
			queryType { name }
			mutationType { name }
			subscriptionType { name }
			types {
				...FullType
			}
		}
	}
	fragment FullType on __Type {
		kind
		name
		fields(includeDeprecated: true) {
			name
		}
	}
`

// Run executes the GraphQL scanner across the provided targets.
func (g *GraphQLScanner) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	results := make(chan Event, len(targets)*len(commonGraphQLEndpoints))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	proxies := GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}
	// Re-initialize client with correct proxy for this tool run.
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	g.client, _ = network.NewStealthClient(profile, proxy)

	for _, target := range targets {
		if !strings.HasPrefix(target, "http") {
			continue // GraphQL only runs over HTTP/S
		}

		target = strings.TrimRight(target, "/")

		for _, endpoint := range commonGraphQLEndpoints {
			url := target + endpoint
			wg.Add(1)

			go func(testURL string) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				found, schemaPreview, err := g.testEndpoint(ctx, testURL)
				if err != nil {
					slog.Debug("GraphQL test failed", "url", testURL, "error", err)
					return
				}

				if found {
					slog.Info("Discovered GraphQL endpoint", "url", testURL)
					props := map[string]string{
						"endpoint": testURL,
					}
					if schemaPreview != "" {
						props["schema_preview"] = schemaPreview
					}
					results <- NewEvent(testURL, g.Name(), "graphql_endpoint", props)
				}

			}(url)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var events []Event
	for res := range results {
		events = append(events, res)
	}

	return events, nil
}

func (g *GraphQLScanner) testEndpoint(ctx context.Context, url string) (bool, string, error) {
	payload := map[string]string{
		"query": introspectionQuery,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, "", nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	// Simple heuristic: if the response contains "__schema" or "data", it's likely a valid introspection result.
	if bytes.Contains(respBody, []byte(`"__schema"`)) || bytes.Contains(respBody, []byte(`"data"`)) {
		// Provide a small preview of the schema (first 500 chars) to avoid blowing up the DB
		preview := string(respBody)
		if len(preview) > 500 {
			preview = preview[:500] + "...(truncated)"
		}
		return true, preview, nil
	}

	return false, "", nil
}
