package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func NewGraphQLScanner() recon.Tool {
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	client, err := network.NewStealthClient(profile, "")
	if err != nil {
		slog.Warn("Failed to create stealth client in graphql constructor", "error", err)
	}
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
				kind
				name
				fields(includeDeprecated: true) {
					name
					type {
						name
						kind
						ofType {
							name
							kind
						}
					}
					args {
						name
						type {
							name
							kind
							ofType {
								name
								kind
							}
						}
					}
				}
			}
		}
	}
`

// Bypass probes for when standard introspection is blocked.
const (
	suggestionProbe = `{"query":"{ __typename }"}`
	aliasBypassQuery = `{"query":"query{__schema{queryType{name}}}"}` // Works with some WAFs that block __schema without alias
)

type TypeInfo struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Fields []struct {
		Name string `json:"name"`
		Type struct {
			Name   string `json:"name"`
			Kind   string `json:"kind"`
			OfType *struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"ofType"`
		} `json:"type"`
		Args []struct {
			Name string `json:"name"`
			Type struct {
				Name   string `json:"name"`
				Kind   string `json:"kind"`
				OfType *struct {
					Name string `json:"name"`
					Kind string `json:"kind"`
				} `json:"ofType"`
			} `json:"type"`
		} `json:"args"`
	} `json:"fields"`
}

type IntrospectionData struct {
	Schema struct {
		QueryType        struct{ Name string } `json:"queryType"`
		MutationType     struct{ Name string } `json:"mutationType"`
		SubscriptionType struct{ Name string } `json:"subscriptionType"`
		Types            []TypeInfo            `json:"types"`
	} `json:"__schema"`
}

// Run executes the GraphQL scanner across the provided targets.
func (g *GraphQLScanner) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	results := make(chan recon.Event, len(targets)*len(commonGraphQLEndpoints)*4)
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	proxies := recon.GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}
	// Re-initialize client with correct proxy for this tool run.
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	var errClient error
	g.client, errClient = network.NewStealthClient(profile, proxy)
	if errClient != nil {
		slog.Warn("Failed to recreate stealth client with proxy", "proxy", proxy, "error", errClient)
	} else if g.client != nil {
		g.client.SetCustomHeaders(scanCtx.Headers)
	}

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

				found, schema, rawSchema, err := g.testEndpoint(ctx, testURL)
				if err != nil {
					slog.Debug("GraphQL test failed", "url", testURL, "error", err)
					return
				}

				if found {
					slog.Info("Discovered GraphQL endpoint", "url", testURL)
					props := map[string]string{
						"endpoint": testURL,
					}
					if rawSchema != "" {
						props["schema_preview"] = rawSchema
					}
					results <- recon.NewEvent(testURL, g.Name(), "graphql_endpoint", props)

					// Perform security checks if schema successfully parsed
					if schema != nil {
						// 1. GraphQL Introspection Enabled Finding
						results <- recon.NewEventWithSeverity(testURL, g.Name(), "vulnerability", map[string]string{
							"vuln_name":   "GraphQL Introspection Enabled",
							"severity":    "medium",
							"description": fmt.Sprintf("GraphQL Introspection is enabled on production endpoint %s, revealing the full schema.", testURL),
						}, "medium")

						// 2. Batching Check
						if ok, bErr := g.checkBatching(ctx, testURL); bErr == nil && ok {
							results <- recon.NewEventWithSeverity(testURL, g.Name(), "vulnerability", map[string]string{
								"vuln_name":   "GraphQL Query Batching Enabled",
								"severity":    "low",
								"description": fmt.Sprintf("The GraphQL endpoint at %s accepts multiple queries in a single request, which can bypass rate-limiting controls.", testURL),
							}, "low")
						}

						// 3. Mutation Auth Bypass Check
						if ok, q, mErr := g.checkMutationBypass(ctx, testURL, schema.Schema.MutationType.Name, schema.Schema.Types); mErr == nil && ok {
							results <- recon.NewEventWithSeverity(testURL, g.Name(), "vulnerability", map[string]string{
								"vuln_name":   "GraphQL Mutation Authorization Bypass",
								"severity":    "high",
								"query":       q,
								"description": fmt.Sprintf("A GraphQL mutation query was successfully executed without authentication headers on %s.", testURL),
							}, "high")
						}

						// 4. IDOR Check
						if ok, q, iErr := g.checkIDOR(ctx, testURL, schema.Schema.QueryType.Name, schema.Schema.Types); iErr == nil && ok {
							results <- recon.NewEventWithSeverity(testURL, g.Name(), "vulnerability", map[string]string{
								"vuln_name":   "GraphQL IDOR via Query Arguments",
								"severity":    "high",
								"query":       q,
								"description": fmt.Sprintf("Sensitive data was retrieved via GraphQL query arguments with guest privileges on %s, suggesting an IDOR vulnerability.", testURL),
							}, "high")
						}
					}
				}

			}(url)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var events []recon.Event
	for res := range results {
		events = append(events, res)
	}

	return events, nil
}

func (g *GraphQLScanner) testEndpoint(ctx context.Context, url string) (bool, *IntrospectionData, string, error) {
	// Try multiple introspection methods including bypass techniques
	probes := []struct {
		name    string
		method  string
		payload string
	}{
		{"standard_post", http.MethodPost, fmt.Sprintf(`{"query":"%s"}`, introspectionQuery)},
		{"suggestion_probe", http.MethodPost, suggestionProbe},
		{"alias_bypass", http.MethodPost, aliasBypassQuery},
		{"get_introspection", http.MethodGet, ""},
	}

	for _, probe := range probes {
		found, schema, rawSchema, err := g.sendProbe(ctx, url, probe.method, probe.payload)
		if err != nil {
			slog.Debug("GraphQL probe failed", "url", url, "probe", probe.name, "error", err)
			continue
		}
		if found {
			return found, schema, rawSchema, nil
		}
	}

	return false, nil, "", nil
}

func (g *GraphQLScanner) sendProbe(ctx context.Context, url, method, payload string) (bool, *IntrospectionData, string, error) {
	var req *http.Request
	var err error

	if method == http.MethodGet {
		// GET-based introspection: ?query={__schema{types{name}}}
		getQuery := `query{__schema{types{name}}}`
		req, err = http.NewRequestWithContext(ctx, method, url+"?query="+getQuery, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewBufferString(payload))
	}
	if err != nil {
		return false, nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return false, nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, nil, "", nil
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return false, nil, "", err
	}

	// Stricter check: response must contain introspection-specific fields,
	// not just generic "data" which could be any JSON API echoing back.
	hasIntrospection := bytes.Contains(respBody, []byte(`"__schema"`)) ||
		bytes.Contains(respBody, []byte(`"queryType"`)) ||
		bytes.Contains(respBody, []byte(`"types"`))
	if !hasIntrospection {
		return false, nil, "", nil
	}

	var parsed struct {
		Data IntrospectionData `json:"data"`
	}
	schemaParsed := &parsed.Data
	if errJSON := json.Unmarshal(respBody, &parsed); errJSON != nil {
		schemaParsed = nil
	}

	preview := string(respBody)
	if len(preview) > 1000 {
		preview = preview[:1000] + "...(truncated)"
	}
	return true, schemaParsed, preview, nil
}

func (g *GraphQLScanner) checkBatching(ctx context.Context, endpoint string) (bool, error) {
	const batchProbeSize = 100
	payload := make([]map[string]string, 0, batchProbeSize)
	for i := 0; i < batchProbeSize; i++ {
		payload = append(payload, map[string]string{"query": "{ __typename }"})
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return false, err
	}

	var results []interface{}
	if err := json.Unmarshal(respBody, &results); err == nil && len(results) >= batchProbeSize {
		return true, nil
	}
	return false, nil
}

func (g *GraphQLScanner) checkMutationBypass(ctx context.Context, endpoint string, mutationType string, types []TypeInfo) (bool, string, error) {
	if mutationType == "" {
		return false, "", nil
	}

	var mutType *TypeInfo
	for i := range types {
		if types[i].Name == mutationType {
			mutType = &types[i]
			break
		}
	}

	if mutType == nil || len(mutType.Fields) == 0 {
		return false, "", nil
	}

	field := mutType.Fields[0]
	queryStr := ""
	typeName := field.Type.Name
	if typeName == "" && field.Type.OfType != nil {
		typeName = field.Type.OfType.Name
	}

	if isScalar(typeName) {
		queryStr = fmt.Sprintf("mutation { %s }", field.Name)
	} else {
		queryStr = fmt.Sprintf("mutation { %s { id } }", field.Name)
	}

	payload := map[string]string{
		"query": queryStr,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return false, "", err
	}

	var respJSON struct {
		Data   interface{} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &respJSON); err != nil {
		return false, "", nil
	}

	hasAuthError := false
	for _, e := range respJSON.Errors {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "unauthenticated") ||
			strings.Contains(msg, "forbidden") || strings.Contains(msg, "denied") ||
			strings.Contains(msg, "login") || strings.Contains(msg, "auth") {
			hasAuthError = true
			break
		}
	}

	if !hasAuthError && (respJSON.Data != nil || len(respJSON.Errors) == 0) {
		return true, queryStr, nil
	}

	return false, "", nil
}

func (g *GraphQLScanner) checkIDOR(ctx context.Context, endpoint string, queryType string, types []TypeInfo) (bool, string, error) {
	if queryType == "" {
		return false, "", nil
	}

	var qType *TypeInfo
	for i := range types {
		if types[i].Name == queryType {
			qType = &types[i]
			break
		}
	}

	if qType == nil {
		return false, "", nil
	}

	for _, field := range qType.Fields {
		var idArgName string
		for _, arg := range field.Args {
			nameLower := strings.ToLower(arg.Name)
			if strings.Contains(nameLower, "id") || strings.Contains(nameLower, "uuid") {
				idArgName = arg.Name
				break
			}
		}

		if idArgName == "" {
			continue
		}

		typeName := field.Type.Name
		if typeName == "" && field.Type.OfType != nil {
			typeName = field.Type.OfType.Name
		}

		queryStr := ""
		if isScalar(typeName) {
			queryStr = fmt.Sprintf("query { %s(%s: \"1\") }", field.Name, idArgName)
		} else {
			var retType *TypeInfo
			for i := range types {
				if types[i].Name == typeName {
					retType = &types[i]
					break
				}
			}

			selection := "id"
			if retType != nil {
				var scalarFields []string
				for _, f := range retType.Fields {
					fType := f.Type.Name
					if fType == "" && f.Type.OfType != nil {
						fType = f.Type.OfType.Name
					}
					if isScalar(fType) {
						scalarFields = append(scalarFields, f.Name)
						if len(scalarFields) >= 3 {
							break
						}
					}
				}
				if len(scalarFields) > 0 {
					selection = strings.Join(scalarFields, " ")
				}
			}
			queryStr = fmt.Sprintf("query { %s(%s: \"1\") { %s } }", field.Name, idArgName, selection)
		}

		payload := map[string]string{
			"query": queryStr,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return false, "", err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
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

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		if err != nil {
			return false, "", err
		}

		var respJSON struct {
			Data   map[string]interface{} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(respBody, &respJSON); err != nil {
			continue
		}

		hasAuthError := false
		for _, e := range respJSON.Errors {
			msg := strings.ToLower(e.Message)
			if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "unauthenticated") ||
				strings.Contains(msg, "forbidden") || strings.Contains(msg, "denied") {
				hasAuthError = true
				break
			}
		}

		if !hasAuthError && respJSON.Data != nil && respJSON.Data[field.Name] != nil {
			return true, queryStr, nil
		}
	}

	return false, "", nil
}

func isScalar(name string) bool {
	switch name {
	case "String", "Int", "Float", "Boolean", "ID":
		return true
	default:
		return false
	}
}

var _ recon.Tool = (*GraphQLScanner)(nil)
