package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Parameter represents a parameter extracted from the Swagger/OpenAPI spec.
type Parameter struct {
	Name     string
	In       string // "query", "path", "header", "body", "formData"
	Required bool
	Type     string
}

// SwaggerParser handles fetching and parsing Swagger v2/OpenAPI v3 specs.
type SwaggerParser struct {
	client *http.Client
}

// NewSwaggerParser creates a new SwaggerParser instance.
func NewSwaggerParser(timeout time.Duration) *SwaggerParser {
	return &SwaggerParser{
		client: NewSafeHTTPClient(timeout),
	}
}

// FetchAndParse downloads and parses an OpenAPI/Swagger spec.
func (p *SwaggerParser) FetchAndParse(ctx context.Context, specURL string) ([]Event, []string, error) {
	u, err := url.Parse(specURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid spec URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", specURL, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch spec: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code fetching spec: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read spec: %w", err)
	}

	return p.Parse(body, u)
}

// Parse extracts endpoints, params, and auth schemes from raw spec content.
func (p *SwaggerParser) Parse(specContent []byte, parsedSpecURL *url.URL) ([]Event, []string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(specContent, &data); err != nil {
		if errYaml := yaml.Unmarshal(specContent, &data); errYaml != nil {
			return nil, nil, fmt.Errorf("failed to parse spec as JSON or YAML: %w", errYaml)
		}
	}

	baseURL := p.resolveBaseURL(parsedSpecURL, data)
	securitySchemes := p.extractSecuritySchemes(data)

	var rootSecurity []interface{}
	if rs, ok := data["security"].([]interface{}); ok {
		rootSecurity = rs
	}

	pathsObj, ok := data["paths"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("spec does not contain a valid 'paths' object")
	}

	events := []Event{}
	targetURLs := []string{}

	// Emit events for the security schemes discovered
	for name, scheme := range securitySchemes {
		props := map[string]string{
			"type":        "auth_scheme",
			"scheme_name": name,
		}
		if t, found := scheme["type"]; found {
			props["scheme_type"] = t
		}
		if inLoc, found := scheme["in"]; found {
			props["in"] = inLoc
		}
		if paramName, found := scheme["name"]; found {
			props["name"] = paramName
		}
		if desc, found := scheme["description"]; found {
			props["description"] = desc
		}

		events = append(events, NewEvent(parsedSpecURL.String(), "swagger_parser", "discovery", props))
	}

	pathParamRegex := regexp.MustCompile(`\{([^}]+)\}`)

	for pathStr, pathVal := range pathsObj {
		pathMap, ok := pathVal.(map[string]interface{})
		if !ok {
			continue
		}

		pathParameters := p.extractParameters(pathMap["parameters"])

		for method, methodVal := range pathMap {
			methodLower := strings.ToLower(method)
			if methodLower != "get" && methodLower != "post" && methodLower != "put" && methodLower != "delete" &&
				methodLower != "options" && methodLower != "head" && methodLower != "patch" && methodLower != "trace" {
				continue
			}

			methodMap, ok := methodVal.(map[string]interface{})
			if !ok {
				continue
			}

			methodParameters := p.extractParameters(methodMap["parameters"])
			params := p.mergeParameters(pathParameters, methodParameters)

			// OpenAPI 3.0 requestBody schema parameters extraction
			if requestBody, ok := methodMap["requestBody"].(map[string]interface{}); ok {
				if content, ok := requestBody["content"].(map[string]interface{}); ok {
					for _, mediaVal := range content {
						if mtMap, ok := mediaVal.(map[string]interface{}); ok {
							if schema, ok := mtMap["schema"].(map[string]interface{}); ok {
								if properties, ok := schema["properties"].(map[string]interface{}); ok {
									for propName, propVal := range properties {
										pType := ""
										if propMap, ok := propVal.(map[string]interface{}); ok {
											pType, _ = propMap["type"].(string)
										}
										params = append(params, Parameter{
											Name: propName,
											In:   "body",
											Type: pType,
										})
									}
								}
							}
						}
					}
				}
			}

			authSchemes := p.getAuthSchemesForOperation(rootSecurity, methodMap)

			// Construct URL with replaced path parameters
			resolvedPath := pathStr
			for _, p := range params {
				if p.In == "path" {
					placeholder := "1"
					if p.Type == "string" {
						placeholder = "test"
					}
					resolvedPath = strings.ReplaceAll(resolvedPath, "{"+p.Name+"}", placeholder)
				}
			}
			resolvedPath = pathParamRegex.ReplaceAllString(resolvedPath, "1")

			// Construct query parameters
			var queryParts []string
			var paramNames []string
			for _, p := range params {
				paramNames = append(paramNames, p.Name)
				if p.In == "query" {
					val := "test"
					if p.Type == "integer" || p.Type == "number" {
						val = "1"
					}
					queryParts = append(queryParts, url.QueryEscape(p.Name)+"="+url.QueryEscape(val))
				}
			}

			fullURL := strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimPrefix(resolvedPath, "/")
			targetURLs = append(targetURLs, fullURL)

			if len(queryParts) > 0 {
				fullURLWithQuery := fullURL + "?" + strings.Join(queryParts, "&")
				targetURLs = append(targetURLs, fullURLWithQuery)
			}

			props := map[string]string{
				"path":   pathStr,
				"method": strings.ToUpper(method),
				"source": parsedSpecURL.String(),
			}
			if len(paramNames) > 0 {
				props["params"] = strings.Join(paramNames, ",")
			}
			if len(authSchemes) > 0 {
				props["auth"] = strings.Join(authSchemes, ",")
			}

			events = append(events, NewEvent(fullURL, "swagger_parser", "api_endpoint", props))
		}
	}

	return events, targetURLs, nil
}

func (p *SwaggerParser) resolveBaseURL(parsedSpecURL *url.URL, data map[string]interface{}) string {
	scheme := parsedSpecURL.Scheme
	host := parsedSpecURL.Host
	basePath := ""

	// Check OpenAPI 3.x servers
	if servers, ok := data["servers"].([]interface{}); ok && len(servers) > 0 {
		if serverMap, ok := servers[0].(map[string]interface{}); ok {
			if sURL, ok := serverMap["url"].(string); ok && sURL != "" {
				u, err := url.Parse(sURL)
				if err == nil {
					if u.IsAbs() {
						return sURL
					}
					basePath = u.Path
					if u.Host != "" {
						host = u.Host
					}
					if u.Scheme != "" {
						scheme = u.Scheme
					}
				}
			}
		}
	}

	// Check Swagger 2.0 host, basePath, schemes
	if sHost, ok := data["host"].(string); ok && sHost != "" {
		host = sHost
	}
	if sBasePath, ok := data["basePath"].(string); ok && sBasePath != "" {
		basePath = sBasePath
	}
	if schemes, ok := data["schemes"].([]interface{}); ok && len(schemes) > 0 {
		if firstScheme, ok := schemes[0].(string); ok && firstScheme != "" {
			scheme = firstScheme
		}
	}

	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	basePath = strings.TrimSuffix(basePath, "/")

	return fmt.Sprintf("%s://%s%s", scheme, host, basePath)
}

func (p *SwaggerParser) extractSecuritySchemes(data map[string]interface{}) map[string]map[string]string {
	schemes := make(map[string]map[string]string)

	if defs, ok := data["securityDefinitions"].(map[string]interface{}); ok {
		for name, val := range defs {
			if sMap, ok := val.(map[string]interface{}); ok {
				schemes[name] = p.parseSecurityScheme(sMap)
			}
		}
	}

	if components, ok := data["components"].(map[string]interface{}); ok {
		if defs, ok := components["securitySchemes"].(map[string]interface{}); ok {
			for name, val := range defs {
				if sMap, ok := val.(map[string]interface{}); ok {
					schemes[name] = p.parseSecurityScheme(sMap)
				}
			}
		}
	}

	return schemes
}

func (p *SwaggerParser) parseSecurityScheme(sMap map[string]interface{}) map[string]string {
	res := make(map[string]string)
	for k, v := range sMap {
		if strVal, ok := v.(string); ok {
			res[k] = strVal
		}
	}
	return res
}

func (p *SwaggerParser) extractParameters(paramsVal interface{}) []Parameter {
	var params []Parameter
	list, ok := paramsVal.([]interface{})
	if !ok {
		return nil
	}
	for _, item := range list {
		pMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := pMap["name"].(string)
		in, _ := pMap["in"].(string)
		required, _ := pMap["required"].(bool)
		pType, _ := pMap["type"].(string)
		if pType == "" {
			if schemaMap, ok := pMap["schema"].(map[string]interface{}); ok {
				pType, _ = schemaMap["type"].(string)
			}
		}
		if name != "" {
			params = append(params, Parameter{
				Name:     name,
				In:       in,
				Required: required,
				Type:     pType,
			})
		}
	}
	return params
}

func (p *SwaggerParser) mergeParameters(pathParams, methodParams []Parameter) []Parameter {
	merged := make(map[string]Parameter)
	for _, p := range pathParams {
		key := p.In + ":" + p.Name
		merged[key] = p
	}
	for _, p := range methodParams {
		key := p.In + ":" + p.Name
		merged[key] = p
	}

	res := make([]Parameter, 0, len(merged))
	for _, p := range merged {
		res = append(res, p)
	}
	return res
}

func (p *SwaggerParser) getAuthSchemesForOperation(rootSecurity []interface{}, opMap map[string]interface{}) []string {
	sec := rootSecurity
	if opSec, ok := opMap["security"].([]interface{}); ok {
		sec = opSec
	}
	if len(sec) == 0 {
		return []string{"none"}
	}
	var schemes []string
	for _, req := range sec {
		if reqMap, ok := req.(map[string]interface{}); ok {
			for k := range reqMap {
				schemes = append(schemes, k)
			}
		}
	}
	if len(schemes) == 0 {
		return []string{"none"}
	}
	return schemes
}
