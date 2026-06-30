package tools

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSwaggerParserJSON(t *testing.T) {
	swaggerJSON := `{
		"swagger": "2.0",
		"info": {
			"title": "Test Swagger JSON API",
			"version": "1.0.0"
		},
		"host": "api.test.local",
		"basePath": "/v1",
		"schemes": ["https"],
		"securityDefinitions": {
			"api_key": {
				"type": "apiKey",
				"name": "X-API-Key",
				"in": "header"
			}
		},
		"paths": {
			"/users/{id}": {
				"get": {
					"summary": "Get user",
					"security": [
						{
							"api_key": []
						}
					],
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"type": "integer"
						},
						{
							"name": "debug",
							"in": "query",
							"required": false,
							"type": "boolean"
						}
					]
				}
			}
		}
	}`

	parser := NewSwaggerParser(2 * time.Second)
	u, _ := url.Parse("https://api.test.local/v1/swagger.json")
	events, targets, err := parser.Parse([]byte(swaggerJSON), u)
	if err != nil {
		t.Fatalf("unexpected error parsing JSON: %v", err)
	}

	foundAuth := false
	for _, ev := range events {
		if ev.Type == "discovery" && ev.Properties["type"] == "auth_scheme" {
			foundAuth = true
			if ev.Properties["scheme_name"] != "api_key" || ev.Properties["scheme_type"] != "apiKey" || ev.Properties["name"] != "X-API-Key" || ev.Properties["in"] != "header" {
				t.Errorf("incorrect auth scheme event properties: %v", ev.Properties)
			}
		}
	}
	if !foundAuth {
		t.Error("expected auth scheme discovery event, not found")
	}

	foundEndpoint := false
	for _, ev := range events {
		if ev.Type == "api_endpoint" {
			foundEndpoint = true
			if ev.Properties["path"] != "/users/{id}" || ev.Properties["method"] != "GET" {
				t.Errorf("incorrect endpoint path or method: %v", ev.Properties)
			}
			if !strings.Contains(ev.Properties["params"], "id") || !strings.Contains(ev.Properties["params"], "debug") {
				t.Errorf("missing parameters in event: %v", ev.Properties["params"])
			}
			if ev.Properties["auth"] != "api_key" {
				t.Errorf("incorrect auth scheme on endpoint: %v", ev.Properties["auth"])
			}
		}
	}
	if !foundEndpoint {
		t.Error("expected api_endpoint event, not found")
	}

	hasQueryTarget := false
	hasBaseTarget := false
	for _, target := range targets {
		if target == "https://api.test.local/v1/users/1" {
			hasBaseTarget = true
		}
		if target == "https://api.test.local/v1/users/1?debug=test" {
			hasQueryTarget = true
		}
	}

	if !hasBaseTarget {
		t.Error("expected target 'https://api.test.local/v1/users/1' not found")
	}
	if !hasQueryTarget {
		t.Error("expected target 'https://api.test.local/v1/users/1?debug=test' not found")
	}
}

func TestSwaggerParserYAML(t *testing.T) {
	openapiYAML := `
openapi: 3.0.0
info:
  title: Test OpenAPI YAML API
  version: 1.0.0
servers:
  - url: /api/v2
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
paths:
  /search:
    get:
      summary: Search items
      security:
        - bearerAuth: []
      parameters:
        - name: q
          in: query
          required: true
          schema:
            type: string
        - name: limit
          in: query
          required: false
          schema:
            type: integer
`

	parser := NewSwaggerParser(2 * time.Second)
	u, _ := url.Parse("https://app.test.local/api-docs")
	events, targets, err := parser.Parse([]byte(openapiYAML), u)
	if err != nil {
		t.Fatalf("unexpected error parsing YAML: %v", err)
	}

	foundAuth := false
	for _, ev := range events {
		if ev.Type == "discovery" && ev.Properties["type"] == "auth_scheme" {
			foundAuth = true
			if ev.Properties["scheme_name"] != "bearerAuth" || ev.Properties["scheme_type"] != "http" {
				t.Errorf("incorrect auth scheme properties: %v", ev.Properties)
			}
		}
	}
	if !foundAuth {
		t.Error("expected auth scheme discovery event")
	}

	foundEndpoint := false
	for _, ev := range events {
		if ev.Type == "api_endpoint" {
			foundEndpoint = true
			if ev.Properties["path"] != "/search" || ev.Properties["method"] != "GET" {
				t.Errorf("incorrect endpoint path or method: %v", ev.Properties)
			}
			if ev.Properties["auth"] != "bearerAuth" {
				t.Errorf("incorrect auth scheme on endpoint: %v", ev.Properties["auth"])
			}
		}
	}
	if !foundEndpoint {
		t.Error("expected api_endpoint event")
	}

	hasQueryTarget := false
	for _, target := range targets {
		if strings.HasPrefix(target, "https://app.test.local/api/v2/search?") {
			if strings.Contains(target, "q=test") && strings.Contains(target, "limit=1") {
				hasQueryTarget = true
			}
		}
	}
	if !hasQueryTarget {
		t.Error("expected query targets containing parameters 'q' and 'limit' not found")
	}
}
