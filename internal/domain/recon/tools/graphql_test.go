package tools

import (
	"context"
	"encoding/json"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGraphQLScanner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		bodyBytes, _ := io.ReadAll(r.Body)
		bodyStr := string(bodyBytes)

		if strings.HasPrefix(bodyStr, "[") {
			w.WriteHeader(http.StatusOK)
			var reqArr []interface{}
			if err := json.Unmarshal(bodyBytes, &reqArr); err == nil {
				respArr := make([]string, len(reqArr))
				for i := range respArr {
					respArr[i] = `{"data":{"__typename":"Query"}}`
				}
				_, _ = w.Write([]byte("[" + strings.Join(respArr, ",") + "]"))
				return
			}
			_, _ = w.Write([]byte(`[{"data":{"__typename":"Query"}}, {"data":{"__typename":"Query"}}, {"data":{"__typename":"Query"}}]`))
			return
		}

		if strings.Contains(bodyStr, "IntrospectionQuery") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"data": {
					"__schema": {
						"queryType": { "name": "Query" },
						"mutationType": { "name": "Mutation" },
						"types": [
							{
								"name": "Query",
								"kind": "OBJECT",
								"fields": [
									{
										"name": "user",
										"type": { "name": "User", "kind": "OBJECT" },
										"args": [
											{ "name": "id", "type": { "name": "ID", "kind": "SCALAR" } }
										]
									}
								]
							},
							{
								"name": "Mutation",
								"kind": "OBJECT",
								"fields": [
									{
										"name": "createUser",
										"type": { "name": "User", "kind": "OBJECT" }
									}
								]
							},
							{
								"name": "User",
								"kind": "OBJECT",
								"fields": [
									{ "name": "id", "type": { "name": "ID", "kind": "SCALAR" } },
									{ "name": "name", "type": { "name": "String", "kind": "SCALAR" } }
								]
							}
						]
					}
				}
			}`))
			return
		}

		if strings.Contains(bodyStr, "mutation") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"data": {
					"createUser": { "id": "1" }
				}
			}`))
			return
		}

		if strings.Contains(bodyStr, "query") && strings.Contains(bodyStr, "user") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"data": {
					"user": { "id": "1", "name": "Test User" }
				}
			}`))
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	tool := &GraphQLScanner{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundIntrospection, foundBatching, foundMutation, foundIDOR bool
	for _, ev := range events {
		if ev.Type == "graphql_endpoint" {
			continue
		}
		name := ev.Properties["vuln_name"]
		switch name {
		case "GraphQL Introspection Enabled":
			foundIntrospection = true
		case "GraphQL Query Batching Enabled":
			foundBatching = true
		case "GraphQL Mutation Authorization Bypass":
			foundMutation = true
		case "GraphQL IDOR via Query Arguments":
			foundIDOR = true
		}
	}

	if !foundIntrospection {
		t.Error("expected to find GraphQL Introspection Enabled")
	}
	if !foundBatching {
		t.Error("expected to find GraphQL Query Batching Enabled")
	}
	if !foundMutation {
		t.Error("expected to find GraphQL Mutation Authorization Bypass")
	}
	if !foundIDOR {
		t.Error("expected to find GraphQL IDOR via Query Arguments")
	}
}
