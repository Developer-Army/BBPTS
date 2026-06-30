package recon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type Introspector struct {
	client  *http.Client
	timeout time.Duration
	headers map[string]string
}

func NewIntrospector(timeout time.Duration) *Introspector {
	return &Introspector{
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
		headers: make(map[string]string),
	}
}

func (gi *Introspector) SetHeader(key, value string) {
	gi.headers[key] = value
}

const IntrospectionQuery = `
{
	__schema {
		queryType { name }
		mutationType { name }
		subscriptionType { name }
		types {
			name
			kind
			description
			fields {
				name
				type {
					name
					kind
					ofType {
						name
						kind
						ofType {
							name
							kind
							ofType {
								name
								kind
							}
						}
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
					defaultValue
					description
				}
				isDeprecated
				deprecationReason
				description
			}
			inputFields {
				name
				type {
					name
					kind
					ofType {
						name
						kind
					}
				}
				defaultValue
				description
			}
			enumValues {
				name
				description
				isDeprecated
				deprecationReason
			}
		}
		directives {
			name
			description
			locations
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
				defaultValue
				description
			}
		}
	}
}
`

type Schema struct {
	QueryType        string      `json:"queryType"`
	MutationType     string      `json:"mutationType"`
	SubscriptionType string      `json:"subscriptionType"`
	Types            []Type      `json:"types"`
	Directives       []Directive `json:"directives"`
}

type Type struct {
	Name        string       `json:"name"`
	Kind        string       `json:"kind"`
	Description string       `json:"description"`
	Fields      []Field      `json:"fields,omitempty"`
	InputFields []InputField `json:"inputFields,omitempty"`
	EnumValues  []EnumValue  `json:"enumValues,omitempty"`
}

type Field struct {
	Name              string  `json:"name"`
	Type              TypeRef `json:"type"`
	Args              []Arg   `json:"args"`
	IsDeprecated      bool    `json:"isDeprecated"`
	DeprecationReason string  `json:"deprecationReason,omitempty"`
	Description       string  `json:"description"`
}

type TypeRef struct {
	Name   string   `json:"name,omitempty"`
	Kind   string   `json:"kind"`
	OfType *TypeRef `json:"ofType,omitempty"`
}

type Arg struct {
	Name         string  `json:"name"`
	Type         TypeRef `json:"type"`
	DefaultValue string  `json:"defaultValue,omitempty"`
	Description  string  `json:"description"`
}

type InputField struct {
	Name         string  `json:"name"`
	Type         TypeRef `json:"type"`
	DefaultValue string  `json:"defaultValue,omitempty"`
	Description  string  `json:"description"`
}

type EnumValue struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	IsDeprecated      bool   `json:"isDeprecated"`
	DeprecationReason string `json:"deprecationReason,omitempty"`
}

type Directive struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Locations   []string `json:"locations"`
	Args        []Arg    `json:"args"`
}

type IntrospectionResponse struct {
	Data struct {
		Schema Schema `json:"__schema"`
	} `json:"data"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

type GraphQLError struct {
	Message string `json:"message"`
}

func (gi *Introspector) Introspect(endpoint string) (*Schema, error) {
	payload := map[string]string{
		"query": IntrospectionQuery,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal introspection query: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range gi.headers {
		req.Header.Set(k, v)
	}

	resp, err := gi.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute introspection query: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var response IntrospectionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL errors: %v", response.Errors)
	}

	slog.Info("GraphQL introspection successful",
		"endpoint", endpoint,
		"types", len(response.Data.Schema.Types),
		"directives", len(response.Data.Schema.Directives),
	)

	return &response.Data.Schema, nil
}

type SchemaAnalysis struct {
	Schema           *Schema
	QueryFields      []string
	MutationFields   []string
	SensitiveFields  []string
	DeprecatedFields []string
	EnumTypes        []string
	InputTypes       []string
}

func (gi *Introspector) Analyze(schema *Schema) *SchemaAnalysis {
	analysis := &SchemaAnalysis{
		Schema: schema,
	}

	for _, t := range schema.Types {

		if strings.HasPrefix(t.Name, "__") {
			continue
		}

		switch t.Kind {
		case "OBJECT":
			switch t.Name {
			case schema.QueryType:
				for _, field := range t.Fields {
					analysis.QueryFields = append(analysis.QueryFields, field.Name)
					if isSensitiveField(field.Name) {
						analysis.SensitiveFields = append(analysis.SensitiveFields, fmt.Sprintf("%s.%s", t.Name, field.Name))
					}
					if field.IsDeprecated {
						analysis.DeprecatedFields = append(analysis.DeprecatedFields, fmt.Sprintf("%s.%s", t.Name, field.Name))
					}
				}
			case schema.MutationType:
				for _, field := range t.Fields {
					analysis.MutationFields = append(analysis.MutationFields, field.Name)
					if isSensitiveField(field.Name) {
						analysis.SensitiveFields = append(analysis.SensitiveFields, fmt.Sprintf("%s.%s", t.Name, field.Name))
					}
					if field.IsDeprecated {
						analysis.DeprecatedFields = append(analysis.DeprecatedFields, fmt.Sprintf("%s.%s", t.Name, field.Name))
					}
				}
			default:

				for _, field := range t.Fields {
					if isSensitiveField(field.Name) {
						analysis.SensitiveFields = append(analysis.SensitiveFields, fmt.Sprintf("%s.%s", t.Name, field.Name))
					}
					if field.IsDeprecated {
						analysis.DeprecatedFields = append(analysis.DeprecatedFields, fmt.Sprintf("%s.%s", t.Name, field.Name))
					}
				}
			}
		case "ENUM":
			analysis.EnumTypes = append(analysis.EnumTypes, t.Name)
		case "INPUT_OBJECT":
			analysis.InputTypes = append(analysis.InputTypes, t.Name)
		}
	}

	slog.Info("GraphQL schema analysis complete",
		"query_fields", len(analysis.QueryFields),
		"mutation_fields", len(analysis.MutationFields),
		"sensitive_fields", len(analysis.SensitiveFields),
		"deprecated_fields", len(analysis.DeprecatedFields),
		"enum_types", len(analysis.EnumTypes),
		"input_types", len(analysis.InputTypes),
	)

	return analysis
}

func isSensitiveField(name string) bool {
	sensitiveKeywords := []string{
		"password", "token", "secret", "key", "auth", "credential",
		"api", "private", "internal", "admin", "user", "email",
		"phone", "ssn", "credit", "card", "payment", "bank",
	}

	lowerName := strings.ToLower(name)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerName, keyword) {
			return true
		}
	}

	return false
}

func (gi *Introspector) GenerateTestQueries(analysis *SchemaAnalysis) []string {
	var queries []string

	for _, field := range analysis.QueryFields {
		query := fmt.Sprintf("query { %s }", field)
		queries = append(queries, query)
	}

	for _, field := range analysis.MutationFields {
		mutation := fmt.Sprintf("mutation { %s }", field)
		queries = append(queries, mutation)
	}

	queries = append(queries, IntrospectionQuery)

	return queries
}

func (sa *SchemaAnalysis) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# GraphQL Schema Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Query Type:** %s\n\n", sa.Schema.QueryType))
	sb.WriteString(fmt.Sprintf("**Mutation Type:** %s\n\n", sa.Schema.MutationType))
	sb.WriteString(fmt.Sprintf("**Subscription Type:** %s\n\n", sa.Schema.SubscriptionType))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Query Fields:** %d\n", len(sa.QueryFields)))
	sb.WriteString(fmt.Sprintf("- **Mutation Fields:** %d\n", len(sa.MutationFields)))
	sb.WriteString(fmt.Sprintf("- **Sensitive Fields:** %d\n", len(sa.SensitiveFields)))
	sb.WriteString(fmt.Sprintf("- **Deprecated Fields:** %d\n", len(sa.DeprecatedFields)))
	sb.WriteString(fmt.Sprintf("- **Enum Types:** %d\n", len(sa.EnumTypes)))
	sb.WriteString(fmt.Sprintf("- **Input Types:** %d\n\n", len(sa.InputTypes)))

	if len(sa.QueryFields) > 0 {
		sb.WriteString("## Query Fields\n\n")
		for _, field := range sa.QueryFields {
			sb.WriteString(fmt.Sprintf("- `%s`\n", field))
		}
		sb.WriteString("\n")
	}

	if len(sa.MutationFields) > 0 {
		sb.WriteString("## Mutation Fields\n\n")
		for _, field := range sa.MutationFields {
			sb.WriteString(fmt.Sprintf("- `%s`\n", field))
		}
		sb.WriteString("\n")
	}

	if len(sa.SensitiveFields) > 0 {
		sb.WriteString("## Sensitive Fields\n\n")
		for _, field := range sa.SensitiveFields {
			sb.WriteString(fmt.Sprintf("- `%s` ️\n", field))
		}
		sb.WriteString("\n")
	}

	if len(sa.DeprecatedFields) > 0 {
		sb.WriteString("## Deprecated Fields\n\n")
		for _, field := range sa.DeprecatedFields {
			sb.WriteString(fmt.Sprintf("- `%s` 🗑️\n", field))
		}
		sb.WriteString("\n")
	}

	if len(sa.EnumTypes) > 0 {
		sb.WriteString("## Enum Types\n\n")
		for _, enumType := range sa.EnumTypes {
			sb.WriteString(fmt.Sprintf("- `%s`\n", enumType))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func (sa *SchemaAnalysis) ToJSON() (string, error) {
	data, err := json.MarshalIndent(sa, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
