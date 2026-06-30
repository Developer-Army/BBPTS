// Package recon provides reconnaissance domain logic
package recon

import (
	"strings"
)

var NucleiTagMapping = map[string][]string{

	"exposed-secrets":   {"exposure", "token", "config"},
	"source-disclosure": {"git", "exposure", "config"},
	"backup-file":       {"backup", "exposure"},
	"graphql":           {"graphql", "introspection"},
	"admin-panel":       {"panel", "login", "default-login"},
	"ci-exposure":       {"jenkins", "ci", "devops"},
	"api-docs":          {"swagger", "openapi"},
	"db-exposure":       {"phpmyadmin", "mysql", "database"},
	"cloud-storage":     {"s3", "aws", "bucket"},
	"dev-environment":   {"debug", "exposure", "config"},

	"api":            {"api", "graphql", "swagger"},
	"auth":           {"login", "default-login", "brute-force", "auth-bypass"},
	"parameterized":  {"sqli", "xss", "ssti", "lfi", "rfi", "ssrf"},
	"subdomain":      {"subdomain-takeover", "cname"},
	"infrastructure": {"tech-detect", "waf-detect"},
}

var NucleiSeverityForPriority = map[string][]string{
	"critical": {"info", "low", "medium", "high", "critical"},
	"high":     {"low", "medium", "high", "critical"},
	"medium":   {"medium", "high", "critical"},
	"low":      {"high", "critical"},
}

func ResolveTags(bbptsTags []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, tag := range bbptsTags {
		nucleiTags, ok := NucleiTagMapping[strings.ToLower(tag)]
		if !ok {
			continue
		}
		for _, nt := range nucleiTags {
			if _, exists := seen[nt]; exists {
				continue
			}
			seen[nt] = struct{}{}
			result = append(result, nt)
		}
	}

	return result
}

func ResolveSeverity(priority string) []string {
	if sevs, ok := NucleiSeverityForPriority[strings.ToLower(priority)]; ok {
		return sevs
	}
	return []string{"high", "critical"}
}

var NucleiTemplateSubsetMapping = map[string][]string{
	"wordpress":   {"wp-*"},
	"laravel":     {"php-*"},
	"drupal":      {"drupal-*"},
	"joomla":      {"joomla-*"},
	"jenkins":     {"jenkins-*"},
	"confluence":  {"confluence-*"},
	"gitlab":      {"gitlab-*"},
	"grafana":     {"grafana-*"},
	"kibana":      {"kibana-*"},
	"jupyter":     {"jupyter-*"},
	"shopify":     {"shopify-*"},
	"magento":     {"magento-*"},
	"django":      {"django-*", "python-*"},
	"rails":       {"rails-*", "ruby-*"},
	"express":     {"node-*", "js-*"},
	"spring boot": {"spring-*", "java-*"},
	"asp.net":     {"aspnet-*", "dotnet-*"},
	"okta":        {"okta-*"},
	"auth0":       {"auth0-*"},
	"keycloak":    {"keycloak-*"},
}

func ResolveTemplateSubsets(techs []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, tech := range techs {
		subsets, ok := NucleiTemplateSubsetMapping[strings.ToLower(strings.TrimSpace(tech))]
		if !ok {
			continue
		}
		for _, sub := range subsets {
			if _, exists := seen[sub]; exists {
				continue
			}
			seen[sub] = struct{}{}
			result = append(result, sub)
		}
	}

	return result
}
