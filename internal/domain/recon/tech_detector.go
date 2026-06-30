// Package recon provides reconnaissance domain logic
package recon

import (
	"strings"
)

type signature struct {
	tech           string
	category       string
	headerPatterns []string
	titlePatterns  []string
}

var signatures = []signature{

	{
		tech:           "cloudflare",
		category:       "waf",
		headerPatterns: []string{"cf-ray:", "__cf_bm=", "cf-cache-status:"},
	},
	{
		tech:           "aws waf",
		category:       "waf",
		headerPatterns: []string{"awselb", "awsalb=", "x-amz-"},
	},
	{
		tech:           "modsecurity",
		category:       "waf",
		headerPatterns: []string{"modsecurity", "x-security-waf"},
	},
	{
		tech:           "imperva",
		category:       "waf",
		headerPatterns: []string{"x-iinfo:", "visid_incap="},
	},
	{
		tech:           "sucuri",
		category:       "waf",
		headerPatterns: []string{"x-sucuri-id", "sucuri"},
	},
	{
		tech:           "akamai waf",
		category:       "waf",
		headerPatterns: []string{"akamaighost"},
	},

	{
		tech:           "cloudflare",
		category:       "cdn",
		headerPatterns: []string{"cf-cache-status:", "server: cloudflare"},
	},
	{
		tech:           "fastly",
		category:       "cdn",
		headerPatterns: []string{"x-fastly-request-id", "x-served-by"},
	},
	{
		tech:           "akamai",
		category:       "cdn",
		headerPatterns: []string{"x-akamai-transformed"},
	},
	{
		tech:           "cloudfront",
		category:       "cdn",
		headerPatterns: []string{"cloudfront", "x-amz-cf-"},
	},

	{
		tech:           "wordpress",
		category:       "cms",
		headerPatterns: []string{"wp-settings-", "wordpress_", "x-pingback:"},
		titlePatterns:  []string{"wordpress"},
	},
	{
		tech:           "drupal",
		category:       "cms",
		headerPatterns: []string{"x-drupal-cache", "x-generator: drupal"},
		titlePatterns:  []string{"drupal"},
	},
	{
		tech:           "joomla",
		category:       "cms",
		headerPatterns: []string{"joomla_"},
		titlePatterns:  []string{"joomla"},
	},
	{
		tech:           "shopify",
		category:       "cms",
		headerPatterns: []string{"x-shopid", "x-shopify-"},
		titlePatterns:  []string{"shopify"},
	},
	{
		tech:           "magento",
		category:       "cms",
		headerPatterns: []string{"magento", "frontend=", "adminhtml="},
	},

	{
		tech:           "laravel",
		category:       "framework",
		headerPatterns: []string{"laravel_session="},
	},
	{
		tech:           "django",
		category:       "framework",
		headerPatterns: []string{"csrftoken=", "wsgiserver"},
	},
	{
		tech:           "next.js",
		category:       "framework",
		headerPatterns: []string{"x-powered-by: next.js"},
	},
	{
		tech:           "rails",
		category:       "framework",
		headerPatterns: []string{"_rails_admin_session", "x-rack-cache", "x-runtime"},
	},
	{
		tech:           "express",
		category:       "framework",
		headerPatterns: []string{"x-powered-by: express"},
	},
	{
		tech:           "spring boot",
		category:       "framework",
		headerPatterns: []string{"jsessionid="},
		titlePatterns:  []string{"whitelabel error page"},
	},
	{
		tech:           "asp.net",
		category:       "framework",
		headerPatterns: []string{"x-aspnet-version", "x-aspnetmvc-version", "asp.net_sessionid", "__requestverificationtoken"},
	},

	{
		tech:           "okta",
		category:       "auth",
		headerPatterns: []string{"x-okta-request-id", "okta-oauth-state"},
		titlePatterns:  []string{"okta"},
	},
	{
		tech:           "auth0",
		category:       "auth",
		headerPatterns: []string{"x-auth0-request-id"},
		titlePatterns:  []string{"auth0"},
	},
	{
		tech:           "keycloak",
		category:       "auth",
		headerPatterns: []string{"keycloak_identity", "keycloak_session"},
	},
}

func Detect(rawHeaders string, title string) []string {
	detected := make(map[string]bool)
	headersLower := strings.ToLower(rawHeaders)
	titleLower := strings.ToLower(title)

	for _, sig := range signatures {
		for _, hp := range sig.headerPatterns {
			if strings.Contains(headersLower, hp) {
				detected[sig.tech] = true
				break
			}
		}
		if !detected[sig.tech] && len(sig.titlePatterns) > 0 {
			for _, tp := range sig.titlePatterns {
				if strings.Contains(titleLower, tp) {
					detected[sig.tech] = true
					break
				}
			}
		}
	}

	result := make([]string, 0, len(detected))
	for tech := range detected {
		result = append(result, tech)
	}
	return result
}
