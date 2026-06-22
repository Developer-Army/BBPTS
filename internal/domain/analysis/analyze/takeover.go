package analyze

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// TakeoverAnalyzer detects potential subdomain takeovers by resolving CNAME records
// and matching them against signatures of vulnerable SaaS platforms.
type TakeoverAnalyzer struct {
	cache       map[string]string
	lookupCNAME func(ctx context.Context, host string) (string, error)
}

// NewTakeoverAnalyzer creates a new TakeoverAnalyzer.
func NewTakeoverAnalyzer() *TakeoverAnalyzer {
	return &TakeoverAnalyzer{
		cache: make(map[string]string),
		lookupCNAME: func(ctx context.Context, host string) (string, error) {
			var r net.Resolver
			return r.LookupCNAME(ctx, host)
		},
	}
}

// TakeoverSignatures maps vulnerable SaaS domains to their description.
var TakeoverSignatures = map[string]string{
	"github.io":             "GitHub Pages subdomain takeover",
	"herokuapp.com":         "Heroku subdomain takeover",
	"herokudns.com":         "Heroku subdomain takeover",
	"s3.amazonaws.com":      "AWS S3 Bucket subdomain takeover",
	"s3-website":            "AWS S3 website subdomain takeover",
	"wordpress.com":         "WordPress subdomain takeover",
	"ghost.io":              "Ghost subdomain takeover",
	"myshopify.com":         "Shopify subdomain takeover",
	"squarespace.com":       "Squarespace subdomain takeover",
	"pantheonsite.io":       "Pantheon subdomain takeover",
	"readmessl.com":         "Readme.io subdomain takeover",
	"bitbucket.io":          "Bitbucket subdomain takeover",
	"cargo.site":            "Cargo subdomain takeover",
}

func (t *TakeoverAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	host := insight.Host
	if host == "" {
		return
	}

	if strings.Contains(host, "://") {
		host = extractHost(host)
	}

	cname, exists := t.cache[host]
	if !exists {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resolved, err := t.lookupCNAME(ctx, host)
		if err == nil {
			cname = strings.ToLower(resolved)
		}
		t.cache[host] = cname
	}

	if cname == "" {
		return
	}

	for sig, vuln := range TakeoverSignatures {
		if strings.Contains(cname, sig) {
			addTag(insight, "subdomain-takeover")
			addReason(insight, "CNAME points to vulnerable SaaS provider: "+cname+" ("+vuln+")")
			addSuggestedTest(insight, "Verify if the target SaaS subdomain is unclaimed/available for registration")
			insight.Score += 35
			break
		}
	}
}
