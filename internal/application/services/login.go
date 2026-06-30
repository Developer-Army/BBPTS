package services

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

func (o *Orchestrator) performLogin(loginURL, user, pass, formUser, formPass string) *recon.AuthSession {
	if loginURL == "" || user == "" || pass == "" {
		return nil
	}

	if !strings.HasPrefix(loginURL, "http://") && !strings.HasPrefix(loginURL, "https://") {
		loginURL = "https://" + loginURL
	}

	if formUser == "" {
		formUser = "username"
	}
	if formPass == "" {
		formPass = "password"
	}

	client := tools.NewSafeHTTPClient(15 * time.Second)
	client.Jar = nil
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	form := url.Values{}
	form.Set(formUser, user)
	form.Set(formPass, pass)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		slog.Warn("login request creation failed", "error", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BBPTS/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("login request failed", "url", loginURL, "error", err)
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		reqDump, _ := httputil.DumpRequestOut(req, false)
		respDump, _ := httputil.DumpResponse(resp, false)
		slog.Warn("login returned non-success status",
			"status", resp.StatusCode,
			"request", string(reqDump),
			"response", string(respDump),
		)
		return nil
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		slog.Warn("login succeeded but no Set-Cookie headers received", "url", loginURL)
		return nil
	}

	headers := make(map[string]string)
	cookieParts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	headers["Cookie"] = strings.Join(cookieParts, "; ")

	slog.Info("login session captured", "url", loginURL, "cookies", len(cookies))
	return &recon.AuthSession{
		Label:   "login_session",
		Headers: headers,
	}
}
