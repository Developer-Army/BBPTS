package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// ProcessTriageIntegrations executes GitHub, Jira, and DefectDojo integrations based on environment configuration.
func ProcessTriageIntegrations(ctx context.Context, r *Report, reportJSONPath string) {
	// 1. DefectDojo upload
	ddURL := os.Getenv("DEFECTDOJO_URL")
	ddToken := os.Getenv("DEFECTDOJO_TOKEN")
	ddProdID := os.Getenv("DEFECTDOJO_PRODUCT_ID")
	if ddURL != "" && ddToken != "" && ddProdID != "" {
		slog.Info("DefectDojo config found, uploading report", "url", ddURL, "product_id", ddProdID)
		if err := uploadToDefectDojo(ctx, ddURL, ddToken, ddProdID, reportJSONPath); err != nil {
			slog.Error("failed to upload report to DefectDojo", "error", err)
		} else {
			slog.Info("successfully uploaded report to DefectDojo")
		}
	}

	// 2. GitHub issues for High/Critical findings
	ghToken := os.Getenv("GITHUB_TOKEN")
	ghRepo := os.Getenv("GITHUB_REPO")
	if ghToken != "" && ghRepo != "" {
		for _, f := range r.Findings {
			sev := strings.ToLower(f.Severity)
			if sev == "critical" || sev == "high" {
				slog.Info("GitHub config found, creating issue for finding", "repo", ghRepo, "title", f.Title)
				if err := createGitHubIssue(ctx, ghToken, ghRepo, f); err != nil {
					slog.Error("failed to create GitHub issue", "error", err)
				}
			}
		}
	}

	// 3. Jira tickets for High/Critical findings
	jiraURL := os.Getenv("JIRA_URL")
	jiraUser := os.Getenv("JIRA_USER")
	jiraToken := os.Getenv("JIRA_TOKEN")
	jiraProj := os.Getenv("JIRA_PROJECT")
	if jiraURL != "" && jiraUser != "" && jiraToken != "" && jiraProj != "" {
		for _, f := range r.Findings {
			sev := strings.ToLower(f.Severity)
			if sev == "critical" || sev == "high" {
				slog.Info("Jira config found, creating ticket for finding", "project", jiraProj, "title", f.Title)
				if err := createJiraTicket(ctx, jiraURL, jiraUser, jiraToken, jiraProj, f); err != nil {
					slog.Error("failed to create Jira ticket", "error", err)
				}
			}
		}
	}
}

func uploadToDefectDojo(ctx context.Context, ddURL, token, productID, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "bbpts-report.json")
	if err != nil {
		return err
	}
	if _, err = io.Copy(part, file); err != nil {
		return err
	}

	_ = writer.WriteField("scan_type", "Gitleaks Scan")
	_ = writer.WriteField("product_id", productID)
	_ = writer.WriteField("active", "true")
	_ = writer.WriteField("verified", "true")
	_ = writer.WriteField("minimum_severity", "Info")

	if err = writer.Close(); err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/v2/import-scan/", strings.TrimSuffix(ddURL, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Token "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("defectdojo returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func createGitHubIssue(ctx context.Context, token, repo string, f DetailedFinding) error {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues", repo)

	issueBody := fmt.Sprintf("### Description\n%s\n\n### Severity\n%s\n\n### Score\n%d\n\n### Target\n%s\n\n### Evidence\n```\n%s\n```\n\n### Impact\n%s\n\n### Remediation\n%s\n",
		f.Description, f.Severity, f.Score, f.Target, f.Evidence, f.Impact, f.Remediation)

	payload := map[string]any{
		"title":  fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Title),
		"body":   issueBody,
		"labels": append([]string{"bug", "security", strings.ToLower(f.Severity)}, f.Tags...),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func createJiraTicket(ctx context.Context, jiraURL, username, token, project string, f DetailedFinding) error {
	apiURL := fmt.Sprintf("%s/rest/api/2/issue", strings.TrimSuffix(jiraURL, "/"))

	issueBody := fmt.Sprintf("Description: %s\n\nSeverity: %s\nScore: %d\nTarget: %s\n\nEvidence:\n%s\n\nImpact: %s\nRemediation: %s",
		f.Description, f.Severity, f.Score, f.Target, f.Evidence, f.Impact, f.Remediation)

	payload := map[string]any{
		"fields": map[string]any{
			"project": map[string]any{
				"key": project,
			},
			"summary":     fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Title),
			"description": issueBody,
			"issuetype": map[string]any{
				"name": "Bug",
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("jira returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// GenerateDynamicExecutiveSummary produces an LLM-assisted or highly descriptive template-based summary.
func GenerateDynamicExecutiveSummary(findings []DetailedFinding) ExecutiveSummary {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey != "" {
		summary, err := queryOpenAISummary(apiKey, findings)
		if err == nil {
			return summary
		}
		slog.Warn("OpenAI summary query failed, falling back to heuristics", "error", err)
	}

	critical := 0
	high := 0
	var keyFindings []string
	var immediateActions []string
	var longTermActions []string

	for _, f := range findings {
		sev := strings.ToLower(f.Severity)
		switch sev {
		case "critical":
			critical++
			keyFindings = append(keyFindings, fmt.Sprintf("Critical exposure identified on %s: %s", f.Target, f.Title))
		case "high":
			high++
			keyFindings = append(keyFindings, fmt.Sprintf("High-severity risk on %s: %s", f.Target, f.Title))
		}
	}

	riskLevel := "Low"
	if critical > 0 {
		riskLevel = "Critical"
		immediateActions = append(immediateActions, "Remediate critical infrastructure exposures immediately", "Revoke any leaked API keys or credentials found")
	} else if high > 0 {
		riskLevel = "High"
		immediateActions = append(immediateActions, "Patch high-severity issues on affected endpoints", "Enforce access controls on administrative paths")
	} else {
		immediateActions = append(immediateActions, "Review low and medium findings during the next maintenance cycle")
	}

	immediateActions = append(immediateActions, "Configure WAF rules to block malicious probes", "Scan exposed repositories for any residual credentials")
	longTermActions = append(longTermActions, "Establish a continuous monitoring program", "Integrate automated secret scanning into git workflows", "Conduct annual penetration testing")

	if len(keyFindings) == 0 {
		keyFindings = append(keyFindings, "No critical or high-severity vulnerabilities were identified during the assessment.")
	}
	if len(keyFindings) > 5 {
		keyFindings = keyFindings[:5]
	}

	return ExecutiveSummary{
		OverallRisk:      riskLevel,
		KeyFindings:      keyFindings,
		ImmediateActions: immediateActions,
		LongTermActions:  longTermActions,
		ComplianceStatus: map[string]bool{
			"OWASP": critical == 0 && high == 0,
			"CWE":   critical == 0,
			"CVE":   true,
		},
	}
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func queryOpenAISummary(apiKey string, findings []DetailedFinding) (ExecutiveSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var sb strings.Builder
	for i, f := range findings {
		if i >= 10 {
			break
		}
		sb.WriteString(fmt.Sprintf("- Title: %s, Severity: %s, Target: %s, Description: %s\n", f.Title, f.Severity, f.Target, f.Description))
	}

	prompt := fmt.Sprintf(`Generate an Executive Summary for a security assessment in JSON format.
The output MUST match this JSON structure:
{
  "overall_risk": "Low/Medium/High/Critical",
  "key_findings": ["finding 1", "finding 2"],
  "immediate_actions": ["action 1", "action 2"],
  "long_term_actions": ["action 1"],
  "compliance_status": {"OWASP": true, "CWE": false, "CVE": true}
}

Vulnerabilities found:
%s`, sb.String())

	payload := map[string]any{
		"model": "gpt-3.5-turbo",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.2,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return ExecutiveSummary{}, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return ExecutiveSummary{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ExecutiveSummary{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ExecutiveSummary{}, fmt.Errorf("OpenAI API returned status %d", resp.StatusCode)
	}

	var res openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return ExecutiveSummary{}, err
	}

	if len(res.Choices) == 0 {
		return ExecutiveSummary{}, fmt.Errorf("no choices returned from OpenAI")
	}

	var summary ExecutiveSummary
	content := res.Choices[0].Message.Content
	if idx := strings.Index(content, "{"); idx != -1 {
		content = content[idx:]
	}
	if idx := strings.LastIndex(content, "}"); idx != -1 {
		content = content[:idx+1]
	}

	if err := json.Unmarshal([]byte(content), &summary); err != nil {
		return ExecutiveSummary{}, err
	}

	return summary, nil
}
