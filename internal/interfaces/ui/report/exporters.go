package ui

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"time"
)

// ZAPAlertSeverity represents OWASP ZAP alert severity levels
type ZAPAlertSeverity string

const (
	ZAPSeverityHigh   ZAPAlertSeverity = "High"
	ZAPSeverityMedium ZAPAlertSeverity = "Medium"
	ZAPSeverityLow    ZAPAlertSeverity = "Low"
	ZAPSeverityInfo   ZAPAlertSeverity = "Informational"
)

// ZAPAlert represents a single alert in ZAP format
type ZAPAlert struct {
	PluginID   int           `xml:"pluginid,attr"`
	Alert      string        `xml:"alert"`
	Name       string        `xml:"name"`
	Riskcode   int           `xml:"riskcode"`
	Confidence int           `xml:"confidence"`
	Riskdesc   string        `xml:"riskdesc"`
	Desc       string        `xml:"desc"`
	Instances  []ZAPInstance `xml:"instances>instance"`
	CWEid      string        `xml:"cweid"`
	WASCID     string        `xml:"wascid"`
	SourceID   string        `xml:"sourceid"`
}

// ZAPInstance represents an instance of a vulnerability in ZAP
type ZAPInstance struct {
	URI      string `xml:"uri"`
	Method   string `xml:"method"`
	Param    string `xml:"param"`
	Attack   string `xml:"attack"`
	Evidence string `xml:"evidence"`
}

// ZAPScan represents the complete ZAP scan report
type ZAPScan struct {
	XMLName xml.Name   `xml:"OWASPZAPReport"`
	Version string     `xml:"version,attr"`
	Alerts  []ZAPAlert `xml:"site>alerts>alertitem"`
}

// CaidoFinding represents a finding in Caido's JSON export format
type CaidoFinding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	URL         string   `json:"url"`
	Method      string   `json:"method"`
	Parameter   string   `json:"parameter"`
	Evidence    string   `json:"evidence"`
	Tags        []string `json:"tags"`
	Status      string   `json:"status"`
	Timestamp   string   `json:"timestamp"`
}

// CaidoReport represents the complete Caido export
type CaidoReport struct {
	Version  string                 `json:"version"`
	Findings []CaidoFinding         `json:"findings"`
	Metadata map[string]interface{} `json:"metadata"`
}

// BurpExtendedIssue represents an enhanced Burp Suite issue with extra metadata
type BurpExtendedIssue struct {
	ID            string `xml:"id,attr"`
	Name          string `xml:"name"`
	Host          string `xml:"host"`
	Path          string `xml:"path"`
	Location      string `xml:"location"`
	Severity      string `xml:"severity"`
	Confidence    string `xml:"confidence"`
	Background    string `xml:"issueBackground"`
	Remediation   string `xml:"remediationBackground"`
	Evidence      string `xml:"evidence"`
	Tags          string `xml:"tags"`
	Source        string `xml:"source"`
	DiscoveryDate string `xml:"discoveryDate"`
}

// ExportToZAP generates an OWASP ZAP-compatible XML report
func ExportToZAP(filename string, findings map[string]interface{}) error {
	zapScan := ZAPScan{
		Version: "2.14.0",
		Alerts:  []ZAPAlert{},
	}

	// Convert findings to ZAP alerts
	if data, ok := findings["alerts"].([]interface{}); ok {
		for _, item := range data {
			if m, ok := item.(map[string]interface{}); ok {
				alert := ZAPAlert{
					Alert:    m["name"].(string),
					Riskdesc: m["severity"].(string),
					Desc:     m["description"].(string),
				}
				zapScan.Alerts = append(zapScan.Alerts, alert)
			}
		}
	}

	data, err := xml.MarshalIndent(zapScan, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ZAP report: %w", err)
	}

	xmlHeader := []byte(xml.Header)
	return os.WriteFile(filename, append(xmlHeader, data...), 0644)
}

// ExportToCaidoJSON generates a Caido-compatible JSON report
func ExportToCaidoJSON(filename string, findings []CaidoFinding) error {
	report := CaidoReport{
		Version:  "1.0",
		Findings: findings,
		Metadata: map[string]interface{}{
			"exportedBy": "BBPTS",
			"exportTime": currentTimestamp(),
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Caido report: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

// ExportToBurpExtended generates an enhanced Burp Suite XML with additional metadata
func ExportToBurpExtended(filename string, issues []BurpExtendedIssue) error {
	type IssueList struct {
		XMLName xml.Name            `xml:"issues"`
		Issues  []BurpExtendedIssue `xml:"issue"`
	}

	issueList := IssueList{Issues: issues}

	data, err := xml.MarshalIndent(issueList, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Burp extended report: %w", err)
	}

	xmlHeader := []byte(xml.Header)
	return os.WriteFile(filename, append(xmlHeader, data...), 0644)
}

// currentTimestamp returns the current ISO 8601 timestamp.
func currentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
