package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// generateJSONReport exports report as JSON
func (rg *ReportGenerator) generateJSONReport(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// SARIF output structs
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifDescription `json:"shortDescription"`
}

type sarifDescription struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func (rg *ReportGenerator) generateSARIFReport(report *Report) error {
	var rules []sarifRule
	var results []sarifResult

	ruleMap := make(map[string]bool)

	for _, f := range report.Findings {
		ruleID := "BBPTS-" + strings.ToUpper(f.Severity)
		if !ruleMap[ruleID] {
			ruleMap[ruleID] = true
			rules = append(rules, sarifRule{
				ID:   ruleID,
				Name: f.Severity + "RiskFinding",
				ShortDescription: sarifDescription{
					Text: fmt.Sprintf("BBPTS %s Severity Risk Finding", f.Severity),
				},
			})
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Message: sarifMessage{Text: fmt.Sprintf("%s: %s (Score: %d)", f.Title, f.Description, f.Score)},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.Target,
						},
						Region: sarifRegion{
							StartLine: 1,
						},
					},
				},
			},
		})
	}

	sarif := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "BBPTS",
						SemanticVersion: "1.5.0",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	outputPath := filepath.Join(rg.config.OutputPath, "report.sarif")
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

