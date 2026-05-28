package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Expected for legacy modes (subdomains, alive)
type Expected struct {
	Target     string   `json:"target"`
	Subdomains []string `json:"subdomains"`
	Alive      []string `json:"alive"`
}

// ExpectedLocalhost for localhost mode
type ExpectedLocalhost struct {
	Target       string   `json:"target"`
	ExpectedTags []string `json:"expected_tags"`
}

// ActualItem for results.json parsing
type ActualItem struct {
	Host     string   `json:"host"`
	Priority string   `json:"priority"`
	Score    int      `json:"score"`
	Tags     []string `json:"tags"`
}

type Actual struct {
	Items []ActualItem `json:"items"`
}

func main() {
	expectedPath := flag.String("expected", "tests/expected/localhost_expected.json", "Path to expected JSON")
	actualPath := flag.String("actual", "tests/reports/results.json", "Path to actual results (JSON or CSV)")
	mode := flag.String("mode", "localhost", "What to evaluate: 'localhost', 'subdomains', or 'alive'")
	failuresPath := flag.String("failures", "tests/targets/failed_targets.txt", "Path to write failed/missed targets")
	flag.Parse()

	if *expectedPath == "" || *actualPath == "" {
		fmt.Println("Usage: evaluator --expected path.json --actual path.json/csv --mode localhost")
		os.Exit(1)
	}

	// 1. Load Expected
	expData, err := os.ReadFile(*expectedPath)
	if err != nil {
		fmt.Printf("Error reading expected file: %v\n", err)
		os.Exit(1)
	}

	if *mode == "localhost" {
		var expected ExpectedLocalhost
		if err := json.Unmarshal(expData, &expected); err != nil {
			fmt.Printf("Error parsing expected JSON (localhost): %v\n", err)
			os.Exit(1)
		}
		evaluateLocalhost(expected, *actualPath, *failuresPath)
	} else {
		var expected Expected
		if err := json.Unmarshal(expData, &expected); err != nil {
			fmt.Printf("Error parsing expected JSON: %v\n", err)
			os.Exit(1)
		}
		evaluateLegacy(expected, *actualPath, *mode, *failuresPath)
	}
}

func evaluateLocalhost(expected ExpectedLocalhost, actualPath, failuresPath string) {
	fmt.Printf("\n========================================\n")
	fmt.Printf(" BBPTS DETECTOR EVALUATION: LOCALHOST\n")
	fmt.Printf("========================================\n\n")

	// Load actual results.json
	actData, err := os.ReadFile(actualPath)
	if err != nil {
		fmt.Printf(" Error reading actual results: %v\n", err)
		os.Exit(1)
	}

	var actual Actual
	if err := json.Unmarshal(actData, &actual); err != nil {
		// Fallback to check if it's the report.json format
		type AlternateReport struct {
			Findings []ActualItem `json:"findings"`
		}
		var alt AlternateReport
		if errAlt := json.Unmarshal(actData, &alt); errAlt == nil && len(alt.Findings) > 0 {
			actual.Items = alt.Findings
		} else {
			fmt.Printf(" Error parsing actual results JSON: %v\n", err)
			os.Exit(1)
		}
	}

	// Find the item matching expected target
	var targetItem *ActualItem
	expectedTargetClean := strings.ToLower(strings.TrimSpace(expected.Target))
	for i := range actual.Items {
		itemHostClean := strings.ToLower(strings.TrimSpace(actual.Items[i].Host))
		if strings.Contains(itemHostClean, expectedTargetClean) || strings.Contains(expectedTargetClean, itemHostClean) {
			targetItem = &actual.Items[i]
			break
		}
	}

	if targetItem == nil {
		msg := fmt.Sprintf(" Target '%s' not found in BBPTS scan results!", expected.Target)
		fmt.Println(msg)
		writeFailures(failuresPath, []string{msg})
		os.Exit(1)
	}

	actualTagsSet := make(map[string]bool)
	for _, tag := range targetItem.Tags {
		actualTagsSet[strings.ToLower(strings.TrimSpace(tag))] = true
	}

	var tp, fn, fp []string

	// Check expected tags (True Positives and False Negatives)
	for _, tag := range expected.ExpectedTags {
		tagClean := strings.ToLower(strings.TrimSpace(tag))
		if actualTagsSet[tagClean] {
			tp = append(tp, tag)
		} else {
			fn = append(fn, tag)
		}
	}

	// Check for extra tags (False Positives)
	expectedTagsSet := make(map[string]bool)
	for _, tag := range expected.ExpectedTags {
		expectedTagsSet[strings.ToLower(strings.TrimSpace(tag))] = true
	}
	for _, tag := range targetItem.Tags {
		tagClean := strings.ToLower(strings.TrimSpace(tag))
		if !expectedTagsSet[tagClean] {
			fp = append(fp, tag)
		}
	}

	fmt.Printf(" Target Evaluated: %s\n", targetItem.Host)
	fmt.Printf(" Finding Priority: %s | Score: %d\n\n", targetItem.Priority, targetItem.Score)

	fmt.Printf(" True Positives (Found expected findings): %d\n", len(tp))
	for _, v := range tp {
		fmt.Printf("   - %s\n", v)
	}
	fmt.Println()

	fmt.Printf(" False Positives (Extra findings): %d\n", len(fp))
	if len(fp) == 0 {
		fmt.Println("   (Perfect! No extra noise)")
	} else {
		for _, v := range fp {
			// Classify priority: discovery is low priority, others might be medium/low unless critical
			priority := "low priority noise"
			if v != "discovery" {
				priority = "unclassified extra finding"
			}
			fmt.Printf("   - %s (%s)\n", v, priority)
		}
	}
	fmt.Println()

	fmt.Printf(" False Negatives (Missed findings): %d\n", len(fn))
	if len(fn) == 0 {
		fmt.Println("   (Perfect! Caught everything expected)")
	} else {
		for _, v := range fn {
			fmt.Printf("   - %s [MISSED]\n", v)
		}
	}
	fmt.Println()

	accuracy := 0.0
	if len(expected.ExpectedTags) > 0 {
		accuracy = float64(len(tp)) / float64(len(expected.ExpectedTags)) * 100
	}
	fmt.Printf(" Accuracy Score: %.2f%%\n", accuracy)
	fmt.Printf("========================================\n")

	if len(fn) > 0 {
		// Log missed ones to terminal in bold red and write to targets failures file
		fmt.Printf("\n\033[1;31m[-] TEST FAILED: Missed %d high-priority expected target findings!\033[0m\n", len(fn))
		writeFailures(failuresPath, fn)
		os.Exit(1)
	}

	// Clean up failures file if passed
	_ = os.Remove(failuresPath)
	fmt.Println("\n\033[1;32m[+] TEST PASSED: Validation complete with 100% coverage of expected findings.\033[0m")
	os.Exit(0)
}

func evaluateLegacy(expected Expected, actualPath, mode, failuresPath string) {
	expectedSet := make(map[string]bool)
	switch mode {
	case "subdomains":
		for _, s := range expected.Subdomains {
			expectedSet[strings.ToLower(strings.TrimSpace(s))] = true
		}
	case "alive":
		for _, a := range expected.Alive {
			expectedSet[strings.ToLower(strings.TrimSpace(a))] = true
		}
	}

	actualSet := make(map[string]bool)

	if strings.HasSuffix(actualPath, ".json") {
		actData, err := os.ReadFile(actualPath)
		if err == nil {
			var actual Actual
			_ = json.Unmarshal(actData, &actual)
			for _, item := range actual.Items {
				hostClean := strings.ToLower(strings.TrimSpace(item.Host))
				switch mode {
				case "subdomains":
					actualSet[hostClean] = true
				case "alive":
					if strings.HasPrefix(hostClean, "http://") || strings.HasPrefix(hostClean, "https://") {
						actualSet[hostClean] = true
					}
				}
			}
		}
	} else {
		// Parse CSV
		f, err := os.Open(actualPath)
		if err != nil {
			fmt.Printf("Error reading actual CSV: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		reader := csv.NewReader(f)
		records, err := reader.ReadAll()
		if err != nil {
			fmt.Printf("Error parsing CSV: %v\n", err)
			os.Exit(1)
		}

		if len(records) > 0 {
			header := records[0]
			hostIdx := 0
			for idx, col := range header {
				if strings.ToLower(strings.TrimSpace(col)) == "host" {
					hostIdx = idx
					break
				}
			}

			for i, row := range records {
				if i == 0 {
					continue // Skip header
				}
				if len(row) <= hostIdx {
					continue
				}
				target := strings.ToLower(strings.TrimSpace(row[hostIdx]))
				switch mode {
				case "subdomains":
					actualSet[target] = true
				case "alive":
					if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
						actualSet[target] = true
					}
				}
			}
		}
	}

	var tp, fp, fn []string
	for t := range actualSet {
		if expectedSet[t] {
			tp = append(tp, t)
		} else {
			fp = append(fp, t)
		}
	}
	for e := range expectedSet {
		if !actualSet[e] {
			fn = append(fn, e)
		}
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf(" ACCURACY REPORT: %s\n", strings.ToUpper(mode))
	fmt.Printf("========================================\n\n")

	fmt.Printf(" True Positives (Found): %d\n", len(tp))
	for _, v := range tp {
		fmt.Printf("   - %s\n", v)
	}
	fmt.Println()

	fmt.Printf(" False Positives (Added/Extra): %d\n", len(fp))
	if len(fp) == 0 {
		fmt.Println("   (Perfect! No extra noise)")
	} else {
		for _, v := range fp {
			fmt.Printf("   - %s\n", v)
		}
	}
	fmt.Println()

	fmt.Printf(" False Negatives (Missed): %d\n", len(fn))
	if len(fn) == 0 {
		fmt.Println("   (Perfect! Caught everything)")
	} else {
		for _, v := range fn {
			fmt.Printf("   - %s\n", v)
		}
	}
	fmt.Println()

	accuracy := 0.0
	if len(expectedSet) > 0 {
		accuracy = float64(len(tp)) / float64(len(expectedSet)) * 100
	}
	fmt.Printf(" Score: %.2f%% Expected Targets Found\n", accuracy)
	fmt.Printf("========================================\n")

	if len(fn) > 0 {
		writeFailures(failuresPath, fn)
		os.Exit(1)
	}
	_ = os.Remove(failuresPath)
	os.Exit(0)
}

func writeFailures(path string, missed []string) {
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("Error creating failures file: %v\n", err)
		return
	}
	defer f.Close()

	for _, m := range missed {
		_, _ = fmt.Fprintln(f, m)
	}
}
