package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ExpectedResult struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	TestNo     string      `json:"test_no"`
	Difficulty string      `json:"difficulty"`
	TestName   string      `json:"test_name"`
	TestTarget interface{} `json:"test_target"`
}

type Stats struct {
	Total  int
	Passed int
	Failed int
}

type VerificationFailure struct {
	ID              string   `json:"id"`
	TargetName      string   `json:"target_name"`
	Difficulty      string   `json:"difficulty"`
	TestName        string   `json:"test_name"`
	ExpectedTargets []string `json:"expected_targets"`
	MissingTargets  []string `json:"missing_targets"`
	Layer1Passed    bool     `json:"layer1_passed"`
	Layer2Passed    bool     `json:"layer2_passed"`
	ReportDir       string   `json:"report_dir"`
}

type DifficultyStatsJSON struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

type VerificationJSONReport struct {
	Timestamp           string                         `json:"timestamp"`
	TotalEvaluated      int                            `json:"total_evaluated"`
	Passed              int                            `json:"passed"`
	Failed              int                            `json:"failed"`
	Accuracy            float64                        `json:"accuracy"`
	DifficultyBreakdown map[string]DifficultyStatsJSON `json:"difficulty_breakdown"`
	Failures            []VerificationFailure          `json:"failures"`
}

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	White  = "\033[37m"
	Bold   = "\033[1m"
)

func main() {
	noL1 := flag.Bool("no-l1", false, "Disable Layer 1 checking (Test Name)")
	diffFilter := flag.String("difficulty", "", "Filter tests by difficulty")
	jsonPath := flag.String("json", "tests/test_result.json", "Path to output JSON test results")
	mdPath := flag.String("markdown", "tests/test_report.md", "Path to output Markdown test report")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: verify <reports_dir> <expected_jsonl_file> [--no-l1]")
		os.Exit(1)
	}

	reportsDir := args[0]
	expectedFile := args[1]

	f, err := os.Open(expectedFile)
	if err != nil {
		fmt.Printf("%s[ERROR] Failed to open expected results: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}
	defer f.Close()

	var tests []ExpectedResult
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var tc ExpectedResult
		if err := json.Unmarshal([]byte(line), &tc); err != nil {
			fmt.Printf("%s[WARNING] Failed to parse JSONL line: %v%s\n", Yellow, err, Reset)
			continue
		}
		tests = append(tests, tc)
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("%s[ERROR] Failed to read expected results: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	totalTests := len(tests)
	passed := 0
	failed := 0
	statsByDiff := make(map[string]*Stats)

	reportContents := make(map[string]string)
	reportDirs := make(map[string]string)
	entries, err := os.ReadDir(reportsDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			targetName := strings.TrimPrefix(entry.Name(), "bbpts-test-")
			targetName = strings.ToLower(strings.ReplaceAll(targetName, "-", ""))
			reportDirs[targetName] = entry.Name()

			var contentBuilder strings.Builder
			err := filepath.Walk(filepath.Join(reportsDir, entry.Name()), func(path string, info fs.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				b, err := os.ReadFile(path)
				if err == nil {
					contentBuilder.Write(b)
					contentBuilder.WriteString("\n")
				}
				return nil
			})
			if err == nil {
				reportContents[targetName] = contentBuilder.String()
			}
		}
	}

	failedLog, _ := os.OpenFile("tests/failed_tests.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if failedLog != nil {
		defer failedLog.Close()
	}

	var failures []VerificationFailure

	for _, tc := range tests {
		diff := strings.ToLower(tc.Difficulty)
		if *diffFilter != "" && diff != strings.ToLower(*diffFilter) {
			continue
		}

		if statsByDiff[diff] == nil {
			statsByDiff[diff] = &Stats{}
		}
		statsByDiff[diff].Total++

		targetKey := strings.ToLower(strings.ReplaceAll(tc.Name, " ", ""))
		targetKey = strings.ReplaceAll(targetKey, "-", "")
		switch tc.Name {
		case "Mock DNS":
			targetKey = "mockdns"
		case "Mock Cloud":
			targetKey = "mockcloud"
		}

		content, exists := reportContents[targetKey]
		if !exists {
			content = ""
		}
		contentLower := strings.ToLower(content)

		l1Passed := *noL1
		if !l1Passed {
			l1Passed = strings.Contains(contentLower, strings.ToLower(tc.TestName))
		}

		var targetsToCheck []string
		switch v := tc.TestTarget.(type) {
		case []interface{}:
			for _, item := range v {
				targetsToCheck = append(targetsToCheck, fmt.Sprintf("%v", item))
			}
		case map[string]interface{}:
			for _, item := range v {
				targetsToCheck = append(targetsToCheck, fmt.Sprintf("%v", item))
			}
		default:
			targetsToCheck = append(targetsToCheck, fmt.Sprintf("%v", tc.TestTarget))
		}

		var missing []string
		for _, t := range targetsToCheck {
			if !strings.Contains(content, t) {
				missing = append(missing, t)
			}
		}
		l2Passed := len(missing) == 0

		reportSubdir := reportDirs[targetKey]
		reportDirPath := ""
		if reportSubdir != "" {
			reportDirPath = filepath.Join(reportsDir, reportSubdir)
		} else {
			reportDirPath = filepath.Join(reportsDir, "bbpts-test-"+targetKey)
		}

		if l1Passed && l2Passed {
			passed++
			statsByDiff[diff].Passed++
		} else {
			failed++
			statsByDiff[diff].Failed++
			failures = append(failures, VerificationFailure{
				ID:              tc.ID,
				TargetName:      tc.Name,
				Difficulty:      tc.Difficulty,
				TestName:        tc.TestName,
				ExpectedTargets: targetsToCheck,
				MissingTargets:  missing,
				Layer1Passed:    l1Passed,
				Layer2Passed:    l2Passed,
				ReportDir:       reportDirPath,
			})

			fmt.Printf("%s[FAIL] Test %s (%s) on %s failed!%s\n", Red, tc.ID, tc.TestName, tc.Name, Reset)
			fmt.Printf("  - Report Dir: %s\n", reportDirPath)

			if !l1Passed {
				msg := fmt.Sprintf("Layer 1: Test name '%s' not found (case-insensitive)", tc.TestName)
				fmt.Printf("  - %s\n", msg)
				if failedLog != nil {
					_, _ = fmt.Fprintf(failedLog, "FAIL: Test %s\n- %s\n", tc.ID, msg)
				}
			}
			if !l2Passed {
				msg := fmt.Sprintf("Layer 2: Target substring(s) not found (case-sensitive): %v", missing)
				fmt.Printf("  - %s\n", msg)
				if failedLog != nil {
					_, _ = fmt.Fprintf(failedLog, "FAIL: Test %s\n- %s\n", tc.ID, msg)
				}
			}
		}
	}

	accuracy := 0.0
	if totalTests > 0 {
		accuracy = float64(passed) / float64(totalTests) * 100
	}

	accColor := Red
	if accuracy == 100 {
		accColor = Green
	} else if accuracy >= 80 {
		accColor = Yellow
	}
	failColor := Green
	if failed > 0 {
		failColor = Red
	}

	fmt.Printf("\n%s┌────────────────────────────────────────────────────────┐%s\n", Cyan, Reset)
	fmt.Printf("%s│%s      %s%sBBPTS DIFFERENTIAL ACCURACY VERIFICATION REPORT%s    %s│%s\n", Cyan, Reset, Bold, White, Reset, Cyan, Reset)
	fmt.Printf("%s├────────────────────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  Total Test Cases Evaluated : %s%s%-25d%s%s│%s\n", Cyan, Reset, Bold, White, totalTests, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  Passed Tests               : %s%-25d%s%s│%s\n", Cyan, Reset, Green, passed, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  Failed Tests               : %s%-25d%s%s│%s\n", Cyan, Reset, failColor, failed, Reset, Cyan, Reset)
	fmt.Printf("%s├────────────────────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  Final Pipeline Accuracy    : %s%-25s%s%s│%s\n", Cyan, Reset, accColor, fmt.Sprintf("%.2f%%", accuracy), Reset, Cyan, Reset)
	fmt.Printf("%s├────────────────────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %sDifficulty Breakdown:%s                                  %s│%s\n", Cyan, Reset, Bold, Reset, Cyan, Reset)

	for _, diff := range []string{"easy", "medium", "advanced"} {
		st := statsByDiff[diff]
		if st == nil {
			continue
		}
		pct := 0.0
		if st.Total > 0 {
			pct = float64(st.Passed) / float64(st.Total) * 100
		}
		col := Red
		if pct == 100 {
			col = Green
		} else if pct >= 80 {
			col = Yellow
		}
		titleDiff := diff
		if len(diff) > 0 {
			titleDiff = strings.ToUpper(diff[:1]) + diff[1:]
		}
		statStr := fmt.Sprintf("%-8s: %d/%d passed (%.1f%%)", titleDiff, st.Passed, st.Total, pct)
		fmt.Printf("%s│%s  %s%-48s%s  %s│%s\n", Cyan, Reset, col, statStr, Reset, Cyan, Reset)
	}
	fmt.Printf("%s└────────────────────────────────────────────────────────┘%s\n", Cyan, Reset)

	jsonReport := VerificationJSONReport{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		TotalEvaluated: totalTests,
		Passed:         passed,
		Failed:         failed,
		Accuracy:       accuracy,
		Failures:       failures,
	}
	jsonReport.DifficultyBreakdown = make(map[string]DifficultyStatsJSON)
	for _, diff := range []string{"easy", "medium", "advanced"} {
		st := statsByDiff[diff]
		if st != nil {
			jsonReport.DifficultyBreakdown[diff] = DifficultyStatsJSON{
				Total:  st.Total,
				Passed: st.Passed,
				Failed: st.Failed,
			}
		}
	}
	if *jsonPath != "" {
		jsonBytes, err := json.MarshalIndent(jsonReport, "", "  ")
		if err == nil {
			err = os.WriteFile(*jsonPath, jsonBytes, 0644)
			if err != nil {
				fmt.Printf("%s[WARNING] Failed to write JSON report to %s: %v%s\n", Yellow, *jsonPath, err, Reset)
			}
		}
	}

	// Write markdown report to *mdPath
	var mdBuilder strings.Builder
	mdBuilder.WriteString("# BBPTS Differential Verification Report\n\n")
	mdBuilder.WriteString(fmt.Sprintf("- **Timestamp**: %s\n", time.Now().UTC().Format(time.RFC3339)))
	mdBuilder.WriteString(fmt.Sprintf("- **Total Evaluated**: %d\n", totalTests))
	mdBuilder.WriteString(fmt.Sprintf("- **Passed**: %d\n", passed))
	mdBuilder.WriteString(fmt.Sprintf("- **Failed**: %d\n", failed))
	mdBuilder.WriteString(fmt.Sprintf("- **Accuracy**: **%.2f%%**\n\n", accuracy))

	mdBuilder.WriteString("## Difficulty Breakdown\n")
	for _, diff := range []string{"easy", "medium", "advanced"} {
		st := statsByDiff[diff]
		if st != nil {
			pct := 0.0
			if st.Total > 0 {
				pct = float64(st.Passed) / float64(st.Total) * 100
			}
			titleDiff := strings.ToUpper(diff[:1]) + diff[1:]
			mdBuilder.WriteString(fmt.Sprintf("- **%s**: %d/%d passed (**%.1f%%**)\n", titleDiff, st.Passed, st.Total, pct))
		}
	}
	mdBuilder.WriteString("\n")

	if failed > 0 {
		mdBuilder.WriteString("## Failed Tests Details\n\n")
		for _, f := range failures {
			mdBuilder.WriteString(fmt.Sprintf("### [FAIL] Test %s: %s (%s)\n", f.ID, f.TestName, f.Difficulty))
			mdBuilder.WriteString(fmt.Sprintf("- **Target App**: %s\n", f.TargetName))
			mdBuilder.WriteString(fmt.Sprintf("- **Report Directory**: [%s](file://%s)\n", filepath.Base(f.ReportDir), f.ReportDir))
			if !f.Layer1Passed {
				mdBuilder.WriteString(fmt.Sprintf("- **Layer 1 Failure**: Test name `%s` not found in report.\n", f.TestName))
			}
			if !f.Layer2Passed {
				mdBuilder.WriteString("- **Layer 2 Failure**: Expected target/evidence substring(s) not found:\n")
				for _, m := range f.MissingTargets {
					mdBuilder.WriteString(fmt.Sprintf("  - `%s` (expected from: `%v`)\n", m, f.ExpectedTargets))
				}
			}
			mdBuilder.WriteString("\n")
		}
	} else {
		mdBuilder.WriteString("## All Tests Passed Successfully!\n")
	}

	if *mdPath != "" {
		err = os.WriteFile(*mdPath, []byte(mdBuilder.String()), 0644)
		if err != nil {
			fmt.Printf("%s[WARNING] Failed to write Markdown report to %s: %v%s\n", Yellow, *mdPath, err, Reset)
		}
	}

	if failed > 0 {
		os.Exit(1)
	}
}
