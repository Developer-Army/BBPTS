package utils

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

type ToolStatus struct {
	Name      string
	Installed bool
	Path      string
	Version   string
}

func CheckEnvironment() []ToolStatus {
	tools := []string{
		"amass", "subfinder", "findomain", "massdns", "assetfinder", "httpx", "dnsx",
		"naabu", "katana", "gau", "hakrawler", "whois",
		"ffuf", "gobuster", "chaos", "dalfox", "nuclei", "shodan", "wafw00f", "trufflehog", "axiom-scan",
	}

	results := make([]ToolStatus, 0, len(tools))
	for _, t := range tools {
		status := ToolStatus{Name: t}
		path, err := exec.LookPath(t)
		if err == nil {
			status.Installed = true
			status.Path = path
			// Try to get version
			versionCmd := "-version"
			if t == "amass" {
				versionCmd = "version"
			}
			cmd := exec.Command(t, versionCmd)
			out, err := cmd.CombinedOutput()
			if err != nil && t == "httpx" {
				// Try Python httpx version check as fallback/detection
				cmd = exec.Command(t, "--version")
				out, _ = cmd.CombinedOutput()
			}

			if err == nil || (t == "httpx" && strings.Contains(string(out), "httpx")) {
				status.Version = strings.TrimSpace(string(out))
				if lines := strings.Split(status.Version, "\n"); len(lines) > 0 {
					status.Version = lines[0]
				}

				// Specific check for httpx conflict
				versionLower := strings.ToLower(status.Version)
				if t == "httpx" && (strings.Contains(versionLower, "python") || strings.Contains(versionLower, "usage: httpx")) {
					status.Version = "CONFLICT: Python httpx detected (PD httpx required)"
				}
			}
		}
		results = append(results, status)
	}
	return results
}

func PrintReport(results []ToolStatus) {
	fmt.Printf("BBPTS Doctor - Environment Diagnostics\n")
	fmt.Printf("OS: %s | Arch: %s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("--------------------------------------------------\n")

	missing := 0
	for _, s := range results {
		icon := "✓"
		if !s.Installed {
			icon = "✗"
			missing++
		}

		fmt.Printf("[%s] %-12s ", icon, s.Name)
		if s.Installed {
			if s.Version != "" {
				if strings.Contains(s.Version, "CONFLICT") {
					fmt.Printf("(%s)", s.Version)
				} else {
					fmt.Printf("(v%s at %s)", s.Version, s.Path)
				}
			} else {
				fmt.Printf("(Installed at %s)", s.Path)
			}
		} else {
			fmt.Printf("(NOT FOUND)")
		}
		fmt.Println()
	}

	fmt.Printf("--------------------------------------------------\n")
	if missing == 0 {
		fmt.Println("All systems go! Your BBPTS environment is healthy.")
	} else {
		fmt.Printf("Diagnostic complete: %d tool(s) missing. Run 'scripts/setup.sh' to fix.\n", missing)
	}
}
