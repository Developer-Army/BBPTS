package utils

import (
	"fmt"
	"io"
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
		"amass", "subfinder", "massdns", "assetfinder", "httpx", "dnsx",
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
			cmd, cmdErr := PrepareSecureCommand(nil, t, versionCmd)
			var out []byte
			if cmdErr == nil {
				out, err = cmd.CombinedOutput()
			}
			if (err != nil || cmdErr != nil) && t == "httpx" {
				// Try Python httpx version check as fallback/detection
				cmd2, cmd2Err := PrepareSecureCommand(nil, t, "--version")
				if cmd2Err == nil {
					out, _ = cmd2.CombinedOutput()
				}
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

func PrintReport(w io.Writer, results []ToolStatus) {
	fmt.Fprintf(w, "BBPTS Doctor - Environment Diagnostics\n")
	fmt.Fprintf(w, "OS: %s | Arch: %s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "--------------------------------------------------\n")

	missing := 0
	for _, s := range results {
		icon := "✓"
		if !s.Installed {
			icon = "✗"
			missing++
		}

		fmt.Fprintf(w, "[%s] %-12s ", icon, s.Name)
		if s.Installed {
			if s.Version != "" {
				if strings.Contains(s.Version, "CONFLICT") {
					fmt.Fprintf(w, "(%s)", s.Version)
				} else {
					fmt.Fprintf(w, "(v%s at %s)", s.Version, s.Path)
				}
			} else {
				fmt.Fprintf(w, "(Installed at %s)", s.Path)
			}
		} else {
			fmt.Fprintf(w, "(NOT FOUND)")
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "--------------------------------------------------\n")
	if missing == 0 {
		fmt.Fprintln(w, "All systems go! Your BBPTS environment is healthy.")
	} else {
		fmt.Fprintf(w, "Diagnostic complete: %d tool(s) missing. Run 'scripts/setup.sh' to fix.\n", missing)
	}
}
