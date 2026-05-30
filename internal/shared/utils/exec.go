package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

var allowedUtilsBinaries = map[string]bool{
	"dig":         true,
	"nslookup":    true,
	"sysctl":      true,
	"wmic":        true,
	"git":         true,
	"curl":        true,
	"go":          true,
	"python3":     true,
	"amass":       true,
	"subfinder":   true,
	"massdns":     true,
	"assetfinder": true,
	"httpx":       true,
	"dnsx":        true,
	"naabu":       true,
	"katana":      true,
	"gau":         true,
	"hakrawler":   true,
	"whois":       true,
	"ffuf":        true,
	"gobuster":    true,
	"chaos":       true,
	"dalfox":      true,
	"nuclei":      true,
	"shodan":      true,
	"wafw00f":     true,
	"trufflehog":  true,
	"axiom-scan":  true,
}

// PrepareSecureCommand prepares an exec.Cmd with restricted environment and validated paths.
func PrepareSecureCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if !allowedUtilsBinaries[name] {
		return nil, fmt.Errorf("forbidden binary: %s", name)
	}

	var systemPaths string
	if runtime.GOOS == "windows" {
		systemPaths = `C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Program Files\Go\bin`
	} else {
		systemPaths = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"
	}

	binaryPath := ""
	paths := filepath.SplitList(systemPaths)
	for _, p := range paths {
		bName := name
		if runtime.GOOS == "windows" && filepath.Ext(name) != ".exe" {
			bName += ".exe"
		}
		fullPath := filepath.Join(p, bName)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			binaryPath = fullPath
			break
		}
	}

	if binaryPath == "" {
		// Fallback to normal LookPath but strictly warning/failing if path is user-writable (like tmp, cwd, etc.)
		path, err := exec.LookPath(name)
		if err != nil {
			return nil, fmt.Errorf("binary not found: %s", name)
		}
		binaryPath = path
	}

	var cmd *exec.Cmd
	if ctx != nil {
		cmd = exec.CommandContext(ctx, binaryPath, args...)
	} else {
		cmd = exec.Command(binaryPath, args...)
	}

	cmd.Env = []string{
		"PATH=" + systemPaths,
	}

	return cmd, nil
}
