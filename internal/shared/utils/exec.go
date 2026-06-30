package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

var AllowedBinaries = map[string]bool{
	"dnsx":              true,
	"nuclei":            true,
	"subfinder":         true,
	"httpx":             true,
	"naabu":             true,
	"dalfox":            true,
	"amass":             true,
	"assetfinder":       true,
	"crtsh":             true,
	"ffuf":              true,
	"feroxbuster":       true,
	"gau":               true,
	"gobuster":          true,
	"gowitness":         true,
	"hakrawler":         true,
	"interactsh":        true,
	"interactsh-client": true,
	"katana":            true,
	"massdns":           true,
	"puredns":           true,
	"shodan":            true,
	"tlsx":              true,
	"trufflehog":        true,
	"uro":               true,
	"chaos":             true,
	"wafw00f":           true,
	"whois":             true,
	"axiom-fleet":       true,
	"axiom-scan":        true,
	"axiom-ls":          true,
	"docker":            true,
	"podman":            true,
	"runsc":             true,
	"sysctl":            true,
	"wmic":              true,
	"taskkill":          true,
	"dig":               true,
	"nslookup":          true,
	"sqlmap":            true,
	"arjun":             true,
	"testssl.sh":        true,
	"git":               true,
	"curl":              true,
	"go":                true,
	"python3":           true,
	"frida":             true,
	"objection":         true,
}

func GetSecurePaths() []string {
	var systemPaths string
	if runtime.GOOS == "windows" {
		systemPaths = `C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Program Files\Go\bin`
	} else {
		systemPaths = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"
	}

	paths := filepath.SplitList(systemPaths)

	if runtime.GOOS != "windows" {

		if home, err := os.UserHomeDir(); err == nil {
			goBin := filepath.Join(home, "go", "bin")
			localBin := filepath.Join(home, ".local", "bin")
			paths = append(paths, goBin, localBin)
		}

		// Lookup original user if running under sudo
		var originalUser *user.User
		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			if u, err := user.LookupId(sudoUID); err == nil {
				originalUser = u
			}
		}
		if originalUser == nil {
			if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
				if u, err := user.Lookup(sudoUser); err == nil {
					originalUser = u
				}
			}
		}

		if originalUser != nil {
			goBin := filepath.Join(originalUser.HomeDir, "go", "bin")
			localBin := filepath.Join(originalUser.HomeDir, ".local", "bin")

			alreadyExists := false
			for _, p := range paths {
				if p == goBin {
					alreadyExists = true
					break
				}
			}
			if !alreadyExists {
				paths = append(paths, goBin, localBin)
			}
		}
	} else {

		if home, err := os.UserHomeDir(); err == nil {
			goBin := filepath.Join(home, "go", "bin")
			localBin := filepath.Join(home, ".local", "bin")
			paths = append(paths, goBin, localBin)
		}
	}

	return paths
}

func PrepareSecureCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if !AllowedBinaries[name] {
		return nil, fmt.Errorf("forbidden binary: %s", name)
	}

	paths := GetSecurePaths()
	newPath := strings.Join(paths, string(os.PathListSeparator))

	binaryPath := ""
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
		"PATH=" + newPath,
	}

	return cmd, nil
}
