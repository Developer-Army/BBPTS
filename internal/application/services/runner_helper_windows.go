//go:build windows

package services

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type commandHandle = *exec.Cmd

func prepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	home, _ := os.UserHomeDir()
	goBin := filepath.Join(home, "go", "bin")
	localBin := filepath.Join(home, ".local", "bin")
	currentPath := os.Getenv("PATH")

	// Create prioritized PATH using os.PathListSeparator
	pathsList := []string{goBin, localBin}
	
	// Add Go standard install path on Windows
	goCommonBin := `C:\Program Files\Go\bin`
	pathsList = append(pathsList, goCommonBin)
	
	// Append current PATH
	pathsList = append(pathsList, filepath.SplitList(currentPath)...)
	
	newPath := strings.Join(pathsList, string(os.PathListSeparator))

	// On Windows, resolve with .exe if needed
	binaryNames := []string{name}
	if !strings.HasSuffix(strings.ToLower(name), ".exe") {
		binaryNames = append(binaryNames, name+".exe")
	}

	// Manually resolve the path to ensure we pick up the correct version
	binaryPath := name
	found := false
	for _, p := range pathsList {
		for _, bName := range binaryNames {
			fullPath := filepath.Join(p, bName)
			if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
				binaryPath = fullPath
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	numCPUs := runtime.NumCPU()
	safeCPUs := int(math.Round(float64(numCPUs) * 0.9))
	if safeCPUs < 1 {
		safeCPUs = 1
	}

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Env = append(os.Environ(),
		"PATH="+newPath,
		"GOMEMLIMIT=2GiB",
		fmt.Sprintf("GOMAXPROCS=%d", safeCPUs),
	)
	return cmd
}

func terminateCommand(cmd commandHandle) {
	if cmd.Process == nil {
		return
	}

	// Best effort: terminate the whole process tree when available.
	// safe to ignore: killing process tree is best-effort during cleanup
	exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	cmd.Process.Kill()
}
