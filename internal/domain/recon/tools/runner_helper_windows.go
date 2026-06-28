//go:build windows

package tools

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

func PrepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	home, _ := os.UserHomeDir()
	goBin := filepath.Join(home, "go", "bin")
	localBin := filepath.Join(home, ".local", "bin")
	currentPath := os.Getenv("PATH")

	// Standard/System PATHs first to prevent command shadowing/hijacking
	var pathsList []string
	goCommonBin := `C:\Program Files\Go\bin`
	pathsList = append(pathsList, goCommonBin)
	pathsList = append(pathsList, filepath.SplitList(currentPath)...)

	// User-writable paths last
	pathsList = append(pathsList, goBin, localBin)

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

	lowRes := recon.LowResourceFromCtx(ctx)

	numCPUs := runtime.NumCPU()
	cpuPercentage := 0.9
	if lowRes {
		cpuPercentage = 0.2
	}
	safeCPUs := int(math.Round(float64(numCPUs) * cpuPercentage))
	if lowRes && safeCPUs > 2 {
		safeCPUs = 2
	}
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

func TerminateCommand(cmd commandHandle) {
	if cmd.Process == nil {
		return
	}

	// Best effort: terminate the whole process tree when available.
	// safe to ignore: killing process tree is best-effort during cleanup
	exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	cmd.Process.Kill()
}
