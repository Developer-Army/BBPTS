//go:build !windows

package services

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

type commandHandle = *exec.Cmd

func prepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	home, _ := os.UserHomeDir()
	goBin := filepath.Join(home, "go", "bin")
	localBin := filepath.Join(home, ".local", "bin")
	currentPath := os.Getenv("PATH")

	// Create prioritized PATH
	newPath := fmt.Sprintf("%s:%s:/usr/local/go/bin:%s", goBin, localBin, currentPath)

	// Manually resolve the path to ensure we pick up the correct version
	// (e.g., go/bin/httpx vs .local/bin/httpx)
	binaryPath := name
	paths := filepath.SplitList(newPath)
	for _, p := range paths {
		fullPath := filepath.Join(p, name)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			binaryPath = fullPath
			break
		}
	}

	// Calculate safe CPU cores for sub-tools: 90% of total cores
	numCPUs := runtime.NumCPU()
	safeCPUs := int(math.Round(float64(numCPUs) * 0.9))
	if safeCPUs < 1 {
		safeCPUs = 1
	}

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(),
		"PATH="+newPath,
		"GOMEMLIMIT=2GiB",
		fmt.Sprintf("GOMAXPROCS=%d", safeCPUs),
	)

	return cmd
}

func terminateCommand(cmd commandHandle) {
	if cmd.Process != nil {
		// safe to ignore: killing process group is best-effort during cleanup
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
