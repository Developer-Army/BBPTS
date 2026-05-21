//go:build windows

package services

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
)

type commandHandle = *exec.Cmd

func prepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	numCPUs := runtime.NumCPU()
	safeCPUs := int(math.Round(float64(numCPUs) * 0.9))
	if safeCPUs < 1 {
		safeCPUs = 1
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(),
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
