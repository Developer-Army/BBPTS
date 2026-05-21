//go:build windows

package services

import (
	"context"
	"os/exec"
	"strconv"
)

type commandHandle = *exec.Cmd

func prepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	return exec.CommandContext(ctx, name, args...)
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
