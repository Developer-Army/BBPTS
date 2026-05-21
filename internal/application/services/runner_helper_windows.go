//go:build windows

package recon

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
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	_ = cmd.Process.Kill()
}
