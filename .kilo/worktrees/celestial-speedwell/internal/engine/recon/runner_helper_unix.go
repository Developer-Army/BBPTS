//go:build !windows

package recon

import (
	"context"
	"os/exec"
	"syscall"
)

type commandHandle = *exec.Cmd

func prepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func terminateCommand(cmd commandHandle) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
