//go:build !windows

package services

import (
	"context"
	"fmt"
	"log/slog"
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

	if ContainerModeFromCtx(ctx) {
		var containerRuntime string
		if _, err := exec.LookPath("docker"); err == nil {
			containerRuntime = "docker"
		} else if _, err := exec.LookPath("podman"); err == nil {
			containerRuntime = "podman"
		}

		if containerRuntime != "" {
			image := name + ":latest"
			if images := DockerImagesFromCtx(ctx); images != nil {
				if img, found := images[name]; found && img != "" {
					image = img
				}
			}

			dockerArgs := []string{"run", "--rm", "-i"}

			// Use gVisor runtime if available
			if _, err := exec.LookPath("runsc"); err == nil {
				dockerArgs = append(dockerArgs, "--runtime=runsc")
			}

			// Drop all privileges & capabilities
			dockerArgs = append(dockerArgs,
				"--cap-drop=all",
				"--security-opt=no-new-privileges:true",
			)

			// Run as non-root user
			uid := os.Getuid()
			gid := os.Getgid()
			if uid > 0 && gid > 0 {
				dockerArgs = append(dockerArgs, "--user", fmt.Sprintf("%d:%d", uid, gid))
			}

			// Mount current working directory as read-only
			if cwd, err := os.Getwd(); err == nil {
				dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:ro", cwd, cwd), "-w", cwd)
			}

			// Mount temporary results directory as read-write
			if tmpDir := GetTmpResultsDir(ctx); tmpDir != "" {
				if absTmpDir, err := filepath.Abs(tmpDir); err == nil {
					dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:rw", absTmpDir, absTmpDir))
				}
			}

			// Mount wordlist directory as read-only
			if wlDir := wordlistsDirFromContext(ctx); wlDir != "" {
				if absWlDir, err := filepath.Abs(wlDir); err == nil {
					dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:ro", absWlDir, absWlDir))
				}
			}

			dockerArgs = append(dockerArgs, image)
			dockerArgs = append(dockerArgs, args...)

			slog.Debug("executing tool in container sandbox", "runtime", containerRuntime, "image", image, "tool", name)
			cmd := exec.CommandContext(ctx, containerRuntime, dockerArgs...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			return cmd
		} else {
			slog.Warn("ContainerMode enabled but neither docker nor podman is available in PATH. Falling back to local execution.")
		}
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
