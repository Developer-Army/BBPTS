//go:build !windows

package tools

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

type commandHandle = *exec.Cmd

func PrepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	if !utils.AllowedBinaries[name] && name != os.Args[0] {
		binaryPath := "/invalid/path/forbidden/" + name
		cmd := exec.CommandContext(ctx, binaryPath, args...)
		return cmd
	}

	pathsList := utils.GetSecurePaths()

	newPath := strings.Join(pathsList, string(os.PathListSeparator))

	binaryPath := ""
	if name == os.Args[0] {
		binaryPath = name
	} else {
		for _, p := range pathsList {
			fullPath := filepath.Join(p, name)
			if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
				binaryPath = fullPath
				break
			}
		}
	}

	if binaryPath == "" {
		binaryPath = "/invalid/path/notfound/" + name
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

	nicePath, niceErr := exec.LookPath("nice")

	if recon.ContainerModeFromCtx(ctx) {
		var containerRuntime string
		if _, err := exec.LookPath("docker"); err == nil {
			containerRuntime = "docker"
		} else if _, err := exec.LookPath("podman"); err == nil {
			containerRuntime = "podman"
		}

		if containerRuntime != "" {
			image := name + ":latest"
			if images := recon.DockerImagesFromCtx(ctx); images != nil {
				if img, found := images[name]; found && img != "" {
					image = img
				}
			}

			dockerArgs := []string{"run", "--rm", "-i"}
			if lowRes {
				dockerArgs = append(dockerArgs, "--cpus=1", "--memory=1g")
			}

			if _, err := exec.LookPath("runsc"); err == nil {
				dockerArgs = append(dockerArgs, "--runtime=runsc")
			}

			dockerArgs = append(dockerArgs,
				"--cap-drop=all",
				"--security-opt=no-new-privileges:true",
			)

			uid := os.Getuid()
			gid := os.Getgid()
			if uid > 0 && gid > 0 {
				dockerArgs = append(dockerArgs, "--user", fmt.Sprintf("%d:%d", uid, gid))
			}

			if cwd, err := os.Getwd(); err == nil {
				dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:ro", cwd, cwd), "-w", cwd)
			}

			if tmpDir := recon.GetTmpResultsDir(ctx); tmpDir != "" {
				if absTmpDir, err := filepath.Abs(tmpDir); err == nil {
					dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:rw", absTmpDir, absTmpDir))
				}
			}

			if wlDir := recon.WordlistsDirFromContext(ctx); wlDir != "" {
				if absWlDir, err := filepath.Abs(wlDir); err == nil {
					dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:ro", absWlDir, absWlDir))
				}
			}

			dockerArgs = append(dockerArgs, image)
			dockerArgs = append(dockerArgs, args...)

			slog.Debug("executing tool in container sandbox", "runtime", containerRuntime, "image", image, "tool", name)

			var cmd *exec.Cmd
			if niceErr == nil {
				priority := "10"
				if lowRes {
					priority = "15"
				}
				niceArgs := append([]string{"-n", priority, containerRuntime}, dockerArgs...)
				cmd = exec.CommandContext(ctx, nicePath, niceArgs...)
			} else {
				cmd = exec.CommandContext(ctx, containerRuntime, dockerArgs...)
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			return cmd
		} else {
			slog.Warn("ContainerMode enabled but neither docker nor podman is available in PATH. Falling back to local execution.")
		}
	}

	var cmd *exec.Cmd
	if niceErr == nil {
		priority := "10"
		if lowRes {
			priority = "15"
		}
		niceArgs := append([]string{"-n", priority, binaryPath}, args...)
		cmd = exec.CommandContext(ctx, nicePath, niceArgs...)
	} else {
		cmd = exec.CommandContext(ctx, binaryPath, args...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(),
		"PATH="+newPath,
		"GOMEMLIMIT=2GiB",
		fmt.Sprintf("GOMAXPROCS=%d", safeCPUs),
	)

	return cmd
}

func TerminateCommand(cmd commandHandle) {
	if cmd.Process != nil {

		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
