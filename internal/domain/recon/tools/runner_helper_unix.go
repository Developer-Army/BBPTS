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
	"syscall"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

type commandHandle = *exec.Cmd

var allowedBinaries = map[string]bool{
	"dnsx":        true,
	"nuclei":      true,
	"subfinder":   true,
	"httpx":       true,
	"naabu":       true,
	"dalfox":      true,
	"amass":       true,
	"assetfinder": true,
	"crtsh":       true,
	"ffuf":        true,
	"gau":         true,
	"gobuster":    true,
	"gowitness":   true,
	"hakrawler":   true,
	"interactsh":  true,
	"katana":      true,
	"massdns":     true,
	"puredns":     true,
	"shodan":      true,
	"trufflehog":  true,
	"uro":         true,
	"wafw00f":     true,
	"whois":       true,
	"axiom-fleet": true,
	"axiom-scan":  true,
	"axiom-ls":    true,
	"docker":      true,
	"podman":      true,
	"runsc":       true,
	"sysctl":      true,
	"wmic":        true,
	"taskkill":    true,
	"dig":         true,
	"nslookup":    true,
}

func PrepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	if !allowedBinaries[name] && name != os.Args[0] {
		binaryPath := "/invalid/path/forbidden/" + name
		cmd := exec.CommandContext(ctx, binaryPath, args...)
		return cmd
	}

	// Create prioritized PATH (placing system directories first to prevent hijacking/shadowing)
	systemPaths := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"

	// Manually resolve the path to ensure we pick up the correct version
	binaryPath := ""
	if name == os.Args[0] {
		binaryPath = name
	} else {
		paths := filepath.SplitList(systemPaths)
		for _, p := range paths {
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

	// Calculate safe CPU cores for sub-tools: 90% of total cores
	numCPUs := runtime.NumCPU()
	safeCPUs := int(math.Round(float64(numCPUs) * 0.9))
	if safeCPUs < 1 {
		safeCPUs = 1
	}

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
			if tmpDir := recon.GetTmpResultsDir(ctx); tmpDir != "" {
				if absTmpDir, err := filepath.Abs(tmpDir); err == nil {
					dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:%s:rw", absTmpDir, absTmpDir))
				}
			}

			// Mount wordlist directory as read-only
			if wlDir := recon.WordlistsDirFromContext(ctx); wlDir != "" {
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
		"PATH="+systemPaths,
		"GOMEMLIMIT=2GiB",
		fmt.Sprintf("GOMAXPROCS=%d", safeCPUs),
	)

	return cmd
}

func TerminateCommand(cmd commandHandle) {
	if cmd.Process != nil {
		// safe to ignore: killing process group is best-effort during cleanup
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
