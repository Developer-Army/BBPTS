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

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

type commandHandle = *exec.Cmd

func PrepareCommand(ctx context.Context, name string, args ...string) commandHandle {
	if !utils.AllowedBinaries[name] && name != os.Args[0] {
		binaryPath := `C:\Windows\System32\invalid_path_forbidden_` + name
		cmd := exec.CommandContext(ctx, binaryPath, args...)
		return cmd
	}

	home, _ := os.UserHomeDir()
	goBin := filepath.Join(home, "go", "bin")
	localBin := filepath.Join(home, ".local", "bin")
	currentPath := os.Getenv("PATH")

	var pathsList []string
	goCommonBin := `C:\Program Files\Go\bin`
	pathsList = append(pathsList, goCommonBin)
	pathsList = append(pathsList, filepath.SplitList(currentPath)...)

	pathsList = append(pathsList, goBin, localBin)

	newPath := strings.Join(pathsList, string(os.PathListSeparator))

	binaryNames := []string{name}
	if !strings.HasSuffix(strings.ToLower(name), ".exe") {
		binaryNames = append(binaryNames, name+".exe")
	}

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

	exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	cmd.Process.Kill()
}
