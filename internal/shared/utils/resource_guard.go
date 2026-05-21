package utils

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"log/slog"
)

// InitializeResourceGuard sets up CPU and memory limits to prevent system freeze/OOM.
func InitializeResourceGuard() {
	// 1. Memory Guard: Set aggressive GC and a soft memory limit (e.g., 85% of total RAM)
	debug.SetGCPercent(50)

	totalMemory := getSystemTotalMemory()
	if totalMemory > 0 {
		// Limit Go memory usage to 85% of total system RAM
		limitBytes := int64(float64(totalMemory) * 0.85)
		debug.SetMemoryLimit(limitBytes)
		slog.Info("Resource Guard: set Go soft memory limit", "limit_mb", limitBytes/(1024*1024))
	} else {
		// Fallback memory limit: 4GB
		debug.SetMemoryLimit(4 * 1024 * 1024 * 1024)
		slog.Info("Resource Guard: set fallback Go soft memory limit to 4GB")
	}

	// 2. CPU Guard: Cap CPU cores used to 90% (leaving at least 10% free for OS and UI rendering)
	numCPUs := runtime.NumCPU()
	safeCPUs := int(float64(numCPUs) * 0.90)
	if safeCPUs < 1 {
		safeCPUs = 1
	}
	runtime.GOMAXPROCS(safeCPUs)
	slog.Info("Resource Guard: set GOMAXPROCS CPU cap", "max_cores", safeCPUs, "total_cores", numCPUs)
}

// getSystemTotalMemory returns the total system memory in bytes, or 0 if unknown.
func getSystemTotalMemory() int64 {
	switch runtime.GOOS {
	case "linux":
		file, err := os.Open("/proc/meminfo")
		if err != nil {
			return 0
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					val, err := strconv.ParseInt(fields[1], 10, 64)
					if err == nil {
						// MemTotal is in kB, convert to bytes
						return val * 1024
					}
				}
			}
		}

	case "darwin":
		// macOS: sysctl -n hw.memsize
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			val, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
			if err == nil {
				return val
			}
		}

	case "windows":
		// Windows: wmic computersystem get TotalPhysicalMemory
		out, err := exec.Command("wmic", "computersystem", "get", "TotalPhysicalMemory").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.Contains(line, "TotalPhysicalMemory") {
					continue
				}
				val, err := strconv.ParseInt(line, 10, 64)
				if err == nil {
					return val
				}
			}
		}
	}
	return 0
}
