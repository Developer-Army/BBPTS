package utils

import (
	"bufio"
	"math"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"log/slog"
)

// InitializeResourceGuard sets up CPU and memory limits with default settings.
func InitializeResourceGuard() {
	ApplyResourceLimits(0, 0, 0, 0)
}

// ApplyResourceLimits dynamically configures the CPU, Memory, and GC limits,
// taking environment variables as the highest precedence overrides.
func ApplyResourceLimits(maxCPUPercent, maxCPUCores, maxMemoryMB, gcPercent int) {
	// 1. Environment overrides
	if envCPU := os.Getenv("BBPTS_MAX_CPU_PERCENT"); envCPU != "" {
		if val, err := strconv.Atoi(envCPU); err == nil && val > 0 && val <= 100 {
			maxCPUPercent = val
		}
	}
	if envCores := os.Getenv("BBPTS_MAX_CPU_CORES"); envCores != "" {
		if val, err := strconv.Atoi(envCores); err == nil && val > 0 {
			maxCPUCores = val
		}
	}
	if envMem := os.Getenv("BBPTS_MAX_MEMORY_MB"); envMem != "" {
		if val, err := strconv.Atoi(envMem); err == nil && val > 0 {
			maxMemoryMB = val
		}
	}
	if envGC := os.Getenv("BBPTS_GC_PERCENT"); envGC != "" {
		if val, err := strconv.Atoi(envGC); err == nil && val > 0 {
			gcPercent = val
		}
	}

	// 2. Memory Guard & GC Percent
	totalMemory := getSystemTotalMemory()
	finalGCPercent := 100 // Go default
	if gcPercent > 0 {
		finalGCPercent = gcPercent
	} else if totalMemory > 0 && totalMemory < 4*1024*1024*1024 {
		finalGCPercent = 50 // Keep GC aggressive for low memory systems (<4GB)
	}
	debug.SetGCPercent(finalGCPercent)

	var limitBytes int64
	if maxMemoryMB > 0 {
		limitBytes = int64(maxMemoryMB) * 1024 * 1024
		debug.SetMemoryLimit(limitBytes)
		slog.Info("Resource Guard: set Go soft memory limit", "limit_mb", maxMemoryMB, "gc_percent", finalGCPercent)
	} else if totalMemory > 0 {
		// Cap memory limit at 2GB (or 85% of total system RAM, whichever is smaller) to protect low-end PCs
		limitBytes = int64(float64(totalMemory) * 0.85)
		twoGB := int64(2 * 1024 * 1024 * 1024)
		if limitBytes > twoGB {
			limitBytes = twoGB
		}
		debug.SetMemoryLimit(limitBytes)
		slog.Info("Resource Guard: set Go soft memory limit", "limit_mb", limitBytes/(1024*1024), "gc_percent", finalGCPercent)
	} else {
		// Fallback memory limit: 2GB
		limitBytes = 2 * 1024 * 1024 * 1024
		debug.SetMemoryLimit(limitBytes)
		slog.Info("Resource Guard: set fallback Go soft memory limit to 2GB", "gc_percent", finalGCPercent)
	}

	// 3. CPU Guard
	numCPUs := runtime.NumCPU()
	safeCPUs := 0
	if maxCPUCores > 0 {
		safeCPUs = maxCPUCores
	} else {
		percent := 90
		if maxCPUPercent > 0 {
			percent = maxCPUPercent
		}
		// Rounding rather than truncation so that 90% of 2 cores = 2 cores
		safeCPUs = int(math.Round(float64(numCPUs) * float64(percent) / 100.0))
	}

	if safeCPUs < 1 {
		safeCPUs = 1
	}
	if safeCPUs > numCPUs {
		safeCPUs = numCPUs
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
