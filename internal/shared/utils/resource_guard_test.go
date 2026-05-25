package utils

import (
	"os"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestApplyResourceLimits_CPUPercent(t *testing.T) {
	// Clear any env overrides first
	os.Unsetenv("BBPTS_MAX_CPU_PERCENT")
	os.Unsetenv("BBPTS_MAX_CPU_CORES")
	os.Unsetenv("BBPTS_MAX_MEMORY_MB")
	os.Unsetenv("BBPTS_GC_PERCENT")

	numCPUs := runtime.NumCPU()

	// Test 100% CPU percent
	ApplyResourceLimits(100, 0, 0, 0)
	currentProcs := runtime.GOMAXPROCS(0)
	if currentProcs != numCPUs {
		t.Errorf("Expected GOMAXPROCS to be %d, got %d", numCPUs, currentProcs)
	}

	// Test 50% CPU percent
	ApplyResourceLimits(50, 0, 0, 0)
	expectedProcs := int(float64(numCPUs)*0.5 + 0.5)
	if expectedProcs < 1 {
		expectedProcs = 1
	}
	currentProcs = runtime.GOMAXPROCS(0)
	if currentProcs != expectedProcs {
		t.Errorf("Expected GOMAXPROCS to be %d, got %d", expectedProcs, currentProcs)
	}
}

func TestApplyResourceLimits_CPUCores(t *testing.T) {
	os.Unsetenv("BBPTS_MAX_CPU_CORES")

	// Set CPU Cores directly via args
	ApplyResourceLimits(0, 1, 0, 0)
	currentProcs := runtime.GOMAXPROCS(0)
	if currentProcs != 1 {
		t.Errorf("Expected GOMAXPROCS to be 1, got %d", currentProcs)
	}
}

func TestApplyResourceLimits_GCPercent(t *testing.T) {
	os.Unsetenv("BBPTS_GC_PERCENT")

	// Set custom GC percent
	ApplyResourceLimits(0, 0, 0, 80)

	// debug.SetGCPercent returns the previous setting
	prev := debug.SetGCPercent(100)
	if prev != 80 {
		t.Errorf("Expected GC percent to be 80, got %d", prev)
	}
}

func TestApplyResourceLimits_EnvOverrides(t *testing.T) {
	os.Setenv("BBPTS_MAX_CPU_CORES", "2")
	os.Setenv("BBPTS_GC_PERCENT", "120")
	defer func() {
		os.Unsetenv("BBPTS_MAX_CPU_CORES")
		os.Unsetenv("BBPTS_GC_PERCENT")
	}()

	ApplyResourceLimits(0, 1, 0, 80) // CPU cores=1, GC=80 in args

	// Env overrides should take precedence: cores=2, GC=120
	currentProcs := runtime.GOMAXPROCS(0)
	numCPUs := runtime.NumCPU()
	expectedCPUs := 2
	if expectedCPUs > numCPUs {
		expectedCPUs = numCPUs
	}
	if currentProcs != expectedCPUs {
		t.Errorf("Expected GOMAXPROCS to be %d from env override, got %d", expectedCPUs, currentProcs)
	}

	prev := debug.SetGCPercent(100)
	if prev != 120 {
		t.Errorf("Expected GC percent to be 120 from env override, got %d", prev)
	}
}
