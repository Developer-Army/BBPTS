package cli

import (
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

func TestApplyPresetAndProfileDefaults_PresetTools(t *testing.T) {
	cfg := &config.Config{
		ToolPresets: map[string]config.ToolPreset{
			"passive": {
				Tools:     "crtsh,httpx",
				Timeout:   "90s",
				RateLimit: 11,
			},
		},
	}
	opts := &Options{Preset: "passive", Timeout: 30 * time.Second}
	ApplyPresetAndProfileDefaults(opts, cfg)
	if opts.Tools != "crtsh,httpx" {
		t.Fatalf("tools: %q", opts.Tools)
	}
	if opts.Timeout != 90*time.Second {
		t.Fatalf("timeout: %v", opts.Timeout)
	}
	if opts.RateLimit != 11 {
		t.Fatalf("rate: %d", opts.RateLimit)
	}
}

func TestApplyPresetAndProfileDefaults_ExplicitToolsUnchanged(t *testing.T) {
	cfg := &config.Config{
		ToolPresets: map[string]config.ToolPreset{
			"passive": {Tools: "crtsh,httpx"},
		},
	}
	opts := &Options{Preset: "passive", Tools: "dnsx,naabu"}
	ApplyPresetAndProfileDefaults(opts, cfg)
	if opts.Tools != "dnsx,naabu" {
		t.Fatalf("tools should stay explicit: %q", opts.Tools)
	}
}

func TestApplyPresetAndProfileDefaults_ProfileRateWhenToolsExplicit(t *testing.T) {
	cfg := &config.Config{
		ProgramProfiles: map[string]config.ProgramProfile{
			"scoped": {RateLimit: 7},
		},
	}
	opts := &Options{Profile: "scoped", Tools: "httpx", RateLimit: 0}
	ApplyPresetAndProfileDefaults(opts, cfg)
	if opts.RateLimit != 7 {
		t.Fatalf("expected profile rate when CLI rate unset: %d", opts.RateLimit)
	}
}

func TestApplyPresetAndProfileDefaults_LightModeFiltersExplicitTools(t *testing.T) {
	cfg := &config.Config{}
	opts := &Options{
		Tools:     "subfinder,ffuf,httpx,nuclei,gobuster",
		LightMode: true,
	}

	ApplyPresetAndProfileDefaults(opts, cfg)

	if opts.Tools != "crtsh,subfinder,httpx" {
		t.Fatalf("unexpected tools after light filter: %q", opts.Tools)
	}
}

func TestApplyPresetAndProfileDefaults_LightModeFiltersDefaultTools(t *testing.T) {
	cfg := &config.Config{}
	opts := &Options{LightMode: true}

	ApplyPresetAndProfileDefaults(opts, cfg)

	want := "crtsh,subfinder,httpx"
	if opts.Tools != want {
		t.Fatalf("unexpected tools for light mode: %q", opts.Tools)
	}
}
