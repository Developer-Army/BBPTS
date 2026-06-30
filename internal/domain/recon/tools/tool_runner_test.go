package tools

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func TestExecToolEmptyTargets(t *testing.T) {
	lines, err := ExecTool(context.Background(), os.Args[0], helperCommandArgs("echo"), nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected no lines, got %d", len(lines))
	}
}

func TestExecToolEchoesTargets(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")

	lines, err := ExecTool(context.Background(), os.Args[0], helperCommandArgs("echo"), []string{"one", "two"})
	if err != nil {
		t.Fatalf("expected command to succeed, got %v", err)
	}
	if len(lines) != 2 || lines[0] != "one" || lines[1] != "two" {
		t.Fatalf("unexpected lines: %#v", lines)
	}
}

func TestExecToolRespectsContextCancellation(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := ExecTool(ctx, os.Args[0], helperCommandArgs("sleep"), []string{"ignored"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func helperCommandArgs(mode string) []string {
	return []string{"-test.run=TestHelperProcess", "--", mode}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	mode := ""
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
			break
		}
	}

	switch mode {
	case "echo":
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "sleep":
		time.Sleep(2 * time.Second)
		os.Exit(0)
	case "waf":
		fmt.Println("some normal output")
		fmt.Println("WAF block detected: 403 forbidden")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
		os.Exit(2)
	}
}

func TestAdaptiveBackoffWAFDetection(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")

	toolName := os.Args[0]

	limits := map[string]int{toolName: 100}
	ctx := recon.WithToolRateLimits(context.Background(), limits)

	initial := ToolRateLimitFromCtx(ctx, toolName)
	if initial != 100 {
		t.Fatalf("expected rate limit 100, got %d", initial)
	}

	lines, err := RunCommandStreamWithInput(ctx, nil, toolName, helperCommandArgs("waf")...)
	if err != nil {
		t.Fatalf("expected clean run, got error: %v", err)
	}

	if len(lines) == 0 {
		t.Fatal("expected mock/helper output lines, got empty")
	}

	throttled := ToolRateLimitFromCtx(ctx, toolName)
	if throttled != 50 {
		t.Errorf("expected throttled rate limit to be 50, got %d", throttled)
	}

	_, err = RunCommandStreamWithInput(ctx, nil, toolName, helperCommandArgs("echo")...)
	if err != nil {
		t.Fatalf("expected clean run, got error: %v", err)
	}

	recovered := ToolRateLimitFromCtx(ctx, toolName)
	if recovered <= 50 {
		t.Errorf("expected recovered rate limit to be > 50, got %d", recovered)
	}
}
