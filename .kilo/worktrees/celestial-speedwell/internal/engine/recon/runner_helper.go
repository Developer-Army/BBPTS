package recon

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

func waitForCommand(ctx context.Context, cmd commandHandle, stderr *bytes.Buffer) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		terminateCommand(cmd)
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			errText := strings.TrimSpace(stderr.String())
			if errText == "" {
				return err
			}
			return fmt.Errorf("%w: %s", err, errText)
		}
		return nil
	}
}

// ExecTool runs an external tool safely. It uses platform-specific process cleanup
// so that a timed out tool does not leave child processes behind.
func ExecTool(ctx context.Context, name string, args []string, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	cmd := prepareCommand(ctx, name, args...)
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s: %w", name, err)
	}

	if err := waitForCommand(ctx, cmd, &stderr); err != nil {
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}

	rawOutput := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var cleanOutput []string
	for _, line := range rawOutput {
		if strings.TrimSpace(line) != "" {
			cleanOutput = append(cleanOutput, strings.TrimSpace(line))
		}
	}

	return cleanOutput, nil
}
