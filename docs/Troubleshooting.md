# BBPTS Troubleshooting Guide

This guide helps you resolve common issues encountered while using BBPTS.

## General Diagnostics
If BBPTS fails to run or behaves unexpectedly, use the built-in diagnostic tool:

```bash
./bbpts -doctor
```
This command checks your environment, installed tools, paths, and permissions.

## Common Issues

### 1. `exit status 1` or Tools Failing
**Symptoms:** Subfinder, httpx, or nuclei immediately exit with an error.
**Solution:**
- Run `./bbpts -doctor` to verify tool installations.
- Ensure the binaries are in your system `$PATH` (e.g., `~/go/bin`).
- Check your internet connectivity.
- Verify target input file formatting (one domain per line).

### 2. TUI Corruption or Overlapping Output
**Symptoms:** The terminal interface becomes garbled or text overlaps.
**Solution:**
- Run BBPTS with `TMUX` or `screen`.
- Resize your terminal window. The TUI requires a minimum of 80x24 dimensions.
- Use `-silent` to run without the TUI if the environment doesn't support it.

### 3. Out of Memory (OOM) Errors
**Symptoms:** BBPTS crashes with an OOM killed message.
**Solution:**
- Reduce concurrency using `-c` flag.
- Limit the number of targets per run.

### 4. Missing Dependencies
If you're missing dependencies, run our install script:
```bash
./scripts/install-dependencies.sh
```

## Debug Mode
For deep troubleshooting, enable debug mode. This will print verbose logs to standard output instead of using the TUI:
```bash
./bbpts -i targets.txt -debug
```
Share these logs when filing an issue on GitHub.
