# BBPTS End-to-End Integration Examples

This document demonstrates complete workflows and integrations for BBPTS.

## Example 1: Full Recon and Vuln Scan

This workflow runs sub-domain enumeration, live host discovery, and a full vulnerability scan using Nuclei.

**Target File (`targets.txt`):**
```
example.com
```

**Command:**
```bash
./bbpts -i targets.txt -o results/
```

**Expected Workflow:**
1. **Subfinder** runs to find subdomains of `example.com`.
2. **HTTPx** probes the discovered subdomains to find live web servers.
3. **Nuclei** runs against the live servers with standard templates.
4. Final results are saved in `results/bbpts_report.json` and `.md`.

## Example 2: Distributed Fleet Mode (Integration)

BBPTS can act as an orchestrator for distributed fleet workers.

**Server Setup:**
```bash
./bbpts server -port 8080
```

**Worker Setup:**
```bash
./bbpts worker -server http://orchestrator-ip:8080
```

**Execution:**
Submit targets to the orchestrator via the REST API or UI. The orchestrator dispatches chunks to the connected workers.

## Example 3: Continuous Monitoring

BBPTS can monitor target lists for changes over time.

**Command:**
```bash
./bbpts -i targets.txt -monitor -interval 24h
```
This runs the pipeline every 24 hours and alerts on *new* subdomains or *new* vulnerabilities discovered since the last run.
