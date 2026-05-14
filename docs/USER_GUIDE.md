# BBPTS User Guide

BBPTS helps organize authorized bug bounty reconnaissance into a staged pipeline: parse scope, run selected tools, keep only in-scope discoveries, score the results, and export reports for manual testing.

## API Key Configuration

Some tools require API keys. Add them to your `config.json`:

```json
{
  "api_keys": {
    "shodan": "your-shodan-api-key",
    "chaos": "your-chaos-api-key"
  }
}
```

**API Key Notes:**
- **Shodan**: Used for passive asset discovery and service fingerprinting
- **Chaos**: Used for DNS and subdomain enrichment (Project Sonar data)

Both are optional—tools will skip gracefully if keys are missing.

## Prepare Targets

Start from the sanitized example file:

```bash
cp targets.example.txt targets.txt
```

Use only assets you are authorized to test. Supported inputs are plain text, CSV with headers such as `url,scope,priority,tags,notes`, and JSON target definitions.

## Run a Scan

```bash
./bbpts -i targets.txt -output results/report.md -summary results/summary.csv
```

Useful options:

- `-tools subfinder,httpx,nuclei`: run a specific tool list.
- `-scope example-program`: enable state tracking and diffs for a named program.
- `-diff`: report only assets/events new since the prior completed scan for that scope.
- `-timeout 30m`: set a global timeout window; the default `0` disables the global timeout.
- `-tui`: opt in to the interactive terminal UI.
- `-web -port 8080`: start the local dashboard.

## Continuous Recon

Run continuous recon only from infrastructure you control:

```bash
./bbpts -i targets.txt -scope example-program -cron 60
```

Do not run active recon from GitHub-hosted Actions. Use a self-hosted runner, VPS, or Docker deployment with a private persistent volume for `results/`, `bbpts.db`, screenshots, and state markers.

## Submission Safety

Auto-submit is optional and off by default. Configure one platform only if you want BBPTS to create reports for you automatically:

```json
{
  "submit": {
    "platform": "hackerone"
  }
}
```

Preview first:

```bash
./bbpts -i targets.txt -scope example-program -dry-run
```

Submit only when ready:

```bash
./bbpts -i targets.txt -scope example-program -auto-submit
```

BBPTS records a hash marker in the state directory after a successful submission so repeated cron runs do not resubmit the same finding.

## Output

BBPTS can write Markdown, CSV, JSON, Burp XML, OWASP ZAP XML, Caido JSON, screenshots, evidence bundles, and state databases. These files can contain sensitive target and vulnerability data and should stay out of git.
