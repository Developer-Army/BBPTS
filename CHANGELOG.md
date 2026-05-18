# Changelog

All notable changes to BBPTS are documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-05-15

### Added
- `--version` / `-v` flag for build-time version output
- `build-full` and `build-fleet` Makefile targets for optional NATS/Redis builds
- `scripts/clean-artifacts.sh` for removing committed binaries and results from git history
- `--metrics` / `--metrics-port` flags — Prometheus metrics are now opt-in
- Scorer: file extension detection (`.bak`, `.sql`, `.env`, etc.)
- Scorer: high-value path pattern library (swagger, actuator, `.git`, etc.)
- Scorer: parameterized URL and sensitive parameter name heuristics
- `docs/JS_ANALYSIS.md` documenting the Goja JS analysis engine choice
- `results/.gitkeep` so the results directory is tracked without committing scan output

### Changed
- NATS and Redis are now optional — gated behind `//go:build nats` and `//go:build redis` tags
- Burp Suite export now generates valid Burp XML (was previously JSON)
- Scorer severity thresholds revised upward to reflect expanded score range
- Prometheus metrics server no longer starts automatically — requires `--metrics` flag
- Improved `.gitignore` to exclude compiled binaries and runtime output

### Fixed
- Binary (`bbpts`) and result files were committed to the repository
- `ExportToBurpConfig` generated JSON instead of Burp-compatible XML
- `--version` flag was wired in ldflags but not exposed as a CLI flag

## [1.0.0] — Initial Release

- Staged recon pipeline with 21+ tool adapters
- Event bus architecture with SQLite-backed state tracking
- Differential scanning (new findings across runs)
- Rules engine with configurable `rules.json`
- Multi-format export: Markdown, CSV, JSON, Burp Suite, Caido, Obsidian
- Alerting: Discord, Slack, Telegram
- Optional platform submission: HackerOne, Bugcrowd
- Distributed fleet support via Axiom + NATS worker mesh
- Circuit breaker and exponential backoff retry in network layer
- Bubbletea TUI + local web dashboard
- Docker, Linux, macOS, and Windows support
