# Changelog

All notable changes to BBPTS are documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] — 2026-06-05

### Added

- **Configurable Port List**: Naabu port list moved from hardcoded to `config.json` (`"ports"` field). Empty = built-in default.
- **Tool Exclusions**: New `-exclude-tools` / `-x` CLI flag to skip specific tools without editing presets.
- **Batch Parallelism**: New `-batch-size` / `-b` flag and `batch_size` config field for concurrent multi-domain scanning.
- **Log Level Control**: New `-log-level` flag (`debug`, `info`, `warn`, `error`) for fine-grained log verbosity.
- **Custom Report Templates**: New `-report-template` flag and `report_template` config field for user-supplied Go `text/template` HTML reports.
- **Containerization Guide**: New `docs/CONTAINERIZATION.md` with Docker usage, volume mounts, and per-tool container roadmap.

### Changed

- **Dockerfile**: Updated with ldflags version injection, massdns binary copy, wordlists, healthcheck, and `dnsutils` runtime dependency.
- **Version**: Bumped to v1.1.2.

---

## [1.1.1] — 2026-06-04

### Added

- **TUI Settings Editor**: Interactive configuration menu accessible via `/configure` (or `/setup` / `/keys`) to update API keys and notification webhooks.
- **TUI Command Listing Hotkey**: Typing `/` inside an empty target input box immediately outputs all available commands.
- **Beginner Quick Start Guide**: Added a step-by-step setup and testing guide at the top of the HTML report.
- **Clickable Target & Evidence Links**: Target domains and all evidence URLs in the HTML report are now clickable links.
- **Interactive Checklists**: Recommended testing checklist is now rendered with interactive checkboxes.
- **Action Steps by Severity**: Context-aware "Next Action" guide added to findings based on risk level.
- **Sleek Dark Mode**: Designed a premium, modern dark mode theme for the HTML report.
- **Global Asset Copying**: `make install` and `make install-user` targets copy configs and wordlists to `~/.bbpts` for global out-of-the-box execution.
- **Verify Command**: Introduced `cmd/verify/main.go` and validation framework test suite.

### Changed

- **Config & Rules Fallbacks**: Wordlists and rules path fallbacks automatically redirect search path to `~/.bbpts` if missing locally.
- **Parallel Recon Optimization**: Redesigned Gobuster, Ffuf, and Dalfox runners with worker pool concurrency and dynamic timeout limits under low-resource environments.
- **Resource Limit Controls**: Enforce CPU and memory limits inside resource_guard.

## [1.1.0] — 2026-05-24

### Added

- **TUI overhaul** (`tui/model.go`): Interactive target-input wizard, real-time scan-abort via `ScanAbortChan`, per-stage tool-list display, scrollable event feed with type/properties, rich progress panels, and animated status indicators.
- **TUI bridge** (`tui/bridge.go`): `PromptForTarget`, `SendInitialTargets`, `ReportStageTools`, and enriched `SendEvent(source, target, eventType, properties)` for full bidirectional orchestrator↔TUI communication.
- **Target pre-validation** (`cli/app.go`): `validateTargetsWithHTTPX` — DNS resolution + httpx liveness probe before any scan stage begins.
- **Global results directory** (`cli/app.go`): All reports (CSV, HackerOne, Bugcrowd, evidence bundle, HTML/JSON/Burp/Caido/ZAP) mirrored to `~/.bbpts/results/` in addition to the local run directory.
- **Persistent SQLite database** moved to `~/.bbpts/bbpts.db` for cross-run persistence.
- **`ProxyInsecure` config field** (`services/orchestrator.go`): Disables TLS verification for intercepting proxies (Burp Suite, mitmproxy).
- **`ReportStageTools` interface method** (`services/orchestrator.go`): Orchestrator now reports tool names per stage to any `ProgressReporter`.
- **Stage-4 mock port-scan events** (`services/mock_tools.go`): Mock pipeline now emits naabu `port_open` events for `api.*` and `mail.*` subdomains.
- **`resource_guard.go`** (`shared/utils/`): New utility for resource lifecycle management.
- **`cache_test.go`** (`application/services/`): Test coverage for the service cache layer.
- **`db_test.go`** (`infrastructure/storage/`): Test coverage for the storage database layer.
- Rate limiting for Shodan queries to prevent API request throttling.
- Unified target normalization for host-based stage-2 tools (dnsx, naabu, shodan).

### Changed

- **Mock data sanitized**: All `example.com` / `Example Inc.` placeholders replaced with `acme-corp.io` / `Acme Corp Ltd.` across mock tools, command outputs, and ~60 test files.
- **`reportEvent` signature** (`services/orchestrator.go`): Now passes full `Event` struct instead of loose `source, target` strings, enabling downstream property enrichment.
- **Target normalization** (`services/orchestrator.go`): `prepareTargetsForTool` refactored — `dnsx`, `naabu`, and `shodan` always receive host-normalised targets regardless of stage number.
- **Context propagation** (`cli/app.go`): `runCtx` now derived from `abortCtx` (abort-signal aware); scan mode injected via `services.WithScanMode`.
- **Timeout scaling** (`cli/app.go`): Scan timeout now multiplied by number of tools in the preset.
- **`--db-type`** now accepts both `"sqlite3"` and `"sqlite"` as valid values.
- **Cache write errors** (`services/orchestrator.go`): Previously silenced `cache.Put` errors now emit `slog.Warn`.
- **Naabu port comment** (`services/naabu.go`): Hardcoded port list is now explicitly documented as a known limitation pending config migration.
- **NATS bus, checkpoint, lease, stream, storage** refactored for internal consistency.
- **Normalizer** (`shared/normalize/normalizer.go`): Improved scope guard and host normalisation logic.
- Improved target WHOIS normalization to strip protocol, path, and port suffixes.
- Enhanced WHOIS parser to handle case-insensitive outputs and registrar key aliases.
- Removed unused stub types and fields from queue stubs and UI model.

### Fixed

- `ims.Store` / `de.StoreResult` return values in `diff_engine_test.go` were silently discarded — now handled with `_ =`.
- `ReportEvent` interface mismatch between bridge and orchestrator resolved — both now use the 4-argument enriched signature.
- Bus, checkpoint, lease, and queue stubs updated to match the new API surface.
- Resolved unhandled error return linter warnings across queue, lease, browser, cache, and test suites.

---

## [1.0.0] — 2026-05-15

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
