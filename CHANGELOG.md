# Changelog

All notable changes to BBPTS are documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.1] — 2026-07-09

### Added
- **Doctor JSON output**: `-doctor` now supports `-json` flag for machine-readable health reports.
- **Nuclei target cap**: Added `nuclei_target_cap` config field to limit nuclei concurrency (defaults to 200).
- **Login form credentials**: Added `login_url`, `login_user`, `login_pass`, `login_form_user`, `login_form_pass` to orchestrator config for automated auth flows.
- **Open redirect scope validation**: Added `inScopeHost` helper and expanded redirect parameter list to 40+ common variants.

### Fixed
- **Open redirect false positives**: Redirect responses now validate destination hostname against scope before flagging.
- **CI workflow errors**: Fixed lint failures in mobile API discovery, mobile static analysis, source map, supply chain, playbook generator, and browser recon tools.
- **Windows runner helper**: Fixed compilation issue on Windows builds.
- **Registry cleanup**: Removed dead tool registration paths and simplified registry initialization.
- **Dependency vulnerabilities**: Upgraded `utls` to v1.8.2 and `circl` to v1.6.1 to resolve govulncheck findings.
- **CI Go version**: Bumped CI workflows from Go 1.23 to 1.24 to match updated dependency requirements.

### Changed
- **Removed MockMode**: Dropped unused `mock_mode` config field from `Config` and `Orchestrator`.
- **Dead code purge**: Removed ~1,000 lines of unused comments, test stubs, and deprecated utility functions across 350+ files.
- **Setup scripts**: Updated `setup.sh` and `setup.bat` with corrected tool install paths.
- **Contributing links**: Surfaced CONTRIBUTING.md and case study links in README.
- **Documentation**: Adding version `[1.5.0.1]` and `[1.5.1]` to CHANGELOG.md

---

## [1.5.0.1] — 2026-07-02

### Fixed
- **CI workflow errors**: Fixed lint failures across mobile API discovery, mobile static analysis, source map, supply chain, playbook generator, and browser recon tools.
- **Code quality**: Resolved lint warnings and compilation issues across tool adapters and test files.

### Changed
- **Documentation**: Surfaced contributing guidelines and case study links in README.

---

## [1.5.0] — 2026-06-30

### Added
- **Program Intelligence Engine**: Added program intelligence engine and hunting playbook generator.
- **Advanced Testing Tools**: Added ReDoS, supply chain, and multi-tenant isolation testing tools.
- **Coverage Heatmap**: Added endpoint coverage heatmap with DB schema and query methods.
- **Second-Order Injection**: Added detector for stored XSS, SSTI, SQLi.
- **Smart Wordlist Generator**: Added tool with tech/industry vocabulary.
- **Business Logic Test Suite**: Added tests for amount, coupon, quantity manipulation.
- **Blind Injection Hub**: Added tool for XSS, SSTI, CMDi, SSRF via OOB.
- **Rate Limit Bypass**: Added detection tool for rate limiting bypasses.
- **Auth Matrix Tool**: Added IDOR and broken access control detection.
- **Specialized Scanners**: Added SOAP, mobile manifest, and cloud credentials scanners.

---

## [1.4.0] — 2026-06-21

### Added
- **Session Cookie Injection**: Introduced `-cookie` flag to inject session credentials into all downstream active scanner tools.
- **CLI Dry-Run Mode**: Introduced `-dry-run` flag to print simulated commands for downstream tools without executing them.
- **Streaming JSONL Asset Store**: Introduced `-asset-store` flag to write real-time, live-updating JSONL asset discoveries and findings to a specified path.
- **Adaptive Backoff Command Monitoring**: Wired `AdaptiveBackoff` into shell runner execution pipeline to monitor tool stdout/stderr for WAF or rate-limit blocks and dynamically throttle `--rate-limit`.
- **CI/CD Pipeline Mode**: Integrated `--ci` and `--fail-on` flags to exit with non-zero exit codes when findings matching or exceeding the target severity threshold are discovered.
- **Scope Enforcement Engine**: Added the `--scope-file` flag to load and enforce domain allow/exclude wildcards prior to scanning.
- **CVSS 3.1 Scoring**: Implemented a standalone, standard-compliant CVSS 3.1 base score and severity rating calculator.
- **Playwright Diagnostics**: Automated Playwright browser installation in `scripts/setup.sh` and added cache/binary validation to `-doctor` diagnostics.
- **Enterprise CTEM Risk Engine (Alpha)**: Hardened risk engine using advanced 7-factor risk scoring, real-time telemetry, ownership models, blast radius evaluation, and NATS JetStream event architecture.
- **Secure Server-side Sessions**: Migrated dashboard authentication from client-side `localStorage` to secure server-side `HttpOnly` cookies.
- **Database Query Tracing**: Implemented distributed trace spans, query duration tracking, and Prometheus metrics for storage and message queue.

### Changed
- **SSRF Enforcement**: Wired `security.IsPrivateAddr` into both the low-level and high-level `StealthClient` network pipelines for strict SSRF mitigation.
- **CTEM State transitions**: Deleted the redundant `internal/domain/workflows` package, consolidating compliance state machine transitions directly inside the CTEM storage engine (`ctem.go`).
- **Version**: Bumped to v1.4.0.

---

## [1.3.0] — 2026-06-11

### Added

- **CTEM Ownership and SLA Engine**: Complete database tables (`teams`, `owners`, `finding_assignments`, `sla_policies`, `escalation_rules`), graph synchronization, and background escalator alert daemon.
- **Pure Go SQLite Driver**: Migrated to CGo-free `modernc.org/sqlite` package, eliminating external SQLite binary and compiler dependencies.
- **HTTPX Pre-validation Filters**: Automatic skipping for invalid domain syntaxes and parked/for-sale HTTP HTML title templates, gating downstream crawlers/fuzzers.
- **TUI Command Window Auto-Resize**: Adjusted command history spacing dynamically to render the commands list on smaller terminals.
- **Directory Input Rejection**: Reject directories (such as `.` or `/`) in target validation, avoiding infinite target parser loops.

### Changed

- **Version**: Bumped to v1.3.0.

---

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
