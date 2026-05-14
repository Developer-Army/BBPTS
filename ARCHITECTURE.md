# BBPTS Architecture

```mermaid
flowchart TD
    CLI[CLI / Flags] --> Config[Config + Program Profiles]
    Config --> App[App Run Loop]
    App --> Input[Input Parser]
    Input --> Scope[Scope Guard + Normalizer]
    Scope --> Orchestrator[Staged Recon Orchestrator]

    Orchestrator --> Stage1[Stage 1: Passive DNS]
    Stage1 --> Stage2[Stage 2: Active Probe]
    Stage2 --> Stage3[Stage 3: Crawl + URL Discovery]
    Stage3 --> Stage4[Stage 4: Fuzz + JS Analysis]
    Stage4 --> Stage5[Stage 5: Verification]

    Orchestrator --> Bus[Event Bus]
    Bus --> Memory[Recon Memory SQLite]
    Bus --> Workers[Optional NATS Worker Mesh]
    Workers --> Bus

    Orchestrator --> Diff[State + Diff Engine]
    Diff --> Rules[Rules Engine]
    Rules --> Analysis[Insight Analysis + Scoring]
    Analysis --> Reports[Markdown / CSV / JSON / Burp / Caido]
    Analysis --> Notify[Slack / Discord / Telegram]
    Analysis --> Submit[Optional Platform Submit]

    App --> TUI[TUI Bridge]
    App --> Dashboard[Local Web Dashboard]
```

## Layers

- `cmd/bbpts`: CLI parsing, config loading, telemetry startup, and mode selection.
- `internal/app`: run loop, recon/persistence/reporting phases, worker entry point, and submit safety gates.
- `internal/engine/recon`: tool adapters, staged orchestration, scope filtering, fleet dispatch, and streaming result artifacts.
- `internal/core`: config, database/storage, event bus, state, notifications, rate limiting, and platform submit clients.
- `internal/analysis`: insight derivation, scoring, evidence bundles, clustering, and report-ready findings.
- `internal/ui`: terminal/TUI views, local dashboard, and report exporters.

## Operational Notes

GitHub-hosted Actions should only build, vet, and test this repository. Continuous reconnaissance belongs on a self-hosted runner, VPS, or local Docker deployment with a private persistent volume for `bbpts.db`, reports, screenshots, and temporary tool output.
