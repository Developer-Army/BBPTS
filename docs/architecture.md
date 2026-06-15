# BBPTS Architecture Guide

This document describes the layering and design patterns used across the BBPTS system.

## Layered Architecture Diagram

The BBPTS codebase is structured around a strict layered architecture:

```mermaid
graph TD
    subgraph CMD [Command Line & Entrypoints]
        direction TB
        bbpts_cmd["cmd/bbpts (CLI Entrypoint)"]
    end

    subgraph INTERFACES [Interfaces Layer]
        direction TB
        cli["internal/interfaces/cli (CLI Engine)"]
        tui["internal/interfaces/ui/tui (Bubbletea Interface)"]
        server["internal/interfaces/ui/server (Web Dashboard API)"]
        workers["internal/interfaces/workers (Task Executors)"]
    end

    subgraph APPLICATION [Application Layer]
        direction TB
        services["internal/application/services (Orchestrator & Services)"]
    end

    subgraph DOMAIN [Domain Layer]
        direction TB
        assets["internal/domain/assets (Asset Registry)"]
        findings["internal/domain/findings (Vulns & Exposures)"]
        risk["internal/domain/risk (CVSS & Scoring Engine)"]
        ownership["internal/domain/ownership (Teams & Contacts)"]
        recon["internal/domain/recon (Recon Parser Modules)"]
        security["internal/domain/security (Sanitizer & SSH/SSRF Guard)"]
    end

    subgraph INFRASTRUCTURE [Infrastructure Layer]
        direction TB
        storage["internal/infrastructure/storage (SQLite database)"]
        queue["internal/infrastructure/queue (NATS JetStream)"]
        browser["internal/infrastructure/browser (Playwright Engine)"]
        network["internal/infrastructure/network (Stealth HTTP client)"]
        telemetry["internal/infrastructure/telemetry (Observability Spans)"]
    end

    %% Dependency flows
    bbpts_cmd --> cli
    cli --> services
    tui --> services
    server --> services
    workers --> services

    services --> DOMAIN
    services --> INFRASTRUCTURE

    %% Cross-domain references
    risk --> assets
    findings --> assets
    ownership --> assets
    recon --> security
```

## Description of Layers

1. **CMD (Entrypoints)**: Handles startup configuration, command-line arguments parsing, and hands execution context off to the Interfaces layer.
2. **Interfaces**: Adapts input/output for different run environments (CLI, Interactive TUI, Dashboard HTTP Server, or Stateless worker nodes).
3. **Application**: Orchestrates core application workflows, executes recon tool wrappers in sequence, and handles background worker leases.
4. **Domain**: Encapsulates core business rules, including target scope filtering, CVSS severity scores, asset relationships, state validation, and input sanitization.
5. **Infrastructure**: Integrates with external systems and the underlying OS (SQLite database persistence, NATS pub/sub message brokers, headless Chromium, network client requests, and OpenTelemetry).
