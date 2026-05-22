# Containerization Guide

BBPTS supports running inside Docker for consistent, reproducible environments.

## Quick Start

```bash
# Build the image
docker build -t bbpts:latest \
  --build-arg VERSION=v1.1.2 \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) .

# Run a scan
docker run --rm -v $(pwd)/results:/app/results \
  bbpts:latest -i targets.txt

# Run doctor inside container
docker run --rm bbpts:latest -doctor

# Interactive mode
docker run --rm -it -v $(pwd)/results:/app/results \
  -v $(pwd)/configs:/app/configs \
  bbpts:latest
```

## Environment Variables

Pass API keys and config via environment:

```bash
docker run --rm \
  -e BBPTS_SHODAN_API_KEY=your_key \
  -e BBPTS_GITHUB_TOKEN=your_token \
  -v $(pwd)/results:/app/results \
  bbpts:latest -i targets.txt
```

## Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| `./results` | `/app/results` | Scan output |
| `./configs` | `/app/configs` | Custom config.json |
| `./wordlists` | `/app/wordlists` | Custom wordlists |

## Per-Tool Container Architecture (v1.2.0 Roadmap)

Future versions will support running individual heavy tools in isolated containers:

```
┌─────────────────────────────────────┐
│          BBPTS Orchestrator         │
│         (host or container)         │
└──────────┬──────────┬───────────────┘
           │          │
    ┌──────▼──┐  ┌────▼────┐
    │ nuclei  │  │  naabu  │  ... per-tool containers
    │ container│  │container│
    └─────────┘  └─────────┘
```

### Pros
- **Isolation**: tool crashes don't kill orchestrator
- **No install headaches**: each tool pinned to known-good version
- **Portable**: works on any Docker/Podman host

### Cons
- **Overhead**: container startup adds ~1-3s per tool invocation
- **Disk**: each tool image ~50-200MB
- **Complexity**: stdin/stdout piping through `docker run` needs wrapper

### Implementation Approach (deferred to v1.2.0)
1. Add `ContainerMode bool` config field
2. In `runner.go`, wrap `exec.Command` calls with `docker run` when enabled
3. Maintain per-tool Dockerfiles in `docker/` directory
4. Auto-detect Docker/Podman at startup via `docker info`

## Current Container Limitations

- Chromium-based tools (gowitness, browser) need `--no-sandbox` flag inside container
- Network scanning tools (naabu, massdns) may need `--network host`
- File system tools output to `/app/results` — always mount a volume
