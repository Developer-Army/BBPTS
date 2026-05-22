# --- Build Stage ---
FROM golang:1.22-bookworm AS builder

# Install build dependencies including Python for uro and make for massdns
RUN apt-get update && apt-get install -y \
    git \
    make \
    libpcap-dev \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Run the setup script to install all tools (Go, Python, Rust)
RUN bash ./scripts/setup.sh

# Build the main binary with version info
ARG VERSION=v1.1.2
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o bbpts ./cmd/bbpts

# --- Final Stage ---
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpcap0.8 \
    chromium \
    jq \
    curl \
    unzip \
    python3 \
    python3-pip \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the main binary
COPY --from=builder /app/bbpts .

# Copy the installed tools (Go binaries)
COPY --from=builder /go/bin/* /usr/local/bin/

# Copy massdns (built from source by setup.sh)
COPY --from=builder /usr/local/bin/massdns /usr/local/bin/massdns

# Copy Python tools (uro)
COPY --from=builder /usr/local/bin/uro /usr/local/bin/uro
COPY --from=builder /usr/local/lib/python3.11/dist-packages /usr/local/lib/python3.11/dist-packages

# Copy Rust tools (feroxbuster)
COPY --from=builder /usr/local/bin/feroxbuster /usr/local/bin/feroxbuster

# Copy configs, wordlists, and default data
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/wordlists ./wordlists

# Create results directory
RUN mkdir -p results /root/.bbpts

# Healthcheck: ensure bbpts binary runs
HEALTHCHECK --interval=30s --timeout=5s CMD ["./bbpts", "--version"]

# Set the entrypoint
ENTRYPOINT ["./bbpts"]
CMD ["--help"]
