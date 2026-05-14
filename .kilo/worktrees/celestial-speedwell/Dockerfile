# --- Build Stage ---
FROM golang:1.22-bookworm AS builder

# Install build dependencies including Python for uro
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

# Build the main binary
RUN go build -o bbpts ./cmd/bbpts

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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the main binary
COPY --from=builder /app/bbpts .

# Copy the installed tools (Go binaries)
COPY --from=builder /go/bin/* /usr/local/bin/

# Copy Python tools (uro)
COPY --from=builder /usr/local/bin/uro /usr/local/bin/uro
COPY --from=builder /usr/local/lib/python3.11/dist-packages /usr/local/lib/python3.11/dist-packages

# Copy Rust tools (feroxbuster)
COPY --from=builder /usr/local/bin/feroxbuster /usr/local/bin/feroxbuster

# Copy configs and default data
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/targets.csv .

# Set the entrypoint
ENTRYPOINT ["./bbpts"]
CMD ["--help"]

