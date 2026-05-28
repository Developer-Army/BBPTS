# --- Official Tool Images ---
FROM projectdiscovery/subfinder:v2.6.6 AS subfinder
FROM projectdiscovery/nuclei:v3.2.9 AS nuclei
FROM projectdiscovery/httpx:v1.6.0 AS httpx
FROM projectdiscovery/katana:v1.1.0 AS katana
FROM projectdiscovery/dnsx:v1.2.1 AS dnsx
FROM projectdiscovery/naabu:v2.3.0 AS naabu
FROM projectdiscovery/tlsx:v1.1.6 AS tlsx
FROM projectdiscovery/chaos-client:v0.2.1 AS chaos

# --- Build Stage ---
FROM golang:1.23-bookworm AS builder

# Install build dependencies including Python for whois/wafw00f and make for massdns
RUN apt-get update && apt-get install -y \
    git \
    make \
    libpcap-dev \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the other Go tools with pinned versions before copying source code for caching
RUN go install github.com/tomnomnom/anew@v0.1.1 \
    && go install github.com/tomnomnom/unfurl@v0.4.3 \
    && go install github.com/tomnomnom/qsreplace@v0.0.3 \
    && go install github.com/lc/gau/v2/cmd/gau@v2.2.3 \
    && go install github.com/ffuf/ffuf/v2@v2.1.0 \
    && go install github.com/hakluke/hakrawler@v2.4.0 \
    && go install github.com/OJ/gobuster/v3@v3.6.0 \
    && go install github.com/hahwul/dalfox/v2@v2.9.0 \
    && go install github.com/sensepost/gowitness@v3.0.3 \
    && go install github.com/d3mondev/puredns/v2@v2.2.0 \
    && go install github.com/tomnomnom/assetfinder@v0.1.1 \
    && go install github.com/szybnev/uro-go/cmd/uro@v0.1.0 \
    && go install github.com/owasp-amass/amass/v4/cmd/amass@v4.2.0

# Compile massdns from source
RUN git clone https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns \
    && make \
    && mv bin/massdns /usr/local/bin/ \
    && rm -rf /tmp/massdns

# Install feroxbuster
RUN curl -sLo /tmp/install-feroxbuster.sh https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh \
    && mkdir -p /usr/local/bin \
    && bash /tmp/install-feroxbuster.sh /usr/local/bin \
    && rm -f /tmp/install-feroxbuster.sh

# Download wordlists in build stage
RUN mkdir -p /app/wordlists \
    && curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt" -o "/app/wordlists/dns-5k.txt" \
    && curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt" -o "/app/wordlists/raft-small-files.txt" \
    && curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o "/app/wordlists/subdomains-top1million-5000.txt" \
    && curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" -o "/app/wordlists/api-endpoints.txt" \
    && curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o "/app/wordlists/seclists_common.txt"

# Copy dependency files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the main binary with version info
ARG VERSION=v1.3.0
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

# Copy Go installed tools
COPY --from=builder /go/bin/* /usr/local/bin/

# Copy massdns
COPY --from=builder /usr/local/bin/massdns /usr/local/bin/

# Copy feroxbuster
COPY --from=builder /usr/local/bin/feroxbuster /usr/local/bin/

# Copy pre-built project discovery tools from official images
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/
COPY --from=katana /usr/local/bin/katana /usr/local/bin/
COPY --from=dnsx /usr/local/bin/dnsx /usr/local/bin/
COPY --from=naabu /usr/local/bin/naabu /usr/local/bin/
COPY --from=tlsx /usr/local/bin/tlsx /usr/local/bin/
COPY --from=chaos /usr/local/bin/chaos /usr/local/bin/

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
