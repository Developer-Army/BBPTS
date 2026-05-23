#!/usr/bin/env bash
set -uo pipefail

## BBPTS Elite Setup Script - Optimized for Low-Resource Hardware
# Part of the "Top 50 in the World" framework initiative.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo " Starting BBPTS Elite Tooling Setup..."
echo ""
echo " Installing the following Go-based tools:"
echo "   * Subdomain & DNS: subfinder, amass, assetfinder, puredns"
echo "   * Probing & Ports: httpx, dnsx, naabu"
echo "   * Discovery & Crawling: katana, gau, hakrawler, gobuster"
echo "   * Vulnerability Scanning: nuclei, dalfox, interactsh-client"
echo "   * Data Processing & Fuzzing: anew, ffuf, trufflehog"
echo ""
echo " Installing Python-based tools:"
echo "   * uro (URL deduplication), wafw00f (Optional)"
echo ""
echo " Installing wordlists:"
echo "   * dns-5k.txt (5k DNS entries)"
echo "   * raft-small-files.txt (directory enumeration)"
echo "   * subdomains-top1million-5000.txt (subdomain brute-force)"
echo "   * api-endpoints.txt (API endpoints)"
echo ""

# 0. PREREQUISITES CHECK
echo " Checking core prerequisites..."
if ! command -v go &> /dev/null; then
    echo " Go is not installed. Attempting to install Go 1.23.0..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin:~/go/bin
        rm /tmp/go.tar.gz
        echo " Go installed successfully for Linux."
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install go
            echo " Go installed successfully via Homebrew."
        else
            echo " Homebrew not found. Please install Homebrew or Go manually."
            exit 1
        fi
    else
        echo " Unsupported OS for automatic Go installation. Please install Go manually."
        exit 1
    fi
else
    echo " 'go' is installed."
fi

for cmd in git docker make gcc; do
    if ! command -v $cmd &> /dev/null; then
        echo "  Warning: '$cmd' is not installed. Some advanced BBPTS features may require it."
    else
        echo " '$cmd' is installed."
    fi
done
echo ""

# 1. GO-BASED ELITE TOOLS
GO_TOOLS=(
    # --- Recon & Subdomains ---
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"    # ADDED: Essential DNS toolkit
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"    # ADDED: TLS certificate parsing
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/owasp-amass/amass/v4/...@latest"
    "github.com/tomnomnom/assetfinder@latest"             # ADDED: Missing core tool
    
    # --- Probing & Ports ---
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    
    # --- Discovery, Crawling & Fuzzing ---
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/ffuf/ffuf/v2@latest"                      # ADDED: Essential for VHOST/Param fuzzing
    "github.com/hakluke/hakrawler@latest"                 # ADDED: Missing core tool
    "github.com/OJ/gobuster/v3@latest"                    # ADDED: Missing core tool
    
    # --- Vulnerability, XSS & OOB ---
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" # ADDED: OOB testing
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/sensepost/gowitness@latest"
    
    # --- Data Processing & Manipulation ---
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/qsreplace@latest"               # ADDED: Parameter manipulation
)

# Native crt.sh Bash Function
crt_sh() {
    local TARGET=$1
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
}

install_go_tool() {
    local tool=$1
    echo "Installing $tool..."
    go install "$tool" || echo " Warning: Failed to install $tool"
}

for tool in "${GO_TOOLS[@]}"; do
    install_go_tool "$tool"
done

# 2. GO-BASED URO (szybnev/uro-go)
echo "Installing uro (Golang port szybnev)..."
go install github.com/szybnev/uro-go/cmd/uro@latest || echo " Warning: Failed to install Go uro"

# 3. RUST-BASED TOOLS (feroxbuster)
if ! command -v feroxbuster &> /dev/null; then
    echo "Installing feroxbuster (Rust binary)..."
    curl -sLo /tmp/install-feroxbuster.sh https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh || true
    if [ -f /tmp/install-feroxbuster.sh ]; then
        bash /tmp/install-feroxbuster.sh --to /usr/local/bin || true
        rm /tmp/install-feroxbuster.sh
    fi
fi

# 4. ADDITIONAL NON-GO TOOLS
# --- Install massdns from source ---
if ! command -v massdns &> /dev/null; then
    echo "Installing massdns..."
    git clone https://github.com/blechschmidt/massdns.git /tmp/massdns || true
    if [ -d /tmp/massdns ]; then
        (cd /tmp/massdns && make) || true
        if [ -f /tmp/massdns/bin/massdns ]; then
            if [ -w /usr/local/bin ]; then
                mv /tmp/massdns/bin/massdns /usr/local/bin/ || true
            else
                mkdir -p ~/.local/bin && mv /tmp/massdns/bin/massdns ~/.local/bin/ || true
            fi
        fi
        rm -rf /tmp/massdns
    fi
fi

# --- Install trufflehog ---
if ! command -v trufflehog &> /dev/null; then
    echo "Installing trufflehog..."
    curl -sSfL -o /tmp/install-trufflehog.sh https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh || true
    if [ -f /tmp/install-trufflehog.sh ]; then
        sh /tmp/install-trufflehog.sh -b ~/.local/bin || true
        rm /tmp/install-trufflehog.sh
    fi
fi

# --- Install shodan CLI (Optional, requires API key) ---
if [ -n "${SHODAN_API_KEY:-}" ]; then
    echo "Installing Shodan CLI..."
    if command -v pip &> /dev/null; then
        pip install shodan || true
        shodan init "$SHODAN_API_KEY" || true
    elif command -v pip3 &> /dev/null; then
        pip3 install shodan || true
        shodan init "$SHODAN_API_KEY" || true
    fi
else
    echo " Note: Shodan CLI installation skipped (requires SHODAN_API_KEY environment variable to be set)."
fi

# --- Install wafw00f (Optional) ---
if ! command -v wafw00f &> /dev/null; then
    echo "Installing wafw00f (Optional)..."
    if command -v pip &> /dev/null; then
        pip install wafw00f || true
    elif command -v pip3 &> /dev/null; then
        pip3 install wafw00f || true
    else
        python3 -m pip install wafw00f 2>/dev/null || true
    fi
fi

if command -v gowitness &> /dev/null; then
    echo " Note: gowitness requires Chrome/Chromium to be installed on your system to take screenshots."
fi

echo -e "\n BBPTS ELITE TOOLS INSTALLED!"
echo "--------------------------------------------------"
echo " WEAK PC TIPS: Use '-t 10' and always pipe to 'anew'."
echo "To build main app: go build ./cmd/bbpts"

# 4. WORDLISTS SETUP
echo -e "\n Setting up wordlists..."

WORDLISTS_DIR="$PROJECT_ROOT/wordlists"
mkdir -p "$WORDLISTS_DIR"

# Download essential wordlists
echo "Downloading DNS wordlist (5k entries)..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt" -o "$WORDLISTS_DIR/dns-5k.txt" || echo " Failed to download DNS wordlist"

echo "Downloading directory wordlist (small)..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt" -o "$WORDLISTS_DIR/raft-small-files.txt" || echo " Failed to download directory wordlist"

echo "Downloading subdomain wordlist..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o "$WORDLISTS_DIR/subdomains-top1million-5000.txt" || echo " Failed to download subdomain wordlist"

echo "Downloading API endpoints wordlist..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" -o "$WORDLISTS_DIR/api-endpoints.txt" || echo " Failed to download API wordlist"

echo "Downloading common web content wordlist..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o "$WORDLISTS_DIR/seclists_common.txt" || echo " Failed to download common wordlist"

echo " WORDLISTS SETUP COMPLETE!"

echo -e "\n Building BBPTS application..."
go build -o bbpts ./cmd/bbpts

echo -e "\n BBPTS setup is complete. The binary 'bbpts' has been built in the current folder."te. The binary 'bbpts' has been built in the current folder."

