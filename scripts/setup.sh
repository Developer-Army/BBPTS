#!/usr/bin/env bash
set -euo pipefail

# BBPTS Elite Setup Script - Optimized for Low-Resource Hardware
# Part of the "Top 50 in the World" framework initiative.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🚀 Starting BBPTS Elite Tooling Setup..."
echo ""
echo "📦 Installing the following Go-based tools:"
echo "   • Subdomain & DNS: subfinder, amass, assetfinder, puredns"
echo "   • Probing & Ports: httpx, dnsx, naabu"
echo "   • Discovery & Crawling: katana, gau, hakrawler"
echo "   • Vulnerability Scanning: nuclei, dalfox, interactsh-client"
echo "   • Data Processing & Fuzzing: anew, gf, ffuf"
echo ""
echo "🐍 Installing Python-based tools:"
echo "   • uro (URL deduplication)"
echo ""
echo "📚 Installing wordlists:"
echo "   • dns-5k.txt (5k DNS entries)"
echo "   • raft-small-files.txt (directory enumeration)"
echo "   • subdomains-top1million-5000.txt (subdomain brute-force)"
echo "   • api-endpoints.txt (API endpoints)"
echo ""

# 1. GO-BASED ELITE TOOLS
GO_TOOLS=(
    # --- Recon & Subdomains ---
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"    # ADDED: Essential DNS toolkit
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"    # ADDED: TLS certificate parsing
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/JosueEncinar/gotator@latest"
    
    # --- Probing & Ports ---
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    
    # --- Discovery, Crawling & Fuzzing ---
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/ffuf/ffuf/v2@latest"                      # ADDED: Essential for VHOST/Param fuzzing
    
    # --- Vulnerability, XSS & OOB ---
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" # ADDED: OOB testing
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/KathanP19/gxss@latest"                    # ADDED: Fast XSS reflection checker
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
    go install "$tool" || echo "⚠️ Warning: Failed to install $tool"
}

for tool in "${GO_TOOLS[@]}"; do
    install_go_tool "$tool"
done

# 2. PYTHON-BASED TOOLS (uro)
if command -v pip3 &> /dev/null; then
    echo "Installing uro (Python)..."
    pip3 install uro --quiet
else
    echo "⚠️ pip3 not found. Skipping uro."
fi

# 3. RUST-BASED TOOLS (feroxbuster)
if ! command -v feroxbuster &> /dev/null; then
    echo "Installing feroxbuster (Rust binary)..."
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash -s -- --to /usr/local/bin || true
fi

echo -e "\n✅ BBPTS ELITE TOOLS INSTALLED!"
echo "--------------------------------------------------"
echo "💻 WEAK PC TIPS: Use '-t 10' and always pipe to 'anew'."
echo "To build main app: go build ./cmd/bbpts"

# 4. WORDLISTS SETUP
echo -e "\n📚 Setting up wordlists..."

WORDLISTS_DIR="$PROJECT_ROOT/wordlists"
mkdir -p "$WORDLISTS_DIR"

# Download essential wordlists
echo "Downloading DNS wordlist (5k entries)..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o "$WORDLISTS_DIR/dns-5k.txt" || echo "⚠️ Failed to download DNS wordlist"

echo "Downloading directory wordlist (small)..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt" -o "$WORDLISTS_DIR/raft-small-files.txt" || echo "⚠️ Failed to download directory wordlist"

echo "Downloading subdomain wordlist..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o "$WORDLISTS_DIR/subdomains-top1million-5000.txt" || echo "⚠️ Failed to download subdomain wordlist"

echo "Downloading API endpoints wordlist..."
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" -o "$WORDLISTS_DIR/api-endpoints.txt" || echo "⚠️ Failed to download API wordlist"

echo "✅ WORDLISTS SETUP COMPLETE!"

echo "\n🔧 Building BBPTS application..."
go build -o bbpts ./cmd/bbpts

echo "\n✅ BBPTS setup is complete. The binary 'bbpts' has been built in the current folder."

