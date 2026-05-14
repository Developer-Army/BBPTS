#!/bin/bash

# BBPTS Dependency Installation Script
# This script installs all required tools for the BBPTS pipeline.

echo "[*] Installing BBPTS Dependencies..."

# Check if Go is installed
if ! command -v go &> /dev/null
then
    echo "[-] Go could not be found. Please install Go 1.20 or later."
    exit 1
fi

echo "[+] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[+] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[+] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[+] Installing naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "[+] Installing gau..."
go install github.com/lc/gau/v2/cmd/gau@latest

echo "[+] Installing hakrawler..."
go install github.com/hakluke/hakrawler@latest

echo "[+] Installing amap..."
go install github.com/hahwul/dalfox/v2@latest

echo "[*] Ensuring ~/go/bin is in your PATH."
if [[ ":$PATH:" == *":$HOME/go/bin:"* ]]; then
  echo "[+] ~/go/bin is already in PATH."
else
  echo "[!] Please add 'export PATH=\$PATH:\$HOME/go/bin' to your ~/.bashrc or ~/.zshrc."
fi

echo "[*] Installation complete!"
