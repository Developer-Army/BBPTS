@echo off
setlocal enabledelayedexpansion

echo BBPTS Setup for Windows
echo.
echo Installing the following Go-based tools:
echo   • Subdomain ^& DNS: subfinder, amass, assetfinder, puredns
echo   • Probing ^& Ports: httpx, dnsx, naabu
echo   • Discovery ^& Crawling: katana, gau, waybackurls, hakrawler
echo   • Vulnerability Scanning: nuclei, dalfox, interactsh-client
echo   • Data Processing ^& Fuzzing: anew, gf, ffuf, gobuster, chaos
echo.
echo Installing wordlists:
echo   • dns-5k.txt (5k DNS entries)
echo   • raft-small-files.txt (directory enumeration)
echo   • subdomains-top1million-5000.txt (subdomain brute-force)
echo   • api-endpoints.txt (API endpoints)
echo.

where go >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Go is not installed or not in PATH.
    exit /b 1
)

echo Installing Go module dependencies...
go mod tidy

echo Installing recommended recon tools...

set TOOLS=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ^
github.com/owasp-amass/amass/v3/cmd/amass@latest ^
github.com/tomnomnom/assetfinder@latest ^
github.com/d3mondev/puredns/v2@latest ^
github.com/projectdiscovery/httpx/cmd/httpx@latest ^
github.com/projectdiscovery/dnsx/cmd/dnsx@latest ^
github.com/projectdiscovery/naabu/cmd/naabu@latest ^
github.com/projectdiscovery/katana/cmd/katana@latest ^
github.com/lc/gau/v2/cmd/gau@latest ^
github.com/tomnomnom/waybackurls@latest ^
github.com/hakluke/hakrawler@latest ^
github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ^
github.com/hahwul/dalfox/v2@latest ^
github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest ^
github.com/tomnomnom/anew@latest ^
github.com/tomnomnom/gf@latest ^
github.com/ffuf/ffuf@latest ^
github.com/OJ/gobuster/v3@latest ^
github.com/projectdiscovery/chaos-client/cmd/chaos@latest

for %%T in (%TOOLS%) do (
    set "TOOL_PATH=%%T"
    rem This is a very basic way to get a potential binary name on Windows
    for /f "delims=@ tokens=1" %%B in ("%%T") do (
        set "FULL_NAME=%%B"
        for %%I in ("!FULL_NAME:/=\!") do set "BIN_NAME=%%~nxI"
    )
    
    where !BIN_NAME! >nul 2>nul
    if !errorlevel! equ 0 (
        echo ^[ok^] !BIN_NAME! already installed.
    ) else (
        echo Installing %%T...
        go install %%T
    )
)

echo.
echo Installing wordlists...

set WORDLISTS_DIR=%USERPROFILE%\.bbpts\wordlists
if not exist "%WORDLISTS_DIR%" mkdir "%WORDLISTS_DIR%"

echo Downloading DNS wordlist (5k entries)...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt' -OutFile '%WORDLISTS_DIR%\dns-5k.txt'" 2>nul
if %errorlevel% neq 0 echo Warning: Failed to download DNS wordlist

echo Downloading directory wordlist (small)...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt' -OutFile '%WORDLISTS_DIR%\raft-small-files.txt'" 2>nul
if %errorlevel% neq 0 echo Warning: Failed to download directory wordlist

echo Downloading subdomain wordlist...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt' -OutFile '%WORDLISTS_DIR%\subdomains-top1million-5000.txt'" 2>nul
if %errorlevel% neq 0 echo Warning: Failed to download subdomain wordlist

echo Downloading API endpoints wordlist...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt' -OutFile '%WORDLISTS_DIR%\api-endpoints.txt'" 2>nul
if %errorlevel% neq 0 echo Warning: Failed to download API wordlist

echo.
echo Building BBPTS executable...
go build -o bbpts.exe .\cmd\bbpts || echo Warning: Failed to build BBPTS executable

echo.
echo Note: For Python-based tools like 'uro', install Python and pip, then run:
echo pip install uro
echo.
echo Setup complete. Ensure %%USERPROFILE%%\go\bin is in your PATH.
echo To run: .\bbpts.exe -doctor
