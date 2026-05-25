@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PROJECT_ROOT=%%~fI"

echo =================================================
echo BBPTS Elite Setup Script for Windows
echo =================================================
echo.

echo "[1/3] Checking prerequisites..."
where go >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] Go is not installed or not in PATH. Attempting to install Go via winget...
    winget install --id GoLang.Go -e --source winget --accept-package-agreements --accept-source-agreements
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install Go automatically. Please install it manually from https://go.dev/
        exit /b 1
    )
    echo [INFO] Go installed successfully! Please restart your terminal to reload the PATH, then run setup.bat again.
    exit /b 0
)

where git >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] Git is not installed or not in PATH. Attempting to install Git via winget...
    winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements
)

where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] Docker is not installed. Some advanced BBPTS features may require it.
) else (
    echo [OK] Docker is installed.
)
echo.

echo [2/3] Installing Go-based Elite Tools...
set "TOOLS="
set "TOOLS=!TOOLS! github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
set "TOOLS=!TOOLS! github.com/d3mondev/puredns/v2@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/httpx/cmd/httpx@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/katana/cmd/katana@latest"
set "TOOLS=!TOOLS! github.com/lc/gau/v2/cmd/gau@latest"
set "TOOLS=!TOOLS! github.com/ffuf/ffuf/v2@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
set "TOOLS=!TOOLS! github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
set "TOOLS=!TOOLS! github.com/hahwul/dalfox/v2@latest"
set "TOOLS=!TOOLS! github.com/sensepost/gowitness@latest"
set "TOOLS=!TOOLS! github.com/tomnomnom/anew@latest"
set "TOOLS=!TOOLS! github.com/tomnomnom/unfurl@latest"
set "TOOLS=!TOOLS! github.com/tomnomnom/qsreplace@latest"
set "TOOLS=!TOOLS! github.com/owasp-amass/amass/v4/...@latest"
set "TOOLS=!TOOLS! github.com/tomnomnom/assetfinder@latest"
set "TOOLS=!TOOLS! github.com/hakluke/hakrawler@latest"
set "TOOLS=!TOOLS! github.com/OJ/gobuster/v3@latest"
set "TOOLS=!TOOLS! github.com/trufflesecurity/trufflehog/v3@latest"

for %%T in (!TOOLS!) do (
    set "TOOL_PATH=%%T"
    for /f "delims=@ tokens=1" %%B in ("%%T") do (
        set "FULL_NAME=%%B"
        for %%I in ("!FULL_NAME:/=\!") do (
            set "BIN_NAME=%%~nxI"
            if "!BIN_NAME!"=="..." (
                set "BIN_NAME=amass"
            )
            if "!BIN_NAME!"=="v2" (
                for %%A in ("!FULL_NAME:\v2=!") do set "BIN_NAME=%%~nxA"
            )
            if "!BIN_NAME!"=="v3" (
                for %%A in ("!FULL_NAME:\v3=!") do set "BIN_NAME=%%~nxA"
            )
            if "!BIN_NAME!"=="v4" (
                for %%A in ("!FULL_NAME:\v4=!") do set "BIN_NAME=%%~nxA"
            )
        )
    )
    
    where !BIN_NAME! >nul 2>nul
    if !errorlevel! equ 0 (
        echo [ok] !BIN_NAME! already installed.
    ) else (
        echo Installing %%T...
        go install %%T
    )
)

echo.
echo [3/3] Installing Go-based uro...
go install github.com/szybnev/uro-go/cmd/uro@latest

echo.
echo Installing additional tools...

if defined SHODAN_API_KEY (
    where shodan >nul 2>nul
    if !errorlevel! neq 0 (
        echo Installing Shodan CLI...
        pip install shodan || pip3 install shodan
        shodan init %SHODAN_API_KEY%
    )
) else (
    echo [INFO] Shodan CLI requires SHODAN_API_KEY environment variable. Skipping.
)

where wafw00f >nul 2>nul
if !errorlevel! neq 0 (
    echo Installing wafw00f (Optional)...
    pip install wafw00f || pip3 install wafw00f
)

where whois >nul 2>nul
if !errorlevel! neq 0 (
    echo Installing whois for Windows from Sysinternals...
    if not exist "%USERPROFILE%\go\bin" mkdir "%USERPROFILE%\go\bin"
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://live.sysinternals.com/whois.exe' -OutFile '%USERPROFILE%\go\bin\whois.exe'" 2>nul
    if !errorlevel! neq 0 (
        echo [WARNING] Failed to download whois.exe.
    ) else (
        echo Accepting whois EULA silently...
        powershell -Command "New-Item -Path 'HKCU:\Software\Sysinternals' -Force 2>nul; New-Item -Path 'HKCU:\Software\Sysinternals\Whois' -Force 2>nul; Set-ItemProperty -Path 'HKCU:\Software\Sysinternals\Whois' -Name 'EulaAccepted' -Value 1 -Type DWord -Force" 2>nul
        echo [OK] whois installed successfully!
    )
)

where massdns >nul 2>nul
if !errorlevel! neq 0 (
    echo [WARNING] 'massdns' not found. Please install massdns manually or ignore on Windows.
)

where feroxbuster >nul 2>nul
if !errorlevel! neq 0 (
    echo [WARNING] 'feroxbuster' not found. Please install feroxbuster manually or ignore on Windows.
)

echo.
echo Installing wordlists...
set WORDLISTS_DIR=%PROJECT_ROOT%\wordlists
if not exist "%WORDLISTS_DIR%" mkdir "%WORDLISTS_DIR%"

echo Downloading DNS wordlist (5k entries)...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt' -OutFile '%WORDLISTS_DIR%\dns-5k.txt'" 2>nul

echo Downloading directory wordlist (small)...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt' -OutFile '%WORDLISTS_DIR%\raft-small-files.txt'" 2>nul

echo Downloading subdomain wordlist...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt' -OutFile '%WORDLISTS_DIR%\subdomains-top1million-5000.txt'" 2>nul

echo Downloading API endpoints wordlist...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt' -OutFile '%WORDLISTS_DIR%\api-endpoints.txt'" 2>nul

echo Downloading common web content wordlist...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt' -OutFile '%WORDLISTS_DIR%\seclists_common.txt'" 2>nul

echo.
echo Building BBPTS executable...
go build -o bbpts.exe .\cmd\bbpts || echo Warning: Failed to build BBPTS executable

echo.
echo =================================================
echo BBPTS setup is complete!
echo Ensure %USERPROFILE%\go\bin is in your PATH.
echo ===================================================
