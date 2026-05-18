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
set TOOLS=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ^
github.com/projectdiscovery/chaos-client/cmd/chaos@latest ^
github.com/projectdiscovery/dnsx/cmd/dnsx@latest ^
github.com/projectdiscovery/tlsx/cmd/tlsx@latest ^
github.com/d3mondev/puredns/v2@latest ^
github.com/projectdiscovery/httpx/cmd/httpx@latest ^
github.com/projectdiscovery/naabu/v2/cmd/naabu@latest ^
github.com/projectdiscovery/katana/cmd/katana@latest ^
github.com/lc/gau/v2/cmd/gau@latest ^
github.com/ffuf/ffuf/v2@latest ^
github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ^
github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest ^
github.com/hahwul/dalfox/v2@latest ^
github.com/KathanP19/Gxss@latest ^
github.com/sensepost/gowitness@latest ^
github.com/tomnomnom/anew@latest ^
github.com/tomnomnom/unfurl@latest ^
github.com/tomnomnom/qsreplace@latest

for %%T in (%TOOLS%) do (
    set "TOOL_PATH=%%T"
    for /f "delims=@ tokens=1" %%B in ("%%T") do (
        set "FULL_NAME=%%B"
        for %%I in ("!FULL_NAME:/=\!") do set "BIN_NAME=%%~nxI"
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
go install github.com/smaranchand/uro@latest

echo.
echo Installing wordlists...
set WORDLISTS_DIR=%PROJECT_ROOT%\wordlists
if not exist "%WORDLISTS_DIR%" mkdir "%WORDLISTS_DIR%"

echo Downloading DNS wordlist (5k entries)...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt' -OutFile '%WORDLISTS_DIR%\dns-5k.txt'" 2>nul

echo Downloading directory wordlist (small)...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt' -OutFile '%WORDLISTS_DIR%\raft-small-files.txt'" 2>nul

echo Downloading API endpoints wordlist...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt' -OutFile '%WORDLISTS_DIR%\api-endpoints.txt'" 2>nul

echo.
echo Building BBPTS executable...
go build -o bbpts.exe .\cmd\bbpts || echo Warning: Failed to build BBPTS executable

echo.
echo =================================================
echo ✅ BBPTS setup is complete!
echo Ensure %USERPROFILE%\go\bin is in your PATH.
echo =================================================
