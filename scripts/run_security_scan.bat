@echo off
REM Security Scan Script for Windows

echo ======================================
echo VulnHunter Security Scan
echo ======================================
echo.

if "%1"=="" (
    echo Usage: %0 ^<target_directory^> [output_name]
    echo Example: %0 original_code\vulnerable_app vulnerable
    exit /b 1
)

set TARGET=%1
set OUTPUT_NAME=%2
if "%OUTPUT_NAME%"=="" set OUTPUT_NAME=scan
set OUTPUT_DIR=analysis\security_scan_results

echo [*] Target: %TARGET%
echo [*] Output name: %OUTPUT_NAME%
echo.

REM Create output directory
if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

REM Run Bandit
echo [*] Running Bandit security scanner...
bandit -r %TARGET% -f json -o "%OUTPUT_DIR%\bandit_%OUTPUT_NAME%.json"
if %errorlevel% leq 1 (
    echo [+] Bandit scan complete
) else (
    echo [-] Bandit scan failed
)
echo.

REM Run Safety check if requirements.txt exists
if exist "%TARGET%\requirements.txt" (
    echo [*] Running Safety dependency check...
    safety check --file "%TARGET%\requirements.txt" --json > "%OUTPUT_DIR%\safety_%OUTPUT_NAME%.json"
    echo [+] Safety check complete
    echo.
)

REM Run custom security scanner
echo [*] Running custom security checks...
python tools\security_scanner.py %TARGET% --output %OUTPUT_DIR% --name %OUTPUT_NAME% --report
echo.

REM Summary
echo ======================================
echo Scan Complete!
echo ======================================
echo.
echo Results saved to: %OUTPUT_DIR%
echo.
echo Files generated:
echo   - bandit_%OUTPUT_NAME%.json
echo   - security_report_%OUTPUT_NAME%.md
echo   - full_results_%OUTPUT_NAME%.json
echo.
echo View the security report:
echo   type %OUTPUT_DIR%\security_report_%OUTPUT_NAME%.md
echo.

pause
