@echo off
:: VideoSecurity Launch Script — Runs with Admin privileges on localhost
:: Opens browser automatically after server starts

title VideoSecurity Server
color 0A

echo ============================================
echo   VideoSecurity - Local Development Server
echo ============================================
echo.

cd /d "C:\Users\Administrator\Desktop\TESTDOTNET"

:: Set environment variables
set ASPNETCORE_ENVIRONMENT=Development
set Hosting__DisableHttpsRedirection=true
set Hosting__AllowInsecureCookies=true
set Seed__AdminEmail=admin@localhost
set Seed__AdminPassword=Admin-Local-Dev!1234
set ASPNETCORE_URLS=http://0.0.0.0:5102
set Embed__AllowedDomains=cifm.polytronx.com

:: Check if dotnet is available
where dotnet >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: .NET SDK not found in PATH.
    pause
    exit /b 1
)

echo [*] Building project...
dotnet build src\VideoSecurity.Web\VideoSecurity.Web.csproj -c Release --nologo -q
if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Build failed. Check errors above.
    pause
    exit /b 1
)

echo [*] Starting server on http://0.0.0.0:5102 (all interfaces)
echo [*] Admin login: admin@localhost / Admin-Local-Dev!1234
echo [*] Embed allowed: cifm.polytronx.com
echo.
echo     Press Ctrl+C to stop the server.
echo ============================================
echo.

:: Open browser after a short delay
start "" cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:5102"

:: Run the server (override launch profile to bind all interfaces)
dotnet run --project src\VideoSecurity.Web\VideoSecurity.Web.csproj -c Release --no-build --urls http://0.0.0.0:5102
