@echo off
setlocal EnableExtensions

rem ============================================================================
rem  Shadow Copy Unlocker  --  UNINSTALL
rem
rem  Removes both parts:
rem    [1/2] vssui     - unregisters the CLSID + Drive property-sheet handler and
rem                      deletes %ProgramData%\ShadowCopyUnlocker\vssui
rem    [2/2] vssadmin  - removes the machine PATH entry and deletes
rem                      %ProgramData%\ShadowCopyUnlocker\vssadmin
rem
rem  System32 was never modified, so nothing else needs restoring.
rem  Requires administrator.
rem
rem  Use  -Part Vssui | Vssadmin  (call uninstall.ps1 directly) for one part only.
rem ============================================================================

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" echo [!] uninstall failed with exit code %RC%
pause

endlocal & exit /b %RC%
