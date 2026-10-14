@echo off
setlocal EnableExtensions

rem ============================================================================
rem  Shadow Copy Unlocker  --  INSTALL
rem
rem  Installs both unlocks into %ProgramData%\ShadowCopyUnlocker :
rem
rem    [1/2] vssui     - the "Shadow Copies" tab in the volume Properties dialog.
rem                      Copies the shipped VSSUI.dll + MUI satellite there and
rem                      registers the shell handler to load it from that path.
rem    [2/2] vssadmin  - the Server-only vssadmin commands.  Patches THIS
rem                      machine's own vssadmin.exe, copies it (and its MUI
rem                      satellites) there and prepends the folder to the machine
rem                      PATH so `vssadmin` overtakes System32.
rem
rem  System32 is never modified.  Requires administrator (machine PATH + HKLM).
rem
rem  Options (call install.ps1 directly to use them):
rem      -Part Vssui | Vssadmin | All      install only one part
rem      -DryRun                           report, change nothing
rem      -VssuiPath <dir|file>             use a different VSSUI.dll
rem ============================================================================

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" echo [!] install failed with exit code %RC%
pause

endlocal & exit /b %RC%
