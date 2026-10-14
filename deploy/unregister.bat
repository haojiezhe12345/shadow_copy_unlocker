@echo off
setlocal EnableExtensions

rem ============================================================================
rem  Shadow Copies property-sheet handler  --  UNREGISTER
rem
rem  Removes the CLSID + Drive property-sheet-handler registration that
rem  register.bat created.  Files on disk are left untouched.
rem
rem  The CLSID is only deleted if its InprocServer32 actually points at a
rem  vssui.dll, so an unrelated/system registration is never clobbered.
rem
rem  Must be run from an ELEVATED command prompt.
rem ============================================================================

set "CLSID={4648F940-EFE3-4BAB-9211-3BE45CD5029D}"
set "CLSKEY=HKLM\SOFTWARE\Classes\CLSID\%CLSID%"
set "PSHKEY=HKLM\SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\%CLSID%"

net session >nul 2>&1
if errorlevel 1 (
    echo [!] This script must be run as Administrator.
    pause
    exit /b 1
)

rem ---- CLSID ---------------------------------------------------------------
set "SERVER="
for /f "tokens=2,*" %%A in ('reg query "%CLSKEY%\InprocServer32" /ve 2^>nul ^| findstr /i "REG_SZ"') do set "SERVER=%%B"

if not defined SERVER (
    echo [i] CLSID %CLSID% is not registered.
    goto :psh
)

echo %SERVER% | findstr /i "vssui.dll" >nul
if errorlevel 1 (
    echo [!] CLSID %CLSID% points to a different server:
    echo       %SERVER%
    echo     Refusing to remove it. Delete it manually if that is intended.
    goto :psh
)

reg delete "%CLSKEY%" /f >nul
if errorlevel 1 (
    echo [!] Failed to delete %CLSKEY%.
    pause
    exit /b 1
)
echo [-] Removed CLSID %CLSID%  ^(server: %SERVER%^)

rem ---- property-sheet handler ----------------------------------------------
:psh
reg query "%PSHKEY%" >nul 2>&1
if not errorlevel 1 (
    reg delete "%PSHKEY%" /f >nul
    echo [-] Removed Drive property-sheet-handler entry.
)

echo.
echo     Reload the shell:  taskkill /f /im explorer.exe  ^&  start explorer.exe
pause
endlocal
exit /b 0
