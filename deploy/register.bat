@echo off
setlocal EnableExtensions

rem ============================================================================
rem  Shadow Copies property-sheet handler  --  REGISTER
rem
rem  Registers the patched vssui.dll that sits NEXT TO this script (or in the
rem  directory given as %1).  Nothing is copied into System32.
rem
rem  Layout expected:
rem      <dir>\VSSUI.dll              <- patched 17763 (best compatibility)
rem      <dir>\en-US\VSSUI.dll.mui    <- REQUIRED satellite (dialog id 1000 + strings)
rem
rem  Usage:
rem      register.bat                       (use this script's own folder)
rem      register.bat "D:\some\folder"      (DLL + en-US\ MUI in that folder)
rem      register.bat "D:\some\VSSUI.dll"   (register that DLL; MUI in its folder)
rem
rem  Must be run from an ELEVATED command prompt.
rem ============================================================================

set "CLSID={4648F940-EFE3-4BAB-9211-3BE45CD5029D}"
set "CLSKEY=HKLM\SOFTWARE\Classes\CLSID\%CLSID%"
set "PSHKEY=HKLM\SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\%CLSID%"

rem ---- resolve target directory / dll --------------------------------------
set "DIR=%~dp0"
if not "%~1"=="" (
    if /i "%~x1"==".dll" (
        for %%I in ("%~1") do set "DIR=%%~dpI"
    ) else (
        set "DIR=%~1"
    )
)
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"
set "DLL=%DIR%\VSSUI.dll"
if /i "%~x1"==".dll" set "DLL=%~f1"
for %%I in ("%DLL%") do set "DIR=%%~dpI"
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"
set "MUI=%DIR%\en-US\VSSUI.dll.mui"

rem ---- checks --------------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
    echo [!] This script must be run as Administrator.
    pause
    exit /b 1
)
if not exist "%DLL%" (
    echo [!] Missing DLL : "%DLL%"
    pause
    exit /b 1
)
if not exist "%MUI%" (
    echo [!] Missing MUI : "%MUI%"
    echo     The en-US\VSSUI.dll.mui satellite is REQUIRED - it contains the
    echo     property page dialog ^(id 1000^) and the tab caption/strings.
    pause
    exit /b 1
)

rem ---- register ------------------------------------------------------------
rem  Only InprocServer32 (and its ThreadingModel) under the CLSID is required.
rem  Do NOT add ProgID / VersionIndependentProgID / TypeLib / Version - those
rem  extra subkeys can make COM refuse to load the in-proc server.
reg add "%CLSKEY%"                   /ve /t REG_SZ /d "VSSShellExt Class" /f >nul
reg add "%CLSKEY%\InprocServer32"    /ve /t REG_SZ /d "%DLL%"               /f >nul
reg add "%CLSKEY%\InprocServer32"    /v ThreadingModel /t REG_SZ /d "Apartment" /f >nul
reg add "%PSHKEY%" /f >nul

if errorlevel 1 (
    echo [!] Registry write failed.
    pause
    exit /b 1
)

echo [+] Registered VSSShellExt
echo       CLSID     : %CLSID%
echo       InprocSrv : %DLL%
echo       Resources : %MUI%
echo.
echo     Reload the shell if the tab does not show up:
echo         taskkill /f /im explorer.exe
echo         start explorer.exe
pause
endlocal
exit /b 0
