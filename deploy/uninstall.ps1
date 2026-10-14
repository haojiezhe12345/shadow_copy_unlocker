<#
    Shadow Copy Unlocker - uninstaller

    Removes exactly what install.ps1 added, for either or both parts:

      Part 1 (vssui)     the CLSID + Drive property-sheet-handler registration,
                         and %ProgramData%\ShadowCopyUnlocker\vssui
                         (the CLSID is only removed if its InprocServer32 really
                         points at a vssui.dll, so an unrelated registration is
                         never clobbered)

      Part 2 (vssadmin)  the machine PATH entry, and
                         %ProgramData%\ShadowCopyUnlocker\vssadmin

    System32 was never modified, so there is nothing else to restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Vssui', 'Vssadmin')]
    [string]$Part = 'All',

    [string]$Root = (Join-Path $env:ProgramData 'ShadowCopyUnlocker')
)

$ErrorActionPreference = 'Stop'

$CLSID       = '{4648F940-EFE3-4BAB-9211-3BE45CD5029D}'
$VssuiDir    = Join-Path $Root 'vssui'
$VssadminDir = Join-Path $Root 'vssadmin'

function Open-Hklm64 {
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
}

function Send-EnvironmentChanged {
    if (-not ('SCU.Native' -as [type])) {
        Add-Type -Namespace SCU -Name Native -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
                                               string lParam, uint fuFlags, uint uTimeout,
                                               out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    [void][SCU.Native]::SendMessageTimeout([IntPtr]0xFFFF, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}

function Get-MachinePath {
    $base = Open-Hklm64
    try {
        $k = $base.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
        if ($null -eq $k) { throw 'cannot open the machine Environment key' }
        return [pscustomobject]@{
            Key  = $k
            Raw  = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Kind = $k.GetValueKind('Path')
        }
    } finally { $base.Close() }
}

function Remove-VssuiRegistration {
    $base = Open-Hklm64
    try {
        $key = "SOFTWARE\Classes\CLSID\$CLSID"
        $server = $null
        $k = $base.OpenSubKey("$key\InprocServer32")
        if ($k) { $server = [string]$k.GetValue('', ''); $k.Close() }

        if ($null -eq $server) {
            Write-Host '  CLSID      : not registered'
        } elseif ($server -notmatch 'vssui\.dll') {
            Write-Host ('  CLSID      : points at a different server, left alone ({0})' -f $server) -ForegroundColor Yellow
        } else {
            $base.DeleteSubKeyTree($key, $false)
            Write-Host ('  CLSID      : removed (was {0})' -f $server)
        }

        $psh = "SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\$CLSID"
        if ($base.OpenSubKey($psh)) {
            $base.DeleteSubKeyTree($psh, $false)
            Write-Host '  handler    : removed'
        }
    } finally { $base.Close() }
}

function Remove-DirSafe {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) {
        Write-Host ('  files      : {0} does not exist' -f $Dir)
        return
    }
    try {
        Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction Stop
        Write-Host ('  files      : removed {0}' -f $Dir)
    } catch {
        Write-Host ('  [!] could not delete {0}' -f $Dir) -ForegroundColor Yellow
        Write-Host '      A file there is still in use (explorer keeps VSSUI.dll loaded once the' -ForegroundColor Yellow
        Write-Host '      tab has been shown). The registration is already gone, so the leftover' -ForegroundColor Yellow
        Write-Host '      folder is harmless; delete it after:  taskkill /f /im explorer.exe' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
$doVssui    = $Part -in @('All', 'Vssui')
$doVssadmin = $Part -in @('All', 'Vssadmin')

Write-Host ''
Write-Host 'Shadow Copy Unlocker - uninstall' -ForegroundColor Cyan
Write-Host ('  install root : {0}' -f $Root)
Write-Host ('  parts        : {0}' -f $Part)
Write-Host ''

if ($doVssui) {
    Write-Host '[1/2] Shadow Copies tab (vssui.dll)' -ForegroundColor Cyan
    Remove-VssuiRegistration
    Remove-DirSafe $VssuiDir
    Write-Host ''
}

if ($doVssadmin) {
    Write-Host '[2/2] vssadmin Server commands (vssadmin.exe)' -ForegroundColor Cyan
    $mp = Get-MachinePath
    try {
        $entries = @($mp.Raw -split ';' | Where-Object { $_ -ne '' })
        $keep = @($entries | Where-Object { $_.TrimEnd('\') -ine $VssadminDir.TrimEnd('\') })
        if ($keep.Count -ne $entries.Count) {
            $mp.Key.SetValue('Path', ($keep -join ';'), $mp.Kind)
            Write-Host '  PATH       : entry removed'
            Send-EnvironmentChanged
        } else {
            Write-Host '  PATH       : no entry to remove'
        }
    } finally { $mp.Key.Close() }
    Remove-DirSafe $VssadminDir
    Write-Host ''
}

# tidy up the now-empty install root
if (Test-Path -LiteralPath $Root) {
    if (-not (Get-ChildItem -LiteralPath $Root -Force)) {
        Remove-Item -LiteralPath $Root -Force
        Write-Host ('cleaned up {0}' -f $Root)
    }
}

Write-Host 'Done. System32 was never modified, so the stock tools are back.' -ForegroundColor Green
if ($doVssui)    { Write-Host 'Reload the shell:  taskkill /f /im explorer.exe  ^&  start explorer.exe' }
if ($doVssadmin) { Write-Host 'Open a NEW terminal for the PATH change to take effect.' }
Write-Host ''
