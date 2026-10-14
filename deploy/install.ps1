<#
    Shadow Copy Unlocker - installer

    Installs both unlocks into a single per-machine location:

        %ProgramData%\ShadowCopyUnlocker\
          vssui\      VSSUI.dll + <lang>\VSSUI.dll.mui   (registered in place)
          vssadmin\   vssadmin.exe + <lang>\vssadmin.exe.mui  (prepended to PATH)

    System32 is never touched by either part.

    Part 1 - the "Shadow Copies" tab in the volume Properties dialog
      The shipped VSSUI.dll (already patched) and its MUI satellite are copied
      into the vssui folder and the shell handler is registered so that COM loads
      the DLL from there:

        HKLM\SOFTWARE\Classes\CLSID\{4648F940-EFE3-4BAB-9211-3BE45CD5029D}
          (default)                  = VSSShellExt Class
          \InprocServer32 (default)  = <...>\vssui\VSSUI.dll
          \InprocServer32 ThreadingModel = Apartment
        HKLM\SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{4648F940-...}

      Only InprocServer32 is required - do NOT add ProgID /
      VersionIndependentProgID / TypeLib / Version; those extra subkeys can make
      COM refuse to load the in-proc server (no page, no tab).

    Part 2 - the Server-only vssadmin commands (Create Shadow, ...)
      vssadmin.exe is OS-version specific (a build from another release will not
      even start: STATUS_ENTRYPOINT_NOT_FOUND), so instead of shipping a fixed
      binary this patches THIS machine's own copy at install time, writes it to
      the vssadmin folder and prepends that folder to the machine PATH so the
      bare `vssadmin` command overtakes System32.

      The patch flips one byte inside CVssSKU::Initialize - the conditional jump
      that selects the "server" branch becomes unconditional (0x76 jbe -> 0xEB
      jmp), so dCurrentSKU becomes 2 exactly as it would on Server Windows and
      the Server-only commands appear.  See patch_vssadmin.py for the annotated
      algorithm.

    Usage
      install.bat                     install both parts (self-elevates)
      install.ps1 -Part Vssui         install only the Properties tab
      install.ps1 -Part Vssadmin      install only the vssadmin commands
      install.ps1 -DryRun             report what would happen, write nothing
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Vssui', 'Vssadmin')]
    [string]$Part = 'All',

    # per-machine install root
    [string]$Root = (Join-Path $env:ProgramData 'ShadowCopyUnlocker'),

    # Part 1 payload: a VSSUI.dll, or a directory holding VSSUI.dll + <lang>\VSSUI.dll.mui
    # (empty = this script's own folder; $PSScriptRoot is not available in a param default)
    [string]$VssuiPath = '',

    # Part 2 payload: the build to patch
    [string]$VssadminSource = (Join-Path $env:SystemRoot 'System32\vssadmin.exe'),

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$CLSID          = '{4648F940-EFE3-4BAB-9211-3BE45CD5029D}'
$CLSID_DESC     = 'VSSShellExt Class'
$VssuiDir       = Join-Path $Root 'vssui'
$VssadminDir    = Join-Path $Root 'vssadmin'

# $PSScriptRoot cannot be used as a param default, so resolve it here
if (-not $VssuiPath) { $VssuiPath = $PSScriptRoot }
if (-not $VssuiPath) { $VssuiPath = (Get-Location).Path }

$SERVER_TAIL    = [byte[]](0x24,0x40,0xF6,0xD8,0x1B,0xC9,0x83,0xE1,0x02,0x83,0xC1,0x02,0x89,0x0D)
$BRANCH_PREFIX  = [byte[]](0x8A,0x84,0x24)          # mov al,[rsp+disp32]
$BRANCH_LEN     = 7
$WANT_MODULE    = 'KERNEL32.dll'
$WANT_IMPORT    = 'GetVersionExW'

# ---------------------------------------------------------------------------
# registry helpers (always the native 64-bit view)
# ---------------------------------------------------------------------------
function Open-Hklm64 {
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
}

function Get-RegValue {
    param([string]$Key, [string]$Name = '')
    $base = Open-Hklm64
    try {
        $k = $base.OpenSubKey($Key)
        if ($null -eq $k) { return $null }
        try { $v = $k.GetValue($Name, $null) } finally { $k.Close() }
        return $v
    } finally { $base.Close() }
}

function Set-VssuiRegistration {
    param([string]$DllPath)
    $base = Open-Hklm64
    try {
        $k = $base.CreateSubKey("SOFTWARE\Classes\CLSID\$CLSID")
        $k.SetValue('', $CLSID_DESC, [Microsoft.Win32.RegistryValueKind]::String)
        $k.Close()

        $k = $base.CreateSubKey("SOFTWARE\Classes\CLSID\$CLSID\InprocServer32")
        $k.SetValue('', $DllPath, [Microsoft.Win32.RegistryValueKind]::String)
        $k.SetValue('ThreadingModel', 'Apartment', [Microsoft.Win32.RegistryValueKind]::String)
        $k.Close()

        $k = $base.CreateSubKey("SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\$CLSID")
        $k.Close()
    } finally { $base.Close() }
}

function Remove-VssuiRegistration {
    $base = Open-Hklm64
    try {
        $key = "SOFTWARE\Classes\CLSID\$CLSID"
        $server = $null
        $k = $base.OpenSubKey("$key\InprocServer32")
        if ($k) { $server = [string]$k.GetValue('', ''); $k.Close() }

        $removed = @()
        if ($null -eq $server) {
            Write-Host '  CLSID     : not registered'
        } elseif ($server -notmatch 'vssui\.dll') {
            Write-Host ("  CLSID     : points at a different server, left alone ({0})" -f $server) -ForegroundColor Yellow
        } else {
            $base.DeleteSubKeyTree($key, $false)
            $removed += 'CLSID'
        }

        $psh = "SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\$CLSID"
        if ($base.OpenSubKey($psh)) {
            $base.DeleteSubKeyTree($psh, $false)
            $removed += 'handler'
        }
        if ($removed.Count) { Write-Host ('  removed   : ' + ($removed -join ' + ')) }
    } finally { $base.Close() }
}

# ---------------------------------------------------------------------------
# PATH helpers
# ---------------------------------------------------------------------------
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
    } finally { $base.Close() }   # the returned Key object stays valid
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

# ---------------------------------------------------------------------------
# payload helpers
# ---------------------------------------------------------------------------
function Write-PayloadFile {
    param([byte[]]$Bytes, [string]$To)
    if (Test-Path -LiteralPath $To) {
        $cur = [IO.File]::ReadAllBytes($To)
        if ($cur.Length -eq $Bytes.Length) {
            $same = $true
            for ($i = 0; $i -lt $cur.Length; $i++) { if ($cur[$i] -ne $Bytes[$i]) { $same = $false; break } }
            if ($same) { return 'unchanged' }
        }
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $To -Parent) | Out-Null
    try {
        [IO.File]::WriteAllBytes($To, $Bytes)
    } catch {
        throw ("cannot write {0} - the file is probably in use (close any Properties dialogs, stop vssadmin, or restart explorer) and re-run." -f $To)
    }
    return 'written'
}

# ---------------------------------------------------------------------------
# vssadmin patch (identical algorithm to patch_vssadmin.py)
# ---------------------------------------------------------------------------
function Find-AllBytes {
    param([byte[]]$Data, [byte[]]$Pattern)
    $first = $Pattern[0]
    $i = 0
    while ($true) {
        $i = [Array]::IndexOf($Data, $first, $i)
        if ($i -lt 0 -or ($i + $Pattern.Length) -gt $Data.Length) { break }
        $ok = $true
        for ($j = 1; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) { $ok = $false; break }
        }
        if ($ok) { $i }
        $i++
    }
}

function Get-PeInfo {
    param([byte[]]$Data)
    if ($Data[0] -ne 0x4D -or $Data[1] -ne 0x5A) { throw 'not a PE file (no MZ)' }
    $e = [BitConverter]::ToInt32($Data, 0x3C)
    if ($Data[$e] -ne 0x50 -or $Data[$e + 1] -ne 0x45) { throw 'not a PE file (no PE signature)' }
    $nsec  = [BitConverter]::ToUInt16($Data, $e + 6)
    $optsz = [BitConverter]::ToUInt16($Data, $e + 20)
    $opt   = $e + 24
    $magic = [BitConverter]::ToUInt16($Data, $opt)
    if ($magic -ne 0x20B) { throw ('expected a 64-bit image, got magic 0x{0:X}' -f $magic) }
    $dd = $opt + 112
    $so = $opt + $optsz
    $secs = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $nsec; $i++) {
        $s = $so + 40 * $i
        $secs.Add([pscustomobject]@{
            VSize   = [BitConverter]::ToUInt32($Data, $s + 8)
            VA      = [BitConverter]::ToUInt32($Data, $s + 12)
            RawSize = [BitConverter]::ToUInt32($Data, $s + 16)
            RawPtr  = [BitConverter]::ToUInt32($Data, $s + 20)
        })
    }
    [pscustomobject]@{ Sections = $secs; DD = $dd; Magic = $magic }
}

function Convert-RvaToOffset {
    param($Pe, [uint32]$Rva)
    foreach ($s in $Pe.Sections) {
        $size = [Math]::Max($s.VSize, $s.RawSize)
        if ($Rva -ge $s.VA -and $Rva -lt ($s.VA + $size)) { return [int]($s.RawPtr + ($Rva - $s.VA)) }
    }
    return -1
}

function Convert-OffsetToRva {
    param($Pe, [int]$Offset)
    foreach ($s in $Pe.Sections) {
        if ($Offset -ge $s.RawPtr -and $Offset -lt ($s.RawPtr + $s.RawSize)) {
            return [uint32]($s.VA + ($Offset - $s.RawPtr))
        }
    }
    return [uint32]::MaxValue
}

function Get-ImportIatRva {
    param($Pe, [byte[]]$Data, [string]$Module, [string]$Func)
    $off = Convert-RvaToOffset $Pe ([BitConverter]::ToUInt32($Data, $Pe.DD + 8))
    if ($off -lt 0) { return -1 }
    while ($true) {
        $ilt     = [BitConverter]::ToUInt32($Data, $off)
        $nameRva = [BitConverter]::ToUInt32($Data, $off + 12)
        $iat     = [BitConverter]::ToUInt32($Data, $off + 16)
        if ($ilt -eq 0 -and $nameRva -eq 0) { return -1 }
        $no = Convert-RvaToOffset $Pe $nameRva
        if ($no -ge 0) {
            $mod = ''
            while ($Data[$no] -ne 0) { $mod += [char]$Data[$no]; $no++ }
            if ($mod -ieq $Module) {
                $which = $iat
                if ($ilt -ne 0) { $which = $ilt }
                $thunk = Convert-RvaToOffset $Pe ([uint32]$which)
                for ($i = 0; $i -lt 4096; $i++) {
                    $v = [BitConverter]::ToUInt64($Data, $thunk + 8 * $i)
                    if ($v -eq 0) { break }
                    if (($v -band ([uint64]1 -shl 63)) -eq 0) {
                        $fo = Convert-RvaToOffset $Pe ([uint32]$v)
                        if ($fo -ge 0) {
                            $fn = ''
                            $p = $fo + 2
                            while ($Data[$p] -ne 0) { $fn += [char]$Data[$p]; $p++ }
                            if ($fn -eq $Func) { return [int]($iat + 8 * $i) }
                        }
                    }
                }
            }
        }
        $off += 20
    }
}

function Test-CallsIat {
    param($Pe, [byte[]]$Data, [int]$From, [int]$To, [int]$IatRva)
    if ($IatRva -lt 0) { return $false }
    for ($i = [Math]::Max(0, $From); $i -lt ($To - 6); $i++) {
        if ($Data[$i] -eq 0xFF -and $Data[$i + 1] -eq 0x15) {
            $src = Convert-OffsetToRva $Pe $i
            if ($src -ne [uint32]::MaxValue) {
                if (([int64]$src + 6 + [BitConverter]::ToInt32($Data, $i + 2)) -eq $IatRva) { return $true }
            }
            $i += 5
        }
    }
    return $false
}

function Invoke-VssAdminPatch {
    param([byte[]]$Data)
    $pe = Get-PeInfo $Data
    $iatRva = Get-ImportIatRva $pe $Data $WANT_MODULE $WANT_IMPORT

    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($tail in @(Find-AllBytes $Data $SERVER_TAIL)) {
        $branch = $tail - $BRANCH_LEN
        if ($branch -lt 0) { continue }
        $bad = $false
        for ($j = 0; $j -lt $BRANCH_PREFIX.Length; $j++) {
            if ($Data[$branch + $j] -ne $BRANCH_PREFIX[$j]) { $bad = $true; break }
        }
        if ($bad) { continue }
        for ($o = $branch - 1; $o -ge [Math]::Max(0, $branch - 48); $o--) {
            $b = $Data[$o]
            if ($b -ge 0x70 -and $b -le 0x7F) {
                if (($o + 2 + [sbyte]$Data[$o + 1]) -eq $branch) {
                    $candidates.Add([pscustomobject]@{ GateOff = $o; Width = 2; Opcode = $b; Branch = $branch }); break
                }
            } elseif ($b -eq 0x0F -and $Data[$o + 1] -ge 0x80 -and $Data[$o + 1] -le 0x8F) {
                if (($o + 6 + [BitConverter]::ToInt32($Data, $o + 2)) -eq $branch) {
                    $candidates.Add([pscustomobject]@{ GateOff = $o; Width = 6; Opcode = $Data[$o + 1]; Branch = $branch }); break
                }
            }
        }
    }
    if ($candidates.Count -eq 0) {
        throw 'SKU gate not found - this does not look like a vssadmin.exe this tool understands (or it is already patched).'
    }
    $verified = @($candidates | Where-Object { Test-CallsIat $pe $Data ($_.GateOff - 0x200) $_.GateOff $iatRva })
    $pool = if ($verified.Count -gt 0) { $verified } else { @($candidates) }
    $pick = $pool | Sort-Object GateOff | Select-Object -First 1

    $bytes = [byte[]]$Data.Clone()
    if ($pick.Width -eq 2) { $bytes[$pick.GateOff] = 0xEB } else { $bytes[$pick.GateOff] = 0xE9 }

    [pscustomobject]@{
        GateOff = $pick.GateOff; Width = $pick.Width; WasOpcode = $pick.Opcode
        Branch = $pick.Branch; Verified = ($verified.Count -gt 0)
        Candidates = $candidates.Count; Bytes = $bytes
    }
}

function Install-Vssadmin {
    param([string]$Source, [string]$Dir, [switch]$DryRun)

    if (-not (Test-Path -LiteralPath $Source)) { throw "not found: $Source" }
    $original = [IO.File]::ReadAllBytes($Source)
    $ver = (Get-Item -LiteralPath $Source).VersionInfo.FileVersion
    Write-Host ('  build      : {0}' -f $ver)

    $r = Invoke-VssAdminPatch $original
    Write-Host ('  gate       : file offset 0x{0:X}  (0x{1:X2} -> 0x{2:X2}, {3}-byte jump)' -f `
        $r.GateOff, $r.WasOpcode, $(if ($r.Width -eq 2) { 0xEB } else { 0xE9 }), $r.Width)
    Write-Host ("  checks     : {0} candidate(s), GetVersionExW call {1}" -f `
        $r.Candidates, $(if ($r.Verified) { 'confirmed' } else { 'NOT confirmed' }))

    if ($DryRun) { return }

    if (-not $r.Verified) { throw 'the located patch site could not be confirmed; refusing to install.' }

    $outExe = Join-Path $Dir 'vssadmin.exe'
    $what = Write-PayloadFile -Bytes $r.Bytes -To $outExe
    Write-Host ("  {0,-10} : {1}" -f $what, $outExe)

    $langs = @()
    foreach ($m in @(Get-ChildItem -Path (Join-Path $env:SystemRoot 'System32\*\vssadmin.exe.mui') -ErrorAction SilentlyContinue)) {
        $lang = Split-Path $m.DirectoryName -Leaf
        $dst = Join-Path $Dir (Join-Path $lang 'vssadmin.exe.mui')
        [void](Write-PayloadFile -Bytes ([IO.File]::ReadAllBytes($m.FullName)) -To $dst)
        $langs += $lang
    }
    if ($langs.Count) { Write-Host ('  MUI        : {0}' -f ($langs -join ', ')) }
    else { Write-Host '  MUI        : (none found - messages may not resolve)' -ForegroundColor Yellow }

    # prepend to the machine PATH so `vssadmin` overtakes System32
    $mp = Get-MachinePath
    try {
        $entries = @($mp.Raw -split ';' | Where-Object { $_ -ne '' })
        $keep = @($entries | Where-Object { $_.TrimEnd('\') -ine $Dir.TrimEnd('\') })
        $new = (@($Dir) + $keep) -join ';'
        if ($mp.Raw -ne $new) {
            $mp.Key.SetValue('Path', $new, $mp.Kind)
            Write-Host '  PATH       : prepended to the machine PATH'
            Send-EnvironmentChanged
        } else {
            Write-Host '  PATH       : already present'
        }
    } finally { $mp.Key.Close() }
}

function Remove-VssadminPathEntry {
    param([string]$Dir)
    $mp = Get-MachinePath
    try {
        $entries = @($mp.Raw -split ';' | Where-Object { $_ -ne '' })
        $keep = @($entries | Where-Object { $_.TrimEnd('\') -ine $Dir.TrimEnd('\') })
        if ($keep.Count -ne $entries.Count) {
            $mp.Key.SetValue('Path', ($keep -join ';'), $mp.Kind)
            Write-Host '  PATH       : entry removed'
            Send-EnvironmentChanged
        } else {
            Write-Host '  PATH       : no entry to remove'
        }
    } finally { $mp.Key.Close() }
}

# ---------------------------------------------------------------------------
# Part 1 - vssui
# ---------------------------------------------------------------------------
function Install-Vssui {
    param([string]$Source, [string]$Dir, [switch]$DryRun)

    $dll = $null
    if (Test-Path -LiteralPath $Source -PathType Leaf) { $dll = (Get-Item -LiteralPath $Source).FullName }
    else {
        $c = Join-Path $Source 'VSSUI.dll'
        if (Test-Path -LiteralPath $c) { $dll = (Get-Item -LiteralPath $c).FullName }
    }
    if (-not $dll) { throw "VSSUI.dll not found (looked in '$Source')" }

    $srcDir = Split-Path $dll -Parent
    $muis = @(Get-ChildItem -Path (Join-Path $srcDir '*\VSSUI.dll.mui') -ErrorAction SilentlyContinue)
    $outDll = Join-Path $Dir 'VSSUI.dll'

    Write-Host ('  source     : {0}' -f $dll)
    Write-Host ('  version    : {0}' -f (Get-Item -LiteralPath $dll).VersionInfo.FileVersion)
    if ($muis.Count) { Write-Host ('  MUI        : {0}' -f (($muis | ForEach-Object { Split-Path $_.DirectoryName -Leaf }) -join ', ')) }
    else { Write-Host '  MUI        : (none found next to the DLL - the tab will not appear)' -ForegroundColor Yellow }

    if ($DryRun) {
        Write-Host ('  would copy : {0}  ->  {1}' -f $dll, $outDll)
        Write-Host '  would register the CLSID + Drive property-sheet handler'
        return
    }

    $what = Write-PayloadFile -Bytes ([IO.File]::ReadAllBytes($dll)) -To $outDll
    Write-Host ("  {0,-10} : {1}" -f $what, $outDll)
    foreach ($m in $muis) {
        $lang = Split-Path $m.DirectoryName -Leaf
        $dst = Join-Path $Dir (Join-Path $lang 'VSSUI.dll.mui')
        [void](Write-PayloadFile -Bytes ([IO.File]::ReadAllBytes($m.FullName)) -To $dst)
    }

    Set-VssuiRegistration -DllPath $outDll
    Write-Host ('  registered : CLSID {0}' -f $CLSID)
    Write-Host ('  InprocSrv  : {0}' -f (Get-RegValue "SOFTWARE\Classes\CLSID\$CLSID\InprocServer32"))
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
$doVssui    = $Part -in @('All', 'Vssui')
$doVssadmin = $Part -in @('All', 'Vssadmin')

Write-Host ''
Write-Host 'Shadow Copy Unlocker' -ForegroundColor Cyan
Write-Host ('  install root : {0}' -f $Root)
Write-Host ('  parts        : {0}' -f $Part)
if ($DryRun) { Write-Host '  mode         : DRY RUN' -ForegroundColor Yellow }
Write-Host ''

if ($doVssui) {
    Write-Host '[1/2] Shadow Copies tab (vssui.dll)' -ForegroundColor Cyan
    Install-Vssui -Source $VssuiPath -Dir $VssuiDir -DryRun:$DryRun
    Write-Host ''
}

if ($doVssadmin) {
    Write-Host '[2/2] vssadmin Server commands (vssadmin.exe)' -ForegroundColor Cyan
    Write-Host ('  source     : {0}' -f $VssadminSource)
    Install-Vssadmin -Source $VssadminSource -Dir $VssadminDir -DryRun:$DryRun
    Write-Host ''
}

Write-Host 'Done.' -ForegroundColor Green
if ($DryRun) { Write-Host 'Nothing was written.' -ForegroundColor Yellow }
else {
    Write-Host ''
    if ($doVssui)    { Write-Host '  Tab      : reload the shell if it does not show up:' ; Write-Host '             taskkill /f /im explorer.exe ^& start explorer.exe' }
    if ($doVssadmin) { Write-Host '  vssadmin : open a NEW terminal, then:  where vssadmin ; vssadmin create shadow /for=C:' }
}
Write-Host ''
