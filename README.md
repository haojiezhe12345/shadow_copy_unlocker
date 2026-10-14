# Volume Shadow Copy (VSS) Unlocker

![platform](https://img.shields.io/badge/platform-Windows%20client-0078D6?logo=windows&logoColor=white)
![arch](https://img.shields.io/badge/arch-x64-lightgrey)
![status](https://img.shields.io/badge/status-working-brightgreen)
![patch](https://img.shields.io/badge/patch-1%20byte%20each-blueviolet)

**Unlock the Server-only Volume Shadow Copy (VSS) features on client Windows.**

Two independent features are Server-only and are hidden on client SKUs. Each is gated by a single
conditional jump inside a Microsoft binary, and each is restored here with a **one-byte patch** plus a
small piece of plumbing:

| | Feature | Binary | Restored by |
|---|---------|--------|-------------|
| **Part 1** | *Shadow Copies* tab in the volume **Properties** dialog | `vssui.dll` | 1-byte patch + CLSID registration + MUI satellite |
| **Part 2** | `vssadmin create shadow` and friends | `vssadmin.exe` | 1-byte patch + patched copy ahead of `System32` on `PATH` |

Both patches are length-preserving and touch exactly one byte — nothing else in the binaries changes,
and both are fully reversible.

---

## Contents

* [Install](#install)
* [Part 1 — the *Shadow Copies* tab](#part-1--the-shadow-copies-tab)
* [Part 2 — `vssadmin` Server commands](#part-2--vssadmin-server-commands)
* [Repository layout](#repository-layout)
* [Version compatibility](#version-compatibility)
* [Troubleshooting](#troubleshooting)
* [How this was found](#how-this-was-found)
* [Disclaimer](#disclaimer)

---

## Install

Both unlocks are installed by the same script, into one per-machine location:

```text
%ProgramData%\ShadowCopyUnlocker\
  vssui\      VSSUI.dll + <lang>\VSSUI.dll.mui          (registered in place)
  vssadmin\   vssadmin.exe + <lang>\vssadmin.exe.mui    (prepended to the machine PATH)
```

1. Open `deploy\` and run **`install.bat`** — it self-elevates (the machine `PATH` and `HKLM` need admin).

2. Open a **new** terminal, then:

   ```bat
   :: Part 1 - open C: -> Properties and look for the "Shadow Copies" tab

   :: Part 2
   where vssadmin
   vssadmin /?
   vssadmin create shadow /for=C:
   ```

3. To undo everything:

   ```bat
   uninstall.bat
   ```

`System32` is never modified by either part, so uninstalling restores the stock tools.

```powershell
# one part only, or a dry run (change nothing)
powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Part Vssui
powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Part Vssadmin
powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -DryRun
```

---

# Part 1 — the *Shadow Copies* tab

**Bring the Server-only _Shadow Copies_ tab back to the volume _Properties_ dialog.**

On non-Server Windows the volume *Properties* sheet has **no** *Shadow Copies* page. This part restores
it with three small, independent pieces:

| # | What | Why it's needed |
|---|------|-----------------|
| 1 | **1-byte patch** to `vssui.dll` | the page provider refuses to run on a client SKU |
| 2 | **CLSID registration** | the handler is not registered on client SKUs |
| 3 | **`en-US\VSSUI.dll.mui`** satellite | the DLL carries no dialog/string resources of its own |

Nothing is copied into `System32` — the DLL is registered **in place**, wherever you put it.

### Before / after

`C:` → *Properties*:

| | Tabs |
|---|---|
| **Before** | General · Tools · Hardware · Sharing · Security · Previous Versions · Quota |
| **After**  | General · Tools · Hardware · Sharing · Security · **Shadow Copies** · Previous Versions · Quota |

> The restored tab is labelled `Shadow Copies` because only the MUI satellite is available.

### Why the tab is missing

The page is implemented by `CVSSShellExt::AddPages` in **`vssui.dll`**. On client SKUs two things stop it:

**1. It is not registered.** On Windows Server the shell has a *Drive* property-sheet handler for the
VSS shell extension; on client Windows that entry is absent, so the handler is never even loaded:

```
HKLM\SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{4648F940-EFE3-4BAB-9211-3BE45CD5029D}
```

**2. It checks the SKU.** Even when it *is* loaded, `AddPages` bails out on a client SKU:

```c
// CVSSShellExt::AddPages  (vssui.dll)
if (IsPostW2KServer(NULL)) {                 // <-- false on client
    if (IsAdministrator()) {
        if (GetDriveTypeW(root) == DRIVE_FIXED) {
            GetVolumeInformationW(...);
            if (filesystem == L"NTFS") { ...create the "Shadow Copies" page... }
        }
    }
} else {
    Trace(L"we've detected a client SKU!");  // <-- client lands here
}
```

`IsPostW2KServer(NULL)` derives its answer from `CVssSKU::Initialize()`, which reads
`GetVersionExW(...).wProductType` and returns *server* only for `VER_NT_SERVER` /
`VER_NT_DOMAIN_CONTROLLER`. There is **no registry switch** for it — so the DLL has to be patched.

**3. The page has no resources of its own.** `vssui.dll` ships only a MUI redirection; the page dialog
(**id 1000**) and the tab caption live in the `en-US\VSSUI.dll.mui` satellite. If that file is missing,
the page is added to the sheet but its dialog cannot be created — comctl32 then silently drops the tab.
This is the *"I registered it and patched it, but still no tab"* case.

### The patch

In `CVSSShellExt::AddPages`, right after the SKU test:

```asm
call  IsPostW2KServer
test  eax, eax
jnz   server_path        ; 75 5B   <-- patched to  EB 5B  (jmp)
...                       ; (fall-through) "we've detected a client SKU!"
```

Flipping the conditional jump into an unconditional one forces the Server path, so the page is created
for any fixed NTFS volume. The patch site is located **robustly** (no hard-coded offsets) by `patch_vssui.py`:

1. find the byte pattern `33 C9 E8 ?? ?? ?? ?? 85 C0 75`
   (`xor ecx,ecx` / `call rel32` / `test eax,eax` / `jnz rel8`);
2. keep only candidates that call the same routine as the rest of the function (**`IsPostW2KServer`**);
3. keep only the candidate whose function — per the PE `.pdata` table — references the wide string
   `"CVSSShellExt::AddPages"`.

The same byte is also cross-checked against the function's `"we've detected a client SKU!"` trace.

### Install

`deploy\install.bat` copies the shipped `VSSUI.dll` (already patched) plus its MUI satellite into
`%ProgramData%\ShadowCopyUnlocker\vssui\`, and registers the shell handler so COM loads the DLL from
there. Nothing goes into `System32`.

If the tab does not appear, reload the shell (the *Properties* sheet is hosted by `explorer.exe`):

```bat
taskkill /f /im explorer.exe
start explorer.exe
```

> **Note** — if your File Explorer windows are hosted by *separate* `explorer.exe` processes, restart
> the one that owns the *Properties* dialog.

To register a different build, point the installer at it (a `VSSUI.dll`, or a folder holding
`VSSUI.dll` + `<lang>\VSSUI.dll.mui`):

```powershell
powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Part Vssui -VssuiPath D:\tools\vssui
```

### Registry reference

`deploy\install.ps1` writes exactly this (only `InprocServer32` is required; the value is the
`%ProgramData%` copy):

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{4648F940-EFE3-4BAB-9211-3BE45CD5029D}]
@="VSSShellExt Class"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{4648F940-EFE3-4BAB-9211-3BE45CD5029D}\InprocServer32]
@="<install dir>\\VSSUI.dll"
"ThreadingModel"="Apartment"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{4648F940-EFE3-4BAB-9211-3BE45CD5029D}]
```

> Do **not** add `ProgID` / `VersionIndependentProgID` / `TypeLib` / `Version` under the CLSID — those
> extra subkeys can make COM refuse to load the in-proc server (no page, no tab).

---

# Part 2 — `vssadmin` Server commands

**Bring back `vssadmin create shadow` (and the other Server-only commands) to client Windows.**

`vssadmin` on a client has a reduced command set. On Windows Server it has five more commands, and the
code for all of them is present in the client binary — it is simply hidden at runtime.

### Before / after

```text
---- Commands Supported ----          ---- Commands Supported ----
                                        Add ShadowStorage        <-- new
                                        Create Shadow            <-- new  ("vssadmin create shadow /for=C:")
Delete Shadows                          Delete Shadows
                                        Delete ShadowStorage     <-- new
List Providers                          List Providers
List Shadows                            List Shadows
List ShadowStorage                      List ShadowStorage
List Volumes                            List Volumes
List Writers                            List Writers
Resize ShadowStorage                    Resize ShadowStorage
                                        Revert Shadow            <-- new
                                        Query Reverts            <-- new
```

> **Caution** — this also unlocks `vssadmin revert shadow`, which reverts a volume *to* a shadow copy.
> That is a destructive operation. It is exactly what a Server exposes; treat it accordingly.

### Why the commands are missing

Every command lives in a table (`g_asAdmCommands`) whose entries carry a **SKU bitmask**. Both the
dispatcher and the help screen only accept an entry when that mask intersects the current SKU:

```c
// CVssAdminCLI::ParseCmdLine / CVssAdminCLI::PrintUsage   (vssadmin.exe)
if ( (entry.skuMask & dCurrentSKU) != 0 && ...)
        ...accept the command...
else
        Throw(L"Invalid command");       // <-- client lands here for Create Shadow
```

`dCurrentSKU` is computed once by `CVssSKU::Initialize()`, from the OS version:

```c
// CVssSKU::Initialize   (vssadmin.exe)
GetVersionExW(&osi);                                        // OSVERSIONINFOEXW
if ( (osi.wProductType - 2) <= 1 )                          // 2=VER_NT_DOMAIN_CONTROLLER, 3=VER_NT_SERVER
    ms_eSKU = (osi.wSuiteMask & VER_SUITE_EMBEDDEDNT) ? 4 : 2;   // server  -> bit 1
else
    ms_eSKU = (osi.wProductType == 1);                      // workstation -> bit 0
```

So a client ends up with `dCurrentSKU == 1` and `Create Shadow` (mask `0x6`) never matches.

This is a **runtime** check, not a build-time difference. Proved by running each build on the *other*
OS:

| Binary | Run on | Result |
|---|---|---|
| client `19041` | **Server 2025** | full 12-command set, `Create Shadow` works |
| Server `26100` | **client Win10 19041** | does not even start — `STATUS_ENTRYPOINT_NOT_FOUND` (`0xC0000139`) |

Because `vssadmin.exe` is OS-version specific, the only build safe to patch is the one the target OS
already ships.

### The patch

In `CVssSKU::Initialize`, the conditional jump that selects the Server branch:

```asm
mov   al, [rsp+0x15A]      ; wProductType
sub   al, 2
cmp   al, 1
jbe   server_branch        ; 76 14   <-- patched to  EB 14  (jmp)
...                        ; (fall-through) ms_eSKU = (wProductType == 1)   -> workstation
server_branch:
mov   al, [rsp+0x158]      ; wSuiteMask
and   al, 40h
...
mov   cs:ms_eSKU, ecx      ; 2  (or 4 for embedded)
```

Making the jump unconditional forces `dCurrentSKU = 2` — *exactly* what a real Server computes — so
both the dispatcher and the help behave as they do on Server Windows.

The site is located **robustly**, never by hard-coded offset:

1. find the Server branch tail byte pattern
   `24 40 F6 D8 1B C9 83 E1 02 83 C1 02 89 0D`
   (`and al,40h` / `neg al` / `sbb ecx,ecx` / `and ecx,2` / `add ecx,2` / `mov cs:ms_eSKU,ecx`) —
   its first instruction is `mov al,[rsp+disp32]` (`8A 84 24 ...`);
2. scan backwards for the conditional jump that targets it — that is the gate;
3. confirm the containing function calls the imported `KERNEL32!GetVersionExW`, i.e. that we really are
   inside `CVssSKU::Initialize`.

Two independent implementations of that algorithm ship here: `patch_vssadmin.py` (reference tool, also
used to produce the versioned copies under `vssadmin_exe\`) and the dependency-free PowerShell port
inside `deploy\install.ps1`.

### Install

`vssadmin.exe` has no registration, so the installer patches **this machine's own** build at install
time, writes it (with its MUI satellites) to `%ProgramData%\ShadowCopyUnlocker\vssadmin\`, and prepends
that folder to the machine `PATH`. Windows resolves `vssadmin` down `PATH` in order, so the patched copy
**overtakes** `System32` — which is never modified, so uninstalling restores the stock tool.

```text
Shadow Copy Unlocker
  install root : C:\ProgramData\ShadowCopyUnlocker
  parts        : All

[2/2] vssadmin Server commands (vssadmin.exe)
  source     : C:\Windows\System32\vssadmin.exe
  build      : 10.0.19041.3691 (WinBuild.160101.0800)
  gate       : file offset 0x11C42  (0x76 -> 0xEB, 2-byte jump)
  checks     : 1 candidate(s), GetVersionExW call confirmed
  written    : C:\ProgramData\ShadowCopyUnlocker\vssadmin\vssadmin.exe
  MUI        : en-US, zh-CN
  PATH       : prepended to the machine PATH
```

Open a **new** command prompt (existing ones keep the environment they started with) and check:

```bat
where vssadmin
vssadmin /?
vssadmin create shadow /for=C:
vssadmin list shadows /for=C:
```

---

## Repository layout

```
Shadow Copy Unlocker/
├─ README.md
├─ patch_vssui.py                       # vssui.dll patcher (Part 1) - Python, robust + friendly
├─ patch_vssadmin.py              # vssadmin.exe patcher (Part 2) - Python, robust + friendly
├─ vssui.reg                      # reference .reg of the Part 1 registry layout
│
├─ deploy/                        # unified installer for BOTH parts
│  ├─ install.bat                 #   self-elevating wrapper -> install.ps1
│  ├─ install.ps1                 #   copy to %ProgramData%, register, patch vssadmin, set PATH
│  ├─ uninstall.bat               #   self-elevating wrapper -> uninstall.ps1
│  ├─ uninstall.ps1               #   remove registration + PATH entry + %ProgramData% folder
│  ├─ VSSUI.dll                   #   Part 1 payload: patched 17763 build (best compatibility)
│  └─ en-US/
│     └─ VSSUI.dll.mui            #   REQUIRED page dialog + strings
│
├─ vssui_dll/                     # Part 1: unpatched + patched builds used for the analysis
│  ├─ 17763.1/      (Server 2019)
│  ├─ 20348.1/      (Server 2022)
│  └─ 26100.5074/   (Server 2025 / Windows 11 25H2)
│
└─ vssadmin_exe/                  # Part 2: builds used for the analysis
   ├─ 19041.3691/   (Windows 10 20H2-22H2)
   └─ 26100.5074/   (Windows 11 24H2/25H2, Server 2025)
```

Installed layout (created by `install.bat`, removed by `uninstall.bat`):

```
%ProgramData%\ShadowCopyUnlocker\
├─ vssui\
│  ├─ VSSUI.dll
│  └─ en-US\VSSUI.dll.mui
└─ vssadmin\
   ├─ vssadmin.exe
   ├─ en-US\vssadmin.exe.mui
   └─ zh-CN\vssadmin.exe.mui     # whichever languages this OS ships
```

## Building the patched binaries

```console
# Part 1 - vssui.dll
$ python patch_vssui.py --dry-run              # report the site, write nothing
$ python patch_vssui.py                        # patch every .\vssui_dll\*\VSSUI.dll
$ python patch_vssui.py path\to\VSSUI.dll      # patch one file -> VSSUI.patched.dll
$ python patch_vssui.py path\to\VSSUI.dll -o out\VSSUI.dll
$ python patch_vssui.py path\to\VSSUI.dll --in-place

# Part 2 - vssadmin.exe
$ python patch_vssadmin.py --dry-run     # report the gate, write nothing
$ python patch_vssadmin.py               # patch every .\vssadmin_exe\*\vssadmin.exe
$ python patch_vssadmin.py path\to\vssadmin.exe -o out\vssadmin.exe
```

Example:

```text
Shadow Copy Unlocker - vssui.dll patcher
  targets : 3 file(s)
  action  : write VSSUI.patched.dll

  vssui_dll\17763.1\VSSUI.dll
      gate @file:0x3077 (rva 0x3C77)  opcode 0x75  IsPostW2KServer rva 0x12278
      function tagged 'AddPages': True   client-SKU trace in function: True
  [ok]   patched 0x3077 (0x75 -> 0xEB)  ->  vssui_dll\17763.1\VSSUI.patched.dll  sha256 9b889c77f9e89c5a...

Shadow Copy Unlocker - vssadmin.exe patcher
  targets : 2 file(s)
  action  : write vssadmin.patched.exe

  vssadmin_exe\19041.3691\vssadmin.exe
      gate @file:0x11C42  jcc short 0x76  branch @0x11C58  GetVersionExW in function: True
  [ok]   patched 0x11C42  ->  vssadmin_exe\19041.3691\vssadmin.patched.exe  sha256 658310cfa8da1fa7...
```

Requires Python 3.8+ and nothing else. (The Part 2 installer does **not** need Python — it has its own
PowerShell implementation of the same algorithm.)

## Version compatibility

**Part 1 — `vssui.dll`** (a DLL is loaded by COM, so a Server build can be used on a client):

| Build | Source OS | Patch offset (`75`→`EB`) | `IsPostW2KServer` RVA | Works on |
|-------|-----------|--------------------------|-----------------------|----------|
| **17763.1** | Server 2019 | `0x3077` | `0x12278` | Windows 10 19041 **and** Windows 11 25H2 — **recommended** |
| 20348.1 | Server 2022 | `0x43C8` | `0x13450` | patched the same way (untested here) |
| 26100.5074 | Server 2025 | `0x53E9` | `0x13DF4` | Windows 11 25H2 (26200) — **not** loadable on Windows 10 19041 |

Each build needs the `vssui.dll.mui` that matches **its own** version.

**Part 2 — `vssadmin.exe`** (an EXE must match the OS, so patch the machine's own build):

| Build | Source OS | Gate file offset (`76`→`EB`) | `IsPostW2KServer` branch |
|-------|-----------|------------------------------|--------------------------|
| **19041.3691** | Windows 10 20H2–22H2 | `0x11C42` | `0x11C58` |
| 26100.5074 | Windows 11 24H2/25H2, Server 2025 | `0x13A96` | `0x13AAD` |

`vssadmin.exe` is OS-version specific: a `26100` build will not start on `19041`
(`STATUS_ENTRYPOINT_NOT_FOUND`). This is why `install.ps1` patches the build already on the machine
instead of shipping a fixed binary.

## Troubleshooting

**Part 1 — the tab**

| Symptom | Cause / fix |
|---|---|
| No *Shadow Copies* tab at all | Handler not registered — run `deploy\install.bat` **elevated**. |
| Page added but tab never shows | `VSSUI.dll.mui` missing in the language folder next to `VSSUI.dll`. |
| Tab shows only after a manual restart | `explorer.exe` had the old handler cached — reload the shell. |
| Still nothing | `VSSUI.dll` **is** loaded (e.g. Process Explorer) but the tab is gone → the SKU patch isn't in the loaded file. Re-run `patch_vssui.py`, redeploy, restart the shell. |
| Nothing on some volumes | The page is only added for **fixed NTFS** volumes (drive type 3), and only for **administrators**. |

**Part 2 — `vssadmin`**

| Symptom | Cause / fix |
|---|---|
| `where vssadmin` still shows `System32` | You are in an old console. Its environment is fixed at start — open a **new** terminal (or log off/on). |
| `Error: Invalid command` for `create shadow` | The resolved `vssadmin.exe` is the stock one. Check `where vssadmin`; re-run `install.bat`. |
| Messages print as *"Unable to load message for id ..."* | The `en-US\vssadmin.exe.mui` / `<lang>\vssadmin.exe.mui` satellites are missing next to the portable exe (happens if you rename/copy the exe by hand). |
| The exe will not start (`0xC0000139`) | You copied a `vssadmin.exe` built for another Windows version. Patch the machine's own build instead. |
| Installer says *"SKU gate not found"* | Unusual build. Run `python patch_vssadmin.py "<path>" --dry-run` and open an issue with the file version. |

## How this was found

**Part 1** — a breakpoint on `comctl32!CreatePropertySheetPageW` while opening `C:` → *Properties*
revealed the handler chain `SHELL32!DCA_AppendClassSheetInfo` → `SHELL32!SHOpenPropSheetW` and named
every page provider: `shell32` (`CDrives`), `ntshrui` (Sharing), `aclui`/`rshx32` (Security), `vssui`
(**Shadow Copies**), `twext` (Previous Versions), `dskquoui` (Quota). The client never loaded `vssui` at
all → registry diff → the missing handler entry. After registration the page was created but the tab
was still absent; tracing `CVSSShellExt::AddPages` showed every check passing, so the drop happened later
when comctl32 tried to build the page dialog. A resource dump showed no `RT_DIALOG`/`RT_STRING` in
`vssui.dll` — supplying the MUI satellite (dialog id 1000) made the tab appear.

**Part 2** — diffing `vssadmin /?` between the two VMs showed five Server-only commands. The client
binary turned out to *contain* `CVssAdminCLI::CreateSnapshot`, so the gate had to be at runtime: running
each build on the other OS confirmed it (client build works on Server; Server build refuses to load on
the client). In IDA, `GetVersionExW` had exactly one caller — `CVssSKU::Initialize` — and `ms_eSKU` had
exactly one consumer, `IsCorrectContext`. Following the dispatch loop in `CVssAdminCLI::ParseCmdLine`
then showed the per-command SKU bitmask (`entry.skuMask & dCurrentSKU`) shared by the help printer.

## Disclaimer

`vssui.dll` and `vssadmin.exe` are Microsoft components. The patched copies here are **not code-signed**
and are provided for interoperability / personal use on machines you own. Use at your own risk —
in particular, `vssadmin revert shadow` is destructive.
