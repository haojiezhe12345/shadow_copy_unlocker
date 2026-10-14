# Shadow Copy Unlocker

![platform](https://img.shields.io/badge/platform-Windows%20client-0078D6?logo=windows&logoColor=white)
![arch](https://img.shields.io/badge/arch-x64-lightgrey)
![status](https://img.shields.io/badge/status-working-brightgreen)
![patch](https://img.shields.io/badge/patch-1%20byte-blueviolet)

**Bring the Server-only _Shadow Copies_ tab back to the volume _Properties_ dialog on client Windows.**

On non-Server Windows the volume *Properties* sheet has **no** *Shadow Copies* page. This project
restores it with three small, independent pieces:

| # | What | Why it's needed |
|---|------|-----------------|
| 1 | **1-byte patch** to `vssui.dll` | the page provider refuses to run on a client SKU |
| 2 | **CLSID registration** | the handler is not registered on client SKUs |
| 3 | **`en-US\VSSUI.dll.mui`** satellite | the DLL carries no dialog/string resources of its own |

Nothing is copied into `System32` — the DLL is registered **in place**, wherever you put it.

---

## Before / after

`C:` → *Properties*:

| | Tabs |
|---|---|
| **Before** | General · Tools · Hardware · Sharing · Security · Previous Versions · Quota |
| **Before** | General · Tools · Hardware · Sharing · Security · **Shadow Copies** · Previous Versions · Quota |

> The restored tab is labelled `Shadow Copies` because only the en-US MUI satellite is available.

---

## Why the tab is missing

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

---

## What the patch does

In `CVSSShellExt::AddPages`, right after the SKU test:

```asm
call  IsPostW2KServer
test  eax, eax
jnz   server_path        ; 75 5B   <-- patched to  EB 5B  (jmp)
...                       ; (fall-through) "we've detected a client SKU!"
```

Flipping the conditional jump into an unconditional one forces the Server path, so the page is created
for any fixed NTFS volume. The patch site is located **robustly** (no hard-coded offsets) by
`patch.py`:

1. find the byte pattern `33 C9 E8 ?? ?? ?? ?? 85 C0 75`
   (`xor ecx,ecx` / `call rel32` / `test eax,eax` / `jnz rel8`);
2. keep only candidates that call the same routine as the rest of the function (**`IsPostW2KServer`**);
3. keep only the candidate whose function — per the PE `.pdata` table — references the wide string
   `"CVSSShellExt::AddPages"`.

The same byte is also cross-checked against the function's `"we've detected a client SKU!"` trace.

---

## Repository layout

```
Shadow Copy Unlocker/
├─ README.md
├─ patch.py                  # robust, self-documenting vssui.dll patcher
├─ vssui.reg                 # reference .reg of the registry layout
├─ deploy/                   # ready-to-use install package
│  ├─ register.bat           #   registers the DLL in place (elevated)
│  ├─ unregister.bat         #   removes exactly what register.bat created
│  ├─ VSSUI.dll              #   patched 17763 build (default)
│  └─ en-US/
│     └─ VSSUI.dll.mui       #   REQUIRED page dialog + strings
└─ vssui_dll/                # unpatched + patched builds used for the analysis
   ├─ 17763.1/     (Server 2019)
   ├─ 20348.1/     (Server 2022)
   └─ 26100.5074/  (Server 2025 / Windows 11 25H2)
```

---

## Quick start

1. Grab the `deploy` folder and put it somewhere permanent (it is the install directory — nothing is
   copied to `System32`). Keep the layout intact:

   ```
   <somewhere>\
     VSSUI.dll
     en-US\VSSUI.dll.mui
   ```

2. Open an **elevated** Command Prompt and register:

   ```bat
   register.bat
   ```

   …or point it at an existing folder / DLL:

   ```bat
   register.bat "D:\tools\vssui"
   register.bat "D:\tools\vssui\VSSUI.dll"
   ```

3. If the tab does not appear, reload the shell (the *Properties* sheet is hosted by `explorer.exe`):

   ```bat
   taskkill /f /im explorer.exe
   start explorer.exe
   ```

4. To undo:

   ```bat
   unregister.bat
   ```

> **Note** — if your File Explorer windows are hosted by *separate* `explorer.exe` processes, restart
> the one that owns the *Properties* dialog.

---

## Building the patched DLL

```console
$ python patch.py --dry-run              # report the site, write nothing
$ python patch.py                        # patch every .\vssui_dll\*\VSSUI.dll
$ python patch.py path\to\VSSUI.dll      # patch one file -> VSSUI.patched.dll
$ python patch.py path\to\VSSUI.dll -o out\VSSUI.dll
$ python patch.py path\to\VSSUI.dll --in-place
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
  ...
```

Requires Python 3.8+ and nothing else.

---

## Version compatibility

| Build | Source OS | Patch offset (`75`→`EB`) | `IsPostW2KServer` RVA | Works on |
|-------|-----------|--------------------------|-----------------------|----------|
| **17763.1** | Server 2019 | `0x3077` | `0x12278` | Windows 10 19041 **and** Windows 11 25H2 — **recommended** |
| 20348.1 | Server 2022 | `0x43C8` | `0x13450` | patched the same way (untested here) |
| 26100.5074 | Server 2025 | `0x53E9` | `0x13DF4` | Windows 11 25H2 (26200) — **not** loadable on Windows 10 19041 |

Each build needs the `vssui.dll.mui` that matches **its own** version. All three DLLs are en-US builds,
so only the `en-US` satellite is required.

---

## Registry reference

`deploy\register.bat` writes exactly this (only `InprocServer32` is required):

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

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| No *Shadow Copies* tab at all | Handler not registered — run `deploy\register.bat` **elevated**. |
| Page added but tab never shows | `en-US\VSSUI.dll.mui` missing next to `VSSUI.dll`. |
| Tab shows only after a manual restart | `explorer.exe` had the old handler cached — reload the shell. |
| Still nothing | `VSSUI.dll` **is** loaded (check with Process Explorer) but the tab is gone → the SKU patch isn't in the loaded file. Re-run `patch.py`, redeploy, restart the shell. |
| Wrong-volume dialog | The page is only added for **fixed NTFS** volumes (drive type 3), and only for **administrators**. |

---

## How this was found (short version)

* Breakpoint on `comctl32!CreatePropertySheetPageW` while opening `C:` → *Properties* revealed the
  handler chain `SHELL32!DCA_AppendClassSheetInfo` → `SHELL32!SHOpenPropSheetW` and named every page
  provider: `shell32` (`CDrives`), `ntshrui` (Sharing), `aclui`/`rshx32` (Security),
  `vssui` (**Shadow Copies**), `twext` (Previous Versions), `dskquoui` (Quota).
* Diffing client vs. Server showed the client never loaded `vssui` at all → registry diff → the
  missing handler entry.
* After registering, the page was created but the tab was still absent. Tracing `CVSSShellExt::AddPages`
  showed every check passing (`IsAdministrator`, `DRIVE_FIXED`, `NTFS`, page handed to
  `AddPropSheetPageProc`), so the drop happened later — when comctl32 tried to build the page dialog.
* A resource dump of `vssui.dll` showed **no** `RT_DIALOG`/`RT_STRING` — only a MUI redirection.
  Supplying `en-US\VSSUI.dll.mui` (which contains dialog id 1000) made the tab appear.

---

## Disclaimer

`vssui.dll` is a Microsoft component. The patched copies here are **not code-signed** and are provided
for interoperability / personal use on machines you own. Use at your own risk.
