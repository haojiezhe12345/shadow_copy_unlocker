#!/usr/bin/env python3
"""
Shadow Copy Unlocker - vssui.dll patcher
========================================

Windows client SKUs hide the Server-only "Shadow Copies" property page.  The
page is provided by ``CVSSShellExt::AddPages`` inside ``vssui.dll``, which
bails out early when it thinks the OS is a client SKU::

    call IsPostW2KServer
    test eax, eax
    jnz  server_path          ; 0x75 -> take the Server branch
    ...                        ; (fall-through) "we've detected a client SKU!"

This tool flips that single conditional jump into an unconditional one
(``0x75`` ``jnz`` -> ``0xEB`` ``jmp``), so the Server branch is always taken.

The patch site is located *robustly* - nothing is hard-coded per build:

  1. find the byte pattern ``33 C9 E8 ?? ?? ?? ?? 85 C0 75``
     (``xor ecx,ecx`` / ``call rel32`` / ``test eax,eax`` / ``jnz rel8``)
  2. keep only candidates whose ``call`` targets the same routine in the
     containing function (i.e. ``IsPostW2KServer``)
  3. keep only the candidate whose function - per the PE ``.pdata`` table -
     references the wide string ``"CVSSShellExt::AddPages"``

Usage
-----
::

    # patch every VSSUI.dll found under .\\vssui_dll (default)
    python patch_vssui.py

    # patch one file, writing VSSUI.patched.dll next to it
    python patch_vssui.py vssui_dll\\17763.1\\VSSUI.dll

    # choose the output, or patch in place
    python patch_vssui.py vssui_dll\\26100.5074\\VSSUI.dll -o out\\VSSUI.dll
    python patch_vssui.py vssui_dll\\20348.1\\VSSUI.dll --in-place

    # just report what would be done
    python patch_vssui.py --dry-run

Notes
-----
* A patched DLL still needs its ``en-US\\VSSUI.dll.mui`` satellite at run time
  (the dialog template and strings live there) and the CLSID registration -
  see the ``deploy\\`` folder.
* Patched output is *not* code-signed; use it the same way you obtained the
  original (client machines do not ship this DLL, so there is no WFP issue).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

__version__ = "1.0"

# jnz (short) -> jmp (short); the following rel8 is left untouched.
PATCH_FROM = 0x75
PATCH_TO = 0xEB

# xor ecx,ecx ; call rel32 ; test eax,eax ; jnz rel8
GATE_PATTERN = [0x33, 0xC9, 0xE8, None, None, None, None, 0x85, 0xC0, PATCH_FROM]

STR_ADDPAGES = "CVSSShellExt::AddPages"
STR_CLIENT_SKU = "we've detected a client SKU!"

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.join(REPO_ROOT, "vssui_dll")


# --------------------------------------------------------------------------- #
# PE helpers
# --------------------------------------------------------------------------- #
def parse_pe(data: bytes):
    """Return (sections, data_directory_offset)."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE file (missing MZ)")
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        raise ValueError("not a PE file (missing PE signature)")
    coff = e + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    optsz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("not a PE32/PE32+ image")
    dd = opt + (112 if magic == 0x20B else 96)
    secs_off = opt + optsz
    sections = []
    for i in range(nsec):
        s = secs_off + 40 * i
        name = data[s:s + 8].rstrip(b"\0").decode("latin1", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((name, va, vsize, rawptr, rawsize))
    if not sections:
        raise ValueError("no sections")
    return sections, dd


def rva2file(sections, rva: int):
    for _name, va, vsize, rawptr, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + (rva - va)
    return None


def file2rva(sections, off: int):
    for _name, va, vsize, rawptr, rawsize in sections:
        if rawptr <= off < rawptr + rawsize:
            return va + (off - rawptr)
    return None


def find_pattern(data: bytes, pattern) -> list[int]:
    n = len(pattern)
    hits = []
    for i in range(len(data) - n + 1):
        if all(p is None or data[i + j] == p for j, p in enumerate(pattern)):
            hits.append(i)
    return hits


def wide(s: str) -> bytes:
    return s.encode("utf-16-le")


def references(data: bytes, sections, start: int, end: int, target_rva: int) -> bool:
    """True if the code in [start,end) has a RIP-relative LEA to target_rva."""
    if start is None or end is None:
        return False
    i = start
    while i < end - 7:
        if data[i] in (0x48, 0x4C) and data[i + 1] == 0x8D and (data[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i + 3)[0]
            src_rva = file2rva(sections, i)
            if src_rva is not None and src_rva + 7 + disp == target_rva:
                return True
            i += 7
        else:
            i += 1
    return False


# --------------------------------------------------------------------------- #
# finding / validating the patch site
# --------------------------------------------------------------------------- #
def find_patch_site(data: bytes) -> dict:
    """Locate the AddPages SKU gate.  Raises RuntimeError if not found."""
    sections, dd = parse_pe(data)

    ex_va, ex_sz = struct.unpack_from("<II", data, dd + 3 * 8)
    ex_off = rva2file(sections, ex_va)
    funcs = []
    if ex_off is not None and ex_sz:
        funcs = sorted(
            struct.unpack_from("<II", data, ex_off + 12 * i)
            for i in range(ex_sz // 12)
        )

    def func_of(rva):
        for beg, end in funcs:
            if beg <= rva < end:
                return beg, end
        return None

    addpages_rva = file2rva(sections, data.find(wide(STR_ADDPAGES)))
    clientsku_rva = file2rva(sections, data.find(wide(STR_CLIENT_SKU)))

    candidates = []
    for off in find_pattern(data, GATE_PATTERN):
        jnz = off + 9
        jnz_rva = file2rva(sections, jnz)
        span = func_of(jnz_rva) if jnz_rva is not None else None
        if span is None:
            continue
        fn_start, fn_end = span
        fb, fe = rva2file(sections, fn_start), rva2file(sections, fn_end)
        call_end = file2rva(sections, off + 7)
        call_target = call_end + struct.unpack_from("<i", data, off + 3)[0]
        candidates.append({
            "gate_off": off,
            "jnz_off": jnz,
            "jnz_rva": jnz_rva,
            "opcode": data[jnz],
            "rel8": data[jnz + 1],
            "call_target": call_target,
            "is_addpages": references(data, sections, fb, fe, addpages_rva),
            "has_client_sku": references(data, sections, fb, fe, clientsku_rva),
        })

    if not candidates:
        raise RuntimeError(
            "SKU gate not found - this build may be already patched, "
            "a different architecture, or not vssui.dll"
        )

    preferred = [c for c in candidates if c["is_addpages"]]
    pool = preferred or candidates
    pool.sort(key=lambda c: c["jnz_off"])
    for c in pool:
        if c["opcode"] == PATCH_FROM:
            return c
    return pool[0]


def patch_bytes(data: bytes, site: dict) -> bytes:
    out = bytearray(data)
    assert out[site["jnz_off"]] == site["opcode"]
    out[site["jnz_off"]] = PATCH_TO
    return bytes(out)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def collect_inputs(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for n in names:
                    if n.lower() == "vssui.dll":
                        files.append(os.path.join(root, n))
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"  ! skipping (not found): {p}")
    return files


def process(path, out_path, in_place, dry_run, show_info):
    """Returns (ok, message)."""
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        return False, f"cannot read: {exc}"

    try:
        site = find_patch_site(data)
    except (ValueError, RuntimeError, struct.error) as exc:
        return False, str(exc)

    label = os.path.relpath(path, REPO_ROOT) if path.startswith(REPO_ROOT) else path
    info = (
        f"gate @file:0x{site['jnz_off']:X} (rva 0x{site['jnz_rva']:X})  "
        f"opcode 0x{site['opcode']:02X}  "
        f"IsPostW2KServer rva 0x{site['call_target']:X}"
    )
    if show_info:
        print(f"  {label}")
        print(f"      {info}")
        print(f"      function tagged 'AddPages': {site['is_addpages']}"
              f"   client-SKU trace in function: {site['has_client_sku']}")

    if site["opcode"] == PATCH_TO:
        if in_place or dry_run:
            return True, f"already patched ({info})"
        # still (re)write the output copy
    elif site["opcode"] != PATCH_FROM:
        return False, f"unexpected gate opcode 0x{site['opcode']:02X} ({info})"

    if dry_run:
        return True, f"would patch 0x{site['jnz_off']:X} (0x{PATCH_FROM:02X} -> 0x{PATCH_TO:02X})"

    patched = patch_bytes(data, site)

    if in_place:
        dest = path
    elif out_path:
        dest = out_path
    else:
        dest = os.path.join(os.path.dirname(path), "VSSUI.patched.dll")

    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(patched)

    # read back and verify
    check = open(dest, "rb").read()
    if check[site["jnz_off"]] != PATCH_TO:
        return False, f"verification failed writing {dest}"

    return True, (
        f"patched 0x{site['jnz_off']:X} (0x{PATCH_FROM:02X} -> 0x{PATCH_TO:02X})"
        f"  ->  {os.path.relpath(dest, REPO_ROOT) if dest.startswith(REPO_ROOT) else dest}"
        f"  sha256 {sha256(patched)[:16]}..."
    )


def build_parser():
    p = argparse.ArgumentParser(
        prog="patch_vssui.py",
        description="Patch vssui.dll so the Server-only 'Shadow Copies' "
                    "property page is created on client Windows.",
        epilog="See README.md for the full story.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "paths", nargs="*",
        help="VSSUI.dll files and/or directories to scan "
             "(default: ./vssui_dll)",
    )
    p.add_argument("-o", "--output", metavar="FILE",
                   help="output path for a single input file")
    p.add_argument("-i", "--in-place", action="store_true",
                   help="overwrite the input file instead of writing VSSUI.patched.dll")
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="report the patch site without writing anything")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only print the result lines")
    p.add_argument("-V", "--version", action="version",
                   version=f"Shadow Copy Unlocker patch_vssui.py {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    paths = args.paths or [DEFAULT_ROOT]
    files = collect_inputs(paths)

    if not files:
        print("No VSSUI.dll files found.")
        return 2
    if args.output and len(files) != 1:
        print("-o/--output can only be used with a single input file.")
        return 2

    if not args.quiet:
        print("Shadow Copy Unlocker - vssui.dll patcher")
        print(f"  targets : {len(files)} file(s)")
        print(f"  action  : {'dry-run' if args.dry_run else ('in-place' if args.in_place else 'write VSSUI.patched.dll')}")
        print()

    ok_count = 0
    fail_count = 0
    for path in files:
        ok, msg = process(path, args.output, args.in_place, args.dry_run,
                          show_info=not args.quiet)
        if ok:
            ok_count += 1
            print(f"  [ok]   {msg}")
        else:
            fail_count += 1
            print(f"  [fail] {os.path.relpath(path, REPO_ROOT) if path.startswith(REPO_ROOT) else path}: {msg}")

    if not args.quiet:
        print()
        print(f"Done: {ok_count} ok, {fail_count} failed.")
        if ok_count and not args.dry_run:
            print("Next: copy the patched DLL + en-US\\VSSUI.dll.mui and run deploy\\register.bat")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
