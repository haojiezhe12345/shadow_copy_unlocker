#!/usr/bin/env python3
"""
Shadow Copy Unlocker - vssadmin.exe patcher
===========================================

Client Windows ships a *reduced* ``vssadmin`` command set.  On a client the help
lists seven commands; on a Server it lists twelve.  The five that are missing on
clients are::

    Add ShadowStorage
    Create Shadow          <-- "vssadmin create shadow /for=C:"
    Delete ShadowStorage
    Revert Shadow
    Query Reverts

``vssadmin.exe`` contains the code for all of them - the commands are simply
hidden at runtime.  Every command lives in a table (``g_asAdmCommands``) whose
entries carry a SKU bitmask, and the dispatcher only accepts a command when::

    (entry.skuMask & dCurrentSKU) != 0        // CVssAdminCLI::ParseCmdLine
    (entry.skuMask & dCurrentSKU) != 0        // CVssAdminCLI::PrintUsage (help)

``dCurrentSKU`` is derived once from ``CVssSKU::Initialize``::

    GetVersionExW(&osi);                     // OSVERSIONINFOEXW
    if ( (osi.wProductType - 2) <= 1 )       // 2=VER_NT_DOMAIN_CONTROLLER, 3=VER_NT_SERVER
        ms_eSKU = (osi.wSuiteMask & VER_SUITE_EMBEDDEDNT) ? 4 : 2;   // server (bit 1)
    else
        ms_eSKU = (osi.wProductType == 1);   // workstation (bit 0)

So a client ends up with ``dCurrentSKU == 1`` and the Server-only commands never
match.

This tool flips that one conditional jump into an unconditional jump, so the
"Server" branch is always taken and ``dCurrentSKU`` becomes ``2`` - exactly what
a real Server computes.  Everything downstream (dispatch **and** help) then
behaves as it does on Server Windows.  The change is a single byte and nothing
else in the binary is touched.

The patch site is located *robustly* - nothing is hard-coded per build:

  1. find the Server branch by its tail byte pattern
     ``24 40 F6 D8 1B C9 83 E1 02 83 C1 02 89 0D``
     (``and al,40h`` / ``neg al`` / ``sbb ecx,ecx`` / ``and ecx,2`` /
      ``add ecx,2`` / ``mov cs:ms_eSKU,ecx``); its first instruction is the
     ``8A 84 24`` (``mov al,[rsp+disp32]``) that loads ``wSuiteMask``
  2. scan backwards for the short/near conditional jump that targets it - that
     is the SKU gate (``jbe`` on every build seen so far)
  3. sanity-check that the containing function calls the imported
     ``KERNEL32!GetVersionExW``, i.e. that we really are inside
     ``CVssSKU::Initialize``

Usage
-----
::

    # patch every vssadmin.exe found under .\\vssadmin_exe (default)
    python patch_vssadmin.py

    # patch one file, writing vssadmin.patched.exe next to it
    python patch_vssadmin.py vssadmin_exe\\26100.5074\\vssadmin.exe

    # choose the output, or patch in place
    python patch_vssadmin.py some\\vssadmin.exe -o out\\vssadmin.exe
    python patch_vssadmin.py some\\vssadmin.exe --in-place

    # just report what would be done
    python patch_vssadmin.py --dry-run

Notes
-----
* Unlike ``vssui.dll``, ``vssadmin.exe`` is an executable, so there is no
  registration: you run the patched copy (or replace the one in ``System32``).
  A patched ``vssadmin.exe`` only loads on Windows versions it was built for -
  a 26100 build will not start on 19041 (it fails with
  ``STATUS_ENTRYPOINT_NOT_FOUND``, 0xC0000139), so patch the build that matches
  the target OS.
* ``vssadmin`` needs its ``en-US\\vssadmin.exe.mui`` satellite for messages;
  if you run a renamed copy, rename the MUI alongside it too, otherwise the
  command still works but messages print as "Unable to load message".
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

__version__ = "1.0"

# and al,40h ; neg al ; sbb ecx,ecx ; and ecx,2 ; add ecx,2 ; mov cs:ms_eSKU,ecx
SERVER_TAIL = bytes.fromhex("2440f6d81bc983e10283c102890d")
MOV_AL_RSP = bytes.fromhex("8a8424")           # mov al, [rsp+disp32]  (3-byte opcode + disp32 = 7)
MOV_AL_RSP_LEN = 7
WANT_IMPORT = ("KERNEL32.dll", "GetVersionExW")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.join(REPO_ROOT, "vssadmin_exe")


# --------------------------------------------------------------------------- #
# PE helpers
# --------------------------------------------------------------------------- #
def parse_pe(data: bytes):
    """Return (sections, data_directory_offset, optional_header_offset, magic)."""
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
    so = opt + optsz
    sections = []
    for i in range(nsec):
        s = so + 40 * i
        name = data[s:s + 8].rstrip(b"\0").decode("latin1", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((name, va, vsize, rawptr, rawsize))
    if not sections:
        raise ValueError("no sections")
    return sections, dd, opt, magic


def rva2file(sections, rva):
    for _n, va, vsize, rawptr, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + (rva - va)
    return None


def file2rva(sections, off):
    for _n, va, vsize, rawptr, rawsize in sections:
        if rawptr <= off < rawptr + rawsize:
            return va + (off - rawptr)
    return None


def import_iat_rva(data, sections, dd, magic, module, func):
    """RVA of the IAT slot for module!func, or None."""
    trva, _tsz = struct.unpack_from("<II", data, dd + 1 * 8)
    off = rva2file(sections, trva)
    if off is None:
        return None
    step = 8 if magic == 0x20B else 4
    while True:
        ilt, ts, fc, name_rva, iat = struct.unpack_from("<IIIII", data, off)
        if ilt == 0 and name_rva == 0:
            return None
        no = rva2file(sections, name_rva)
        mod = data[no:].split(b"\0")[0].decode("latin1") if no is not None else ""
        if mod.lower() == module.lower():
            thunk = rva2file(sections, ilt or iat)
            if thunk is None:
                return None
            for i in range(4096):
                v = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, thunk + step * i)[0]
                if v == 0:
                    break
                if not (v & (1 << (63 if magic == 0x20B else 31))):
                    fo = rva2file(sections, v)
                    fn = data[fo + 2:].split(b"\0")[0].decode("latin1") if fo is not None else ""
                    if fn == func:
                        return iat + step * i
        off += 20


def find_all(data, pat, limit=64):
    hits, i = [], 0
    while len(hits) < limit:
        i = data.find(pat, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    return hits


def calls_iat(data, sections, start_off, end_off, iat_rva):
    """True if any `FF 15 rel32` in [start,end) resolves to iat_rva."""
    i = start_off
    while i < end_off - 6:
        if data[i] == 0xFF and data[i + 1] == 0x15:
            src = file2rva(sections, i)
            if src is not None:
                target = src + 6 + struct.unpack_from("<i", data, i + 2)[0]
                if target == iat_rva:
                    return True
            i += 6
        else:
            i += 1
    return False


# --------------------------------------------------------------------------- #
# locating / validating the patch site
# --------------------------------------------------------------------------- #
def find_gate(data: bytes) -> dict:
    """Locate the SKU gate in CVssSKU::Initialize.  Raises RuntimeError."""
    sections, dd, opt, magic = parse_pe(data)

    iat_rva = import_iat_rva(data, sections, dd, magic, *WANT_IMPORT)

    candidates = []
    for tail in find_all(data, SERVER_TAIL):
        branch = tail - MOV_AL_RSP_LEN
        if branch < 0 or data[branch:branch + 3] != MOV_AL_RSP:
            continue
        # scan backwards for a jump that targets the Server branch
        for o in range(branch - 1, max(0, branch - 48), -1):
            b = data[o]
            if 0x70 <= b <= 0x7F:                       # jcc rel8
                if o + 2 + struct.unpack_from("<b", data, o + 1)[0] == branch:
                    candidates.append({"gate_off": o, "width": 2, "opcode": b,
                                       "branch_off": branch, "tail_off": tail})
                    break
            elif b == 0x0F and 0x80 <= data[o + 1] <= 0x8F:   # jcc rel32
                if o + 6 + struct.unpack_from("<i", data, o + 2)[0] == branch:
                    candidates.append({"gate_off": o, "width": 6, "opcode": data[o + 1],
                                       "branch_off": branch, "tail_off": tail})
                    break
    if not candidates:
        raise RuntimeError(
            "SKU gate not found - the file may be already patched, a different "
            "architecture, or not vssadmin.exe"
        )

    # prefer a short jcc that is confirmed to sit in a function calling GetVersionExW
    def verified(c):
        if iat_rva is None:
            return True
        return calls_iat(data, sections, c["gate_off"] - 0x200, c["gate_off"], iat_rva)

    pool = [c for c in candidates if verified(c)] or candidates
    pool.sort(key=lambda c: c["gate_off"])
    c = pool[0]
    c["iat_ok"] = iat_rva is not None and verified(c)
    c["already"] = (c["width"] == 2 and data[c["gate_off"]] == 0xEB) or \
                   (c["width"] == 6 and data[c["gate_off"]] == 0xE9)
    return c


def is_unconditional(c):
    return c["already"]


def patch_bytes(data: bytes, c: dict) -> bytes:
    out = bytearray(data)
    if c["width"] == 2:
        out[c["gate_off"]] = 0xEB            # jmp short
    else:
        out[c["gate_off"]] = 0xE9            # jmp near
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
            for root, _d, names in os.walk(p):
                for n in names:
                    if n.lower() == "vssadmin.exe":
                        files.append(os.path.join(root, n))
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"  ! skipping (not found): {p}")
    return sorted(files)


def process(path, out_path, in_place, dry_run, show_info):
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        return False, f"cannot read: {exc}"

    try:
        c = find_gate(data)
    except (ValueError, RuntimeError, struct.error) as exc:
        return False, str(exc)

    label = os.path.relpath(path, REPO_ROOT) if path.startswith(REPO_ROOT) else path
    info = ("gate @file:0x%X  %s  branch @0x%X  GetVersionExW in function: %s"
            % (c["gate_off"],
               ("jcc short 0x%02X" % c["opcode"]) if c["width"] == 2 else ("jcc near 0x%02X" % c["opcode"]),
               c["branch_off"], c["iat_ok"]))
    if show_info:
        print(f"  {label}")
        print(f"      {info}")

    if is_unconditional(c):
        return True, f"already patched ({info})"

    if dry_run:
        return True, f"would patch 0x{c['gate_off']:X} ({info})"

    patched = patch_bytes(data, c)

    if in_place:
        dest = path
    elif out_path:
        dest = out_path
    else:
        dest = os.path.join(os.path.dirname(path), "vssadmin.patched.exe")

    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(patched)

    check = open(dest, "rb").read()
    if check[c["gate_off"]] not in (0xEB, 0xE9):
        return False, f"verification failed writing {dest}"

    return True, ("patched 0x%X  ->  %s  sha256 %s..."
                  % (c["gate_off"],
                     os.path.relpath(dest, REPO_ROOT) if dest.startswith(REPO_ROOT) else dest,
                     sha256(patched)[:16]))


def build_parser():
    p = argparse.ArgumentParser(
        prog="patch_vssadmin.py",
        description="Patch vssadmin.exe so the Server-only commands "
                    "(Create Shadow, Revert Shadow, Add/Delete ShadowStorage, "
                    "Query Reverts) are available on client Windows.",
        epilog="See README.md for the full story.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="*",
                   help="vssadmin.exe files and/or directories to scan "
                        "(default: ./vssadmin_exe)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="output path for a single input file")
    p.add_argument("-i", "--in-place", action="store_true",
                   help="overwrite the input file instead of writing vssadmin.patched.exe")
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="report the patch site without writing anything")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only print the result lines")
    p.add_argument("-V", "--version", action="version",
                   version=f"Shadow Copy Unlocker patch_vssadmin.py {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    paths = args.paths or [DEFAULT_ROOT]
    files = collect_inputs(paths)

    if not files:
        print("No vssadmin.exe files found.")
        return 2
    if args.output and len(files) != 1:
        print("-o/--output can only be used with a single input file.")
        return 2

    if not args.quiet:
        print("Shadow Copy Unlocker - vssadmin.exe patcher")
        print(f"  targets : {len(files)} file(s)")
        print(f"  action  : {'dry-run' if args.dry_run else ('in-place' if args.in_place else 'write vssadmin.patched.exe')}")
        print()

    ok = fail = 0
    for path in files:
        good, msg = process(path, args.output, args.in_place, args.dry_run,
                            show_info=not args.quiet)
        if good:
            ok += 1
            print(f"  [ok]   {msg}")
        else:
            fail += 1
            rel = os.path.relpath(path, REPO_ROOT) if path.startswith(REPO_ROOT) else path
            print(f"  [fail] {rel}: {msg}")

    if not args.quiet:
        print()
        print(f"Done: {ok} ok, {fail} failed.")
        if ok and not args.dry_run:
            print("Next: run the patched vssadmin.exe (or replace System32\\vssadmin.exe),")
            print("      keeping vssadmin.exe.mui alongside so messages resolve.")

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
