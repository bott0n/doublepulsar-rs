#!/usr/bin/env python3
"""Post-build verifier for the extracted x64 UDRL shellcode binary.

Usage:
    verify_shellcode.py <path/to/Titan.x64.bin>

Guards against the two failure modes that produce a silently-broken loader:

1. G_END invariant - the CONFIG struct is appended by the CNA directly after
   the loader image, and lib.rs computes it as GetIp() + 11. That only works
   if GetIp is the LAST code in the file and its call instruction sits at
   exactly (file_size - 11). A linker/script change that moves or pads the
   tail silently misparses rc4_len/key and crashes at load time.

2. Out-of-blob references - objcopy --dump-section emits only the merged
   .text output section. If the linker script fails to fold an input section
   (e.g. .bss/COMMON orphans), code still references it rip-relatively at an
   address that is not part of the emitted file at all. At runtime those
   references land past the end of the injected blob (unmapped memory or the
   appended encrypted beacon), corrupting it.

Exit code 0 = safe to ship, 1 = broken build.
"""

import re
import subprocess
import sys
import tempfile

# Expected tail of the file: GetIp's call rel32 (5) + pop rax (1)
# + sub rax,5 (4) + ret (1) = 11 bytes, matching G_END() in src/lib.rs.
GETIP_TAIL = bytes.fromhex("e800000000") + b"X" + bytes.fromhex("4883e805c3")
G_END_OFFSET = 11  # must match G_END() in src/lib.rs


def fail(msg):
    print(f"[verify] FAIL: {msg}")
    sys.exit(1)


def check_tail(blob):
    """GetIp must be the final 11 bytes so G_END() == file size."""
    if blob[-len(GETIP_TAIL):] != GETIP_TAIL:
        fail(
            f"file does not end with the x64 GetIp sequence "
            f"(expected ...{GETIP_TAIL.hex()}, got ...{blob[-len(GETIP_TAIL):].hex()}) - "
            "G_END() would point into the wrong place and the CNA-appended "
            "CONFIG would be misparsed"
        )
    getip_off = len(blob) - G_END_OFFSET
    print(f"[verify] OK: GetIp at +{getip_off:#x}, G_END() == file size ({len(blob)} bytes)")


def check_references(blob):
    """No rip-relative target may fall outside [0, file_size)."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
            tmp.write(blob)
            tmp.flush()
            out = subprocess.run(
                ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", tmp.name],
                capture_output=True, timeout=120,
            ).stdout.decode(errors="replace")
    except FileNotFoundError:
        fail("objdump not found in PATH - cannot scan references")
    if not out:
        fail("objdump produced no disassembly")

    oob = []
    for line in out.splitlines():
        byte_m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)", line)
        ins_m = re.match(
            r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*\t(?:lea|mov[a-z]*|cmp|add|sub)\s+(0x-?[0-9a-f]+)\(%rip\)",
            line,
        )
        if not (byte_m and ins_m):
            continue
        addr = int(ins_m.group(1), 16)
        insn_len = len(byte_m.group(2).split())
        rel = int(ins_m.group(2), 16)
        if rel >= 0x80000000:
            rel -= 0x100000000
        target = (addr + insn_len + rel) & 0xFFFFFFFFFFFFFFFF
        if not 0 <= target < len(blob):
            oob.append((hex(addr), hex(target), line.strip()[:80]))

    if oob:
        print(f"[verify] FAIL: {len(oob)} rip-relative references outside the blob:")
        for addr, target, text in oob[:15]:
            print(f"  @{addr} -> {target}  {text}")
        print(
            "[verify] these addresses are not part of the dumped .text section "
            "(linker orphan such as .bss/COMMON) - fix scripts/linker.ld"
        )
        sys.exit(1)
    print("[verify] OK: 0 out-of-blob rip-relative references")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    path = sys.argv[1]
    try:
        blob = open(path, "rb").read()
    except OSError as e:
        fail(f"cannot read {path}: {e}")
    if not blob:
        fail(f"{path} is empty")
    print(f"[verify] x64 shellcode: {path} ({len(blob)} bytes)")
    check_tail(blob)
    check_references(blob)
    print(f"[verify] PASS: {path} is safe to splice")


if __name__ == "__main__":
    main()
