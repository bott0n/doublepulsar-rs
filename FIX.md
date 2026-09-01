# UDRL Loader Fixes — 2026-08-26

Engineering log for the crashes observed when running the Rust UDRL
(`udrl/`, Titan.cna-compatible) and their fixes. Ordered by causal discovery.

Payload layout reference (produced by `udrl/bin/Titan.cna`):

```
[Loader shellcode (Titan.x64.bin)][4B BE rc4_len][16B RC4 key][RC4 beacon]
                                    ^ CONFIG, parsed at G_END()
```

`G_END()` in `udrl/src/lib.rs` is hardcoded to `GetIp() + 11`, so GetIp's
`call/pop/sub/ret` sequence must be the **last 11 bytes** of the loader image.

---

## Fix 1 — Loader crashed on execution: `.bss` statics missing from the shellcode

**File:** `udrl/scripts/linker.ld`

**Symptom:** payload crashed immediately under a plain shellcode loader.

**Root cause:** the linker script merged only `.text$*`, `.rdata*`, `.data*`,
`.idata*`, `.CRT*`, `.tls*`, `.ctors*`, `.edata*` into the single `.text`
output section that `objcopy --dump-section .text` emits. Zero-initialized
statics (`.bss` + `COMMON`) were left as linker orphans: the DLL carried a
`.bss` at VMA `0x14000` (0x110 bytes), and 9 rip-relative references inside
the shipped `Titan.x64.bin` pointed at it — addresses that are **not part of
the emitted file at all**. At runtime those references resolved past the end
of the injected blob (into the appended encrypted beacon or unmapped memory):
reads returned ciphertext garbage, lazy-init writes corrupted the beacon, and
the subsequent RC4 decrypt produced a garbage PE → wild `e_lfanew` deref →
access violation in `loader()`.

Evidence: linked DLL section table (`.bss` outside `.text`), disassembly scan
showing `lea 0x8bae(%rip)`-style references resolving to VMA `0x14000+`.

**Fix:** fold the orphans into the dumped section, keeping `.text$ZZ` (GetIp)
last so the G_END invariant holds:

```ld
*( .rodata* );
/* Zero-initialized statics MUST be folded in: objcopy only dumps this one
   output section, so any .bss/COMMON left as an orphan lands at an address
   that is not part of the emitted shellcode at all. */
*( .bss* );
*( COMMON );
KEEP( *(.text$ZZ) );
```

---

## Fix 2 — Build-time verifier so a broken link cannot ship silently

**Files:** `udrl/scripts/verify_shellcode.py`, `udrl/Makefile.toml`

`cargo make x64` and `cargo make x64-debug` now run a post-extract verifier
that fails the build on either regression class:

1. **G_END tail invariant** — file must end with GetIp's exact 11 bytes, so
   `G_END() == file size` and the CNA-appended CONFIG is parsed correctly.
2. **Out-of-blob references** — zero rip-relative targets may fall outside
   `[0, file_size)` (the Fix 1 failure mode).

Both checks pass on the current build (67291 → 47963-byte loaders across the
rounds, always ending `e8 00000000 58 4883e805 c3`).

---

## Fix 3 — EKKO sleep chain: gadget immediate ≠ frame size (crash after first checkin)

**Files:** `crates/uwd/src/stack.rs`, `crates/hypnus/src/common.rs`

**Symptom:** beacon checked in, then crashed at the first `Sleep ≥ 1s`
(i.e. the first EKKO timer-chain execution).

**Root cause:** `scan_add_rsp_ret` searched kernelbase for a hardcoded
`add rsp, 0x58; ret` (`48 83 C4 58 C3`) and returned the **unwind frame size
of whichever function first contained the pattern**. `spoof_stack_layout`
spaces the fake return-address slots by that frame size, but at runtime the
gadget skips exactly the immediate (`0x58`). The two numbers are equal only
by coincidence on whichever kernelbase build the author tested. On any other
build, the `ret` after `add rsp, 0x58` popped the wrong stack slot (another
fake-chain address such as `EnumDateFormatsExA+0x17`, the `0` terminator, or
garbage) and jumped there.

**Fix:** new `find_self_sized_add_rsp_gadget()` — for each `.pdata` function
it builds the epilogue pattern **from that function's own frame size**
(`48 83 C4 <imm8> C3`, plus the `48 81 C4 <imm32> C3` form for large frames),
so the immediate and the returned frame size are equal by construction on
any Windows build. `scan_add_rsp_ret` now uses it.

---

## Fix 4 — EKKO callback stub entered `NtContinue` with `TestAlert = TRUE`

**File:** `crates/hypnus/src/common.rs` (`alloc_callback`)

The chain-step stub did `mov rcx,rdx; mov rax,[rcx+0x78]; jmp rax` — leaving
`rdx` holding the `Context` pointer, which `NtContinue` reads as its second
argument `TestAlert = TRUE`. That forces APC delivery on the pool worker
mid-chain; Win10/11 pool threads routinely have pending APCs, so an APC could
dispatch onto the spoofed/fake stack. The stub now zeroes `rdx`
(`31 D2 xor edx,edx`) before jumping.

---

## Fix 5 — CFG: timer callback stubs never registered as valid call targets

**Files:** `crates/hypnus/src/common.rs`, `crates/hypnus/src/ekko.rs`

**Symptom:** payload stable in ordinary loaders, killed in CFG-enabled hosts
(shellcode sideloaded into signed binaries). Reproduced locally by enabling
CFG at runtime (`SetProcessMitigationPolicy`).

**Root cause:** ntdll's thread-pool dispatch indirect-calls the three timer
stubs (trampoline, callback, set-event), which live on freshly allocated RX
pages. `handle_cfg()` registered NT functions inside ntdll but nothing could
register raw pages — the existing `set_valid_call_targets` only handles
module-internal addresses (it needs a module base to compute the bitmap
offset). Under CFG, the first timer callback hit an invalid target →
access violation on the pool worker.

**Fix:** new `set_valid_call_target_any()` — registers module-internal
addresses via the existing module path and raw RX pages page-relative via
`SetProcessValidCallTargets`. `ekko()` now registers the jmp gadget and all
three stubs right after allocation.

---

## Fix 6 — CET shadow stacks: default sleep obfuscation switched to `sleep-xor`

**File:** `udrl/Cargo.toml`

**Symptom:** all EKKO builds still fastfailed in the MockingJay sideload host.
Windows Event ID 1000 showed `Exception code: 0xc0000409` in `ntdll.dll` at a
constant offset, on Win11 24H2 (10.0.26100), in CETCOMPAT binaries
(`wpr.exe`, `a.exe`).

**Root cause:** **CET user shadow stacks**. Shadow stacks validate every
`ret` against a parallel hardware stack. The EKKO/Foliage/Zilean chains
deliberately `ret` into gadget addresses that no `call` ever pushed — the
exact condition shadow stacks exist to detect. The failure is an uncatchable
`__fastfail` (0xC0000409). This is fundamental to ROP-based sleep chains: no
registration or fallback inside the chain can fix it. It also explains the
full environment matrix: mingw-built test loaders (no CET relocations) and
CFG-only hosts were clean; only CETCOMPAT hosts died.

**Fix:** default features changed from `sleep-ekko` to `sleep-xor`:

```toml
default = ["sleep-xor", "spoof-uwd"]
```

`sleep-xor` uses a plain `Sleep` plus XOR masking of the tracked sections and
the isolated heap — no `NtContinue` gadget dance, CET-immune — and was
verified stable through multiple sleep cycles in the sideload host.
`sleep-ekko` (with Fixes 3–5) remains available as an opt-in feature for
targets without shadow-stack enforcement.

---

## Known issues / notes

- **x86 `G_END()` latent bug (not fixed, x86 unused):** `G_END()` is
  `GetIp() + 11` for both architectures, but the x86 GetIp assembles to 10
  bytes (`call/pop eax/sub eax,5/ret`). An x86 build would parse the CONFIG
  one byte early. The one-byte pad fix was intentionally reverted — only x64
  is in scope.
- **Host loader contract:** the UDRL requires the whole blob contiguous in
  one buffer (CONFIG directly follows the loader at runtime), entry executed
  at offset 0, the buffer alive for the process lifetime (`ace()` parks a
  thread inside it), and a real stack (~30 KB+) on the executing thread.
  A diagnostic loader honoring this contract with a Vectored Exception
  Handler reporter is kept at `/home/kali/payload_test.c`
  (`payload_test.exe <payload.bin> [cfg]`).
- **Sacrificial stomp module** is `d3d10.dll` (`udrl/src/loader.rs`). If a
  sideload host ever names its payload DLL `d3d10.dll`, the loader would
  stomp the module hosting its own payload — avoid that name.
- Profile requirements from `Titan.cna`: `stage.sleep_mask` requires
  `stage.obfuscate "true"`; `smartinject "false"` and `sleep_mask "false"`
  per `bin/Titan.profile`.

## Verification summary

| Check | Method |
|---|---|
| Payload structure (size/key/beacon) | Python RC4 decrypt → `MZ` PE32+ `0x8664` |
| G_END tail + blob-reference invariants | `scripts/verify_shellcode.py` wired into `cargo make x64` |
| EKKO chain end-to-end | debug-console build: `ekko: enter → … → chain complete → ekko done` across two sleep cycles, zero exceptions |
| CFG hardening | `payload_test.exe <payload> cfg` (runtime `SetProcessMitigationPolicy`) runs clean |
| CET hosts | Event ID 1000 `0xC0000409` diagnosis; `sleep-xor` default stable in the same host |
