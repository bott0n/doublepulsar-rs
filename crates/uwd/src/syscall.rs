//! SSN (System Service Number) resolution for direct syscalls.
//!
//! Resolves the SSN from an ntdll stub so the ASM spoof stub can execute
//! the `syscall` instruction directly instead of calling through ntdll.
//!
//! # Resolution strategies
//!
//! **Hell's Gate** - reads SSN from an unhooked stub:
//! ```text
//! 4C 8B D1       mov r10, rcx
//! B8 XX XX 00 00 mov eax, <SSN>    ← bytes 4-5 are the SSN
//! ```
//!
//! **Halo's Gate** - stub is hooked (starts with 0xE9 JMP). Scans neighbor
//! stubs ±32 bytes apart, adjusts SSN by the neighbor distance.
//!
//! **Tartarus Gate** - partial hook at byte +3 (0xE9). Same neighbor scan.
//!
//! # Difference from dinvk
//!
//! dinvk's `ssn()` takes a function name string and walks the export table
//! with jenkins3 hashing. Our version takes the already-resolved function
//! pointer directly (from `NtdllModule.*_ptr`) and just reads stub bytes.

use core::{ffi::c_void, ptr::read};

/// Maximum neighbor distance to scan (Hell's/Halo's/Tartarus Gate).
const RANGE: usize = 255;

/// Byte offset between adjacent ntdll syscall stubs (downward).
const DOWN: usize = 32;

/// Byte offset between adjacent ntdll syscall stubs (upward).
const UP: isize = -32;

/// Resolves the SSN for an Nt function by reading its ntdll stub.
///
/// Uses Hell's Gate (unhooked) -> Halo's Gate (hooked) -> Tartarus Gate (partial hook).
///
/// # Arguments
///
/// * `func_addr` - Pointer to the start of the ntdll stub (already resolved).
///
/// # Returns
///
/// The SSN as a `u16`, or `None` if resolution fails.
///
/// # Safety
///
/// `func_addr` must point to a valid ntdll syscall stub in readable memory.
#[link_section = ".text$E"]
pub unsafe fn ssn(func_addr: *const u8) -> Option<u16> {
    // Hell's Gate: unhooked stub
    // 4C 8B D1    mov r10, rcx
    // B8 XX XX 00 00  mov eax, <SSN>
    if read(func_addr) == 0x4C
        && read(func_addr.add(1)) == 0x8B
        && read(func_addr.add(2)) == 0xD1
        && read(func_addr.add(3)) == 0xB8
        && read(func_addr.add(6)) == 0x00
        && read(func_addr.add(7)) == 0x00
    {
        let high = read(func_addr.add(5)) as u16;
        let low = read(func_addr.add(4)) as u16;
        return Some((high << 8) | low);
    }

    // Halo's Gate: stub starts with JMP (0xE9) - hooked by software
    if read(func_addr) == 0xE9 {
        for idx in 1..RANGE {
            // Check neighbor stub downward (+idx * 32 bytes)
            if read(func_addr.add(idx * DOWN)) == 0x4C
                && read(func_addr.add(1 + idx * DOWN)) == 0x8B
                && read(func_addr.add(2 + idx * DOWN)) == 0xD1
                && read(func_addr.add(3 + idx * DOWN)) == 0xB8
                && read(func_addr.add(6 + idx * DOWN)) == 0x00
                && read(func_addr.add(7 + idx * DOWN)) == 0x00
            {
                let high = read(func_addr.add(5 + idx * DOWN)) as u16;
                let low = read(func_addr.add(4 + idx * DOWN)) as u16;
                return Some((high << 8) | (low - idx as u16));
            }

            // Check neighbor stub upward (-idx * 32 bytes)
            if read(func_addr.offset(idx as isize * UP)) == 0x4C
                && read(func_addr.offset(1 + idx as isize * UP)) == 0x8B
                && read(func_addr.offset(2 + idx as isize * UP)) == 0xD1
                && read(func_addr.offset(3 + idx as isize * UP)) == 0xB8
                && read(func_addr.offset(6 + idx as isize * UP)) == 0x00
                && read(func_addr.offset(7 + idx as isize * UP)) == 0x00
            {
                let high = read(func_addr.offset(5 + idx as isize * UP)) as u16;
                let low = read(func_addr.offset(4 + idx as isize * UP)) as u16;
                return Some((high << 8) | (low + idx as u16));
            }
        }
    }

    // Tartarus Gate: partial hook at byte +3 (JMP at offset 3)
    if read(func_addr.add(3)) == 0xE9 {
        for idx in 1..RANGE {
            // Check neighbor stub downward
            if read(func_addr.add(idx * DOWN)) == 0x4C
                && read(func_addr.add(1 + idx * DOWN)) == 0x8B
                && read(func_addr.add(2 + idx * DOWN)) == 0xD1
                && read(func_addr.add(3 + idx * DOWN)) == 0xB8
                && read(func_addr.add(6 + idx * DOWN)) == 0x00
                && read(func_addr.add(7 + idx * DOWN)) == 0x00
            {
                let high = read(func_addr.add(5 + idx * DOWN)) as u16;
                let low = read(func_addr.add(4 + idx * DOWN)) as u16;
                return Some((high << 8) | (low - idx as u16));
            }

            // Check neighbor stub upward
            if read(func_addr.offset(idx as isize * UP)) == 0x4C
                && read(func_addr.offset(1 + idx as isize * UP)) == 0x8B
                && read(func_addr.offset(2 + idx as isize * UP)) == 0xD1
                && read(func_addr.offset(3 + idx as isize * UP)) == 0xB8
                && read(func_addr.offset(6 + idx as isize * UP)) == 0x00
                && read(func_addr.offset(7 + idx as isize * UP)) == 0x00
            {
                let high = read(func_addr.offset(5 + idx as isize * UP)) as u16;
                let low = read(func_addr.offset(4 + idx as isize * UP)) as u16;
                return Some((high << 8) | (low + idx as u16));
            }
        }
    }

    None
}

/// Finds the `syscall; ret` instruction address inside an ntdll stub.
///
/// Scans for bytes `0F 05 C3` within 255 bytes of the function address.
///
/// # Arguments
///
/// * `func_addr` - Pointer to the start of the ntdll stub.
///
/// # Returns
///
/// Address of the `syscall` instruction (0F 05), or `None` if not found.
///
/// # Safety
///
/// `func_addr` must point into readable ntdll memory with at least 255
/// bytes accessible after it.
#[link_section = ".text$E"]
pub unsafe fn get_syscall_address(func_addr: *const u8) -> Option<*const c_void> {
    for i in 1..255usize {
        if read(func_addr.add(i)) == 0x0F
            && read(func_addr.add(i + 1)) == 0x05
            && read(func_addr.add(i + 2)) == 0xC3
        {
            return Some(func_addr.add(i) as *const c_void);
        }
    }
    None
}
