//! Low-level Windows API abstraction layer for `no_std` environments.
//!
//! Provides hash-based dynamic resolution of NT, Kernel32, KernelBase, and Advapi32
//! function pointers at runtime, avoiding static imports that would appear in the IAT.
//! All resolved functions are stored as typed pointers in module structs and called
//! through thin wrapper methods that optionally apply call-stack spoofing (`spoof-uwd`)
//! or indirect syscall dispatch (`spoof-syscall`) via feature flags.

#![no_std]
#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_imports,
    unexpected_cfgs,
    integer_to_ptr_transmutes
)]

/// Core API structs, wrapper methods, and runtime resolution for ntdll, kernel32,
/// kernelbase, and advapi32.
pub mod api;

/// Debug console logging infrastructure, feature-gated behind `debug-console`.
pub mod log;

/// Utility functions: DJB2 hashing, memory operations, PE parsing, gadget scanning,
/// module/export resolution, and memory protection helpers.
pub mod util;

/// Raw Windows type definitions, constants, and function pointer type aliases.
pub mod windows;

// ---------------------------------------------------------------------------
// UWD call-stack spoofing re-exports (feature-gated)
// ---------------------------------------------------------------------------

/// Re-export `uwd` crate so that `crate::spoof::uwd::*` paths resolve in
/// `api/src/api.rs` when spoof features are enabled.
#[cfg(feature = "spoof-uwd")]
pub mod spoof {
    pub use uwd;
}

/// Re-export the `spoof_syscall!` macro at crate root so `crate::spoof_syscall!(...)` works.
#[cfg(feature = "spoof-syscall")]
pub use uwd::spoof_syscall;
/// Re-export the `spoof_uwd!` macro at crate root so `crate::spoof_uwd!(...)` works.
#[cfg(feature = "spoof-uwd")]
pub use uwd::spoof_uwd;
