//! UWD (UnWinDer-based) call stack spoofing.
//!
//! Constructs synthetic stack frames that pass `RtlVirtualUnwind` validation,
//! making spoofed API calls appear to originate from legitimate Windows call chains.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐
//! │  lib.rs     │    │  stack.rs    │    │  types.rs        │
//! │  macros     │───►│  .pdata scan │───►│  Config struct   │
//! │  spoof_uwd! │    │  frame build │    │  UNWIND_INFO     │
//! │  spoof_sc!  │    │  gadget find │    │  FramePool       │
//! └──────┬──────┘    └──────────────┘    └──────────────────┘
//!        │
//!        ▼
//!   ASM stub (SpoofSynthetic)
//!        │
//!        ▼
//!   Target function executes with spoofed call stack
//! ```
//!
//! # Modules
//!
//! - [`stack`] - .pdata parsing, frame size calculation, gadget/prolog scanning, config building
//! - [`types`] - `Config`, `UNWIND_INFO`/`UNWIND_CODE`, `FramePool`, `FrameCandidate`
//! - `ntdef` - Shared PE types, Windows definitions, and `memmem` (external crate)
//! - [`syscall`] - SSN resolution via Hell's/Halo's/Tartarus Gate (feature-gated)
//!
//! # Feature flags
//!
//! - `spoof-uwd` - Enables the [`spoof_uwd!`] macro and `SpoofSynthetic` extern.
//! - `spoof-syscall` - Enables the [`syscall`] module and [`spoof_syscall!`] macro
//!   for direct syscall dispatch with stack spoofing.

#![no_std]
#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_imports
)]

/// Synthetic stack frame construction: .pdata parsing, gadget scanning, config building.
pub mod stack;

/// Data structures for the ASM spoof stub: `Config`, `UNWIND_INFO`, `FramePool`.
pub mod types;

/// SSN resolution for direct syscalls (Hell's Gate, Halo's Gate, Tartarus Gate).
#[cfg(feature = "spoof-syscall")]
pub mod syscall;

pub use {
    stack::{build_config, build_syscall_config, rotate_config},
    types::Config,
};

// ---------------------------------------------------------------------------
// ASM entry point - linked from the NASM object built by build.rs
// ---------------------------------------------------------------------------
#[cfg(feature = "spoof-uwd")]
extern "C" {
    /// ASM stub that builds synthetic stack frames and dispatches the spoofed call.
    pub fn SpoofSynthetic(config: *mut Config) -> *const core::ffi::c_void;
}

// ---------------------------------------------------------------------------
// Self-referential re-export module for $crate resolution in macros.
//
// When `api` re-exports `spoof_uwd!`, the macro's `$crate` still resolves to
// `uwd`. The macro uses `$crate::spoof::uwd::types::Config` etc., so we need
// this path to exist within `uwd` itself.
// ---------------------------------------------------------------------------
#[doc(hidden)]
pub mod spoof {
    pub mod uwd {
        #[cfg(feature = "spoof-syscall")]
        pub use crate::syscall;
        pub use crate::{
            stack::{build_config, build_syscall_config, rotate_config},
            types,
        };
    }
}

/// Executes a function call with UWD call stack spoofing.
///
/// Copies the shared `Config`, rotates frame candidates via `rdtsc` entropy,
/// loads the target function and arguments, then calls the ASM stub
/// `SpoofSynthetic` which builds synthetic stack frames and executes the call.
///
/// # Arguments
///
/// * `$config` - `&Config` - pre-built configuration from [`build_config`]
/// * `$func` - Target function pointer to call
/// * `$arg...` - Up to 11 arguments passed to the target function
///
/// # Returns
///
/// The return value from `SpoofSynthetic` (the target function's return value
/// as `*const c_void`).
///
/// # Example
///
/// ```ignore
/// let result = spoof_uwd!(&config, some_api_fn, arg1, arg2, arg3);
/// ```
#[cfg(feature = "spoof-uwd")]
#[macro_export]
macro_rules! spoof_uwd {
    ($config:expr, $func:expr $(, $arg:expr)* $(,)?) => {{
        use core::ffi::c_void;
        let mut config: $crate::spoof::uwd::types::Config = *$config;

        unsafe { $crate::spoof::uwd::rotate_config(&mut config); }

        config.spoof_function = $func as *const c_void;
        config.is_syscall = 0;

        config.arg01 = core::ptr::null();
        config.arg02 = core::ptr::null();
        config.arg03 = core::ptr::null();
        config.arg04 = core::ptr::null();
        config.arg05 = core::ptr::null();
        config.arg06 = core::ptr::null();
        config.arg07 = core::ptr::null();
        config.arg08 = core::ptr::null();
        config.arg09 = core::ptr::null();
        config.arg10 = core::ptr::null();
        config.arg11 = core::ptr::null();

        let args: &[*const c_void] = &[$($arg as *const c_void),*];
        config.number_args = args.len() as u64;

        if args.len() > 0  { config.arg01 = args[0]; }
        if args.len() > 1  { config.arg02 = args[1]; }
        if args.len() > 2  { config.arg03 = args[2]; }
        if args.len() > 3  { config.arg04 = args[3]; }
        if args.len() > 4  { config.arg05 = args[4]; }
        if args.len() > 5  { config.arg06 = args[5]; }
        if args.len() > 6  { config.arg07 = args[6]; }
        if args.len() > 7  { config.arg08 = args[7]; }
        if args.len() > 8  { config.arg09 = args[8]; }
        if args.len() > 9  { config.arg10 = args[9]; }
        if args.len() > 10 { config.arg11 = args[10]; }

        $crate::SpoofSynthetic(&mut config)
    }};
}

/// Executes a direct syscall with UWD call stack spoofing.
///
/// Like [`spoof_uwd!`] but resolves the SSN (System Service Number) and
/// `syscall` instruction address from the ntdll stub, then dispatches
/// directly via the `syscall` instruction instead of calling through ntdll.
///
/// # Resolution flow
///
/// ```text
/// func_addr (ntdll stub) ──► ssn()              ──► SSN (u16)
///                         ──► get_syscall_address ──► syscall;ret addr
/// ```
///
/// # Arguments
///
/// * `$config` - `&Config` - pre-built configuration from [`build_syscall_config`]
/// * `$func` - Pointer to the ntdll stub (e.g., `NtAllocateVirtualMemory`)
/// * `$arg...` - Up to 11 arguments passed to the syscall
///
/// # Returns
///
/// The syscall return value (NTSTATUS as `*const c_void`).
#[cfg(feature = "spoof-syscall")]
#[macro_export]
macro_rules! spoof_syscall {
    ($config:expr, $func:expr $(, $arg:expr)* $(,)?) => {{
        use core::ffi::c_void;
        let mut config: $crate::spoof::uwd::types::Config = *$config;

        unsafe { $crate::spoof::uwd::rotate_config(&mut config); }

        let func_addr = $func as *const u8;
        let ssn = unsafe { $crate::spoof::uwd::syscall::ssn(func_addr) }
            .unwrap_or(0);
        let syscall_addr = unsafe { $crate::spoof::uwd::syscall::get_syscall_address(func_addr) }
            .unwrap_or(func_addr as *const c_void);

        config.spoof_function = syscall_addr;
        config.is_syscall = 1;
        config.ssn = ssn as u32;

        config.arg01 = core::ptr::null();
        config.arg02 = core::ptr::null();
        config.arg03 = core::ptr::null();
        config.arg04 = core::ptr::null();
        config.arg05 = core::ptr::null();
        config.arg06 = core::ptr::null();
        config.arg07 = core::ptr::null();
        config.arg08 = core::ptr::null();
        config.arg09 = core::ptr::null();
        config.arg10 = core::ptr::null();
        config.arg11 = core::ptr::null();

        let args: &[*const c_void] = &[$($arg as *const c_void),*];
        config.number_args = args.len() as u64;

        if args.len() > 0  { config.arg01 = args[0]; }
        if args.len() > 1  { config.arg02 = args[1]; }
        if args.len() > 2  { config.arg03 = args[2]; }
        if args.len() > 3  { config.arg04 = args[3]; }
        if args.len() > 4  { config.arg05 = args[4]; }
        if args.len() > 5  { config.arg06 = args[5]; }
        if args.len() > 6  { config.arg07 = args[6]; }
        if args.len() > 7  { config.arg08 = args[7]; }
        if args.len() > 8  { config.arg09 = args[8]; }
        if args.len() > 9  { config.arg10 = args[9]; }
        if args.len() > 10 { config.arg11 = args[10]; }

        $crate::SpoofSynthetic(&mut config)
    }};
}
