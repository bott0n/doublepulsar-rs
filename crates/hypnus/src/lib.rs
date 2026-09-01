//! Sleep obfuscation library for authorized security research and adversary simulation.
//!
//! Hypnus encrypts the process image in memory during sleep and changes page permissions
//! from RX to RW, making the code invisible to memory scanners. It also spoofs the
//! thread's call stack and register context to appear as a normal idle Windows thread.
//!
//! Three dispatch mechanisms are provided, each executing the same 10-step NtContinue
//! context chain on a worker thread:
//!
//! - **Ekko** (`sleep-ekko`): Thread pool timer callbacks via `TpAllocTimer`/`TpSetTimer`.
//! - **Foliage** (`sleep-foliage`): APC queue on a dedicated suspended thread via `NtQueueApcThread`.
//! - **Zilean** (`sleep-zilean`): Thread pool wait callbacks via `TpAllocWait`/`TpSetWait`.
//! - **XOR** (`sleep-xor`): Simple XOR-based memory masking (no context chain).
//!
//! Enable exactly one technique via Cargo feature flags.

#![no_std]
#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_imports
)]

/// Shared infrastructure: encryption, JMP gadget scanning, stack/context spoofing,
/// CFG bypass, and shellcode stub allocation used by all three chain-based techniques.
pub mod common;

/// Timer-based sleep obfuscation using thread pool timers (`TpAllocTimer`/`TpSetTimer`).
#[cfg(feature = "sleep-ekko")]
pub mod ekko;

/// APC-based sleep obfuscation using `NtQueueApcThread` on a suspended thread.
#[cfg(feature = "sleep-foliage")]
pub mod foliage;

/// Wait-based sleep obfuscation using thread pool waits (`TpAllocWait`/`TpSetWait`).
#[cfg(feature = "sleep-zilean")]
pub mod zilean;

/// Simple XOR-based memory section masking without the NtContinue context chain.
#[cfg(feature = "sleep-xor")]
pub mod xor;
