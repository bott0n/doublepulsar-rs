//! Build script for the UDRL (User-Defined Reflective Loader).
//!
//! Assembles architecture-specific NASM sources (`start.asm`, `misc.asm`) into
//! object files and links them into the final binary via the `cc` crate.
//!
//! Supported targets:
//!   - `x86_64-pc-windows-gnu` (win64 / PE32+)
//!   - `i686-pc-windows-gnu`   (win32 / PE32)
//!
//! Call stack spoofing assembly lives in the `uwd` crate and is **not** compiled
//! here - only the loader entry point and helper stubs are assembled.

use std::{env, process::Command};

/// Assemble a single NASM source file into a COFF object.
///
/// # Arguments
///
/// * `format` - NASM output format (`"win64"` or `"win32"`).
/// * `src`    - Path to the `.asm` source file.
/// * `obj`    - Path for the output `.o` object file.
fn assemble(format: &str, src: &str, obj: &str) {
    let status = Command::new("nasm")
        .args(&["-f", format, src, "-o", obj])
        .status()
        .unwrap_or_else(|e| panic!("Failed to run nasm on {src}: {e}"));

    if !status.success() {
        panic!("nasm failed to assemble {src}");
    }
}

fn main() {
    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();

    // Output object paths (placed in Cargo's OUT_DIR so they don't pollute the tree).
    let start_obj = format!("{out_dir}/start.o");
    let misc_obj = format!("{out_dir}/misc.o");

    if target.contains("x86_64") {
        // Assemble x64 entry point and helper stubs (PE32+ / COFF).
        assemble("win64", "asm/x64/start.asm", &start_obj);
        assemble("win64", "asm/x64/misc.asm", &misc_obj);
    } else if target.contains("i686") {
        // Assemble x86 entry point and helper stubs (PE32 / COFF).
        assemble("win32", "asm/x86/start.asm", &start_obj);
        assemble("win32", "asm/x86/misc.asm", &misc_obj);
    } else {
        panic!("Unsupported target: {target}");
    }

    // Link assembled objects into the final static library.
    cc::Build::new()
        .object(&start_obj)
        .object(&misc_obj)
        .compile("asm");

    // Rebuild when assembly sources or the linker script change.
    println!("cargo:rerun-if-changed=asm/x64/start.asm");
    println!("cargo:rerun-if-changed=asm/x64/misc.asm");
    println!("cargo:rerun-if-changed=asm/x86/start.asm");
    println!("cargo:rerun-if-changed=asm/x86/misc.asm");
    println!("cargo:rerun-if-changed=scripts/linker.ld");
}
