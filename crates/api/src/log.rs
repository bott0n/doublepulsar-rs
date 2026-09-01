//! Debug console logging infrastructure for runtime diagnostics.
//!
//! All logging is feature-gated behind `debug-console` - when disabled, every macro
//! expands to nothing and zero code is emitted. When enabled, an attached console is
//! created via `AllocConsole` and messages are written to `STD_OUTPUT_HANDLE` using
//! `WriteFile`.
//!
//! Three severity levels are provided: [`Level::Trace`], [`Level::Debug`], and
//! [`Level::Info`], each with a corresponding macro ([`log_trace!`], [`log_debug!`],
//! [`log_info!`]). Each macro supports two forms:
//!
//! - `log_info!(b"message")` - plain text.
//! - `log_info!(b"message", value)` - text followed by a `0x`-prefixed hex value.

#[cfg(feature = "debug-console")]
use {
    crate::{
        hash_str,
        util::{get_export_by_hash, get_loaded_module_by_hash},
        windows::*,
    },
    core::{mem::transmute, ptr},
};

/// Log a message at [`Level::Info`].
///
/// Two forms:
/// - `log_info!(b"message")` - plain text.
/// - `log_info!(b"message", value)` - text with trailing hex value.
///
/// Compiles to nothing when the `debug-console` feature is disabled.
#[macro_export]
macro_rules! log_info {
    ($msg:literal) => {{
        #[cfg(feature = "debug-console")]
        unsafe {
            $crate::log::log_message($crate::log::Level::Info, $msg)
        }
    }};
    ($msg:literal, $value:expr) => {{
        #[cfg(feature = "debug-console")]
        unsafe {
            $crate::log::log_message_hex($crate::log::Level::Info, $msg, $value as usize)
        }
    }};
}

/// Log a message at [`Level::Debug`].
///
/// Same forms as [`log_info!`]. Compiles to nothing without `debug-console`.
#[macro_export]
macro_rules! log_debug {
    ($msg:literal) => {{
        #[cfg(feature = "debug-console")]
        unsafe {
            $crate::log::log_message($crate::log::Level::Debug, $msg)
        }
    }};
    ($msg:literal, $value:expr) => {{
        #[cfg(feature = "debug-console")]
        unsafe {
            $crate::log::log_message_hex($crate::log::Level::Debug, $msg, $value as usize)
        }
    }};
}

/// Log a message at [`Level::Trace`].
///
/// Same forms as [`log_info!`]. Compiles to nothing without `debug-console`.
#[macro_export]
macro_rules! log_trace {
    ($msg:literal) => {{
        #[cfg(feature = "debug-console")]
        unsafe {
            $crate::log::log_message($crate::log::Level::Trace, $msg)
        }
    }};
    ($msg:literal, $value:expr) => {{
        #[cfg(feature = "debug-console")]
        unsafe {
            $crate::log::log_message_hex($crate::log::Level::Trace, $msg, $value as usize)
        }
    }};
}

/// Re-exports of the logging macros under short aliases.
#[allow(unused_imports)]
pub use {log_debug as debug, log_info as info, log_trace as trace};

/// Log severity level used to prefix output lines.
#[allow(dead_code)]
pub enum Level {
    /// Finest-grained diagnostics (prefixed `[TRACE]`).
    Trace,
    /// Intermediate diagnostics (prefixed `[DEBUG]`).
    Debug,
    /// High-level operational messages (prefixed `[INFO ]`).
    Info,
}

/// Write a plain-text log line to the debug console.
///
/// # Arguments
///
/// * `level` - Severity level that determines the prefix tag.
/// * `msg` - Raw byte string to print (no null terminator required).
///
/// # Safety
///
/// Resolves kernel32 exports at runtime via PEB walking. The caller must ensure
/// the process has a valid PEB and that kernel32 is loaded.
#[link_section = ".text$E"]
#[inline(never)]
#[cfg(feature = "debug-console")]
pub unsafe fn log_message(level: Level, msg: &[u8]) {
    if let Some((handle, write_file)) = ensure_console() {
        let mut writer = ConsoleWriter {
            buf: [0u8; 512],
            len: 0,
            handle,
            write_file,
        };

        writer.push_bytes(match level {
            Level::Trace => b"[TRACE] ",
            Level::Debug => b"[DEBUG] ",
            Level::Info => b"[INFO ] ",
        });

        writer.push_bytes(msg);
        writer.push_bytes(b"\r\n");
        writer.flush();
    }
}

/// Write a log line with a trailing `0x`-prefixed hex value to the debug console.
///
/// # Arguments
///
/// * `level` - Severity level that determines the prefix tag.
/// * `msg` - Raw byte string label (no null terminator required).
/// * `value` - Value to format as 16-digit lowercase hex.
///
/// # Safety
///
/// Same requirements as [`log_message`].
#[link_section = ".text$E"]
#[inline(never)]
#[cfg(feature = "debug-console")]
pub unsafe fn log_message_hex(level: Level, msg: &[u8], value: usize) {
    if let Some((handle, write_file)) = ensure_console() {
        let mut writer = ConsoleWriter {
            buf: [0u8; 512],
            len: 0,
            handle,
            write_file,
        };

        writer.push_bytes(match level {
            Level::Trace => b"[TRACE] ",
            Level::Debug => b"[DEBUG] ",
            Level::Info => b"[INFO ] ",
        });

        writer.push_bytes(msg);
        writer.push_bytes(b": ");
        writer.push_hex(value);
        writer.push_bytes(b"\r\n");
        writer.flush();
    }
}

/// Resolve console handles and `WriteFile` from kernel32 via PEB hash lookup.
///
/// Calls `AllocConsole` to ensure a console is attached, then returns the
/// stdout handle and `WriteFile` function pointer.
///
/// # Returns
///
/// `Some((handle, WriteFile))` on success, `None` if kernel32 is not loaded or
/// the stdout handle is null.
#[cfg(feature = "debug-console")]
#[inline(always)]
#[link_section = ".text$E"]
unsafe fn ensure_console() -> Option<(HANDLE, FnWriteFile)> {
    let kernel32 = get_loaded_module_by_hash(hash_str!("kernel32.dll"));
    if kernel32 == 0 {
        return None;
    }

    let alloc_console: FnAllocConsole = transmute(get_export_by_hash(
        kernel32,
        hash_str!("AllocConsole") as usize,
    ));
    let get_std_handle: FnGetStdHandle = transmute(get_export_by_hash(
        kernel32,
        hash_str!("GetStdHandle") as usize,
    ));
    let write_file: FnWriteFile = transmute(get_export_by_hash(
        kernel32,
        hash_str!("WriteFile") as usize,
    ));

    alloc_console();

    let handle = get_std_handle(STD_OUTPUT_HANDLE);
    if handle.is_null() {
        return None;
    }

    Some((handle, write_file))
}

/// Fixed-size buffer writer for console output (512 bytes).
///
/// Accumulates bytes via [`push_bytes`](ConsoleWriter::push_bytes) and
/// [`push_hex`](ConsoleWriter::push_hex), then flushes to the console
/// handle via `WriteFile`.
#[cfg(feature = "debug-console")]
struct ConsoleWriter {
    buf: [u8; 512],
    len: usize,
    handle: HANDLE,
    write_file: FnWriteFile,
}

#[cfg(feature = "debug-console")]
impl ConsoleWriter {
    /// Flush the accumulated buffer to the console via `WriteFile` and reset length.
    #[inline(always)]
    #[link_section = ".text$E"]
    unsafe fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        let mut written: DWORD = 0;
        (self.write_file)(
            self.handle,
            self.buf.as_ptr() as *const _,
            self.len as DWORD,
            &mut written,
            ptr::null_mut(),
        );
        self.len = 0;
    }

    /// Append raw bytes to the buffer, stopping at capacity.
    #[inline(always)]
    #[link_section = ".text$E"]
    unsafe fn push_bytes(&mut self, bytes: &[u8]) {
        let mut idx = 0usize;
        while self.len < self.buf.len() && idx < bytes.len() {
            self.buf[self.len] = bytes[idx];
            self.len += 1;
            idx += 1;
        }
    }

    /// Format `value` as a 16-digit `0x`-prefixed lowercase hex string and append.
    #[inline(always)]
    #[link_section = ".text$E"]
    unsafe fn push_hex(&mut self, value: usize) {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        self.push_bytes(b"0x");
        for i in (0..16).rev() {
            let nibble = ((value >> (i * 4)) & 0xF) as usize;
            if self.len < self.buf.len() {
                self.buf[self.len] = HEX_CHARS[nibble];
                self.len += 1;
            }
        }
    }
}
