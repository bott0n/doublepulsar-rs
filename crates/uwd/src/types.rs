//! UNWIND_INFO structures and Config for UWD synthetic stack spoofing.
//!
//! This module defines the data structures used by the UWD spoof system:
//!
//! 1. [`UNWIND_CODE`] / [`UNWIND_INFO`] - Mirror of the Windows x64 exception ABI
//!    structures used to parse `.pdata`/UNWIND_INFO and calculate stack frame sizes.
//!
//! 2. [`UNWIND_OP_CODES`] / [`Registers`] - Enums for interpreting unwind operations
//!    and identifying saved registers.
//!
//! 3. [`Config`] - The bridge between Rust and the ASM spoof stub. Populated by
//!    [`build_config()`](super::stack::build_config), consumed by `SpoofSynthetic()`.
//!
//! # Why UWD defines its own UNWIND_CODE/UNWIND_INFO
//!
//! The `api` crate's `windows.rs` defines `UNWIND_CODE` as a flat struct:
//! ```text
//! struct UNWIND_CODE { CodeOffset: u8, UnwindOpAndInfo: u8 }
//! ```
//!
//! UWD needs a **union** so the same 2-byte slot can be read as either:
//! - `Anonymous.OpAndInfo` - when parsing opcode/info bits
//! - `FrameOffset` - when reading a raw `u16` value (multi-slot opcodes)
//!
//! This matches how the Windows unwinder actually interprets these slots.
//!
//! # Memory layout of UNWIND_INFO in a PE
//!
//! ```text
//! ┌────────────────────────────┐ offset 0
//! │ VersionAndFlags      (u8)  │  bits 0-2: version, bits 3-7: flags
//! │ SizeOfProlog         (u8)  │  prologue size in bytes
//! │ CountOfCodes         (u8)  │  number of UNWIND_CODE slots
//! │ FrameRegisterAndOffset(u8) │  bits 0-3: frame reg, bits 4-7: offset
//! ├────────────────────────────┤ offset 4
//! │ UNWIND_CODE[0]       (u16) │  first unwind operation
//! │ UNWIND_CODE[1]       (u16) │  second (or extra data for [0])
//! │ ...                        │
//! │ UNWIND_CODE[n-1]     (u16) │  last unwind operation
//! ├────────────────────────────┤ offset 4 + n*2 (aligned to 4 bytes)
//! │ ExceptionHandler     (u32) │  if UNW_FLAG_EHANDLER set
//! │   - or -                   │
//! │ RUNTIME_FUNCTION     (12B) │  if UNW_FLAG_CHAININFO set (chained entry)
//! └────────────────────────────┘
//! ```
//!
//! # References
//!
//! - [Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)

use core::ffi::c_void;

/// Indicates the presence of an exception handler in the function.
pub const UNW_FLAG_EHANDLER: u8 = 0x1;

/// Indicates the presence of an unwind handler in the function.
pub const UNW_FLAG_UHANDLER: u8 = 0x2;

/// Indicates chained unwind information is present.
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

// ============================================================================
// UNWIND_CODE
// ============================================================================

/// Union representing a single unwind operation code.
///
/// Each UNWIND_CODE is 2 bytes (u16). It can be read as either:
/// - `FrameOffset`: raw u16 value (used by UWOP_ALLOC_LARGE as extra slot)
/// - `Anonymous`: structured CodeOffset + OpAndInfo fields
#[repr(C)]
pub union UNWIND_CODE {
    /// Raw 16-bit frame offset (used as extra data by some opcodes).
    pub FrameOffset: u16,

    /// Structured fields of the unwind code.
    pub Anonymous: UNWIND_CODE_0,
}

/// Structured fields of an UNWIND_CODE entry (2 bytes).
///
/// ```text
/// Byte 0: CodeOffset  - offset in prologue where this op applies
/// Byte 1: OpAndInfo   - UnwindOp (bits 0-3) | OpInfo (bits 4-7)
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNWIND_CODE_0 {
    /// Byte offset from the start of the prologue.
    pub CodeOffset: u8,
    /// UnwindOp (bits 0-3) and OpInfo (bits 4-7) packed together.
    pub OpAndInfo: u8,
}

impl UNWIND_CODE_0 {
    /// The unwind operation code (lower 4 bits of `OpAndInfo`).
    ///
    /// # Returns
    ///
    /// One of the [`UNWIND_OP_CODES`] values (0-10).
    #[inline(always)]
    pub fn UnwindOp(&self) -> u8 {
        self.OpAndInfo & 0x0F
    }

    /// Additional operation-specific information (upper 4 bits of `OpAndInfo`).
    ///
    /// # Returns
    ///
    /// Meaning depends on the opcode: register index for PUSH_NONVOL,
    /// allocation size encoding for ALLOC_SMALL, etc.
    #[inline(always)]
    pub fn OpInfo(&self) -> u8 {
        (self.OpAndInfo >> 4) & 0x0F
    }
}

// ============================================================================
// UNWIND_INFO
// ============================================================================

/// Unwind info header (4 bytes, followed by variable-length UNWIND_CODE array).
///
/// UWD defines its own UNWIND_INFO that returns the union-based UNWIND_CODE
/// type (needed to read FrameOffset as raw u16 for multi-slot opcodes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNWIND_INFO {
    /// Version (bits 0-2) and flags (bits 3-7).
    pub VersionAndFlags: u8,
    pub SizeOfProlog: u8,
    pub CountOfCodes: u8,
    /// Frame register (bits 0-3) and frame register offset (bits 4-7).
    pub FrameRegisterAndOffset: u8,
}

impl UNWIND_INFO {
    /// Extract the flags field (bits 3-7 of `VersionAndFlags`).
    ///
    /// # Returns
    ///
    /// Combination of `UNW_FLAG_EHANDLER`, `UNW_FLAG_UHANDLER`, `UNW_FLAG_CHAININFO`.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.VersionAndFlags >> 3
    }

    /// Extract the frame register index (bits 0-3 of `FrameRegisterAndOffset`).
    ///
    /// # Returns
    ///
    /// Register index (0 = no frame register, 5 = RBP, etc.).
    #[inline]
    pub fn frame_register(&self) -> u8 {
        self.FrameRegisterAndOffset & 0x0F
    }

    /// Extract the frame register offset (bits 4-7 of `FrameRegisterAndOffset`).
    ///
    /// # Returns
    ///
    /// Scaled offset: actual displacement = `frame_offset() * 16`.
    #[inline]
    pub fn frame_offset(&self) -> u8 {
        self.FrameRegisterAndOffset >> 4
    }

    /// Returns pointer to the UNWIND_CODE array (union-based).
    ///
    /// The array starts immediately after the 4-byte UNWIND_INFO header.
    ///
    /// # Safety
    ///
    /// `self` must point to a valid UNWIND_INFO in mapped PE memory.
    #[inline(always)]
    pub unsafe fn codes(&self) -> *const UNWIND_CODE {
        (self as *const Self).add(1) as *const UNWIND_CODE
    }

    /// Returns the chained `RUNTIME_FUNCTION` entry after the codes array.
    ///
    /// Only valid when `flags() & UNW_FLAG_CHAININFO != 0`. The chained entry
    /// sits after the UNWIND_CODE array (aligned to 4 bytes).
    ///
    /// # Safety
    ///
    /// `self` must point to a valid UNWIND_INFO with `UNW_FLAG_CHAININFO` set.
    #[inline(always)]
    pub unsafe fn chained_entry(&self) -> *const ntdef::windows::IMAGE_RUNTIME_FUNCTION_ENTRY {
        let count = self.CountOfCodes as usize;
        let aligned = if count % 2 == 1 { count + 1 } else { count };
        self.codes().add(aligned) as *const ntdef::windows::IMAGE_RUNTIME_FUNCTION_ENTRY
    }
}

// ============================================================================
// UNWIND_OP_CODES
// ============================================================================

/// Unwind operation codes used by the Windows x64 exception handling model.
///
/// Each describes one prologue instruction that modifies RSP or saves a register:
/// - PUSH_NONVOL: push <reg>                    → +8 bytes
/// - ALLOC_LARGE: sub rsp, <large>              → +N bytes
/// - ALLOC_SMALL: sub rsp, <small>              → +(OpInfo+1)*8 bytes
/// - SET_FPREG:   lea rbp, [rsp+offset]         → sets frame pointer
/// - SAVE_NONVOL: mov [rsp+off], <reg>          → no stack change
/// - SAVE_XMM128: movaps [rsp+off], <xmm>       → no stack change
/// - PUSH_MACH_FRAME: machine frame (interrupt)  → +0x40 or +0x48
#[repr(u8)]
#[allow(dead_code)]
pub enum UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE = 1,
    UWOP_ALLOC_SMALL = 2,
    UWOP_SET_FPREG = 3,
    UWOP_SAVE_NONVOL = 4,
    UWOP_SAVE_NONVOL_BIG = 5,
    UWOP_EPILOG = 6,
    UWOP_SPARE_CODE = 7,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128BIG = 9,
    UWOP_PUSH_MACH_FRAME = 10,
}

impl TryFrom<u8> for UNWIND_OP_CODES {
    type Error = ();

    #[inline(always)]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 10 {
            Ok(unsafe { core::mem::transmute::<u8, UNWIND_OP_CODES>(value) })
        } else {
            Err(())
        }
    }
}

// ============================================================================
// Registers
// ============================================================================

/// Enumeration of x86_64 general-purpose registers.
///
/// Used to identify which register is pushed/saved in unwind codes.
/// The index matches the OpInfo field in UWOP_PUSH_NONVOL.
#[derive(Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Registers {
    Rax = 0,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl PartialEq<usize> for Registers {
    #[inline(always)]
    fn eq(&self, other: &usize) -> bool {
        *self as usize == *other
    }
}

// ============================================================================
// Per-call frame rotation pool
// ============================================================================

/// Maximum number of candidates per rotation pool slot.
pub const POOL_SIZE: usize = 8;

/// A pre-computed candidate for frame rotation.
///
/// Stores the ready-to-use address and frame size that can be directly
/// written into Config fields. For prologs, `addr` is the fake return
/// address (function base + call instruction offset). For gadgets,
/// `addr` is the gadget address itself.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FrameCandidate {
    /// Pre-computed address (return address for prologs, gadget address for gadgets).
    pub addr: *const c_void,
    /// Stack frame size.
    pub size: u64,
    /// RBP stack offset (only meaningful for second/push-rbp frames, 0 otherwise).
    pub rbp_offset: u64,
}

impl Default for FrameCandidate {
    #[inline(always)]
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Pool of pre-collected prolog/gadget candidates for per-call rotation.
///
/// Built once during `build_config()`. Before each spoofed call, the
/// `spoof_uwd!` macro calls `rotate_config()` which picks different
/// candidates from this pool using the TSC (Time Stamp Counter) as a
/// per-call entropy source. This ensures every API call presents a
/// different intermediate call stack to the unwinder.
///
/// Each pool slot contains up to `POOL_SIZE` candidates found by scanning
/// the source module's `.pdata` section during initialization.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FramePool {
    /// SET_FPREG prolog candidates (for first_frame_fp / first_frame_size).
    pub first_frames: [FrameCandidate; POOL_SIZE],
    /// Number of valid entries in first_frames.
    pub first_count: u8,
    /// Push-RBP prolog candidates (for second_frame_fp / second_frame_size / rbp_stack_offset).
    pub second_frames: [FrameCandidate; POOL_SIZE],
    /// Number of valid entries in second_frames.
    pub second_count: u8,
    /// `jmp [rbx]` gadget candidates (for jmp_rbx_gadget / jmp_rbx_frame_size).
    pub jmp_rbx: [FrameCandidate; POOL_SIZE],
    /// Number of valid entries in jmp_rbx.
    pub jmp_rbx_count: u8,
    /// `add rsp, 0x58; ret` gadget candidates (for add_rsp_gadget / add_rsp_frame_size).
    pub add_rsp: [FrameCandidate; POOL_SIZE],
    /// Number of valid entries in add_rsp.
    pub add_rsp_count: u8,
}

impl Default for FramePool {
    #[inline(always)]
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

// ============================================================================
// Config (spoof call parameters passed to ASM stub)
// ============================================================================

/// Configuration structure passed to the spoof ASM routine (`SpoofSynthetic`).
///
/// Contains all the information the assembly stub needs to build
/// synthetic stack frames and execute the spoofed call. Populated once
/// by `build_config()`, then reused across calls - only `spoof_function`,
/// `number_args`, and `arg01..arg11` change per call.
///
/// # Memory layout (must match ASM STRUC exactly)
///
/// ```text
/// Offset  Size  Rust field            ASM field                   Description
/// ──────  ────  ────────────────────  ──────────────────────────  ────────────────────────
/// 0x00    8     rtl_user_addr         RtlUserThreadStartAddr      Thread root address
/// 0x08    8     rtl_user_thread_size  RtlUserThreadStartFrameSize Frame size (from .pdata)
/// 0x10    8     base_thread_addr      BaseThreadInitThunkAddr      2nd thread frame address
/// 0x18    8     base_thread_size      BaseThreadInitThunkFrameSize Frame size (from .pdata)
/// 0x20    8     first_frame_fp        FirstFrame                   1st spoofed ret addr
/// 0x28    8     second_frame_fp       SecondFrame                  2nd spoofed ret addr
/// 0x30    8     jmp_rbx_gadget        JmpRbxGadget                 FF 23 gadget address
/// 0x38    8     add_rsp_gadget        AddRspXGadget                48 83 C4 58 C3 gadget
/// 0x40    8     first_frame_size      FirstFrameSize               Stack alloc for 1st frame
/// 0x48    8     second_frame_size     SecondFrameSize              Stack alloc for 2nd frame
/// 0x50    8     jmp_rbx_frame_size    JmpRbxGadgetFrameSize        Frame size around gadget
/// 0x58    8     add_rsp_frame_size    AddRspXGadgetFrameSize       Frame size around gadget
/// 0x60    8     rbp_stack_offset      RbpOffset                    Where RBP is saved
/// 0x68    8     spoof_function        SpooFunction                 Target function to call
/// 0x70    8     return_address        ReturnAddress                (reserved)
/// 0x78    4     is_syscall            IsSyscall (RESD 1)           0=normal, 1=syscall
/// 0x7C    4     ssn                   Ssn       (RESD 1)           Syscall number
/// 0x80    8     number_args           NArgs     (RESQ 1)           Argument count
/// 0x88    8     arg01                 Arg01                        1st argument (rcx)
/// 0x90    8     arg02                 Arg02                        2nd argument (rdx)
/// ...     ...   ...                   ...                          ...
/// 0xD8    8     arg11                 Arg11                        11th argument (stack)
/// ```
///
/// # How the ASM stub uses this
///
/// ```text
/// SpoofSynthetic(rcx = &mut Config):
///
///   1. Save callee-saved registers (rbp, rbx, r15)
///   2. Allocate 0x210 bytes of working space
///   3. Build synthetic stack (bottom-up):
///      push 0                    ← null terminator (stack root)
///      sub rsp, RtlUserThread... ← frame for RtlUserThreadStart
///      push RtlUserThreadStart+0x21  ← fake return address
///      sub rsp, BaseThread...   ← frame for BaseThreadInitThunk
///      push BaseThreadInitThunk+0x14 ← fake return address
///      push FirstFrame          ← 1st spoofed frame
///      plant RBP at RbpOffset   ← link 1st→2nd frame for unwinder
///      push SecondFrame         ← 2nd spoofed frame
///      push JmpRbxGadget        ← stack pivot gadget
///      push AddRspXGadget       ← cleanup gadget
///   4. Load function args into registers (rcx, rdx, r8, r9, stack)
///   5. jmp r11                  ← call target (no CALL = no ret addr pushed)
///   6. Target returns → hits add rsp gadget → hits jmp [rbx] → RestoreSynthetic
/// ```
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Config {
    /// Address of RtlUserThreadStart (top of legitimate call chain).
    pub rtl_user_addr: *const c_void,

    /// Stack size of RtlUserThreadStart frame.
    pub rtl_user_thread_size: u64,

    /// Address of BaseThreadInitThunk (second frame in chain).
    pub base_thread_addr: *const c_void,

    /// Stack size of BaseThreadInitThunk frame.
    pub base_thread_size: u64,

    /// First (fake) return address frame.
    pub first_frame_fp: *const c_void,

    /// Second (ROP) return address frame.
    pub second_frame_fp: *const c_void,

    /// Gadget: `jmp [rbx]`.
    pub jmp_rbx_gadget: *const c_void,

    /// Gadget: `add rsp, X; ret`.
    pub add_rsp_gadget: *const c_void,

    /// Stack size of first spoofed frame.
    pub first_frame_size: u64,

    /// Stack size of second spoofed frame.
    pub second_frame_size: u64,

    /// Stack frame size where the `jmp [rbx]` gadget resides.
    pub jmp_rbx_frame_size: u64,

    /// Stack frame size where the `add rsp, X` gadget resides.
    pub add_rsp_frame_size: u64,

    /// Offset on the stack where `rbp` is pushed.
    pub rbp_stack_offset: u64,

    /// The function to be spoofed / called.
    pub spoof_function: *const c_void,

    /// Return address (used as stack-resume point after call).
    pub return_address: *const c_void,

    /// Whether the target is a syscall (0 = no, 1 = yes).
    /// Matches ASM STRUC: `IsSyscall RESD 1` (4 bytes at offset 0x78).
    pub is_syscall: u32,

    /// System Service Number (SSN) for direct syscalls.
    /// Matches ASM STRUC: `Ssn RESD 1` (4 bytes at offset 0x7C).
    pub ssn: u32,

    /// Number of arguments to pass to the spoofed function.
    /// Matches ASM STRUC: `NArgs RESQ 1` (8 bytes at offset 0x80).
    pub number_args: u64,
    pub arg01: *const c_void,
    pub arg02: *const c_void,
    pub arg03: *const c_void,
    pub arg04: *const c_void,
    pub arg05: *const c_void,
    pub arg06: *const c_void,
    pub arg07: *const c_void,
    pub arg08: *const c_void,
    pub arg09: *const c_void,
    pub arg10: *const c_void,
    pub arg11: *const c_void,

    // --- Rust-only fields below (not accessed by ASM) ---
    /// Pool of prolog/gadget candidates for per-call rotation.
    /// Populated by build_config, used by rotate_config before each spoofed call.
    pub frame_pool: FramePool,
}

impl Default for Config {
    #[inline(always)]
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
