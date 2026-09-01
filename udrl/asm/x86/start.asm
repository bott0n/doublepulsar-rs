[BITS 32]

;--------------------------------------------------------------------------
; _Start (x86) - 32-bit assembly entry point and stack alignment trampoline
;
; PURPOSE:
;   Provides the initial entry point for the reflective loader on 32-bit systems.
;   Ensures proper stack alignment before transferring control to Rust code.
;
; WHY THIS EXISTS:
;   1. x86 calling convention benefits from 16-byte stack alignment (SSE)
;   2. Caller may not provide aligned stack (shellcode, injection, etc.)
;   3. Allocates shadow space for consistency with x64 (32 bytes)
;   4. Provides clean transition from assembly to Rust
;
; EXECUTION FLOW:
;   1. Save caller's ESI register (preserve calling context)
;   2. Align stack to 16-byte boundary (optional but recommended for SSE)
;   3. Allocate shadow space (32 bytes for consistency)
;   4. Call Rust _Entry() function
;   5. Restore stack and ESI on return
;
; SECTION PLACEMENT:
;   Placed in .text$A to ensure it comes BEFORE Rust code in .text$B.
;   This guarantees the assembly entry point is at the beginning of the
;   .text section, making it the first code executed.
;
; CALLING CONVENTION:
;   x86 cdecl (arguments on stack, caller cleans up)
;   Stack alignment: 16 bytes (for SSE compatibility)
;
; REGISTERS:
;   ESI - Temporarily used to save original stack pointer
;   ESP - Stack pointer (aligned and shadow space allocated)
;   All other registers preserved by called functions
;
; NOTE:
;   x86 uses underscore prefix (_Start, _Entry) for C name mangling.
;--------------------------------------------------------------------------
EXTERN _Entry
GLOBAL _Start

[SECTION .text$A]

_Start:
    push   esi                 ; Step 1: Save caller's ESI register
    mov    esi, esp            ; Step 2: Save original stack pointer in ESI
    and    esp, 0FFFFFFF0h     ; Step 3: Align stack to 16-byte boundary
    sub    esp, 020h           ; Step 4: Allocate 32 bytes shadow space
    call   _Entry              ; Step 5: Transfer control to Rust _Entry()
    mov    esp, esi            ; Step 6: Restore original stack pointer
    pop    esi                 ; Step 7: Restore caller's ESI register
    ret                        ; Step 8: Return to caller
