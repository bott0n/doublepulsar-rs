[BITS 64]

;--------------------------------------------------------------------------
; Start (x64) - Assembly entry point and stack alignment trampoline
;
; PURPOSE:
;   Provides the initial entry point for the reflective loader. This function
;   ensures proper stack alignment before transferring control to Rust code.
;
; WHY THIS EXISTS:
;   1. x64 calling convention requires 16-byte stack alignment
;   2. Caller may not provide aligned stack (shellcode, injection, etc.)
;   3. Must allocate shadow space for Windows x64 calling convention
;   4. Provides clean transition from assembly to Rust
;
; EXECUTION FLOW:
;   1. Save caller's RSI register (preserve calling context)
;   2. Align stack to 16-byte boundary (required by x64 ABI)
;   3. Allocate shadow space (32 bytes for Windows x64)
;   4. Call Rust Entry() function
;   5. Restore stack and RSI on return
;
; SECTION PLACEMENT:
;   Placed in .text$A to ensure it comes BEFORE Rust code in .text$B.
;   This guarantees the assembly entry point is at the beginning of the
;   .text section, making it the first code executed.
;
; CALLING CONVENTION:
;   Windows x64 (rcx=arg1, rdx=arg2, r8=arg3, r9=arg4)
;   Shadow space: 32 bytes (0x20) on stack for first 4 register args
;
; REGISTERS:
;   RSI - Temporarily used to save original stack pointer
;   RSP - Stack pointer (aligned and shadow space allocated)
;   All other registers preserved by called functions
;--------------------------------------------------------------------------
EXTERN Entry
GLOBAL Start

[SECTION .text$A]

Start:
    push   rsi                 ; Step 1: Save caller's RSI register
    mov    rsi, rsp            ; Step 2: Save original stack pointer in RSI
    and    rsp, 0FFFFFFFFFFFFFFF0h ; Step 3: Align stack to 16-byte boundary
    sub    rsp, 020h           ; Step 4: Allocate 32 bytes shadow space
    call   Entry               ; Step 5: Transfer control to Rust Entry()
    mov    rsp, rsi            ; Step 6: Restore original stack pointer
    pop    rsi                 ; Step 7: Restore caller's RSI register
    ret                        ; Step 8: Return to caller
