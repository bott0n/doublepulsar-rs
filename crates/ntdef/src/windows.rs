#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::c_void;

pub type BYTE = u8;
pub type WORD = u16;
pub type DWORD = u32;
pub type PDWORD = *mut DWORD;
pub type LPDWORD = *mut DWORD;
pub type LONG = i32;
pub type ULONG = u32;
pub type ULONG_PTR = usize;
pub type PVOID = *mut c_void;
pub type LPVOID = *mut c_void;
pub type HANDLE = PVOID;
pub type HMODULE = HANDLE;
pub type BOOL = i32;
pub type UINT = u32;
pub type WCHAR = u16;
pub type c_uchar = u8;
pub type UCHAR = c_uchar;
pub type BOOLEAN = UCHAR;
pub type SIZE_T = ULONG_PTR;
pub type PHANDLE = *mut HANDLE;
pub type __uint64 = u64;
pub type __int64 = i64;
pub type DWORD64 = __uint64;
pub type ULONGLONG = __uint64;
pub type LONGLONG = __int64;
pub type PULONG = *mut ULONG;
pub type c_ulong = u32;
pub const FALSE: BOOL = 0;
pub const TRUE: BOOL = 1;
pub type PSIZE_T = *mut ULONG_PTR;
pub type DWORD_PTR = ULONG_PTR;

pub type c_char = i8;
pub type c_ushort = u16;
pub type CHAR = c_char;
pub type USHORT = c_ushort;
pub type PCHAR = *mut CHAR;
pub type PCH = *const i8;
pub type PSTR = *mut u8;
pub type PWSTR = *mut u16;
pub type LPCSTR = *const i8;
pub type LPCWSTR = *const u16;
pub type PCWSTR = *const WCHAR;
pub type PCSZ = *const c_char;
pub type PCANSI_STRING = PSTRING;

pub type HINTERNET = LPVOID;
pub type INTERNET_PORT = WORD;

#[repr(C)]
pub union LARGE_INTEGER {
    pub struct_: LARGE_INTEGER_STRUCT,
    pub u: LARGE_INTEGER_U,
    pub QuadPart: LONGLONG,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LARGE_INTEGER_STRUCT {
    pub LowPart: DWORD,
    pub HighPart: LONG,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LARGE_INTEGER_U {
    pub LowPart: DWORD,
    pub HighPart: LONG,
}

pub type PLARGE_INTEGER = *mut LARGE_INTEGER;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}
pub type PLIST_ENTRY = *mut LIST_ENTRY;

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut WCHAR,
}
pub type PUNICODE_STRING = *mut UNICODE_STRING;

#[repr(C)]
pub struct STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PCHAR,
}

pub type PSTRING = *mut STRING;
pub type PANSI_STRING = PSTRING;
pub type PUSTRING = *mut USTRING;

#[repr(C)]
pub struct USTRING {
    pub Length: ULONG,
    pub MaximumLength: ULONG,
    pub Buffer: PCHAR,
}

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: ULONG,
    pub Length: ULONG,
    pub Flags: ULONG,
    pub DebugFlags: ULONG,
    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: ULONG,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: PVOID,
    pub StartingX: ULONG,
    pub StartingY: ULONG,
    pub CountX: ULONG,
    pub CountY: ULONG,
    pub CountCharsX: ULONG,
    pub CountCharsY: ULONG,
    pub FillAttribute: ULONG,
    pub WindowFlags: ULONG,
    pub ShowWindowFlags: ULONG,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; 32],
    pub EnvironmentSize: ULONG_PTR,
    pub EnvironmentVersion: ULONG_PTR,
    pub PackageDependencyData: PVOID,
    pub ProcessGroupId: ULONG,
    pub LoaderThreads: ULONG,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: HANDLE,
}

#[repr(C)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: USHORT,
    pub Length: USHORT,
    pub TimeStamp: ULONG,
    pub DosPath: STRING,
}

pub type PRTL_USER_PROCESS_PARAMETERS = *mut RTL_USER_PROCESS_PARAMETERS;

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: ULONG,
    pub Initialized: BOOLEAN,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: PVOID,
    pub ShutdownInProgress: BOOLEAN,
    pub ShutdownThreadId: HANDLE,
}
pub type PPEB_LDR_DATA = *mut PEB_LDR_DATA;

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LDR_DATA_TABLE_ENTRY_u1,
    pub DllBase: PVOID,
    pub EntryPoint: PLDR_INIT_ROUTINE,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub u2: LDR_DATA_TABLE_ENTRY_u2,
    pub ObsoleteLoadCount: USHORT,
    pub TlsIndex: USHORT,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: ULONG,
    pub EntryPointActivationContext: *mut ACTIVATION_CONTEXT,
    pub Lock: PVOID,
    pub DdagNode: PLDR_DDAG_NODE,
    pub NodeModuleLink: LIST_ENTRY,
    pub LoadContext: *mut LDRP_LOAD_CONTEXT,
    pub ParentDllBase: PVOID,
    pub SwitchBackContext: PVOID,
    pub BaseAddressIndexNode: RTL_BALANCED_NODE,
    pub MappingInfoIndexNode: RTL_BALANCED_NODE,
    pub OriginalBase: ULONG_PTR,
    pub LoadTime: LARGE_INTEGER,
    pub BaseNameHashValue: ULONG,
    pub LoadReason: LDR_DLL_LOAD_REASON,
    pub ImplicitPathOptions: ULONG,
    pub ReferenceCount: ULONG,
    pub DependentLoadFlags: ULONG,
    pub SigningLevel: UCHAR,
}

pub type PLDR_SERVICE_TAG_RECORD = *mut LDR_SERVICE_TAG_RECORD;
pub type PLDR_DDAG_NODE = *mut LDR_DDAG_NODE;
pub type PLDR_INIT_ROUTINE =
    Option<unsafe extern "system" fn(DllHandle: PVOID, Reason: ULONG, Context: PVOID) -> BOOLEAN>;

#[repr(C)]
pub struct LDR_SERVICE_TAG_RECORD {
    pub Next: *mut LDR_SERVICE_TAG_RECORD,
    pub ServiceTag: ULONG,
}

#[repr(C)]
pub struct LDR_DDAG_NODE {
    pub Modules: LIST_ENTRY,
    pub ServiceTagList: PLDR_SERVICE_TAG_RECORD,
    pub LoadCount: ULONG,
    pub LoadWhileUnloadingCount: ULONG,
    pub LowestLink: ULONG,
    pub u: LDR_DDAG_NODE_u,
    pub IncomingDependencies: LDRP_CSLIST,
    pub State: LDR_DDAG_STATE,
    pub CondenseLink: SINGLE_LIST_ENTRY,
    pub PreorderNumber: ULONG,
}
pub type LDR_DDAG_STATE = u32;

#[repr(C)]
pub union LDR_DDAG_NODE_u {
    pub Dependencies: LDRP_CSLIST,
    pub RemovalLink: SINGLE_LIST_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SINGLE_LIST_ENTRY {
    pub Next: *mut SINGLE_LIST_ENTRY,
}

pub type PSINGLE_LIST_ENTRY = *mut SINGLE_LIST_ENTRY;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LDRP_CSLIST {
    pub Tail: PSINGLE_LIST_ENTRY,
}

#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_u2 {
    pub FlagGroup: [UCHAR; 4],
    pub Flags: ULONG,
}

#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_u1 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}

pub struct LDRP_LOAD_CONTEXT {
    pub BaseDllName: UNICODE_STRING,
    pub somestruct: PVOID,
    pub Flags: ULONG,
    pub pstatus: *mut NTSTATUS,
    pub ParentEntry: *mut LDR_DATA_TABLE_ENTRY,
    pub Entry: *mut LDR_DATA_TABLE_ENTRY,
    pub WorkQueueListEntry: LIST_ENTRY,
    pub ReplacedEntry: *mut LDR_DATA_TABLE_ENTRY,
    pub pvImports: *mut *mut LDR_DATA_TABLE_ENTRY,
    pub ImportDllCount: ULONG,
    pub TaskCount: LONG,
    pub pvIAT: PVOID,
    pub SizeOfIAT: ULONG,
    pub CurrentDll: ULONG,
    pub piid: PIMAGE_IMPORT_DESCRIPTOR,
    pub OriginalIATProtect: ULONG,
    pub GuardCFCheckFunctionPointer: PVOID,
    pub pGuardCFCheckFunctionPointer: *mut PVOID,
}

pub type PLDR_DATA_TABLE_ENTRY = *mut LDR_DATA_TABLE_ENTRY;

pub type LDR_DLL_LOAD_REASON = u32;
#[repr(C)]
pub struct RTL_BALANCED_NODE {
    pub u: RTL_BALANCED_NODE_u,
    pub ParentValue: ULONG_PTR,
}

pub union RTL_BALANCED_NODE_u {
    _rtlb_: [usize; 2],
    _rtbn_ptr: [*mut RTL_BALANCED_NODE; 2],
    _rtlbns_struct: RTL_BALANCED_NODE_s,
}

#[derive(Clone, Copy)]
pub struct RTL_BALANCED_NODE_s {
    _Left: *mut RTL_BALANCED_NODE,
    _Right: *mut RTL_BALANCED_NODE,
}

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: BOOLEAN,
    pub ReadImageFileExecOptions: BOOLEAN,
    pub BeingDebugged: BOOLEAN,
    pub BitField: BOOLEAN,
    pub Mutant: HANDLE,
    pub ImageBaseAddress: PVOID,
    pub Ldr: PPEB_LDR_DATA,
    pub ProcessParameters: PRTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: PVOID,
    pub ProcessHeap: PVOID,
    pub FastPebLock: PRTL_CRITICAL_SECTION,
    pub IFEOKey: PVOID,
    pub AtlThunkSListPtr: PSLIST_HEADER,
    pub CrossProcessFlags: ULONG,
    pub u: PEB_u,
    pub SystemReserved: [ULONG; 1],
    pub AtlThunkSListPtr32: ULONG,
    pub ApiSetMap: PAPI_SET_NAMESPACE,
    pub TlsExpansionCounter: ULONG,
    pub TlsBitmap: PVOID,
    pub TlsBitmapBits: [ULONG; 2],
    pub ReadOnlySharedMemoryBase: PVOID,
    pub SharedData: PVOID,
    pub ReadOnlyStaticServerData: *mut PVOID,
    pub AnsiCodePageData: PVOID,
    pub OemCodePageData: PVOID,
    pub UnicodeCaseTableData: PVOID,
    pub NumberOfProcessors: ULONG,
    pub NtGlobalFlag: ULONG,
    pub CriticalSectionTimeout: ULARGE_INTEGER,
    pub HeapSegmentReserve: SIZE_T,
    pub HeapSegmentCommit: SIZE_T,
    pub HeapDeCommitTotalFreeThreshold: SIZE_T,
    pub HeapDeCommitFreeBlockThreshold: SIZE_T,
    pub NumberOfHeaps: ULONG,
    pub MaximumNumberOfHeaps: ULONG,
    pub ProcessHeaps: *mut PVOID,
    pub GdiSharedHandleTable: PVOID,
    pub ProcessStarterHelper: PVOID,
    pub GdiDCAttributeList: ULONG,
    pub LoaderLock: PRTL_CRITICAL_SECTION,
    pub OSMajorVersion: ULONG,
    pub OSMinorVersion: ULONG,
    pub OSBuildNumber: USHORT,
    pub OSCSDVersion: USHORT,
    pub OSPlatformId: ULONG,
    pub ImageSubsystem: ULONG,
    pub ImageSubsystemMajorVersion: ULONG,
    pub ImageSubsystemMinorVersion: ULONG,
    pub ActiveProcessAffinityMask: ULONG_PTR,
    pub GdiHandleBuffer: GDI_HANDLE_BUFFER,
    pub PostProcessInitRoutine: PVOID,
    pub TlsExpansionBitmap: PVOID,
    pub TlsExpansionBitmapBits: [ULONG; 32],
    pub SessionId: ULONG,
    pub AppCompatFlags: ULARGE_INTEGER,
    pub AppCompatFlagsUser: ULARGE_INTEGER,
    pub pShimData: PVOID,
    pub AppCompatInfo: PVOID,
    pub CSDVersion: UNICODE_STRING,
    pub ActivationContextData: PVOID,
    pub ProcessAssemblyStorageMap: PVOID,
    pub SystemDefaultActivationContextData: PVOID,
    pub SystemAssemblyStorageMap: PVOID,
    pub MinimumStackCommit: SIZE_T,
    pub FlsCallback: *mut PVOID,
    pub FlsListHead: LIST_ENTRY,
    pub FlsBitmap: PVOID,
    pub FlsBitmapBits: [ULONG; 4],
    pub FlsHighIndex: ULONG,
    pub WerRegistrationData: PVOID,
    pub WerShipAssertPtr: PVOID,
    pub pUnused: PVOID,
    pub pImageHeaderHash: PVOID,
    pub TracingFlags: ULONG,
    pub CsrServerReadOnlySharedMemoryBase: ULONGLONG,
    pub TppWorkerpListLock: PRTL_CRITICAL_SECTION,
    pub TppWorkerpList: LIST_ENTRY,
    pub WaitOnAddressHashTable: [PVOID; 128],
    pub TelemetryCoverageHeader: PVOID,
    pub CloudFileFlags: ULONG,
    pub CloudFileDiagFlags: ULONG,
    pub PlaceholderCompatibilityMode: CHAR,
    pub PlaceholderCompatibilityModeReserved: [CHAR; 7],
    pub LeapSecondData: *mut LEAP_SECOND_DATA,
    pub LeapSecondFlags: ULONG,
    pub NtGlobalFlag2: ULONG,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SLIST_ENTRY {
    pub Next: *mut SLIST_ENTRY,
}

pub type PSLIST_ENTRY = *mut SLIST_ENTRY;

#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SLIST_HEADER_X64 {
    pub BitFields1: ULONGLONG,
    pub BitFields2: ULONGLONG,
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SLIST_HEADER_S {
    pub Alignment: ULONGLONG,
    pub Region: ULONGLONG,
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
pub union SLIST_HEADER {
    pub s: SLIST_HEADER_S,
    pub x64: SLIST_HEADER_X64,
    pub raw: [ULONGLONG; 2],
}

pub type PSLIST_HEADER = *mut SLIST_HEADER;

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SLIST_HEADER_S {
    pub Next: SLIST_ENTRY,
    pub Depth: WORD,
    pub Reserved: WORD,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
pub union SLIST_HEADER {
    pub Alignment: ULONGLONG,
    pub s: SLIST_HEADER_S,
}

#[repr(C)]
pub union PEB_u {
    pub KernelCallbackTable: PVOID,
    pub UserSharedInfoPtr: PVOID,
}

pub type PAPI_SET_NAMESPACE = *mut API_SET_NAMESPACE;

#[repr(C)]
pub struct API_SET_NAMESPACE {
    pub Version: ULONG,
    pub Size: ULONG,
    pub Flags: ULONG,
    pub Count: ULONG,
    pub EntryOffset: ULONG,
    pub HashOffset: ULONG,
    pub HashFactor: ULONG,
}

pub type GDI_HANDLE_BUFFER = [ULONG; 60];

#[repr(C)]
pub union ULARGE_INTEGER {
    pub s: ULARGE_INTEGER_S,
    pub QuadPart: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ULARGE_INTEGER_S {
    pub LowPart: u32,
    pub HighPart: u32,
}

pub type PULARGE_INTEGER = *mut ULARGE_INTEGER;

pub type PRTL_CRITICAL_SECTION = *mut RTL_CRITICAL_SECTION;

#[repr(C)]
pub struct RTL_CRITICAL_SECTION {
    pub DebugInfo: PRTL_CRITICAL_SECTION_DEBUG,
    pub LockCount: LONG,
    pub RecursionCount: LONG,
    pub OwningThread: HANDLE,
    pub LockSemaphore: HANDLE,
    pub SpinCount: ULONG_PTR,
}

pub type PRTL_CRITICAL_SECTION_DEBUG = *mut RTL_CRITICAL_SECTION_DEBUG;

#[repr(C)]
pub struct RTL_CRITICAL_SECTION_DEBUG {
    pub Type: WORD,
    pub CreatorBackTraceIndex: WORD,
    pub CriticalSection: *mut RTL_CRITICAL_SECTION,
    pub ProcessLocksList: LIST_ENTRY,
    pub EntryCount: DWORD,
    pub ContentionCount: DWORD,
    pub Flags: DWORD,
    pub CreatorBackTraceIndexHigh: WORD,
    pub SpareWORD: WORD,
}

#[repr(C)]
pub struct LEAP_SECOND_DATA {
    _unused: [u8; 0],
}

pub type PPEB = *mut PEB;

#[repr(C)]
pub struct TEB {
    pub NtTib: NT_TIB,
    pub EnvironmentPointer: PVOID,
    pub ClientId: CLIENT_ID,
    pub ActiveRpcHandle: PVOID,
    pub ThreadLocalStoragePointer: PVOID,
    pub ProcessEnvironmentBlock: PPEB,
    pub LastErrorValue: ULONG,
    pub CountOfOwnedCriticalSections: ULONG,
    pub CsrClientThread: PVOID,
    pub Win32ThreadInfo: PVOID,
    pub User32Reserved: [ULONG; 26],
    pub UserReserved: [ULONG; 5],
    pub WOW32Reserved: PVOID,
    pub CurrentLocale: LCID,
    pub FpSoftwareStatusRegister: ULONG,
    pub ReservedForDebuggerInstrumentation: [PVOID; 16],
    pub SystemReserved1: [PVOID; 30],
    pub PlaceholderCompatibilityMode: CHAR,
    pub PlaceholderReserved: [CHAR; 11],
    pub ProxiedProcessId: ULONG,
    pub ActivationStack: ACTIVATION_CONTEXT_STACK,
    pub WorkingOnBehalfTicket: [UCHAR; 8],
    pub ExceptionCode: NTSTATUS,
    pub ActivationContextStackPointer: PACTIVATION_CONTEXT_STACK,
    pub InstrumentationCallbackSp: ULONG_PTR,
    pub InstrumentationCallbackPreviousPc: ULONG_PTR,
    pub InstrumentationCallbackPreviousSp: ULONG_PTR,
    pub TxFsContext: ULONG,
    pub InstrumentationCallbackDisabled: BOOLEAN,
    pub GdiTebBatch: GDI_TEB_BATCH,
    pub RealClientId: CLIENT_ID,
    pub GdiCachedProcessHandle: HANDLE,
    pub GdiClientPID: ULONG,
    pub GdiClientTID: ULONG,
    pub GdiThreadLocalInfo: PVOID,
    pub Win32ClientInfo: [ULONG_PTR; 62],
    pub glDispatchTable: [PVOID; 233],
    pub glReserved1: [ULONG_PTR; 29],
    pub glReserved2: PVOID,
    pub glSectionInfo: PVOID,
    pub glSection: PVOID,
    pub glTable: PVOID,
    pub glCurrentRC: PVOID,
    pub glContext: PVOID,
    pub LastStatusValue: NTSTATUS,
    pub StaticUnicodeString: UNICODE_STRING,
    pub StaticUnicodeBuffer: [WCHAR; 261],
    pub DeallocationStack: PVOID,
    pub TlsSlots: [PVOID; 64],
    pub TlsLinks: LIST_ENTRY,
    pub Vdm: PVOID,
    pub ReservedForNtRpc: PVOID,
    pub DbgSsReserved: [PVOID; 2],
    pub HardErrorMode: ULONG,
    pub Instrumentation: [PVOID; 11],
    pub ActivityId: GUID,
    pub SubProcessTag: PVOID,
    pub PerflibData: PVOID,
    pub EtwTraceData: PVOID,
    pub WinSockData: PVOID,
    pub GdiBatchCount: ULONG,
    pub u: TEB_u,
    pub GuaranteedStackBytes: ULONG,
    pub ReservedForPerf: PVOID,
    pub ReservedForOle: PVOID,
    pub WaitingOnLoaderLock: ULONG,
    pub SavedPriorityState: PVOID,
    pub ReservedForCodeCoverage: ULONG_PTR,
    pub ThreadPoolData: PVOID,
    pub TlsExpansionSlots: *mut PVOID,
    pub DeallocationBStore: PVOID,
    pub BStoreLimit: PVOID,
    pub MuiGeneration: ULONG,
    pub IsImpersonating: ULONG,
    pub NlsCache: PVOID,
    pub pShimData: PVOID,
    pub HeapVirtualAffinity: USHORT,
    pub LowFragHeapDataSlot: USHORT,
    pub CurrentTransactionHandle: HANDLE,
    pub ActiveFrame: PTEB_ACTIVE_FRAME,
    pub FlsData: PVOID,
    pub PreferredLanguages: PVOID,
    pub UserPrefLanguages: PVOID,
    pub MergedPrefLanguages: PVOID,
    pub MuiImpersonation: ULONG,
    pub CrossTebFlags: USHORT,
    pub SameTebFlags: USHORT,
    pub TxnScopeEnterCallback: PVOID,
    pub TxnScopeExitCallback: PVOID,
    pub TxnScopeContext: PVOID,
    pub LockCount: ULONG,
    pub WowTebOffset: LONG,
    pub ResourceRetValue: PVOID,
    pub ReservedForWdf: PVOID,
    pub ReservedForCrt: ULONGLONG,
    pub EffectiveContainerId: GUID,
}

#[repr(C)]
pub struct NT_TIB {
    pub ExceptionList: *mut EXCEPTION_REGISTRATION_RECORD,
    pub StackBase: PVOID,
    pub StackLimit: PVOID,
    pub SubSystemTib: PVOID,
    pub u: NT_TIB_u,
    pub ArbitraryUserPointer: PVOID,
    pub _Self: *mut NT_TIB,
}

#[repr(C)]
pub union NT_TIB_u {
    pub FiberData: PVOID,
    pub Version: DWORD,
}

pub type EXCEPTION_DISPOSITION = u32;

pub type PEXCEPTION_ROUTINE = Option<
    unsafe extern "system" fn(
        ExceptionRecord: *mut EXCEPTION_RECORD,
        EstablisherFrame: PVOID,
        ContextRecord: *mut CONTEXT,
        DispatcherContext: PVOID,
    ) -> EXCEPTION_DISPOSITION,
>;

#[repr(C)]
pub struct EXCEPTION_REGISTRATION_RECORD {
    pub Next: *mut EXCEPTION_REGISTRATION_RECORD,
    pub Handler: PEXCEPTION_ROUTINE,
}

#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: DWORD,
    pub ExceptionFlags: DWORD,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: PVOID,
    pub NumberParameters: DWORD,
    pub ExceptionInformation: [ULONG_PTR; 15],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TEB_u {
    pub CurrentIdealProcessor: PROCESSOR_NUMBER,
    pub IdealProcessorValue: ULONG,
    pub s: TEB_u_s,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TEB_u_s {
    pub ReservedPad0: UCHAR,
    pub ReservedPad1: UCHAR,
    pub ReservedPad2: UCHAR,
    pub IdealProcessor: UCHAR,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PROCESSOR_NUMBER {
    pub Group: USHORT,
    pub Number: UCHAR,
    pub Reserved: UCHAR,
}

pub type PTEB = *mut TEB;
pub type PTEB_ACTIVE_FRAME = *mut TEB_ACTIVE_FRAME;
pub type PTEB_ACTIVE_FRAME_CONTEXT = *mut TEB_ACTIVE_FRAME_CONTEXT;
pub type LCID = ULONG;
pub type PACTIVATION_CONTEXT_STACK = *mut ACTIVATION_CONTEXT_STACK;
pub type PRTL_ACTIVATION_CONTEXT_STACK_FRAME = *mut RTL_ACTIVATION_CONTEXT_STACK_FRAME;

#[repr(C)]
pub struct ACTIVATION_CONTEXT_STACK {
    pub ActiveFrame: *mut RTL_ACTIVATION_CONTEXT_STACK_FRAME,
    pub FrameListCache: LIST_ENTRY,
    pub Flags: ULONG,
    pub NextCookieSequenceNumber: ULONG,
    pub StackId: ULONG,
}

#[repr(C)]
pub struct RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    pub Previous: PRTL_ACTIVATION_CONTEXT_STACK_FRAME,
    pub ActivationContext: *mut ACTIVATION_CONTEXT,
    pub Flags: ULONG,
}

#[repr(C)]
pub struct ACTIVATION_CONTEXT {
    pub dummy: *mut c_void,
}

#[repr(C)]
pub struct TEB_ACTIVE_FRAME_CONTEXT {
    pub Flags: ULONG,
    pub FrameName: PSTR,
}

#[repr(C)]
pub struct TEB_ACTIVE_FRAME {
    pub Flags: ULONG,
    pub Previous: *mut TEB_ACTIVE_FRAME,
    pub Context: PTEB_ACTIVE_FRAME_CONTEXT,
}

#[repr(C)]
pub struct GUID {
    pub Data1: c_ulong,
    pub Data2: c_ushort,
    pub Data3: c_ushort,
    pub Data4: [c_uchar; 8],
}

#[repr(C)]
pub struct GDI_TEB_BATCH {
    pub Offset: ULONG,
    pub HDC: ULONG_PTR,
    pub Buffer: [ULONG; 310],
}

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}
pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}
pub type PIMAGE_DATA_DIRECTORY = *mut IMAGE_DATA_DIRECTORY;

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: u64,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub BaseOfData: DWORD,
    pub ImageBase: DWORD,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: DWORD,
    pub SizeOfStackCommit: DWORD,
    pub SizeOfHeapReserve: DWORD,
    pub SizeOfHeapCommit: DWORD,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

pub type PIMAGE_NT_HEADERS = *mut IMAGE_NT_HEADERS;

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}
pub type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;

#[repr(C)]
#[derive(Copy, Clone)]
pub union IMAGE_SECTION_HEADER_Misc {
    pub physical_address: u32,
    pub virtual_size: u32,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [BYTE; 8],
    pub Misc: IMAGE_SECTION_HEADER_Misc,
    pub VirtualAddress: DWORD,
    pub SizeOfRawData: DWORD,
    pub PointerToRawData: DWORD,
    pub PointerToRelocations: DWORD,
    pub PointerToLinenumbers: DWORD,
    pub NumberOfRelocations: WORD,
    pub NumberOfLinenumbers: WORD,
    pub Characteristics: DWORD,
}

pub type PIMAGE_SECTION_HEADER = *mut IMAGE_SECTION_HEADER;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress: DWORD,
    pub EndAddress: DWORD,
    pub UnwindInfoAddress: DWORD,
}

pub type PIMAGE_RUNTIME_FUNCTION_ENTRY = *mut IMAGE_RUNTIME_FUNCTION_ENTRY;

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub u: IMAGE_IMPORT_DESCRIPTOR_u,
    pub TimeDateStamp: DWORD,
    pub ForwarderChain: DWORD,
    pub Name: DWORD,
    pub FirstThunk: DWORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IMAGE_IMPORT_DESCRIPTOR_u {
    pub Characteristics: DWORD,
    pub OriginalFirstThunk: DWORD,
}

pub type PIMAGE_IMPORT_DESCRIPTOR = *mut IMAGE_IMPORT_DESCRIPTOR;

#[repr(C)]
pub struct IMAGE_THUNK_DATA64 {
    pub u1: IMAGE_THUNK_DATA64_u1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IMAGE_THUNK_DATA64_u1 {
    pub ForwarderString: ULONGLONG,
    pub Function: ULONGLONG,
    pub Ordinal: ULONGLONG,
    pub AddressOfData: ULONGLONG,
}

pub type IMAGE_THUNK_DATA = IMAGE_THUNK_DATA64;
pub type PIMAGE_THUNK_DATA = *mut IMAGE_THUNK_DATA64;

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: WORD,
    pub Name: [u8; 1],
}

pub type PIMAGE_IMPORT_BY_NAME = *mut IMAGE_IMPORT_BY_NAME;

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: DWORD,
    pub SizeOfBlock: DWORD,
}

pub type PIMAGE_BASE_RELOCATION = *mut IMAGE_BASE_RELOCATION;

#[repr(C)]
pub struct IMAGE_RELOC {
    pub value: u16,
}

impl IMAGE_RELOC {
    #[inline(always)]
    pub fn offset(&self) -> u16 {
        self.value & 0x0FFF
    }

    #[inline(always)]
    pub fn reloc_type(&self) -> u16 {
        self.value >> 12
    }
}

pub type PIMAGE_RELOC = *mut IMAGE_RELOC;

#[inline]
pub unsafe fn IMAGE_SNAP_BY_ORDINAL(ordinal: u64) -> bool {
    (ordinal & IMAGE_ORDINAL_FLAG64) != 0
}

#[inline]
pub unsafe fn IMAGE_ORDINAL(ordinal: u64) -> u16 {
    (ordinal & 0xFFFF) as u16
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn NtCurrentTeb() -> PTEB {
    unsafe {
        let teb: PTEB;
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, preserves_flags)
        );
        teb
    }
}

#[cfg(target_arch = "x86")]
#[inline(always)]
pub unsafe fn NtCurrentTeb() -> PTEB {
    unsafe {
        let teb: PTEB;
        core::arch::asm!(
            "mov {}, fs:[0x18]",
            out(reg) teb,
            options(nostack, preserves_flags)
        );
        teb
    }
}

#[inline(always)]
pub unsafe fn IMAGE_FIRST_SECTION(nt: PIMAGE_NT_HEADERS) -> PIMAGE_SECTION_HEADER {
    unsafe {
        (nt as *mut u8).add(core::mem::size_of::<IMAGE_NT_HEADERS>()) as PIMAGE_SECTION_HEADER
    }
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn NtCurrentPeb() -> *mut PEB {
    let peb: *mut PEB;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );
    peb
}

#[cfg(target_arch = "x86")]
pub unsafe fn NtCurrentPeb() -> *mut PEB {
    let peb: *mut PEB;
    core::arch::asm!(
        "mov {}, fs:[0x30]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );
    peb
}

pub type NTSTATUS = LONG;
pub const THREAD_ALL_ACCESS: u32 = 2097151u32;
pub type PSECURITY_DESCRIPTOR = PVOID;
pub type PUSER_THREAD_START_ROUTINE =
    Option<unsafe extern "system" fn(ThreadParameter: PVOID) -> NTSTATUS>;
pub type PCLIENT_ID = *mut CLIENT_ID;
pub type PCONTEXT = *mut CONTEXT;
pub const CONTEXT_CONTROL: DWORD = 1_048_577;
pub const CONTEXT_FULL: DWORD = 1_048_587;

#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct CONTEXT {
    pub P1Home: DWORD64,
    pub P2Home: DWORD64,
    pub P3Home: DWORD64,
    pub P4Home: DWORD64,
    pub P5Home: DWORD64,
    pub P6Home: DWORD64,
    pub ContextFlags: DWORD,
    pub MxCsr: DWORD,
    pub SegCs: WORD,
    pub SegDs: WORD,
    pub SegEs: WORD,
    pub SegFs: WORD,
    pub SegGs: WORD,
    pub SegSs: WORD,
    pub EFlags: DWORD,
    pub Dr0: DWORD64,
    pub Dr1: DWORD64,
    pub Dr2: DWORD64,
    pub Dr3: DWORD64,
    pub Dr6: DWORD64,
    pub Dr7: DWORD64,
    pub Rax: DWORD64,
    pub Rcx: DWORD64,
    pub Rdx: DWORD64,
    pub Rbx: DWORD64,
    pub Rsp: DWORD64,
    pub Rbp: DWORD64,
    pub Rsi: DWORD64,
    pub Rdi: DWORD64,
    pub R8: DWORD64,
    pub R9: DWORD64,
    pub R10: DWORD64,
    pub R11: DWORD64,
    pub R12: DWORD64,
    pub R13: DWORD64,
    pub R14: DWORD64,
    pub R15: DWORD64,
    pub Rip: DWORD64,
    pub u: CONTEXT_u,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: DWORD64,
    pub DebugControl: DWORD64,
    pub LastBranchToRip: DWORD64,
    pub LastBranchFromRip: DWORD64,
    pub LastExceptionToRip: DWORD64,
    pub LastExceptionFromRip: DWORD64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union CONTEXT_u {
    pub all: [u64; 64],
    pub flt_save: XMM_SAVE_AREA32,
    pub s: CONTEXT_u_s,
}

pub type XMM_SAVE_AREA32 = XSAVE_FORMAT;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CONTEXT_u_s {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct XSAVE_FORMAT {
    pub ControlWord: WORD,
    pub StatusWord: WORD,
    pub TagWord: BYTE,
    pub Reserved1: BYTE,
    pub ErrorOpcode: WORD,
    pub ErrorOffset: DWORD,
    pub ErrorSelector: WORD,
    pub Reserved2: WORD,
    pub DataOffset: DWORD,
    pub DataSelector: WORD,
    pub Reserved3: WORD,
    pub MxCsr: DWORD,
    pub MxCsr_Mask: DWORD,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [BYTE; 96],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct M128A {
    pub Low: ULONGLONG,
    pub High: LONGLONG,
}

pub type PTHREAD_START_ROUTINE =
    Option<unsafe extern "system" fn(lpThreadParameter: LPVOID) -> DWORD>;

pub const STATUS_SUCCESS: NTSTATUS = 0x00000000;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001u32 as i32;

pub type FnLoadLibraryA = unsafe extern "system" fn(lpLibFileName: PSTR) -> HMODULE;

pub type FnLoadLibraryExA =
    unsafe extern "system" fn(lpLibFileName: LPCSTR, hFile: HANDLE, dwFlags: DWORD) -> HMODULE;

pub type FnGetProcAddress = unsafe extern "system" fn(hModule: HMODULE, lpProcName: PSTR) -> PVOID;

pub type FnMessageBoxA =
    unsafe extern "system" fn(hWnd: PVOID, lpText: PSTR, lpCaption: PSTR, uType: u32) -> i32;

pub type FnRtlCreateUserThread = unsafe extern "system" fn(
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
) -> NTSTATUS;

pub type FnNtGetContextThread =
    unsafe extern "system" fn(ThreadHandle: HANDLE, ThreadContext: PCONTEXT) -> NTSTATUS;

pub type FnNtSetContextThread =
    unsafe extern "system" fn(ThreadHandle: HANDLE, ThreadContext: PCONTEXT) -> NTSTATUS;

pub type FnNtResumeThread =
    unsafe extern "system" fn(ThreadHandle: HANDLE, PreviousSuspendCount: PULONG) -> NTSTATUS;

pub type FnRtlUserThreadStart =
    unsafe extern "system" fn(Function: PTHREAD_START_ROUTINE, Parameter: PVOID);

pub type FnWaitForSingleObject =
    unsafe extern "system" fn(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;

pub type FnWaitForSingleObjectEx =
    unsafe extern "system" fn(hHandle: HANDLE, dwMilliseconds: DWORD, bAlertable: BOOL) -> DWORD;

pub type FnNtWaitForSingleObject = unsafe extern "system" fn(
    Handle: HANDLE,
    Alertable: BOOLEAN,
    Timeout: PLARGE_INTEGER,
) -> NTSTATUS;

pub type FnSleep = unsafe extern "system" fn(dwMilliseconds: DWORD);

pub type FnExitThread = unsafe extern "system" fn(dwExitCode: DWORD) -> !;

pub type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: PSIZE_T,
    AllocationType: ULONG,
    Protect: ULONG,
) -> NTSTATUS;

pub type FnNtFreeVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: PSIZE_T,
    FreeType: ULONG,
) -> NTSTATUS;

pub type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: PSIZE_T,
    NewProtect: ULONG,
    OldProtect: PULONG,
) -> NTSTATUS;

pub type PRTL_HEAP_PARAMETERS = *mut RTL_HEAP_PARAMETERS;
#[repr(C)]
pub struct RTL_HEAP_PARAMETERS {
    pub Length: ULONG,
    pub SegmentReserve: SIZE_T,
    pub SegmentCommit: SIZE_T,
    pub DeCommitFreeBlockThreshold: SIZE_T,
    pub DeCommitTotalFreeThreshold: SIZE_T,
    pub MaximumAllocationSize: SIZE_T,
    pub VirtualMemoryThreshold: SIZE_T,
    pub InitialCommit: SIZE_T,
    pub InitialReserve: SIZE_T,
    pub CommitRoutine: PRTL_HEAP_COMMIT_ROUTINE,
    pub Reserved: [SIZE_T; 2],
}

pub type PRTL_HEAP_COMMIT_ROUTINE = Option<
    unsafe extern "system" fn(
        Base: PVOID,
        CommitAddress: *mut PVOID,
        CommitSize: PSIZE_T,
    ) -> NTSTATUS,
>;

pub type FnRtlCreateHeap = unsafe extern "system" fn(
    Flags: ULONG,
    HeapBase: PVOID,
    ReserveSize: SIZE_T,
    CommitSize: SIZE_T,
    Lock: PVOID,
    Parameters: PRTL_HEAP_PARAMETERS,
) -> PVOID;
pub type FnRtlAllocateHeap =
    unsafe extern "system" fn(HeapHandle: PVOID, Flags: ULONG, Size: SIZE_T) -> PVOID;

pub type FnRtlFreeHeap =
    unsafe extern "system" fn(HeapHandle: PVOID, Flags: ULONG, BaseAddress: PVOID) -> BOOLEAN;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RTL_HEAP_WALK_ENTRY_u_Block {
    pub Settable: SIZE_T,
    pub TagIndex: USHORT,
    pub AllocatorBackTraceIndex: USHORT,
    pub Reserved: [ULONG; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RTL_HEAP_WALK_ENTRY_u_Segment {
    pub CommittedSize: ULONG,
    pub UnCommittedSize: ULONG,
    pub FirstEntry: PVOID,
    pub LastEntry: PVOID,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union RTL_HEAP_WALK_ENTRY_u {
    pub Block: RTL_HEAP_WALK_ENTRY_u_Block,
    pub Segment: RTL_HEAP_WALK_ENTRY_u_Segment,
}

#[repr(C)]
pub struct RTL_HEAP_WALK_ENTRY {
    pub DataAddress: PVOID,
    pub DataSize: SIZE_T,
    pub OverheadBytes: UCHAR,
    pub SegmentIndex: UCHAR,
    pub Flags: USHORT,
    pub u: RTL_HEAP_WALK_ENTRY_u,
}

pub type PRTL_HEAP_WALK_ENTRY = *mut RTL_HEAP_WALK_ENTRY;

pub type FnRtlWalkHeap =
    unsafe extern "system" fn(HeapHandle: PVOID, Entry: PRTL_HEAP_WALK_ENTRY) -> NTSTATUS;

pub type FnDbgPrint = unsafe extern "C" fn(Format: *const u8, ...) -> NTSTATUS;

pub type FnInternetConnectA = unsafe extern "system" fn(
    hInternet: HINTERNET,
    lpszServerName: LPCSTR,
    nServerPort: INTERNET_PORT,
    lpszUserName: LPCSTR,
    lpszPassword: LPCSTR,
    dwService: DWORD,
    dwFlags: DWORD,
    dwContext: DWORD_PTR,
) -> HINTERNET;

pub type FnInternetOpenA = unsafe extern "system" fn(
    lpszAgent: LPCSTR,
    dwAccessType: DWORD,
    lpszProxy: LPCSTR,
    lpszProxyBypass: LPCSTR,
    dwFlags: DWORD,
) -> HINTERNET;

pub type FnHttpOpenRequestA = unsafe extern "system" fn(
    hConnect: HINTERNET,
    lpszVerb: LPCSTR,
    lpszObjectName: LPCSTR,
    lpszVersion: LPCSTR,
    lpszReferrer: LPCSTR,
    lplpszAcceptTypes: *const LPCSTR,
    dwFlags: DWORD,
    dwContext: DWORD_PTR,
) -> HINTERNET;

pub type FnHttpSendRequestA = unsafe extern "system" fn(
    hRequest: HINTERNET,
    lpszHeaders: LPCSTR,
    dwHeadersLength: DWORD,
    lpOptional: LPVOID,
    dwOptionalLength: DWORD,
) -> BOOL;

pub type FnHttpQueryInfoA = unsafe extern "system" fn(
    hRequest: HINTERNET,
    dwInfoLevel: DWORD,
    lpBuffer: LPVOID,
    lpdwBufferLength: LPDWORD,
    lpdwIndex: LPDWORD,
) -> BOOL;

pub type FnInternetReadFile = unsafe extern "system" fn(
    hFile: HINTERNET,
    lpBuffer: LPVOID,
    dwNumberOfBytesToRead: DWORD,
    lpdwNumberOfBytesRead: LPDWORD,
) -> BOOL;

pub type FnInternetQueryDataAvailable = unsafe extern "system" fn(
    hFile: HINTERNET,
    lpdwNumberOfBytesAvailable: LPDWORD,
    dwFlags: DWORD,
    dwContext: DWORD_PTR,
) -> BOOL;

pub type FnInternetCloseHandle = unsafe extern "system" fn(hInternet: HINTERNET) -> BOOL;

pub type FnWinHttpOpen = unsafe extern "system" fn(
    pszAgentW: LPCWSTR,
    dwAccessType: DWORD,
    pszProxyW: LPCWSTR,
    pszProxyBypassW: LPCWSTR,
    dwFlags: DWORD,
) -> HINTERNET;

pub type FnWinHttpConnect = unsafe extern "system" fn(
    hSession: HINTERNET,
    pswzServerName: LPCWSTR,
    nServerPort: u16,
    dwReserved: DWORD,
) -> HINTERNET;

pub type FnWinHttpOpenRequest = unsafe extern "system" fn(
    hConnect: HINTERNET,
    pwszVerb: LPCWSTR,
    pwszObjectName: LPCWSTR,
    pwszVersion: LPCWSTR,
    pwszReferrer: LPCWSTR,
    ppwszAcceptTypes: *const LPCWSTR,
    dwFlags: DWORD,
) -> HINTERNET;

pub type FnWinHttpSendRequest = unsafe extern "system" fn(
    hRequest: HINTERNET,
    lpszHeaders: LPCWSTR,
    dwHeadersLength: DWORD,
    lpOptional: LPVOID,
    dwOptionalLength: DWORD,
    dwTotalLength: DWORD,
    dwContext: DWORD_PTR,
) -> BOOL;

pub type FnWinHttpReceiveResponse =
    unsafe extern "system" fn(hRequest: HINTERNET, lpReserved: LPVOID) -> BOOL;

pub type FnWinHttpQueryHeaders = unsafe extern "system" fn(
    hRequest: HINTERNET,
    dwInfoLevel: DWORD,
    pwszName: LPCWSTR,
    lpBuffer: LPVOID,
    lpdwBufferLength: LPDWORD,
    lpdwIndex: LPDWORD,
) -> BOOL;

pub type FnWinHttpReadData = unsafe extern "system" fn(
    hRequest: HINTERNET,
    lpBuffer: LPVOID,
    dwNumberOfBytesToRead: DWORD,
    lpdwNumberOfBytesRead: LPDWORD,
) -> BOOL;

pub type FnWinHttpQueryDataAvailable =
    unsafe extern "system" fn(hRequest: HINTERNET, lpdwNumberOfBytesAvailable: LPDWORD) -> BOOL;

pub type FnWinHttpCloseHandle = unsafe extern "system" fn(hInternet: HINTERNET) -> BOOL;

pub type FnDnsExtractRecordsFromMessage_UTF8 =
    unsafe extern "system" fn(pDnsBuffer: PVOID, wMessageLength: WORD, ppRecord: *mut PVOID) -> i32;

pub type FnDnsWriteQuestionToBuffer_UTF8 = unsafe extern "system" fn(
    pDnsBuffer: PVOID,
    pdwBufferSize: LPDWORD,
    lpstrName: LPCSTR,
    wType: WORD,
    Xid: WORD,
    fRecursionDesired: BOOL,
) -> BOOL;

pub type FnWSASocketA = unsafe extern "system" fn(
    af: i32,
    socket_type: i32,
    protocol: i32,
    lpProtocolInfo: LPVOID,
    g: u32,
    dwFlags: DWORD,
) -> usize;

pub type FnAllocConsole = unsafe extern "system" fn() -> BOOL;
pub type FnGetStdHandle = unsafe extern "system" fn(nStdHandle: DWORD) -> HANDLE;
pub type FnWriteFile = unsafe extern "system" fn(
    hFile: HANDLE,
    lpBuffer: *const c_void,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: *mut DWORD,
    lpOverlapped: PVOID,
) -> BOOL;

pub type DLLMAIN =
    unsafe extern "system" fn(ImageBase: HMODULE, Reason: DWORD, Parameter: LPVOID) -> BOOLEAN;

pub const DLL_PROCESS_DETACH: DWORD = 0;
pub const DLL_PROCESS_ATTACH: DWORD = 1;
pub const DLL_THREAD_ATTACH: DWORD = 2;
pub const DLL_THREAD_DETACH: DWORD = 3;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY64 {
    pub StartAddressOfRawData: u64,
    pub EndAddressOfRawData: u64,
    pub AddressOfIndex: u64,
    pub AddressOfCallBacks: u64,
    pub SizeOfZeroFill: u32,
    pub Characteristics: u32,
}

pub const IMAGE_REL_BASED_DIR64: u32 = 10;
pub const IMAGE_REL_BASED_HIGHLOW: u32 = 3;
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

pub const IMAGE_SCN_MEM_EXECUTE: DWORD = 0x20000000;
pub const IMAGE_SCN_MEM_READ: DWORD = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: DWORD = 0x80000000;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_TOP_DOWN: u32 = 0x100000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;
pub const PAGE_WRITECOPY: DWORD = 0x08;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const HEAP_GROWABLE: u32 = 0x00000002;
pub const HEAP_ZERO_MEMORY: DWORD = 0x00000008;
pub const RTL_PROCESS_HEAP_ENTRY_BUSY: USHORT = 0x0001;
pub const PAGE_SIZE: usize = 0x1000;
pub const EVENT_ALL_ACCESS: DWORD = 2_031_619;
pub const DONT_RESOLVE_DLL_REFERENCES: DWORD = 0x00000001;

pub const MB_OK: u32 = 0x00000000;
pub const STD_OUTPUT_HANDLE: DWORD = 0xFFFFFFF5u32;

pub type FnRtlInitAnsiString =
    unsafe extern "system" fn(DestinationString: PANSI_STRING, SourceString: PCSZ);

pub type FnRtlAnsiStringToUnicodeString = unsafe extern "system" fn(
    DestinationString: PUNICODE_STRING,
    SourceString: PCANSI_STRING,
    AllocateDestinationString: BOOLEAN,
) -> NTSTATUS;

pub type FnRtlInitUnicodeString =
    unsafe extern "system" fn(DestinationString: PUNICODE_STRING, SourceString: PCWSTR);

pub type FnLdrLoadDll = unsafe extern "system" fn(
    DllPath: PWSTR,
    DllCharacteristics: PULONG,
    DllName: PUNICODE_STRING,
    DllHandle: *mut PVOID,
) -> NTSTATUS;

pub type FnLdrGetProcedureAddress = unsafe extern "system" fn(
    DllHandle: PVOID,
    ProcedureName: PANSI_STRING,
    ProcedureNumber: ULONG,
    ProcedureAddress: *mut PVOID,
) -> NTSTATUS;

pub type FnRtlFreeUnicodeString = unsafe extern "system" fn(UnicodeString: PUNICODE_STRING);

pub type FnRtlRandomEx = unsafe extern "C" fn(Seed: PULONG) -> ULONG;

pub type FnLdrUnloadDll = unsafe extern "system" fn(DllHandle: PVOID) -> NTSTATUS;

pub type FnNtAlertResumeThread =
    unsafe extern "system" fn(ThreadHandle: HANDLE, PreviousSuspendCount: PULONG) -> NTSTATUS;

pub type FnNtClose = unsafe extern "system" fn(Handle: HANDLE) -> NTSTATUS;

pub type FnNtSetEvent =
    unsafe extern "system" fn(EventHandle: HANDLE, PreviousState: *mut LONG) -> NTSTATUS;

pub type FnNtContinue =
    unsafe extern "system" fn(ContextRecord: PCONTEXT, TestAlert: BOOLEAN) -> NTSTATUS;

pub type ACCESS_MASK = DWORD;

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: PUNICODE_STRING,
    pub Attributes: ULONG,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}
pub type POBJECT_ATTRIBUTES = *mut OBJECT_ATTRIBUTES;

#[repr(C)]
pub enum EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent,
}

pub type FnNtCreateEvent = unsafe extern "system" fn(
    EventHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    EventType: EVENT_TYPE,
    InitialState: BOOLEAN,
) -> NTSTATUS;

pub type PPS_ATTRIBUTE_LIST = *mut PS_ATTRIBUTE_LIST;

#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    pub TotalLength: SIZE_T,
    pub Attributes: [PS_ATTRIBUTE; 1],
}

#[repr(C)]
pub struct PS_ATTRIBUTE {
    pub Attribute: ULONG_PTR,
    pub Size: SIZE_T,
    pub u: PS_ATTRIBUTE_u,
    pub ReturnLength: PSIZE_T,
}

#[repr(C)]
pub union PS_ATTRIBUTE_u {
    pub Value: ULONG_PTR,
    pub ValuePtr: PVOID,
}

pub type FnNtCreateThreadEx = unsafe extern "system" fn(
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
) -> NTSTATUS;

pub type FnNtOpenThread = unsafe extern "system" fn(
    ThreadHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ClientId: PCLIENT_ID,
) -> NTSTATUS;

pub const ProcessCookie: PROCESSINFOCLASS = 36;
pub const ProcessUserModeIOPL: PROCESSINFOCLASS = 16;
pub type PROCESSINFOCLASS = u32;

pub type FnNtQueryInformationProcess = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: PROCESSINFOCLASS,
    ProcessInformation: PVOID,
    ProcessInformationLength: ULONG,
    ReturnLength: *mut ULONG,
) -> NTSTATUS;

#[repr(C, packed)]
pub struct EXTENDED_PROCESS_INFORMATION {
    pub ExtendedProcessInfo: ULONG,
    pub ExtendedProcessInfoBuffer: ULONG,
}
pub type PEXTENDED_PROCESS_INFORMATION = *mut EXTENDED_PROCESS_INFORMATION;

#[repr(u32)]
pub enum SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeparation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
    SystemNumaProximityNodeInformation = 101,
    SystemDynamicTimeZoneInformation = 102,
    SystemCodeIntegrityInformation = 103,
    SystemProcessorMicrocodeUpdateInformation = 104,
    SystemProcessorBrandString = 105,
    SystemVirtualAddressInformation = 106,
    SystemLogicalProcessorAndGroupInformation = 107,
    SystemProcessorCycleTimeInformation = 108,
    SystemStoreInformation = 109,
    SystemRegistryAppendString = 110,
    SystemAitSamplingValue = 111,
    SystemVhdBootInformation = 112,
    SystemCpuQuotaInformation = 113,
    SystemNativeBasicInformation = 114,
    SystemErrorPortTimeouts = 115,
    SystemLowPriorityIoInformation = 116,
    SystemTpmBootEntropyInformation = 117,
    SystemVerifierCountersInformation = 118,
    SystemPagedPoolInformationEx = 119,
    SystemSystemPtesInformationEx = 120,
    SystemNodeDistanceInformation = 121,
    SystemAcpiAuditInformation = 122,
    SystemBasicPerformanceInformation = 123,
    SystemQueryPerformanceCounterInformation = 124,
    SystemSessionBigPoolInformation = 125,
    SystemBootGraphicsInformation = 126,
    SystemScrubPhysicalMemoryInformation = 127,
    SystemBadPageInformation = 128,
    SystemProcessorProfileControlArea = 129,
    SystemCombinePhysicalMemoryInformation = 130,
    SystemEntropyInterruptTimingInformation = 131,
    SystemConsoleInformation = 132,
    SystemPlatformBinaryInformation = 133,
    SystemPolicyInformation = 134,
    SystemHypervisorProcessorCountInformation = 135,
    SystemDeviceDataInformation = 136,
    SystemDeviceDataEnumerationInformation = 137,
    SystemMemoryTopologyInformation = 138,
    SystemMemoryChannelInformation = 139,
    SystemBootLogoInformation = 140,
    SystemProcessorPerformanceInformationEx = 141,
    SystemCriticalProcessErrorLogInformation = 142,
    SystemSecureBootPolicyInformation = 143,
    SystemPageFileInformationEx = 144,
    SystemSecureBootInformation = 145,
    SystemEntropyInterruptTimingRawInformation = 146,
    SystemPortableWorkspaceEfiLauncherInformation = 147,
    SystemFullProcessInformation = 148,
    SystemKernelDebuggerInformationEx = 149,
    SystemBootMetadataInformation = 150,
    SystemSoftRebootInformation = 151,
    SystemElamCertificateInformation = 152,
    SystemOfflineDumpConfigInformation = 153,
    SystemProcessorFeaturesInformation = 154,
    SystemRegistryReconciliationInformation = 155,
    SystemEdidInformation = 156,
    SystemManufacturingInformation = 157,
    SystemEnergyEstimationConfigInformation = 158,
    SystemHypervisorDetailInformation = 159,
    SystemProcessorCycleStatsInformation = 160,
    SystemVmGenerationCountInformation = 161,
    SystemTrustedPlatformModuleInformation = 162,
    SystemKernelDebuggerFlags = 163,
    SystemCodeIntegrityPolicyInformation = 164,
    SystemIsolatedUserModeInformation = 165,
    SystemHardwareSecurityTestInterfaceResultsInformation = 166,
    SystemSingleModuleInformation = 167,
    SystemAllowedCpuSetsInformation = 168,
    SystemVsmProtectionInformation = 169,
    SystemInterruptCpuSetsInformation = 170,
    SystemSecureBootPolicyFullInformation = 171,
    SystemCodeIntegrityPolicyFullInformation = 172,
    SystemAffinitizedInterruptProcessorInformation = 173,
    SystemRootSiloInformation = 174,
    SystemCpuSetInformation = 175,
    SystemCpuSetTagInformation = 176,
    SystemWin32WerStartCallout = 177,
    SystemSecureKernelProfileInformation = 178,
    SystemCodeIntegrityPlatformManifestInformation = 179,
    SystemInterruptSteeringInformation = 180,
    SystemSupportedProcessorArchitectures = 181,
    SystemMemoryUsageInformation = 182,
    SystemCodeIntegrityCertificateInformation = 183,
    SystemPhysicalMemoryInformation = 184,
    SystemControlFlowTransition = 185,
    SystemKernelDebuggingAllowed = 186,
    SystemActivityModerationExeState = 187,
    SystemActivityModerationUserSettings = 188,
    SystemCodeIntegrityPoliciesFullInformation = 189,
    SystemCodeIntegrityUnlockInformation = 190,
    SystemIntegrityQuotaInformation = 191,
    SystemFlushInformation = 192,
    SystemProcessorIdleMaskInformation = 193,
    SystemSecureDumpEncryptionInformation = 194,
    SystemWriteConstraintInformation = 195,
    SystemKernelVaShadowInformation = 196,
    SystemHypervisorSharedPageInformation = 197,
    SystemFirmwareBootPerformanceInformation = 198,
    SystemCodeIntegrityVerificationInformation = 199,
    SystemFirmwarePartitionInformation = 200,
    SystemSpeculationControlInformation = 201,
    SystemDmaGuardPolicyInformation = 202,
    SystemEnclaveLaunchControlInformation = 203,
    SystemWorkloadAllowedCpuSetsInformation = 204,
    SystemCodeIntegrityUnlockModeInformation = 205,
    SystemLeapSecondInformation = 206,
    SystemFlags2Information = 207,
    SystemSecurityModelInformation = 208,
    SystemCodeIntegritySyntheticCacheInformation = 209,
    SystemFeatureConfigurationInformation = 210,
    SystemFeatureConfigurationSectionInformation = 211,
    SystemFeatureUsageSubscriptionInformation = 212,
    SystemSecureSpeculationControlInformation = 213,
    SystemSpacesBootInformation = 214,
    SystemFwRamdiskInformation = 215,
    SystemWheaIpmiHardwareInformation = 216,
    SystemDifSetRuleClassInformation = 217,
    SystemDifClearRuleClassInformation = 218,
    SystemDifApplyPluginVerificationOnDriver = 219,
    SystemDifRemovePluginVerificationOnDriver = 220,
    SystemShadowStackInformation = 221,
    SystemBuildVersionInformation = 222,
    SystemPoolLimitInformation = 223,
    SystemCodeIntegrityAddDynamicStore = 224,
    SystemCodeIntegrityClearDynamicStores = 225,
    SystemDifPoolTrackingInformation = 226,
    SystemPoolZeroingInformation = 227,
    SystemDpcWatchdogInformation = 228,
    SystemDpcWatchdogInformation2 = 229,
    SystemSupportedProcessorArchitectures2 = 230,
    SystemSingleProcessorRelationshipInformation = 231,
    SystemXfgCheckFailureInformation = 232,
    SystemIommuStateInformation = 233,
    SystemHypervisorMinrootInformation = 234,
    SystemHypervisorBootPagesInformation = 235,
    SystemPointerAuthInformation = 236,
    SystemSecureKernelDebuggerInformation = 237,
    SystemOriginalImageFeatureInformation = 238,
    SystemMemoryNumaInformation = 239,
    SystemMemoryNumaPerformanceInformation = 240,
    SystemCodeIntegritySignedPoliciesFullInformation = 241,
    SystemSecureCoreInformation = 242,
    SystemTrustedAppsRuntimeInformation = 243,
    SystemBadPageInformationEx = 244,
    SystemResourceDeadlockTimeout = 245,
    SystemBreakOnContextUnwindFailureInformation = 246,
    SystemOslRamdiskInformation = 247,
    MaxSystemInfoClass = 248,
}

#[repr(u32)]
pub enum PROCESS_MITIGATION_POLICY {
    ProcessDEPPolicy = 0,
    ProcessASLRPolicy = 1,
    ProcessDynamicCodePolicy = 2,
    ProcessStrictHandleCheckPolicy = 3,
    ProcessSystemCallDisablePolicy = 4,
    ProcessMitigationOptionsMask = 5,
    ProcessExtensionPointDisablePolicy = 6,
    ProcessControlFlowGuardPolicy = 7,
    ProcessSignaturePolicy = 8,
    ProcessFontDisablePolicy = 9,
    ProcessImageLoadPolicy = 10,
    ProcessSystemCallFilterPolicy = 11,
    ProcessPayloadRestrictionPolicy = 12,
    ProcessChildProcessPolicy = 13,
    ProcessSideChannelIsolationPolicy = 14,
    ProcessUserShadowStackPolicy = 15,
    ProcessRedirectionTrustPolicy = 16,
    ProcessUserPointerAuthPolicy = 17,
    ProcessSEHOPPolicy = 18,
    MaxProcessMitigationPolicy = 19,
}

pub type PPS_APC_ROUTINE =
    Option<unsafe extern "C" fn(ApcArgument1: PVOID, ApcArgument2: PVOID, ApcArgument3: PVOID)>;

pub type FnNtQueueApcThread = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ApcRoutine: PVOID,
    ApcArgument1: PVOID,
    ApcArgument2: PVOID,
    ApcArgument3: PVOID,
) -> NTSTATUS;

pub type FnNtSignalAndWaitForSingleObject = unsafe extern "system" fn(
    SignalHandle: HANDLE,
    WaitHandle: HANDLE,
    Alertable: BOOLEAN,
    Timeout: PLARGE_INTEGER,
) -> NTSTATUS;

pub type FnNtTerminateThread =
    unsafe extern "system" fn(ThreadHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;

pub type FnNtTestAlert = unsafe extern "system" fn() -> NTSTATUS;

pub type FnNtDuplicateObject = unsafe extern "system" fn(
    SourceProcessHandle: HANDLE,
    SourceHandle: HANDLE,
    TargetProcessHandle: HANDLE,
    TargetHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    HandleAttributes: ULONG,
    Options: ULONG,
) -> NTSTATUS;

pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;

pub type FnRtlExitUserThread = unsafe extern "system" fn(ExitStatus: NTSTATUS) -> !;

pub type PCFG_CALL_TARGET_INFO = *mut CFG_CALL_TARGET_INFO;
pub const CFG_CALL_TARGET_VALID: ULONG_PTR = 0x00000001;

#[repr(C)]
pub struct CFG_CALL_TARGET_INFO {
    pub Offset: ULONG_PTR,
    pub Flags: ULONG_PTR,
}

pub type FnSetProcessValidCallTargets = unsafe extern "system" fn(
    hProcess: HANDLE,
    VirtualAddress: PVOID,
    RegionSize: SIZE_T,
    NumberOfOffsets: ULONG,
    OffsetInformation: PCFG_CALL_TARGET_INFO,
) -> BOOL;

pub type FnSystemFunction032 = unsafe extern "system" fn(Data: PUSTRING, Key: PUSTRING) -> NTSTATUS;
pub type FnSystemFunction040 =
    unsafe extern "system" fn(Memory: PVOID, MemorySize: ULONG, OptionFlags: ULONG) -> NTSTATUS;
pub type FnSystemFunction041 =
    unsafe extern "system" fn(Memory: PVOID, MemorySize: ULONG, OptionFlags: ULONG) -> NTSTATUS;
pub type FnSystemFunction042 =
    unsafe extern "system" fn(Memory: PVOID, MemorySize: ULONG, OptionFlags: ULONG) -> NTSTATUS;

pub const WT_EXECUTEINTIMERTHREAD: u32 = 0x00000020;

pub type FnRtlCreateTimerQueue =
    unsafe extern "system" fn(TimerQueueHandle: *mut HANDLE) -> NTSTATUS;

pub type FnRtlDeleteTimerQueue = unsafe extern "system" fn(TimerQueueHandle: HANDLE) -> NTSTATUS;

pub type FnRtlCreateTimer = unsafe extern "system" fn(
    TimerQueueHandle: HANDLE,
    Handle: *mut HANDLE,
    Function: PVOID,
    Context: PVOID,
    DueTime: u32,
    Period: u32,
    Flags: u32,
) -> NTSTATUS;

pub const TH32CS_SNAPTHREAD: u32 = 0x00000004;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub const INFINITE: u32 = 0xFFFFFFFF;

#[repr(C)]
pub struct THREADENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ThreadID: u32,
    pub th32OwnerProcessID: u32,
    pub tpBasePri: i32,
    pub tpDeltaPri: i32,
    pub dwFlags: u32,
}

pub type FnCreateToolhelp32Snapshot =
    unsafe extern "system" fn(dwFlags: u32, th32ProcessID: u32) -> HANDLE;

pub type FnThread32First =
    unsafe extern "system" fn(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;

pub type FnThread32Next =
    unsafe extern "system" fn(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;

pub type FnOpenThread = unsafe extern "system" fn(
    dwDesiredAccess: u32,
    bInheritHandle: BOOL,
    dwThreadId: u32,
) -> HANDLE;

pub type FnDuplicateHandle = unsafe extern "system" fn(
    hSourceProcessHandle: HANDLE,
    hSourceHandle: HANDLE,
    hTargetProcessHandle: HANDLE,
    lpTargetHandle: *mut HANDLE,
    dwDesiredAccess: u32,
    bInheritHandle: BOOL,
    dwOptions: u32,
) -> BOOL;

pub type FnGetThreadContext =
    unsafe extern "system" fn(hThread: HANDLE, lpContext: PCONTEXT) -> BOOL;

pub type FnSetThreadContext =
    unsafe extern "system" fn(hThread: HANDLE, lpContext: PCONTEXT) -> BOOL;

pub type FnSetEvent = unsafe extern "system" fn(hEvent: HANDLE) -> BOOL;

pub type FnRtlCaptureContext = unsafe extern "system" fn(ContextRecord: PCONTEXT);

pub type FnGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;
pub type FnGetCurrentProcessId = unsafe extern "system" fn() -> u32;
pub type FnGetCurrentThreadId = unsafe extern "system" fn() -> u32;

pub type FnVirtualProtect = unsafe extern "system" fn(
    lpAddress: PVOID,
    dwSize: SIZE_T,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> BOOL;

pub type FnVirtualAlloc = unsafe extern "system" fn(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) -> LPVOID;

pub type FnVirtualFree =
    unsafe extern "system" fn(lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) -> BOOL;

pub type FnDisableThreadLibraryCalls = unsafe extern "system" fn(hLibModule: PVOID) -> BOOL;

pub type FnBaseThreadInitThunk =
    unsafe extern "system" fn(Unknown: u32, StartAddress: PVOID, Argument: PVOID);

pub type FnRtlAcquireSRWLockExclusive = unsafe extern "system" fn(SRWLock: PVOID);

pub type FnZwWaitForWorkViaWorkerFactory = unsafe extern "system" fn(
    WorkerFactoryHandle: HANDLE,
    MiniPacket: PVOID,
    Timeout: PLARGE_INTEGER,
) -> NTSTATUS;

pub type FnEnumDateFormatsExA =
    unsafe extern "system" fn(lpDateFmtEnumProcExA: PVOID, Locale: u32, dwFlags: u32) -> BOOL;

pub type FnNtLockVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: PSIZE_T,
    MapType: ULONG,
) -> NTSTATUS;

pub const VM_LOCK_1: ULONG = 1;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UNWIND_OP {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE = 1,
    UWOP_ALLOC_SMALL = 2,
    UWOP_SET_FPREG = 3,
    UWOP_SAVE_NONVOL = 4,
    UWOP_SAVE_NONVOL_FAR = 5,
    UWOP_EPILOG = 6,
    UWOP_SPARE_CODE = 7,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR = 9,
    UWOP_PUSH_MACHFRAME = 10,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNWIND_CODE {
    pub CodeOffset: u8,
    pub UnwindOpAndInfo: u8,
}

impl UNWIND_CODE {
    #[inline]
    pub fn unwind_op(&self) -> u8 {
        self.UnwindOpAndInfo & 0x0F
    }

    #[inline]
    pub fn op_info(&self) -> u8 {
        self.UnwindOpAndInfo >> 4
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNWIND_INFO {
    pub VersionAndFlags: u8,
    pub SizeOfProlog: u8,
    pub CountOfCodes: u8,
    pub FrameRegisterAndOffset: u8,
}

impl UNWIND_INFO {
    #[inline]
    pub fn version(&self) -> u8 {
        self.VersionAndFlags & 0x07
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.VersionAndFlags >> 3
    }

    #[inline]
    pub fn frame_register(&self) -> u8 {
        self.FrameRegisterAndOffset & 0x0F
    }

    #[inline]
    pub fn frame_offset(&self) -> u8 {
        self.FrameRegisterAndOffset >> 4
    }

    pub unsafe fn codes(&self) -> *const UNWIND_CODE {
        (self as *const Self).add(1) as *const UNWIND_CODE
    }

    pub unsafe fn chained_entry(&self) -> *const IMAGE_RUNTIME_FUNCTION_ENTRY {
        let count = self.CountOfCodes as usize;
        let aligned = if count % 2 == 1 { count + 1 } else { count };
        self.codes().add(aligned) as *const IMAGE_RUNTIME_FUNCTION_ENTRY
    }
}

pub type PUNWIND_INFO = *mut UNWIND_INFO;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct TP_POOL_STACK_INFORMATION {
    pub StackReserve: SIZE_T,
    pub StackCommit: SIZE_T,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TP_CALLBACK_ENVIRON_V3 {
    pub Version: DWORD,
    pub Pool: PVOID,
    pub CleanupGroup: PVOID,
    pub CleanupGroupCancelCallback: PVOID,
    pub RaceDll: PVOID,
    pub ActivationContext: isize,
    pub FinalizationCallback: PVOID,
    pub u: TP_CALLBACK_ENVIRON_V3_u,
    pub CallbackPriority: i32,
    pub Size: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TP_CALLBACK_ENVIRON_V3_u {
    pub Flags: DWORD,
    pub s: TP_CALLBACK_ENVIRON_V3_s,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TP_CALLBACK_ENVIRON_V3_s {
    pub _bitfield: DWORD,
}

impl Default for TP_CALLBACK_ENVIRON_V3 {
    fn default() -> Self {
        Self {
            Version: 3,
            Pool: core::ptr::null_mut(),
            CleanupGroup: core::ptr::null_mut(),
            CleanupGroupCancelCallback: core::ptr::null_mut(),
            RaceDll: core::ptr::null_mut(),
            ActivationContext: 0,
            FinalizationCallback: core::ptr::null_mut(),
            u: TP_CALLBACK_ENVIRON_V3_u { Flags: 0 },
            CallbackPriority: 1,
            Size: core::mem::size_of::<TP_CALLBACK_ENVIRON_V3>() as DWORD,
        }
    }
}

pub type FnTpAllocPool =
    unsafe extern "system" fn(PoolReturn: *mut PVOID, Reserved: PVOID) -> NTSTATUS;

pub type FnTpSetPoolStackInformation = unsafe extern "system" fn(
    Pool: PVOID,
    PoolStackInformation: *mut TP_POOL_STACK_INFORMATION,
) -> NTSTATUS;

pub type FnTpSetPoolMinThreads =
    unsafe extern "system" fn(Pool: PVOID, MinThreads: DWORD) -> NTSTATUS;

pub type FnTpSetPoolMaxThreads = unsafe extern "system" fn(Pool: PVOID, MaxThreads: DWORD);

pub type FnTpAllocTimer = unsafe extern "system" fn(
    Timer: *mut PVOID,
    Callback: PVOID,
    Context: PVOID,
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
) -> NTSTATUS;

pub type FnTpSetTimer = unsafe extern "system" fn(
    Timer: PVOID,
    DueTime: PLARGE_INTEGER,
    Period: DWORD,
    WindowLength: DWORD,
);

pub type FnTpAllocWait = unsafe extern "C" fn(
    WaitReturn: *mut PTP_WAIT,
    Callback: PTP_WAIT_CALLBACK,
    Context: PVOID,
    CallbackEnviron: PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;

pub type PTP_WAIT_CALLBACK = Option<
    unsafe extern "system" fn(
        Instance: PTP_CALLBACK_INSTANCE,
        Context: PVOID,
        Wait: PTP_WAIT,
        WaitResult: TP_WAIT_RESULT,
    ),
>;
pub type TP_WAIT_RESULT = DWORD;

pub type PTP_CALLBACK_INSTANCE = *mut TP_CALLBACK_INSTANCE;

#[repr(C)]
pub struct TP_CALLBACK_INSTANCE {
    pub dummy: *mut c_void,
}
pub type PTP_CALLBACK_ENVIRON = *mut TP_CALLBACK_ENVIRON_V3;

pub type FnTpSetWait =
    unsafe extern "system" fn(Wait: PTP_WAIT, Handle: HANDLE, Timeout: PLARGE_INTEGER);

pub type PTP_WAIT = *mut TP_WAIT;

#[repr(C)]
pub struct TP_WAIT {
    pub dummy: *mut c_void,
}

pub type FnTpReleaseCleanupGroup = unsafe extern "system" fn(CleanupGroup: PTP_CLEANUP_GROUP);

pub type PTP_CLEANUP_GROUP = *mut TP_CLEANUP_GROUP;

#[repr(C)]
pub struct TP_CLEANUP_GROUP {
    pub dummy: *mut c_void,
}

pub type FnCloseThreadpool = unsafe extern "system" fn(Pool: PVOID);

pub type LPFIBER_START_ROUTINE = Option<unsafe extern "system" fn(lpFiberParameter: PVOID)>;

pub type FnConvertThreadToFiber = unsafe extern "system" fn(lpParameter: PVOID) -> PVOID;

pub type FnConvertFiberToThread = unsafe extern "system" fn() -> BOOL;

pub type FnCreateFiber = unsafe extern "system" fn(
    dwStackSize: SIZE_T,
    lpStartAddress: LPFIBER_START_ROUTINE,
    lpParameter: PVOID,
) -> PVOID;

pub type FnDeleteFiber = unsafe extern "system" fn(lpFiber: PVOID);

pub type FnSwitchToFiber = unsafe extern "system" fn(lpFiber: PVOID);

pub const MEM_IMAGE: DWORD = 0x1000000;

#[repr(C)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: PVOID,
    pub AllocationBase: PVOID,
    pub AllocationProtect: DWORD,
    pub RegionSize: SIZE_T,
    pub State: DWORD,
    pub Protect: DWORD,
    pub Type: DWORD,
}

pub type FnNtQueryVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    MemoryInformationClass: u32,
    MemoryInformation: PVOID,
    MemoryInformationLength: usize,
    ReturnLength: *mut usize,
) -> NTSTATUS;
