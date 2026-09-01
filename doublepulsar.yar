rule DoublePulsar_UDRL_Loader
{
    meta:
        description = "Detects DoublePulsar Cobalt Strike UDRL (User-Defined Reflective Loader) shellcode"
        author = "memN0ps"
        date = "2026-03-15"
        reference = "https://github.com/memN0ps/doublepulsar-rs"
        license = "MIT"

    strings:
        $entry = { 56 48 89 E6 48 83 E4 F0 48 83 EC 20 E8 05 00 00 00 48 89 F4 5E C3 }
        $udrl_dll = "udrl.dll"
        $entry_export = "Entry"
        $tp_alloc_timer = "TpAllocTimer"
        $tp_set_timer = "TpSetTimer"
        $tp_alloc_wait = "TpAllocWait"
        $tp_set_wait = "TpSetWait"
        $convert_fiber = "ConvertThreadToFiber"
        $switch_fiber = "SwitchToFiber"
        $sysf032 = "SystemFunction032"
        $rtl_create_heap = "RtlCreateHeap"
        $rtl_walk_heap = "RtlWalkHeap"
        $internet_connect = "InternetConnectA"
        $set_valid_call = "SetProcessValidCallTargets"
        $nt_queue_apc = "NtQueueApcThread"
        $nt_test_alert = "NtTestAlert"

    condition:
        $entry at 0
        and $udrl_dll and $entry_export
        and $sysf032
        and $rtl_create_heap and $rtl_walk_heap
        and (
            ($tp_alloc_timer and $tp_set_timer) or
            ($tp_alloc_wait and $tp_set_wait) or
            ($nt_queue_apc and $nt_test_alert) or
            ($convert_fiber and $switch_fiber)
        )
        and ($internet_connect or $set_valid_call)
        and filesize > 50KB and filesize < 200KB
}

rule DoublePulsar_UDRL_Strings
{
    meta:
        description = "Detects DoublePulsar UDRL via unique string combinations"
        author = "memN0ps"
        date = "2026-03-15"
        reference = "https://github.com/memN0ps/doublepulsar-rs"
        license = "MIT"

    strings:
        $udrl = "udrl.dll"
        $sf032 = "SystemFunction032"
        $sf040 = "SystemFunction040"
        $sf041 = "SystemFunction041"
        $tp_timer = "TpAllocTimer"
        $tp_wait = "TpAllocWait"
        $tp_pool = "TpAllocPool"
        $heap_walk = "RtlWalkHeap"
        $heap_create = "RtlCreateHeap"
        $spoof = "EnumDateFormatsExA"
        $valid_targets = "SetProcessValidCallTargets"

    condition:
        $udrl
        and ($sf032 and $sf040 and $sf041)
        and ($tp_timer or $tp_wait)
        and $tp_pool
        and $heap_walk and $heap_create
        and $spoof
        and $valid_targets
        and filesize > 50KB and filesize < 200KB
}
